#include "filesys/inode.h"
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "buffer-cache.h"
#include "devices/block.h"

/* Debug */
#include "threads/thread.h"
#include "userprog/process.h"

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

static struct lock open_inodes_lock;

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors (off_t size){
	return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* Checks if the index in the array is set, if it is then will return that
   block sector. Otherwise if create is true then it will create that sector
   allocating from the free list then return the new sector */
static block_sector_t check_alloc_install(uint32_t *array, uint32_t idx,
		bool create, bool *changed){

	block_sector_t alloc = ZERO_SECTOR;
	if(array[idx] == ZERO_SECTOR){
		//printf("Array index ZERO\n");
		if(!create){
			//printf("not create\n");
			return ZERO_SECTOR;
		}
		if(!free_map_allocate (1, &alloc)){
			//printf("not alloc\n");
			return ZERO_SECTOR;
		}
		ASSERT(alloc != 1953394531);
		array[idx] = alloc;
		*changed = true;
	}/*else{
		//printf("Array index nonZERO\n");

	}*/
	return array[idx];
}

/* Offset array is an array starting with the offset of the sector
   in the block, the offset of the indirect sector in the array,
   then the offset of the double indirect block in the array,
   then the offset of the triple indirect block in the array.
   Array changes between calls to this recursive function the caller
   of the function will provide an array in the base inode and the offset
   of the sector in the correct place in the offset array. The depth will
   be the following triple indirect blocks depth = 3, double indirect blocks
   depth = 2, regular indirect blocks depth = 1. Depth should never be passed
   in 0 or something bad will happen */
static block_sector_t recursive_read_sector(uint32_t *array, uint32_t *offset_array,
		uint32_t depth, bool create, bool *changed){

	ASSERT(depth > 0);
	block_sector_t ret;
	struct cache_entry *entry ;
	struct indirect_block i_block;

	block_sector_t this_sector =
			check_alloc_install(array, offset_array[depth], create, changed);

	if(this_sector == ZERO_SECTOR){
		return ZERO_SECTOR;
	}

	bool lower_level_changed = false;

	entry = bcache_get_and_lock(this_sector, CACHE_INDIRECT);

	memcpy(&i_block, entry->data, BLOCK_SECTOR_SIZE);
	bcache_unlock(entry, UNLOCK_NORMAL);

	if(depth == 1){
		/* This is a regular indirect pointer block just check if the sector is set
		   and set it to a new sector if necessary*/
		ret = check_alloc_install(i_block.ptrs, offset_array[depth-1], create,
				&lower_level_changed);
	}else{
		/* This is a triple or double indirect block so we need to look up the
		   sector from one of the blocks that we are pointing to */
		ret = recursive_read_sector(i_block.ptrs, offset_array, depth - 1,
				create, &lower_level_changed);
	}

	if(lower_level_changed){
		/* An entry in this indirect block has been created so we need to update the
		   cache (maybe flush to disk??? UNLOCK_FLUSH)*/
		entry = bcache_get_and_lock(this_sector, CACHE_INDIRECT);
		memcpy(entry->data, &i_block, BLOCK_SECTOR_SIZE);
		entry->flags |= CACHE_E_DIRTY;
		bcache_unlock(entry, UNLOCK_NORMAL);
	}
	return ret;
}

/* Returns the block device sector that contains byte offset at pos,
   if create is true will create anything that is necessary along
   the traversal of the inode structure. If create is false and we
   find any pointers to the ZERO_SECTOR along our traversal then we
   will return the ZERO_SECTOR. */
static block_sector_t byte_to_sector (const struct inode *inode, off_t pos, bool create){
	ASSERT (inode != NULL);

	uint32_t file_sector = pos / BLOCK_SECTOR_SIZE;

	//printf("Byte to sector File sector %u create %u\n", file_sector, create);

	block_sector_t ret = ZERO_SECTOR;

	uint32_t offset_array[4];

	ASSERT(inode->sector != ZERO_SECTOR);

	struct cache_entry *entry = bcache_get_and_lock(inode->sector, CACHE_INODE);

	struct disk_inode inode_d;

	memcpy(&inode_d, entry->data, BLOCK_SECTOR_SIZE);

	bcache_unlock(entry, UNLOCK_NORMAL);

	bool changed = false;

	/* For conciseness in space the i suffix/prefix signifies an indirect block
	   a d signifies a double indirect block and a t signifies a triply
	   indirect block */
	if(file_sector < NUM_REG_BLK){
		/* Read directly from inode */
		//printf("read direct\n");
		ret = check_alloc_install(inode_d.block_ptrs, file_sector, create, &changed);
		//bcache_unlock(entry, UNLOCK_NORMAL);
		//printf("byte to sector ret reg block sector %u\n", ret);
	}else{
		/* The number of the indirect sector that the data resides on*/
		uint32_t i_file_sector =
				((PTR_PER_BLK)+(file_sector - NUM_REG_BLK))/PTR_PER_BLK;

		/* The offset in the indirect block of the sector we are looking for */
		uint32_t i_sec_offset = (file_sector - NUM_REG_BLK) % PTR_PER_BLK;

		/* minus one because of the way we calculated indt_sec_num, and it
		   isn't an index */
		if((i_file_sector-1) < NUM_IND_BLK){

			offset_array[0] = i_sec_offset;
			offset_array[1] = i_file_sector -1;

			//printf("read indirect\n");
			//ret = i_read_sector(inode_d->i_ptrs, (i_file_sector-1),
			//						i_sec_offset, create, &changed);

			ret = recursive_read_sector(inode_d.i_ptrs, offset_array, 1, create, &changed);

			//printf("byte to sector ret ind block sector %u\n", ret);
		}else{

			/* The number of the double indirect sector that the indirect sector
		   	   resides on*/
			uint32_t d_file_sector =
					((PTR_PER_BLK)+((i_file_sector-1)-NUM_IND_BLK))/PTR_PER_BLK;
			uint32_t d_sec_offset=((i_file_sector-1)-NUM_IND_BLK)%PTR_PER_BLK;

			/* Minus one because of the way that dbl indt sec is calculated*/
			if((d_file_sector-1) < NUM_DBL_BLK){

				offset_array[0] = i_sec_offset;
				offset_array[1] = d_sec_offset;
				offset_array[2] = d_file_sector -1;

				//printf("read double indirect\n");
				//ret = d_read_sector(inode_d->d_ptrs, (d_file_sector-1),
				//		    				 d_sec_offset, i_sec_offset, create, &changed);

				ret = recursive_read_sector(inode_d.d_ptrs, offset_array, 1, create, &changed);

				//bcache_unlock(entry, UNLOCK_NORMAL);
				//printf("byte to sector ret dbl block sector %u\n", ret);
			}else{
				//printf("read triple indirect\n");
				/* The number of the triple indirect block that this sector
				   resides on. Can really only be 1 or zero*/
				uint32_t t_file_sector =
					  ((PTR_PER_BLK)+((d_file_sector-1)-NUM_DBL_BLK))/PTR_PER_BLK;
				uint32_t t_sec_offset=((d_file_sector-1)-NUM_DBL_BLK)%PTR_PER_BLK;
				if(t_file_sector > NUM_TRP_BLK){
					/* our inodes only support at most one triple indirect sector
					   so the request for this offset is greater than 1 GB and can
					   not be satisfied*/
					//bcache_unlock(entry, UNLOCK_NORMAL);
					//printf("byte to sector ret trip1 block sector %u\n", ZERO_SECTOR);
					return ZERO_SECTOR;
				}
				offset_array[0] = i_sec_offset;
				offset_array[1] = d_sec_offset;
				offset_array[2] = t_sec_offset;
				offset_array[3] = (t_file_sector-1);

				//ret = t_read_sector(inode_d->t_ptrs, (t_file_sector-1),
				//		t_sec_offset, d_sec_offset, i_sec_offset, create, &changed);

				ret = recursive_read_sector(inode_d.t_ptrs, offset_array, 1, create, &changed);

				//printf("byte to sector ret trip block sector %u\n", ret);
			}
		}
	}

	/* The block that we looked at to get the sector was updated by this call
	   so we need to update the cache (maybe flush to disk??? UNLOCK_FLUSH)*/
	if(changed){
		struct cache_entry *entry = bcache_get_and_lock(inode->sector, CACHE_INODE);
		ASSERT(entry != NULL);
		memcpy(entry->data, &inode_d, BLOCK_SECTOR_SIZE);
		entry->flags |= CACHE_E_DIRTY;
		bcache_unlock(entry, UNLOCK_NORMAL);
	}
	return ret;
}

/* Initializes the inode module. */
void inode_init (void){
	list_init (&open_inodes);
	lock_init (&open_inodes_lock);
	bcache_init();
}

/* Creates a new inode, writing the inode itself immediately
   to the system. The inode is created with length,
   however nothing is allocated, when things get read in they
   will be all zeroes Files grow with writes only.
   When a seek/write combo creates empty sectors between the
   EOF and the new write those sectors will point to the ZERO_SECTOR
   Returns true if sector is already allocated. */
bool inode_create (block_sector_t sector, off_t length, bool is_dir){
	//printf("inode create dir %u\n", is_dir);

	ASSERT(sector != ZERO_SECTOR);

	if(!free_map_is_allocated(sector)){
		/* Make this an assert perhaps ?*/
		//printf("not alloc\n");
		return false;
	}

	/* Make sure that we have the correct sized disk inode*/
	ASSERT(sizeof(struct disk_inode));

	struct cache_entry *e = bcache_get_and_lock(sector, CACHE_INODE);
	struct disk_inode *disk_inode = (struct disk_inode*)e->data;

	/* This sets all the block pointers to 0 also */
	memset(disk_inode, 0, BLOCK_SECTOR_SIZE);

	/* Allocate as writes come in */
	disk_inode->file_length = length;
	disk_inode->magic = INODE_MAGIC;
	if(is_dir){
		disk_inode->flags |= INODE_IS_DIR;
	}
	bcache_unlock(e, UNLOCK_FLUSH);

	//printf("create ret\n");
	return true;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *inode_open (block_sector_t sector){
	struct list_elem *e;
	struct inode *inode;

	ASSERT(sector != ZERO_SECTOR);

	if(!free_map_is_allocated(sector)){
		/* Make this an assert perhaps ?*/
		//printf("inode open nULL 1\n");
		return NULL;
	}

	//printf("opening inode at sector %u\n", sector);

	/* Inodes need the open_inodes_lock to close and
	   remove the inode */
	lock_acquire(&open_inodes_lock);
	/* Check whether this inode is already open. */
	for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
			e = list_next (e)){
		inode = list_entry (e, struct inode, elem);
		lock_acquire(&inode->meta_data_lock);

		if (inode->sector == sector){
			if(!inode->removed){
				//printf("Reoppend\n");
				inode->open_cnt++;
			}else{
				/* Can't open this inode any more */
				inode = NULL;
			}
			lock_release(&inode->meta_data_lock);
			lock_release(&open_inodes_lock);
			//printf("return one inode null? %u\n", inode == NULL);
			return inode;
		}
		lock_release(&inode->meta_data_lock);
	}
	lock_release(&open_inodes_lock);

	/* Allocate memory. */
	inode = malloc (sizeof *inode);
	if (inode == NULL){
		/* Out of memory uh oh*/
		//printf("out of memory null\n");
		return NULL;
	}
	/* Initialize. */
	inode->sector = sector;
	inode->open_cnt = 1;
	inode->deny_write_cnt = 0;
	inode->removed = false;
	lock_init(&inode->writer_lock);
	lock_init(&inode->reader_lock);
	lock_init(&inode->meta_data_lock);

	//printf("bcache it\n");
	/* if just created will already be in the cache and on disk*/
	struct cache_entry *entry = bcache_get_and_lock(sector, CACHE_INODE);
	struct disk_inode *data = (struct disk_inode*)entry->data;

	inode->cur_length = data->file_length;

	bcache_unlock(entry, UNLOCK_NORMAL);

	lock_acquire(&open_inodes_lock);
	list_push_front (&open_inodes, &inode->elem);
	lock_release(&open_inodes_lock);
	//printf("Return inode final\n");
	return inode;
}

/* Reopens and returns INODE if it hasn't been removed*/
struct inode *inode_reopen (struct inode *inode){
	ASSERT(inode != NULL);
	lock_acquire(&inode->meta_data_lock);
	if(inode->removed){
		lock_release(&inode->meta_data_lock);
		return NULL;
	}
	inode->open_cnt ++;
	lock_release(&inode->meta_data_lock);
	return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber (const struct inode *inode){
	return inode->sector;
}

static void free_block_sectors(uint32_t *array, uint32_t size){
	uint32_t i;
	for(i = 0; i < size; i++){
		if(array[i] != ZERO_SECTOR){
			/* These blocks have already been invalidated in
			   our cache as long as we don't get them here*/
			block_write(fs_device, array[i], zeroed_sector);
			free_map_release (array[i], 1);
			array[i] = 0;
		}
	}
}

/* Recursive clean up :) */
static void free_indirect_blocks(uint32_t *array, uint32_t size, uint32_t count){
	uint32_t i;
	for(i = 0; i < size; i++){
		if(array[i] != ZERO_SECTOR){
			struct cache_entry *entry =
					bcache_get_and_lock(array[i], CACHE_DATA);
			struct indirect_block *b = (struct indirect_block*)entry->data;
			if(count == 1){
				free_block_sectors(b->ptrs, PTR_PER_BLK);
			}else{
				free_indirect_blocks(b->ptrs, PTR_PER_BLK, --count);
			}
			block_write(fs_device, array[i], zeroed_sector);
			free_map_release(array[i], 1);
			bcache_unlock(entry, UNLOCK_INVALIDATE);
		}
	}
}


/* Closes INODE and writes it to disk !!! May wait on IO.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close (struct inode *inode){
	/* Ignore null pointer. */
	if(inode == NULL){
		return;
	}

	/* Acquire both locks, make sure no IO occurs
	   with the global lock held*/
	lock_acquire(&open_inodes_lock);
	lock_acquire(&inode->meta_data_lock);

	/* Release resources if this was the last opener. */
	if(--inode->open_cnt == 0){

		/* Flush the entire cache to disk now because all our
		   data may be changed and we don't know which sectors
		   are in the cache so just write all of it out now*/
		bcache_flush();

		/* Remove from inode list and release lock. */
		//printf("inode closed\n");
		list_remove (&inode->elem);

		/* Deallocate blocks if removed. */
		if(inode->removed){
			//printf("inode removed\n");
			/* the data we were protecting has been read*/
			lock_release(&inode->meta_data_lock);
			lock_release(&open_inodes_lock);

			struct cache_entry *entry =
					bcache_get_and_lock(inode->sector, CACHE_DATA);
			struct disk_inode *d_inode = (struct disk_inode*)entry->data;
			/* Here we need to go through the entire
			   inode structure and get all of the sectors
			   that are allocated up to length and free them
			   in the map*/
			free_block_sectors(d_inode->block_ptrs, NUM_REG_BLK);

			free_indirect_blocks(d_inode->i_ptrs, NUM_IND_BLK, 1);

			free_indirect_blocks(d_inode->d_ptrs, NUM_IND_BLK, 2);

			free_indirect_blocks(d_inode->t_ptrs, NUM_IND_BLK, 3);

			free_map_release (inode->sector, 1);

			bcache_unlock(entry, UNLOCK_INVALIDATE);

			/* Invalidate the cache because we may have entries
			   in it from this file which are stale and not to be
			   written back to disk at all because they may belong
			   to another file by the time they are evicted!!*/
			bcache_invalidate();

			/* Zero out the sector */
			block_write(fs_device, inode->sector, zeroed_sector);
			//printf("removed and freeing entries in freemap\n");

		}else{
			//printf("inode not removed\n");
			/* the data we were protecting has been read*/
			lock_release(&inode->meta_data_lock);
			lock_release(&open_inodes_lock);
		}
		free (inode);
	}else{
		/* the data we were protecting has been read*/
		lock_release(&inode->meta_data_lock);
		lock_release(&open_inodes_lock);
		//printf("inode not closed\n");
	}

}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove (struct inode *inode){
	ASSERT (inode != NULL);
	/* Should always be called with open
	   count greater than one unless
	   we coded wrong. Only when open count
	   goes to 0 will the inode be freed.*/
	lock_acquire(&inode->meta_data_lock);
	inode->removed = true;
	lock_release(&inode->meta_data_lock);
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset){
	uint8_t *buffer = buffer_;
	off_t bytes_read = 0;

	//printf("size %u, offset %u ino length %u ino%u\n", size, offset, inode->cur_length, inode->sector);

	lock_acquire(&inode->reader_lock);
	off_t eof = inode->cur_length;
	lock_release(&inode->reader_lock);

	/* offset is beyond the end of file no
	   reading to be done */
	if(offset >= eof){
		return 0;
	}

	/* Only read up to eof then stop*/
	if(offset+size >= eof){
		size = eof - offset;
	}

	while (size > 0){
		/* Disk sector to read, starting byte offset within sector. */
		block_sector_t sector_idx = byte_to_sector (inode, offset, false);
		//printf("read sector %u\n", sector_idx);

		block_sector_t next_sector =
				byte_to_sector(inode, offset + BLOCK_SECTOR_SIZE, false);

		//printf("read next sector %u\n", next_sector);
		int sector_ofs = offset % BLOCK_SECTOR_SIZE;

		/* Bytes left in inode, bytes left in sector, lesser of the two. */
		off_t inode_left = eof - offset;
		int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
		int min_left = inode_left < sector_left ? inode_left : sector_left;

		/* Number of bytes to actually copy out of this sector. */
		int chunk_size = size < min_left ? size : min_left;
		if (chunk_size <= 0){
			break;
		}

		/* REad ahead the next sector if it isn't all zeroes*/
		if(next_sector != ZERO_SECTOR){
			//printf("bef read ahead\n");
			bcache_asynch_read(next_sector);
			//printf("read ahead\n");
		}

		if(sector_idx == ZERO_SECTOR){
			/* Read all zeros for the entire sector. Sparse files with sector
			   pointers that point to ZERO_SECTOR don't actually have that
			   sector allocated.*/
			memcpy(buffer + bytes_read, zeroed_sector, chunk_size);
		}else{
			struct cache_entry *entry = bcache_get_and_lock(sector_idx, CACHE_DATA);

			printf("Got entry with sector %u looking at sector idx %u offset %u pid %u\n", entry->sector_num, sector_idx, offset, thread_current()->process->pid);

			memcpy (buffer + bytes_read, entry->data + sector_ofs, chunk_size);

			bcache_unlock(entry, UNLOCK_NORMAL);

		}
		/* Advance. */
		size -= chunk_size;
		offset += chunk_size;
		bytes_read += chunk_size;
		//printf("size %d\n", size);
	}

	//printf("read ret\n");
	return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if a kernel panic occurs. Grows the file if the
   write goes past the end of file marker. */
off_t inode_write_at (struct inode *inode, const void *buffer_, off_t size,
		off_t offset){
	//printf("inode write %u %u inode %u\n", size, offset, inode->sector);
	const uint8_t *buffer = buffer_;
	off_t bytes_written = 0;

	uint32_t filesys_size =(block_size(fs_device)*BLOCK_SECTOR_SIZE);

	bool extending = false;
	//printf("Acquire meta\n");
	lock_acquire(&inode->meta_data_lock);
	if (inode->deny_write_cnt){
		lock_release(&inode->meta_data_lock);
		return 0;
	}
	lock_release(&inode->meta_data_lock);

	//printf("Acquire eof locks\n");
	lock_acquire(&inode->writer_lock);
	lock_acquire(&inode->reader_lock);
	off_t eof = inode->cur_length;
	lock_release(&inode->reader_lock);

	//printf("eof is %d\n", eof);

	if((offset+size) >= eof){
		if((uint32_t)(offset+size) >= filesys_size){
			size = filesys_size - offset;
		}

		extending = true;
		//printf("extending!\n");
	}else{
		lock_release(&inode->writer_lock);
	}

	//printf("locks acquired\n");
	/* We do nothing special for the sectors between
	   eof and the write that we are making, this means
	   that the block pointers for them will still be
	   read null, but when writing to them they will
	   not need to be extended but be created automatically
	   by byte_to_sector*/

	while (size > 0){
		/* Sector to write, starting byte offset within sector.
		   byte_to_sector will allocate and install the sector in
		   the inode for us! It will not, however, be in the cache*/
		//printf("Byte to sector\n");
		block_sector_t sector_idx = byte_to_sector (inode, offset, true);

		//printf("sector idx %u\n", sector_idx);

		if(sector_idx == 0){
			if(extending){
				lock_release(&inode->writer_lock);
			}
			return bytes_written;
		}

		int sector_ofs = offset % BLOCK_SECTOR_SIZE;

		/* We only care about the end of the sector. */
		int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;

		/* Number of bytes to actually write into this sector.
		   write until the end of the sector or until size bytes
		   have been written. */
		int chunk_size = size < sector_left ? size : sector_left;
		if (chunk_size <= 0){
			break;
		}

		printf("bcache get sector %u offset %u pid %u\n", sector_idx, offset, thread_current()->process->pid);
		struct cache_entry *entry = bcache_get_and_lock(sector_idx, CACHE_DATA);

		if(entry == NULL){
			if(extending){
				lock_release(&inode->writer_lock);
			}

			return bytes_written;
		}

		//printf("Got entry with sector %u looking at sector idx %u
		//sector offset %u chunk size %u bytes written %u\n",
		//entry->sector_num, sector_idx, sector_ofs, chunk_size, bytes_written);
		memcpy (entry->data + sector_ofs, buffer + bytes_written, chunk_size);

		//printf("Change flag\n");
		entry->flags |= CACHE_E_DIRTY;

		bcache_unlock(entry, UNLOCK_NORMAL);

		/* Advance. */
		size -= chunk_size;
		offset += chunk_size;
		bytes_written += chunk_size;
	}

	if(extending){
		lock_acquire(&inode->reader_lock);
		//printf("New eof %u\n", offset);
		inode->cur_length = offset;
		struct cache_entry *entry = bcache_get_and_lock(inode->sector, CACHE_INODE);
		struct disk_inode *inode_d = (struct disk_inode*)entry->data;
		inode_d->file_length = offset;
		bcache_unlock(entry, UNLOCK_FLUSH);
		lock_release(&inode->reader_lock);
		lock_release(&inode->writer_lock);
	}

	//printf("inode write end %u\n", bytes_written);
	return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write (struct inode *inode){
	lock_acquire(&inode->meta_data_lock);
	inode->deny_write_cnt++;
	ASSERT (inode->deny_write_cnt <= inode->open_cnt);
	lock_release(&inode->meta_data_lock);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write (struct inode *inode){
	lock_acquire(&inode->meta_data_lock);
	ASSERT (inode->deny_write_cnt > 0);
	ASSERT (inode->deny_write_cnt <= inode->open_cnt);
	inode->deny_write_cnt--;
	lock_release(&inode->meta_data_lock);
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length (struct inode *inode){
	lock_acquire(&inode->reader_lock);
	off_t eof = inode->cur_length;
	lock_release(&inode->reader_lock);
	return eof;
}

/* Removes the inode if it is a directory and it isn't
   open. Returns true on success and false on failure*/
bool inode_remove_dir(struct inode *inode){
	bool removed = false;
	if(inode == NULL){
		return removed;
	}
	lock_acquire(&inode->meta_data_lock);
	//printf("open count is %u\n", inode->open_cnt);
	if(inode->open_cnt == 1 && inode_is_dir(inode)){
		removed = true;
		inode->removed = true;
	}
	lock_release(&inode->meta_data_lock);
	return removed;
}

bool inode_is_dir(struct inode *inode){
	//printf("Inode is dir\n");
	if(inode == NULL){
		//printf("inode is dir was null\n");
		return NULL;
	}
	//printf("inode sector %u\n", inode->sector);
	struct cache_entry *entry = bcache_get_and_lock(inode->sector, CACHE_INODE);
	struct disk_inode *inode_d = (struct disk_inode*)entry->data;
	bool is_dir = (inode_d->flags & INODE_IS_DIR) != 0;
	bcache_unlock(entry, UNLOCK_NORMAL);
	//printf("inode return\n");
	return is_dir;
}
