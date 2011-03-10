#include "filesys/inode.h"
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "buffer-cache.h"

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
static block_sector_t check_alloc_install(uint32_t *array, uint32_t idx, bool create){
	block_sector_t alloc;
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
		array[idx] = alloc;
	}/*else{
		//printf("Array index nonZERO\n");
	}*/
	return array[idx];
}

/* Array can be from either a double indirect block or an inode */
static block_sector_t i_read_sector(uint32_t*array, uint32_t i_off,
		uint32_t sector_off, bool create){

	/* Read indirect block from inode and
	   then read the sector from there*/
	block_sector_t ret;

	block_sector_t i_sector =
			check_alloc_install(array, i_off, create);

	if(i_sector == ZERO_SECTOR){
		return ZERO_SECTOR;
	}

	struct cache_entry *i_entry =
			bcache_get_and_lock(i_sector, CACHE_INDIRECT);

	struct indirect_block *i_block = (struct indirect_block*)i_entry->data;

	ret = check_alloc_install(i_block->ptrs, sector_off, create);

	bcache_unlock(i_entry, UNLOCK_NORMAL);
	return ret; /* May be ZERO_SECTOR */
}

/* array is the array in which to find the dbl indirect sector num
   in our case either the array in the inode or an array in a triple
   indirect block*/
static block_sector_t d_read_sector(uint32_t *array, uint32_t d_off,
		uint32_t i_off, uint32_t sector_off, bool create){
	/*Read in dbl, then read in indirect, then return
	  the address there */
	block_sector_t ret;

	block_sector_t d_sector =
			check_alloc_install(array, d_off, create);
	if(d_sector == ZERO_SECTOR){
		return ZERO_SECTOR;
	}

	struct cache_entry *d_entry =
			bcache_get_and_lock(d_sector, CACHE_INDIRECT);
	struct indirect_block *d_block = (struct indirect_block*)d_entry->data;

	/* read sector from indirect */

	ret = i_read_sector(d_block->ptrs, i_off, sector_off, create);

	bcache_unlock(d_entry, UNLOCK_NORMAL);
	return ret; /* May be ZERO_SECTOR */
}

static block_sector_t t_read_sector(uint32_t *array, uint32_t t_off,
		uint32_t d_off, uint32_t i_off, uint32_t sector_off, bool create){
	block_sector_t ret;

	block_sector_t t_sector =
			check_alloc_install(array, t_off, create);
	if(t_sector == ZERO_SECTOR){
		return ZERO_SECTOR;
	}

	struct cache_entry *t_entry =
			bcache_get_and_lock(t_sector, CACHE_INDIRECT);
	struct indirect_block *t_block = (struct indirect_block*)t_entry->data;

	/* read sector from double indirect block */
	ret = d_read_sector(t_block->ptrs, d_off, i_off, sector_off, create);
	bcache_unlock(t_entry, UNLOCK_NORMAL);
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

	struct cache_entry *entry = bcache_get_and_lock(inode->sector, CACHE_INODE);
	struct disk_inode *inode_d = (struct disk_inode*)entry->data;

	/* For conciseness in space the i suffix/prefix signifies an indirect block
	   a d signifies a double indirect block and a t signifies a triply
	   indirect block */
	if(file_sector < NUM_REG_BLK){
		/* Read directly from inode */
		ret = check_alloc_install(inode_d->block_ptrs, file_sector, create);
		bcache_unlock(entry, UNLOCK_NORMAL);
		//printf("byte to sector ret reg block sector %u\n", ret);
		return ret; /* May be zero sector still ;) */
	}else{
		/* The number of the indirect sector that the data resides on*/
		uint32_t i_file_sector =
				((PTR_PER_BLK)+(file_sector - NUM_REG_BLK))/PTR_PER_BLK;

		uint32_t i_sec_offset = (file_sector - NUM_REG_BLK) % PTR_PER_BLK;

		/* minus one because of the way we calculated indt_sec_num */
		if((i_file_sector-1) < NUM_IND_BLK){

			ret = i_read_sector(inode_d->i_ptrs, (i_file_sector-1),
									i_sec_offset, create);

			bcache_unlock(entry, UNLOCK_NORMAL);
			//printf("byte to sector ret ind block sector %u\n", ret);
			return ret; /* May be ZERO_SECTOR */
		}else{

			/* The number of the double indirect sector that the indirect sector
		   	   resides on*/
			uint32_t d_file_sector =
					((PTR_PER_BLK)+((i_file_sector-1)-NUM_IND_BLK))/PTR_PER_BLK;
			uint32_t d_sec_offset=((i_file_sector-1)-NUM_IND_BLK)%PTR_PER_BLK;

			/* Minus one because of the way that dbl indt sec is calculated*/
			if((d_file_sector-1) < NUM_DBL_BLK){

				ret = d_read_sector(inode_d->d_ptrs, (d_file_sector-1),
						    				 d_sec_offset, i_sec_offset, create);

				bcache_unlock(entry, UNLOCK_NORMAL);
				//printf("byte to sector ret dbl block sector %u\n", ret);
				return ret;
			}else{

				/* The number of the triple indirect block that this sector
				   resides on. Can really only be 1 or zero*/
				uint32_t t_file_sector =
					  ((PTR_PER_BLK)+((d_file_sector-1)-NUM_DBL_BLK))/PTR_PER_BLK;
				uint32_t t_sec_offset=((d_file_sector-1)-NUM_DBL_BLK)%PTR_PER_BLK;
				if(t_file_sector > NUM_TRP_BLK){
					/* our inodes only support at most one triple indirect sector
					   so the request for this offset is greater than 1 GB and can
					   not be satisfied*/
					bcache_unlock(entry, UNLOCK_NORMAL);
					//printf("byte to sector ret trip1 block sector %u\n", ZERO_SECTOR);
					return ZERO_SECTOR;
				}
				ret = t_read_sector(inode_d->t_ptrs, (t_file_sector-1),
						t_sec_offset, d_sec_offset, i_sec_offset, create);
				bcache_unlock(entry, UNLOCK_NORMAL);
				//printf("byte to sector ret trip block sector %u\n", ret);
				return ret;
			}
		}
	}
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
	printf("inode create dir %u\n", is_dir);

	if(!free_map_is_allocated(sector)){
		/* Make this an assert perhaps ?*/
		printf("not alloc\n");
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

	printf("create ret\n");
	return true;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *inode_open (block_sector_t sector){
	struct list_elem *e;
	struct inode *inode;


	if(!free_map_is_allocated(sector)){
		/* Make this an assert perhaps ?*/
		printf("inode open nULL 1\n");
		return NULL;
	}

	printf("opening inode at sector %u\n", sector);

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
			printf("return one inode null? %u\n", inode == NULL);
			return inode;
		}
		lock_release(&inode->meta_data_lock);
	}
	lock_release(&open_inodes_lock);

	/* Allocate memory. */
	inode = malloc (sizeof *inode);
	if (inode == NULL){
		/* Out of memory uh oh*/
		printf("out of memory null\n");
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

	printf("bcache it\n");
	struct cache_entry *entry = bcache_get_and_lock(inode->sector, CACHE_INODE);
	struct disk_inode *inode_d = (struct disk_inode*)entry->data;
	bool is_dir = (inode_d->flags & INODE_IS_DIR) != 0;
	bcache_unlock(entry, UNLOCK_NORMAL);
	//printf("inode return\n");
	return is_dir;
}
