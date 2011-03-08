#include "filesys/free-map.h"
#include <bitmap.h>
#include <debug.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/synch.h"

static struct file *free_map_file;   /* Free map file. */
static struct bitmap *free_map;      /* Free map, one bit per sector. */

static struct lock free_map_lock;

/* Initializes the free map. */
void free_map_init (void){
	free_map = bitmap_create (block_size (fs_device));
	lock_init(free_map_lock);
	//printf("Freemap %p and %d\n", free_map, free_map->bit_cnt);
	if(free_map == NULL){
		PANIC ("bitmap creation failed--file system device is too large");
	}
	bitmap_mark (free_map, ZERO_SECTOR);
	bitmap_mark (free_map, FREE_MAP_SECTOR);
	bitmap_mark (free_map, ROOT_DIR_SECTOR);
}

/* Allocates CNT consecutive sectors from the free map and stores
   the first into *SECTORP.
   Returns true if successful, false if not enough consecutive
   sectors were available or if the free_map file could not be
   written. */
bool free_map_allocate (size_t cnt, block_sector_t *sectorp){
	lock_acquire(&free_map_lock);
	block_sector_t sector = bitmap_scan_and_flip (free_map, 0, cnt, false);
	lock_release(&free_map_lock);
	//printf("free map allocate\n");

	/* make changes permanent
	if(free_map_file != NULL && sector != BITMAP_ERROR
			&& !bitmap_write (free_map, free_map_file)){
		bitmap_set_multiple (free_map, sector, cnt, false);
		sector = BITMAP_ERROR;
	}
	*/
	if(sector != BITMAP_ERROR){
		*sectorp = sector;
	}
	//printf("free map allocate end\n");
	return sector != BITMAP_ERROR;
}



bool free_map_is_allocated(block_sector_t sector){
	lock_acquire(&free_map_lock);
	bool is_alloc =bitmap_test(free_map, sector);
	lock_release(&free_map_lock);
	return is_alloc;
}

/* Makes CNT sectors starting at SECTOR available for use. */
void free_map_release (block_sector_t sector, size_t cnt){
	ASSERT (bitmap_all (free_map, sector, cnt));
	lock_acquire(&free_map_lock);
	bitmap_set_multiple (free_map, sector, cnt, false);
	lock_release(&free_map_lock);
	//printf("free map release");

	/* Make changes permanent */
	//bitmap_write (free_map, free_map_file);
}

/* Opens the free map file and reads it from disk.
   only called by filesys_init so provides no locking
   because the filesys is only inited by one thread
   before any other threads are allowed to run*/
void free_map_open (void){
	//printf("freemap open");
	struct inode *i = inode_open (FREE_MAP_SECTOR);
	ASSERT(i != NULL);
	free_map_file = file_open (i);
	if(free_map_file == NULL){
		PANIC ("can't open free map");
	}
	if(!bitmap_read (free_map, free_map_file)){
		PANIC ("can't read free map");
	}
}

/* Writes the free map to disk and closes the free map file.
   No locking provided here either for the same reason as free
   map open. This is only called in filesys init and filesys
   format, both running only one thread.*/
void free_map_close (void){
	//printf("freemap close\n");
	free_map_persist();
	file_close (free_map_file);
}

/* Creates a new free map file on disk and writes the free map to
   it. No locking on this beezy either.*/
void free_map_create (void){
	//printf("freemap create\n");
	/* Create inode. */
	if(!inode_create (FREE_MAP_SECTOR, bitmap_file_size (free_map))){
		PANIC ("free map creation failed");
	}

	/* Write bitmap to file. */
	free_map_file = file_open (inode_open (FREE_MAP_SECTOR));
	if(free_map_file == NULL){
		PANIC ("can't open free map");
	}

	/* Should allocate all sectors here*/
	if(!bitmap_write (free_map, free_map_file)){
		PANIC ("can't write free map");
	}
}

void free_map_persist(void){
	/* This function should have found all of the sectors in the
	   free map file already allocated*/
	if(free_map_file == NULL){
		return;
	}
	/* We count on the atomicity of setting and flipping bits to
	   provide a close approximation of the free map at this moment
	   give or take minor losses. Because this will be called every
	   10-30 seconds we don't mind too much though. If the filesys
	   shutsdown normally then this will be called without races
	   from the single main thread.*/
	bitmap_write (free_map, free_map_file);
}
