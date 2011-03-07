#ifndef BUFFER_CACHE_H_
#define BUFFER_CACHE_H_

#include "devices/block.h"
#include <list.h>
#include <hash.h>
#include "threads/synch.h"
#include <stdbool.h>
#include <stdint.h>

/* Max number of cache slots */
#define MAX_CACHE_SLOTS 64

/* The number of meta priorities */
#define NUM_PRIORITIES 3

enum meta_priority{
	CACHE_INODE,		/* This cache entry will represent
						   inode datat and should be highly
						   valued */
	CACHE_INDIRECT,     /* This cache entry represents an indirect
						   Block and is somewhat valued  */
	CACHE_DATA			/* This cache entry represents plain data
						   and should only be really valued if there
						   are major accesses to it */
};

struct cache_entry{
	block_sector_t sector_num;        /* The sector that this entry holds*/
	uint8_t data [BLOCK_SECTOR_SIZE]; /* The almighty DATA */
	bool dirty;						  /* Whether this cache entry is dirty
										 set by the caller of bcache_get_lock*/
	struct lock entry_lock;           /* Lock on the cache_entry, this is valid
										 because we must guarantee atomicity on
										 the block level so only one thread can
										 access this entry at any given time */
	struct list_elem eviction_elem;   /* list elem for one of the eviction lists*/
	struct hash_elem lookup_elem;     /* hash_elem to quickly look up this entry */
	uint32_t access_count;			  /* A count to be incremented in bcache_get
										 and used to premote the priority of the
										 cache entry if necessary */
	enum meta_priority cur_pri;		  /* The current priority of this cache entry*/
};

void bcache_init(void);
struct cache_entry *bcache_get_and_lock(block_sector_t sector, enum meta_priority pri);
void bcache_unlock(struct cache_entry *entry);

void bcache_asynch_sector_fetch(block_sector_t sector);
void bcache_flush(void);

#endif /* BUFFER_CACHE_H_ */
