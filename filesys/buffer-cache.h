#ifndef BUFFER_CACHE_H_
#define BUFFER_CACHE_H_

#include "devices/block.h"
#include <list.h>
#include <hash.h>
#include "threads/synch.h"
#include <stdbool.h>
#include <stdint.h>

/* Max number of cache slots */
#define MAX_CACHE_SLOTS 63

/* The number of meta priorities */
#define NUM_PRIORITIES 3

/* The zero sector counts toward our size of the cache*/
uint8_t zeroed_sector[BLOCK_SECTOR_SIZE];

enum meta_priority{
	/* This cache entry will represent  inode datat and
	   should be highly valued */
	CACHE_INODE,

	/* This cache entry represents an indirect block and is somewhat valued*/
	CACHE_INDIRECT,

	/* This cache entry represents plain data and should only be really
	 valued if there are major accesses to it (i.e. it gets promoted)*/
	CACHE_DATA
};

/* Whether this cache entry is dirty set by the caller of bcache_get_lock*/
#define CACHE_E_DIRTY  1

/* Whether this cache entry is in the the middle of being evicted*/
#define CACHE_E_EVICTING  (1<<1)

/* Whether this cache entry has been used before */
#define CACHE_E_INITIALIZED (1<<2)

/* The cache entry is invalid */
#define CACHE_E_INVALID (1<<3)

struct cache_entry{
	/* The sector that this entry holds*/
	block_sector_t sector_num;

	 /* The almighty DATA */
	uint8_t data [BLOCK_SECTOR_SIZE];

 	/* Flags for the cache_entry */
	uint8_t flags;

	/* Lock on the cache_entry, this is valid because we must
	   guarantee atomicity on the block level so only one thread
	   can access this entry at any given time */
	struct lock entry_lock;

	/* list elem for one of the eviction lists*/
	struct list_elem eviction_elem;

	/* hash_elem to quickly look up this entry */
	struct hash_elem lookup_e;

	/* A count to be incremented in bcache_get and used to
	   premote the priority of the cache entry if necessary */
	uint32_t num_hits;

	/* The current priority of this cache entry used for eviction*/
	enum meta_priority cur_pri;


	/* The number of threads that are actively trying to access this
	   cache block, incremented in bcache_get. This is to make sure
	   that one thread does not read new data because it's data got evicted */
	uint32_t num_accessors;

	/* Condition that is signaled on in bcache unlock.
	   Wakes up the evicting thread so that it may finish
	   evicting the cache block*/
	struct condition num_accessors_dec;

	/* A condition that wakes all people waitin
   	   on eviction to finish for this cache entry */
	struct condition eviction_done;

};

/* definitions to change the behavior of the unlock function */

/* Unlocks the cache entry normally*/
#define UNLOCK_NORMAL 0

/* Unlocks the cache entry after forcing disk update*/
#define UNLOCK_FLUSH 1

/*Unlocks the cache entry after setting its status to an invalid entry */
#define UNLOCK_INVALIDATE 2

void bcache_init(void);
struct cache_entry *bcache_get_and_lock(block_sector_t sector, enum meta_priority pri);
void bcache_unlock(struct cache_entry *entry, uint32_t flag);

void bcache_asynch_read(block_sector_t sector);
void bcache_flush(void);
void bcache_invalidate(void);


void bcache_asynch_read_(void *sector);

#endif /* BUFFER_CACHE_H_ */
