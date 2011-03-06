#include "buffer-cache.h"
#include "filesys.h"
#include "threads/thread.h"
#include <debug.h>
#include <string.h>

/* If accesses are greater than (cur_pri)*PROMOTE_THRESHOLD
   then we will move the priority of this cache block up to
   the next highest level to reduce the chance that it is
   evicted. We will also reset its accessed count.
   ARBITRARY NUMBER CHANGE WITH EXPERIMENTATION*/
#define PROMOTE_THRESHOLD 50

/* A hash that provides efficient lookup of sectors
   and to return the cache_entry quickly*/
static struct hash lookup_hash;
static struct lock lookup_hash_lock;

/* The number of eviction lists needs to correspond
   to the number of entries in the enum meta_priority */
static struct list eviction_lists[NUM_PRIORITIES];
static struct lock eviction_lists_lock;

/* Our cache, implemented as an array of cache entries */
static struct cache_entry cache[MAX_CACHE_SLOTS];

static struct cache_entry *bcache_evict(void);

/* Shortcuts for lots of typing and possible type errors */
#define HASH_ELEM const struct hash_elem
#define AUX void *aux UNUSED

/* HASH table functions*/
static unsigned bcache_entry_hash(HASH_ELEM *e, AUX);
static bool bcache_entry_compare(HASH_ELEM *a, HASH_ELEM *b, AUX);

void bcache_init(void){
	uint32_t i;
	hash_init(&lookup_hash);
	for(i = 0; i < NUM_PRIORITIES; i ++){
		list_init(&eviction_lists[i]);
	}
	lock_init(&lookup_hash_lock);
	lock_init(&eviction_lists_lock);

	/* Initialize all of the cache entries*/
	for(i = 0; i < MAX_CACHE_SLOTS; i ++){
		cache[i].sector_num = 0;
		cache[i].dirty = false;
		lock_init(&cache[i].entry_lock);
		memset(&cache[i].data, 0, BLOCK_SECTOR_SIZE);
		list_push_back(&eviction_lists[CACHE_DATA], &cache[i].eviction_elem);
	}
}

/* This function looks up the sector in our buffer cache, if it finds it it will
   increment the accessed counter, move it to the back of the appropriate eviction
   list lock it atomically and return it to the user locked. This cache entry must
   then be unlocked by the caller or the risk of dead lock is immense.
   If the cache entry was not located then this call will get an evict a cache entry,
   move it's data to disk if necessary, and then read in the sector to the data
   field of the cache entry. At this point the meta_priority will be used to determine
   how important this cache entry is, otherwise the parameter is ignored. */
struct cache_entry *bcache_get_and_lock(block_sector_t sector, enum meta_priority pri){
	struct cache_entry key, *to_return;
	struct hash_elem *return_entry;
	key.sector_num = sector;
	lock_acquire(&lookup_hash_lock);
	return_entry = hash_find(&lookup_hash, &key.lookup_elem);
	if(return_entry != NULL){
		to_return = hash_entry(return_entry, struct cache_entry, lookup_elem);

		/* It has been accessed and needs to
		   be moved to the end of its eviction list
		   or the end of its new list if it gets promoted*/
		lock_acquire(&eviction_lists_lock);
		list_remove(&to_return->eviction_elem);
		lock_release(&eviction_lists_lock);

		/* Promote here if necessary
		to_return->access_count ++;
		if(to_return->cur_pri != CACHE_INODE){
			if(to_return->access_count >
					(to_return->cur_pri * PROMOTE_THRESHOLD)){
				to_return->cur_pri --;
				to_return->access_count = 0;
			}
		}
		Looks like it will work will add in after initial
		testing
		*/

		lock_acquire(&eviction_lists_lock);
		list_push_back(&eviction_lists[to_return->cur_pri],
									&to_return->eviction_elem);
		lock_release(&eviction_lists_lock);

		/* Lock the cache entry and return it */
		lock_acquire(&to_return.entry_lock);
		lock_release(&lookup_hash_lock);
		return to_return;
	}else{
		to_return = bcache_evict();
		if(to_return->sector_num != 0){
			to_return = hash_delete(&lookup_hash, &to_return->lookup_elem);
			ASSERT(to_return != NULL);
			ASSERT(hash_entry(to_return, struct cache_entry, lookup_elem)
					== to_return);
		}

		to_return->sector_num = sector;
		to_return->access_count = 1;
		to_return->cur_pri = pri;
		to_return->dirty = false;

		lock_acquire(&eviction_lists_lock);
		list_push_back(&eviction_lists[to_return->cur_pri],
									&to_return->eviction_elem);
		lock_release(&eviction_lists_lock);

		to_return = hash_insert(&lookup_hash, &to_return->lookup_elem);
		if(to_return != NULL){
			PANIC("Collision using sector numbers as keys");
		}

		/* Read data into the cache data section and return */
		block_read (fs_device, to_return->sector_num, to_return->data);
		return to_return;
	}

}

/* Unlocks the cache_entry so that another thread can use it */
void bcache_unlock(struct cache_entry *entry){
	lock_release(&entry->entry_lock);
}

static void bcache_asynch_func(void *sector){
	struct cache_entry *e =
			bcache_get_and_lock(&(block_sector_t*)sector, CACHE_DATA);
	bcache_unlock(e);
}

/* Fetches the given sector and puts it in the cache. Will evict a current
   cache entry. Will give the block the CACHE_DATA priority*/
void bcache_asynch_sector_fetch(block_sector_t sector){
	block_sector_t sector_to_send;
	thread_create_kernel("extra", PRI_MAX, bcache_asynch_func, &sector_to_send);
}

void bcache_flush(void){
	uint32_t i;
	for(i = 0; i < MAX_CACHE_SLOTS; i ++){
		lock_acquire(&cache[i].entry_lock);
		if(cache[i].dirty){
			block_write(fs_device, cache[i].sector_num, cache[i].data);
			cache[i].dirty = false;
		}
		lock_release(&cache[i].entry_lock);
	}
}

static struct cache_entry *bcache_evict(void){
	/* The evict lock should always be acquired after acquiring the
	   lookup hash lock. This can be moved to new function*/
	struct cache_entry *evicted;
	lock_acquire(&eviction_lists_lock);
	uint32_t i;
	for(i = NUM_PRIORITIES; i >= 0; i--){
		if(list_empty(&eviction_lists[i])){
			continue;
		}else{
			evicted = list_entry(list_pop_front(&eviction_lists[i]),
					             struct cache_entry, eviction_elem);
			break;
		}
	}
	lock_release(&eviction_lists_lock);

	return evicted;
}

/* HASH table functions*/
static unsigned bcache_entry_hash(HASH_ELEM *e, AUX){
	return hash_bytes(&hash_entry(e, struct cache_entry,
				lookup_elem)->sector_num, sizeof(block_sector_t));
}

static bool bcache_entry_compare(HASH_ELEM *a, HASH_ELEM *b, AUX){
	ASSERT(a != NULL);
	ASSERT(b != NULL);
	return (hash_entry(a, struct cache_entry, lookup_elem)->sector_num <
			hash_entry(b, struct cache_entry, lookup_elem)->sector_num);
}
