#include "buffer-cache.h"
#include "filesys.h"
#include "threads/thread.h"
#include <debug.h>
#include <string.h>
#include <uint_set.h>
#include "free-map.h"
#include "devices/timer.h"
#include "threads/malloc.h"

/* If accesses are greater than (cur_pri)*PROMOTE_THRESHOLD
   then we will move the priority of this cache block up to
   the next highest level to reduce the chance that it is
   evicted. We will also reset its accessed count.
   ARBITRARY NUMBER CHANGE WITH EXPERIMENTATION*/
#define PROMOTE_THRESHOLD 50

/* The time for the daemon to flush all data out to disk
   in milliseconds */
#define FLUSH_REFRESH_TIME 30000

/* A hash that provides efficient lookup of sectors
   and to return the cache_entry quickly*/
static struct hash lookup_hash;

/* The number of eviction lists needs to correspond
   to the number of entries in the enum meta_priority */
static struct list eviction_lists[NUM_PRIORITIES];

static struct condition evict_list_changed;

/* This lock is necessary for you to perform operations
   on the lookup hash and the eviction lists concurently
   This lock must NOT be held when doing ANY I/O doing so
   would thwart concurency soooo bad */
static struct lock cache_lock;


/* Used to get rid of a race condition */
static struct uint_set evicted_sectors;
static struct condition evicted_sector_wait;


/* Our cache, implemented as an array of cache entries */
static struct cache_entry cache[MAX_CACHE_SLOTS];

static struct cache_entry *bcache_evict(void);

/* Shortcuts for lots of typing and possible type errors */
#define HASH_ELEM const struct hash_elem
#define AUX void *aux UNUSED

/* HASH table functions*/
static unsigned bcache_entry_hash(HASH_ELEM *e, AUX);
static bool bcache_entry_compare(HASH_ELEM *a, HASH_ELEM *b, AUX);

static void spawn_daemon_thread(void);

void bcache_init(void){
	uint32_t i;

	uint_set_init(&evicted_sectors);
	hash_init(&lookup_hash, bcache_entry_hash, bcache_entry_compare, NULL);
	for(i = 0; i < NUM_PRIORITIES; i ++){
		list_init(&eviction_lists[i]);
	}
	lock_init(&cache_lock);
	cond_init(&evict_list_changed);
	cond_init(&evicted_sector_wait);

	memset(zeroed_sector, 0, BLOCK_SECTOR_SIZE);

	/* Initialize all of the cache entries*/
	for(i = 0; i < MAX_CACHE_SLOTS; i ++){
		cache[i].sector_num = 0;
		cache[i].flags = 0;
		cache[i].num_accessors = 0;
		lock_init(&cache[i].entry_lock);
		cond_init(&cache[i].num_accessors_dec);
		cond_init(&cache[i].eviction_done);
		memset(&cache[i].data, 0, BLOCK_SECTOR_SIZE);
		list_push_back(&eviction_lists[CACHE_DATA], &cache[i].eviction_elem);
	}
	spawn_daemon_thread();
}

/* This function looks up the sector in our buffer cache, if it finds it it will
   increment the accessed counter, move it to the back of the appropriate eviction
   list lock it atomically and return it to the user locked. This cache entry must
   then be unlocked by the caller or the risk of dead lock is immense.
   If the cache entry was not located then this call will get an evict a cache entry,
   move it's data to disk if necessary, and then read in the sector to the data
   field of the cache entry. At this point the meta_priority will be used to determine
   how important this cache entry is, otherwise the parameter is ignored.
   Returns NULL with no lock held if the sector is the ZERO_SECTOR */
struct cache_entry *bcache_get_and_lock(block_sector_t sector, enum meta_priority pri){
	//printf("bcache get sector %u\n", sector);
	/* Requests for the zero sector will return NULL */
	if(sector == ZERO_SECTOR){
		return NULL;
	}

	struct cache_entry key, *c_entry;
	struct hash_elem *ret_entry;
	key.sector_num = sector;
	lock_acquire(&cache_lock);
	ret_entry = hash_find(&lookup_hash, &key.lookup_e);
	if(ret_entry != NULL && !(hash_entry(ret_entry,
			struct cache_entry, lookup_e)->flags & CACHE_E_INVALID)){
		c_entry = hash_entry(ret_entry, struct cache_entry, lookup_e);

		//printf("Exists and %u\n", c_entry->flags & CACHE_E_EVICTING);
		/* While this frame is in the middle of being switched
		   wait, while(evicting == true)*/
		while(c_entry->flags & CACHE_E_EVICTING){
			//printf("waiting\n");
			cond_wait(&c_entry->eviction_done, &cache_lock);
		}

		c_entry->num_accessors ++;

		/* It has been accessed and needs to
		   be moved to the end of its eviction list
		   or the end of its new list if it gets promoted*/
		list_remove(&c_entry->eviction_elem);

		/* Promote here if necessary */
		c_entry->num_hits ++;
		if(c_entry->cur_pri != CACHE_INODE){
			if(c_entry->num_hits >
					(c_entry->cur_pri * PROMOTE_THRESHOLD)){
				c_entry->cur_pri --;
				c_entry->num_hits = 0;
			}
		}

		/* Put at the end of the appropriate evict list */
		list_push_back(&eviction_lists[c_entry->cur_pri],
									&c_entry->eviction_elem);

		lock_release(&cache_lock);

		/* Lock the cache entry and return it, many possible threads
		   can get here so that condition is dealt with in the eviction
		   process. Can't acquire this lock inside the cache lock because
		   then the cache lock might block on IO when, for example the
		   cache entry flushes its data in bcache unlock*/
		lock_acquire(&c_entry->entry_lock);
		return c_entry;
	}else{
		struct hash_elem *check;
		if(ret_entry == NULL){
			/* We are here because the element didn't exist in the
			   lookup hash and hence didn't exist we will evict one*/
			c_entry = bcache_evict();
		}else{
			/* We are here because a lookup was requested for an entry that
			   was invalidated Return the same entry, with the data read in
			   from disk*/
			c_entry = hash_entry(ret_entry, struct cache_entry, lookup_e);
		}

		//printf("Doesn't exist choosing %u to delete %u\n", c_entry->sector_num,\
				(c_entry->flags & CACHE_E_INITIALIZED));

		if(c_entry->flags & CACHE_E_INITIALIZED){
			check =	hash_delete(&lookup_hash, &c_entry->lookup_e);
			ASSERT(check != NULL);
			ASSERT(hash_entry(check, struct cache_entry, lookup_e)==c_entry);
		}

		/* Save the sector number that we will right the
		   cache entry data out to*/
		block_sector_t sector_to_save = c_entry->sector_num;

		c_entry->sector_num = sector;
		c_entry->flags |= (CACHE_E_EVICTING); /*Evicting = true*/

		check = hash_insert(&lookup_hash, &c_entry->lookup_e);
		if(check != NULL){
			PANIC("Collision using sector numbers as keys");
		}

		bool is_valid = !(c_entry->flags & CACHE_E_INVALID);

		/* Make any threads that want the sector that we are right
		   now evicting wait until we are done writing the sector
		   to disk. */
		if(c_entry->flags & CACHE_E_INITIALIZED && is_valid){
			/* If the entry is initialized and valid then add the
			   int to the set, otherwise we will have deadlock
			   because we are evicting the sector that we are
			   reading in now so it will cond_wait forever*/
			uint_set_add_member(&evicted_sectors, sector_to_save);
		}

		/* Wait until no one is accessing this cache entry anymore*/
		while(c_entry->num_accessors != 0){
			//printf("waiting 1\n");
			cond_wait(&c_entry->num_accessors_dec, &cache_lock);
		}

		/* Check to see here if the item has been invalidated
		   while we waited, should not have become valid if it
		   was invalid before*/
		is_valid = !(c_entry->flags & CACHE_E_INVALID);


		/* No one else is accessing the old data in the cache
		   entry and anyone that wants to read the new data
		   will wait until this cache entry is no longer evicting
		   the old data. Can now finish changing the meta data
		   in the cache entry*/
		c_entry->num_hits = 1; /* Brand new cache entry caller first access*/
		c_entry->num_accessors = 1;  /*The caller will be the sole accessor*/
		c_entry->cur_pri = pri;

		/* While we are trying to read in a sector that is
		   in the middle of being written outm we will wait, because
		   if we don't we may read in stale data from the disk*/
		while(uint_set_is_member(&evicted_sectors, sector)){
			//printf("waiting 2\n");
			cond_wait(&evicted_sector_wait, &cache_lock);
		}

		lock_release(&cache_lock);

		if((c_entry->flags & CACHE_E_INITIALIZED) &&
			is_valid && (c_entry->flags & CACHE_E_DIRTY)){
			/* Write the dirty old block out except when the
			   cache entry is brand new. Or when it has been invalidated*/
			//printf("bcache writing sector %u\n", sector_to_save);
			block_write(fs_device, sector_to_save, c_entry->data);
		}

		/* Read the new data from disk into the cache data section*/
		//printf("bcache read sector %u\n", to_return->sector_num);
		block_read (fs_device, c_entry->sector_num, c_entry->data);

		lock_acquire(&cache_lock);

		/* Wake any thread that is waiting on their sector to be
		   written out to disk before reading it in from disk
		   Removing integers that aren't in the set does nothing*/
		uint_set_remove(&evicted_sectors, sector_to_save);
		cond_broadcast(&evicted_sector_wait, &cache_lock);

		/* Put at the end of an eviction list */
		list_push_back(&eviction_lists[c_entry->cur_pri],
									&c_entry->eviction_elem);

		/* prevent other threads from getting in to this  entry */
		lock_acquire(&c_entry->entry_lock);

		/* Set my flags */
		c_entry->flags &= ~(CACHE_E_DIRTY);   /*Dirty = false*/
		c_entry->flags &= ~(CACHE_E_EVICTING);/*evicting = false*/
		c_entry->flags |= CACHE_E_INITIALIZED;/*Initialized = true*/

		/* Wake up threads that might have found an empty evict list */
		cond_broadcast(&evict_list_changed, &cache_lock);

		lock_release(&cache_lock);

		return c_entry;
	}

}

/* Unlocks the cache_entry so that another thread can use it,
   if flush_now == true will write the data out to disk immediately
   and keep the entry in the cache. This is useful when writing data
   to an inode. Another approach would be to implement journaling for
   inodes and directories.*/
void bcache_unlock(struct cache_entry *entry, uint32_t flag){

	/* This is the only IO that is performed with the cache_entry
	   lock held. This is the reason whe we can only acquire the
	   cache_entry lock while holding the cache lock at the end
	   of eviction, when we know that no other thread is about to
	   call this function with flush now == true. Otherwise we would
	   be holding the cache lock while doing IO which is a no-no */
	if(UNLOCK_FLUSH == flag){
		block_write(fs_device, entry->sector_num, entry->data);
	}

	lock_release(&entry->entry_lock);

	lock_acquire(&cache_lock);
	entry->num_accessors--;

	/* Invalidate the cache entry so that it will not be written to
	   disk*/
	if(UNLOCK_INVALIDATE == flag){
		entry->flags |= CACHE_E_INVALID;
	}
	/* Wake up the evictor of this thread*/
	cond_signal(&entry->num_accessors_dec, &cache_lock);
	lock_release(&cache_lock);
}

/* Removes all entries in our cache, now!*/
void bcache_invalidate(void){
	lock_acquire(&cache_lock);
	/* If the process is right now
	   evicting this cache entry it will show
	   the evicting flag, in which case it is not
	   in an eviction list yet and it is not safe
	   to remove it*/
	uint32_t i;
	for(i = 0; i < MAX_CACHE_SLOTS; i ++){
		lock_acquire(&cache[i].entry_lock);
		/* We have the lock of this entry so
	       no one else can be accessing it. */
		if(cache[i].flags & CACHE_E_EVICTING ||
				cache[i].num_accessors != 0 ||
				!(cache[i].flags & CACHE_E_INITIALIZED)){
			lock_release(&cache[i].entry_lock);
			continue;
		}else{
			/* Safe to destroy this entry because it is not in the middle of
			   being evicted and we know that no one is waiting on the lock
			   we are holding. People that could be waiting are waiting on
			   the eviction status to be changed or accessors to go to 0.
			   Because the ohter flags are set the way they are we know
			   this entry is in an eviction list and in the hash.*/
			list_remove(&cache[i].eviction_elem);
			struct hash_elem *check =
					hash_delete(&lookup_hash, &cache[i].lookup_e);
			ASSERT(check != NULL);
			ASSERT(hash_entry(check, struct cache_entry, lookup_e) == &cache[i]);

			/* Clear the data */
			cache[i].flags = 0;
			cache[i].sector_num = 0;
			cache[i].num_accessors = 0;
			cache[i].num_hits = 0;
			cache[i].cur_pri = CACHE_DATA;

			list_push_front(&eviction_lists[CACHE_DATA], &cache[i].eviction_elem);
			lock_release(&cache[i].entry_lock);
		}
	}

	lock_release(&cache_lock);
}

static void persist_disk(void *none UNUSED){
	while(true){
		timer_msleep(FLUSH_REFRESH_TIME);
		bcache_flush();
		free_map_persist();
	}
}

static void spawn_daemon_thread(void){
	thread_create_kernel("daemon", PRI_MAX, persist_disk, NULL);
}

/* Reads in the sector */
static void bcache_asynch_read_(void *sector){
	//printf("asynch got here %u\n", *(block_sector_t*)sector);
	struct cache_entry *e =
			bcache_get_and_lock(*(block_sector_t*)sector, CACHE_DATA);
	//printf("asynch got here p2\n");
	if(e != NULL){
		bcache_unlock(e, UNLOCK_NORMAL);
	}
	//printf("asynch got here p3\n");
	free(sector);
}

/* Fetches the given sector and puts it in the cache. Will evict a current
   cache entry. Will give the block the CACHE_DATA priority*/
void bcache_asynch_read(block_sector_t sector){
	block_sector_t *sector_to_send = (block_sector_t*)malloc(sizeof(block_sector_t));
	ASSERT(sector_to_send != NULL);
	*sector_to_send = sector;
	tid_t err = thread_create_kernel("extra", PRI_MAX, bcache_asynch_read_, (void*)sector_to_send);
	if(err == TID_ERROR){
		free(sector_to_send);
	}
}

/* Flushes the buffer cache to disk */
void bcache_flush(void){
	//printf("flush\n");
	uint32_t i;
	for(i = 0; i < MAX_CACHE_SLOTS; i ++){
		//printf("acquire\n");
		lock_acquire(&cache[i].entry_lock);
		/* We only flush if the following conditions apply:
		   the entry must be initialized, dirty, not in the middle
		   of eviction, and not invalidated. Following these conditions
		   we can grab the lock at the tail end of bcache_get without fear
		   of holding the global lock while we do IO */
		if(cache[i].flags & CACHE_E_DIRTY &&
				!(cache[i].flags & CACHE_E_EVICTING) &&
				!(cache[i].flags & CACHE_E_INVALID) &&
				(cache[i].flags & CACHE_E_INITIALIZED)){
			//printf("write\n");
			block_write(fs_device, cache[i].sector_num, cache[i].data);
			cache[i].flags &= ~(CACHE_E_DIRTY);
		}
		lock_release(&cache[i].entry_lock);
		//printf("release\n");
	}
}

/* Returns true if all the eviction lists are empty
   returns false if at least one list has an entry
   in it*/
static bool all_evict_lists_empty(void){
	ASSERT(lock_held_by_current_thread(&cache_lock));
	bool empty = true;
	uint32_t i;
	for(i = 0; i < NUM_PRIORITIES; i ++){
		if(!list_empty(&eviction_lists[i])){
			empty = false;
		}
	}
	return empty;
}

static struct cache_entry *bcache_evict(void){
	/* The evict lock should always be acquired after acquiring the
	   lookup hash lock. This can be moved to new function*/
	ASSERT(lock_held_by_current_thread(&cache_lock));

	while(all_evict_lists_empty()){
		cond_wait(&evict_list_changed, &cache_lock);
	}

	/* There is a non empty list we can evict
	   something*/
	struct cache_entry *evicted = NULL;
	int32_t i;
	for(i = (NUM_PRIORITIES - 1); i >= 0; i--){
		if(list_empty(&eviction_lists[i])){
			continue;
		}else{
			evicted = list_entry(list_pop_front(&eviction_lists[i]),
					             struct cache_entry, eviction_elem);
			break;
		}
	}
	ASSERT(evicted != NULL);
	return evicted;
}

/* HASH table functions*/
static unsigned bcache_entry_hash(HASH_ELEM *e, AUX){
	return hash_bytes(&hash_entry(e, struct cache_entry,
				lookup_e)->sector_num, sizeof(block_sector_t));
}

static bool bcache_entry_compare(HASH_ELEM *a, HASH_ELEM *b, AUX){
	ASSERT(a != NULL);
	ASSERT(b != NULL);
	return (hash_entry(a, struct cache_entry, lookup_e)->sector_num <
			hash_entry(b, struct cache_entry, lookup_e)->sector_num);
}
