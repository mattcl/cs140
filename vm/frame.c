#include "frame.h"
#include <debug.h>
#include "evict.h"
#include "threads/thread.h"
#include <bitmap.h>
#include <hash.h>
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "devices/timer.h"
#include "userprog/pagedir.h"
#include <stdint.h>
#include <string.h>

static struct frame_table f_table;

/* Shortcuts for lots of typing and possible type errors */
#define HASH_ELEM const struct hash_elem
#define AUX void *aux UNUSED

#define COUNT_THRESHOLD 25

/* HASH table functions*/
static unsigned frame_hash_func (HASH_ELEM *e, AUX);
static bool frame_hash_compare (HASH_ELEM *a, HASH_ELEM *b, AUX);

/* Initializes the frame table. Setting the bitmap and the
   hash table that represents each frame */
void frame_init(void){
	f_table.used_frames = bitmap_create(palloc_number_user_pages());
	lock_init(&f_table.frame_map_lock);
	hash_init(&f_table.frame_hash, &frame_hash_func, &frame_hash_compare, NULL);
	evict_init(COUNT_THRESHOLD);
//	printf("Palloc num pages %lu our slots %u\n", palloc_number_user_pages(), frame_table_size());
}

/* Gets a page which is in a frame, evicts if there are no available frames
   Whenever allocated memory for a user process call this function instead of
   palloc. the flags must contain user. If the frame recieved used to hold
   data it will be erased before being returned. This page will be pinned
   to the frame so the user must call unpin when this frame is evictable*/
void  *frame_get_page (enum palloc_flags flags, void *uaddr){
	if((flags & PAL_USER) == 0){
		PANIC("Can not allocate a page for kernel from the user pool");
	}

	struct frame_entry *entry = frame_first_free(flags, uaddr);

	if(entry == NULL){
		printf("evict\n");
		return evict_page(&f_table, uaddr, flags);
	}else{
		return palloc_kaddr_at_uindex(entry->position_in_bitmap);
	}
}

/* This function looks in the bitmap to find a free frame, if the
   frame is free and exists it will clear out the page if necessary
   and it will return the entry with setting is_pinned to true
   and the upage and thread installed in the frame entry, or NULL if
   the map is full*/
struct frame_entry *frame_first_free (enum palloc_flags flags, void *uaddr){

	lock_acquire(&f_table.frame_map_lock);

	size_t frame_idx = bitmap_scan (f_table.used_frames, 0, 1 , false);

	if(frame_idx == BITMAP_ERROR){
		/* completely full */
		lock_release(&f_table.frame_map_lock);
		return NULL;
	}

	/* Check to see if the frame_hash_entry already exists */
	struct frame_entry *entry = frame_at_position(frame_idx);

	/* If entry != NULL then we already have a frame entry
	   created for this frame, verify it should be free then
	   return it, if it is null make a new entry put it into
	   the hash and then return it*/
	if(entry != NULL){
		/* We know that if the entry is != NULL and it was
		   at a position that was marked as free that it really
		   is no longer in use, bit table entry only set to 0
		   after the current thread is finished with the memory
		   set in frame_clear_page*/
		ASSERT(entry->cur_thread == NULL && entry->uaddr == NULL);
		entry->uaddr = uaddr;
		if((flags & PAL_ZERO) != 0){
			memset(palloc_kaddr_at_uindex(entry->position_in_bitmap), 0 , PGSIZE);
		}
	}else{
		uint8_t *kpage = palloc_get_page (flags);

		frame_idx = palloc_get_user_page_index(kpage);

		entry = calloc(1, sizeof(struct frame_entry));

		if(entry == NULL){
			PANIC("Out of KERNEL MEMORY!!!");
		}

		entry->position_in_bitmap = frame_idx;
		entry->uaddr = uaddr;
		sema_init(&entry->wait, 0);

		struct hash_elem *frame_entry = hash_insert(&f_table.frame_hash, &entry->elem);
		/*  returns something if it wasn't inserted of NULL if it
			was inserted. Go Figure. If process == NULL all is good
			otherwise bad times;*/
		if(frame_entry != NULL){
			PANIC("INdexing on bitmap index failed");
		}
	}

	entry->pinned_to_frame = true;
	entry->cur_thread = thread_current();

	bitmap_set(f_table.used_frames, frame_idx, true);
	lock_release(&f_table.frame_map_lock);

	return entry;
}

/* Given the kernel address returned from frame_get_page,
   which is pinned, this function will unpin the page in this
   frame, making it a candidate for eviction. If called from
   else where then we will start getting problems*/
void frame_unpin (void *kaddr){
	/*Error checking needs implementation*/
	size_t frame_idx = palloc_get_user_page_index(kaddr);

	lock_acquire(&f_table.frame_map_lock);
	struct frame_entry *frame = frame_at_position(frame_idx);

	/* If frame was null here but became non null after we
	   released the frame table lock then we know that the
	   kaddr passed in wasn't obtained by frame_get_page so
	   we don't care about it */
	if(frame != NULL){
		frame->pinned_to_frame = false;
	}
	lock_release(&f_table.frame_map_lock);
}

/* Clears the frame that the kaddr is currently in,
   or does nothing if the kaddr is not mapped to a frame.
   Called */
bool frame_clear_page (void *kaddr){

	/*Error checking needs implementation*/
	size_t frame_idx = palloc_get_user_page_index(kaddr);

	lock_acquire(&f_table.frame_map_lock);

	struct frame_entry *frame = frame_at_position(frame_idx);

	/* If the frame is not null then we need to remove our
	   data from it. We do this without locking the frame
	   so that we don't deadlock with eviction which is
	   looking into each frame to see which it can evict.
	   But to get the frame that it is looking at it has to
	   hold the frame_map_lock. Which we are holding so race
	   condition between viewing the removed frame will be atomic,
	   frame's are never dealocated so if frame == NULL then
	   frame_clear_page is called with an invalid kaddr */
	if(frame != NULL){
		if(frame->pinned_to_frame){
			/* Don't continue evicting this memory, we are
			   putting it on the swap right now */
			sema_down(&frame->wait);
		}else if(frame->cur_thread == thread_current()){
			/*  Check that this page is still in this frame, it
				may have been moved elsewhere in the eviction step
				so if we are in this frame remove ourselves*/
			frame->pinned_to_frame = false;
			frame->uaddr = NULL;
			frame->cur_thread = NULL;
			bitmap_set(f_table.used_frames, frame_idx, false);
		}
	}else{
		PANIC("INVALID PAGE REMOVED FROM FRAME");
		/* return false;*/
	}

	lock_release(&f_table.frame_map_lock);

	return true;
}

uint32_t frame_table_size (void){
	return bitmap_size(f_table.used_frames);
}

/* we assert that the frame map lock is held when this function
   is called, gets the frame_entry at this position if it exists*/
struct frame_entry *frame_at_position(size_t bit_num){
	ASSERT(lock_held_by_current_thread(&f_table.frame_map_lock));
	struct frame_entry key;
	key.position_in_bitmap = bit_num;
	struct hash_elem *frame_hash_elem = hash_find(&f_table.frame_hash, &key.elem);
	if(frame_hash_elem != NULL){
		return hash_entry(frame_hash_elem, struct frame_entry, elem);
	}else {
		return NULL;
	}
}

static unsigned frame_hash_func (HASH_ELEM *e, AUX){
	return hash_bytes(&hash_entry(e, struct frame_entry, elem)->position_in_bitmap, sizeof(uint32_t));
}

static bool frame_hash_compare (HASH_ELEM *a, HASH_ELEM *b, AUX){
	ASSERT(a != NULL);
	ASSERT(b != NULL);
	return (hash_entry(a, struct frame_entry, elem)->position_in_bitmap <
			hash_entry(b, struct frame_entry, elem)->position_in_bitmap);
}

