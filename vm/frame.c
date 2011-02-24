#include "frame.h"
#include <debug.h>
#include "evict.h"
#include "threads/thread.h"
#include <bitmap.h>
#include <hash.h>
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "devices/timer.h"
#include <stdint.h>

static struct frame_table f_table;

/* Shortcuts for lots of typing and possible type errors */
#define HASH_ELEM const struct hash_elem
#define AUX void *aux UNUSED

#define COUNT_THRESHOLD 1

/* HASH table functions*/
static unsigned frame_hash_func (HASH_ELEM *e, AUX);
static bool frame_hash_compare (HASH_ELEM *a, HASH_ELEM *b, AUX);

/* Initializes the frame table. Setting the bitmap and the
   hash table that represents each frame */
void frame_init(void){
	//printf("Palloc num pages %lu\n", palloc_number_user_pages());
	f_table.used_frames = bitmap_create(palloc_number_user_pages());
	lock_init(&f_table.frame_map_lock);
	hash_init(&f_table.frame_hash, &frame_hash_func, &frame_hash_compare, NULL);
	evict_init(COUNT_THRESHOLD);
}

/* Gets a page which is in a frame, evicts if there are no available frames
   Whenever allocated memory for a user process call this function instead of
   palloc. the flags must contain user. If the frame recieved used to hold
   data it will be erased before being returned*/
void  *frame_get_page (enum palloc_flags flags, void *uaddr){
	if((flags & PAL_USER) == 0){
		PANIC("Can not allocate a page for kernel from the user pool");
	}

	lock_acquire (&f_table.frame_map_lock);
	size_t frame_idx = bitmap_scan (f_table.used_frames, 0, 1 , false);
	lock_release (&f_table.frame_map_lock);
	//printf("Frame idx = %ul\n", frame_idx);
	if(frame_idx == BITMAP_ERROR){
		printf("evict\n");
		return evict_page(uaddr);
	}

	uint8_t *kpage = palloc_get_page (flags);

	frame_idx = palloc_get_user_page_index(kpage);

	struct frame_entry *f_hash_entry = calloc(1, sizeof(struct frame_entry));

	if(f_hash_entry == NULL){
		PANIC("Out of KERNEL MEMORY!!!");
	}

	f_hash_entry->position_in_bitmap = frame_idx;
	f_hash_entry->pinned_to_frame = false;
	f_hash_entry->cur_pagedir = thread_current()->pagedir;
	f_hash_entry->uaddr = uaddr;

	lock_acquire (&f_table.frame_map_lock);
	bitmap_set(f_table.used_frames, frame_idx, true);

	struct hash_elem *frame_entry = hash_insert(&f_table.frame_hash, &f_hash_entry->elem);
	lock_release (&f_table.frame_map_lock);

	/* returns something if it wasn't inserted of NULL if it
	   was inserted. Go Figure. If process == NULL all is good
	   otherwise bad times;*/
	if(frame_entry != NULL){
		PANIC("Weird Error occured");
	}

	return palloc_get_kaddr_user_index(frame_idx);
}

/* Clears the frame that the page_addr is currently in, or does nothing if the page_addr is not
   currently in a frame */
bool frame_clear_page (void *kernel_page_addr){
	/*Error checking needs implementation*/
	size_t frame_idx = palloc_get_user_page_index(kernel_page_addr);

	struct frame_entry *frame = frame_at_position(frame_idx);

	if(frame != NULL){
		lock_acquire(&f_table.frame_map_lock);
		hash_delete(&f_table.frame_hash, &frame->elem);
		bitmap_set(f_table.used_frames, frame_idx, false);
		lock_release(&f_table.frame_map_lock);
	}else{
		PANIC("INVALID PAGE REMOVED FROM FRAME");
		/* return false;*/
	}
	palloc_free_page (kernel_page_addr);
	return true;
}

uint32_t frame_table_size (void){
	return bitmap_size(f_table.used_frames);
}

struct frame_entry *frame_at_position(size_t bit_num){
	struct frame_entry key;
	key.position_in_bitmap = bit_num;
	lock_acquire(&f_table.frame_map_lock);
	struct hash_elem *frame_hash_elem = hash_find(&f_table.frame_hash, &key.elem);
	lock_release(&f_table.frame_map_lock);
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

