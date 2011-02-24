
#ifndef FRAME_H_
#define FRAME_H_

#include <bitmap.h>
#include <hash.h>
#include "threads/palloc.h"
#include "threads/synch.h"
#include <stdint.h>

struct frame_table {
	struct bitmap *used_frames;		/*   The bitmap that tracks used/free
		 	 	 	 	 	 	 	 	 frames*/
	struct lock frame_map_lock;		/*	 Lock to the frame bitmap  */
	struct hash frame_hash;			/*   */
};

struct frame_entry{
	uint32_t position_in_bitmap; 		/*The key into the hash table*/
	bool pinned_to_frame;
	void *cur_pagedir;
	struct thread *cur_thread;
	void *uaddr;
	struct hash_elem elem;
};

void frame_init(void);

/* Gets a page which is in a frame, evicts if there are no available frames
   Whenever allocated memory for a user process call this function instead of
   palloc*/
void  *frame_get_page (enum palloc_flags flags, void * uaddr);
bool frame_clear_page (void *kernel_page_addr);

size_t frame_table_size (void);
struct frame_entry  *frame_at_position(size_t bit_num);


#endif /* FRAME_H_ */
