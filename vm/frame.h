
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

struct frame_hash_entry{
	uint32_t position_in_bitmap; 		/*The key into the hash table*/
	bool pinned_to_frame;
	void *current_page_dir;
	void *page;
	struct hash_elem elem;
};

void frame_init(void);

/* Gets a page which is in a frame, evicts if there are no available frames
   Whenever allocated memory for a user process call this function instead of
   palloc*/
void  *frame_get_page (enum palloc_flags flags);

#endif /* FRAME_H_ */
