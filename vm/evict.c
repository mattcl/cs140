#include "evict.h"
#include <stdbool.h>
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"
#include <debug.h>

static size_t evict_hand;
static size_t clear_hand;
static size_t threshold;

static void *relocate_page (struct frame_entry *f);

/* returns the key to the frame that is now available, use the entry
   to install this page into the pagedir of the evicting thread that
   is asking for memory.   

   MEMORY - If we try to evict a page, it's medium should say that it is
   in memory or it does not make sense that we are evicting it.

   SWAP - If we evict something in memory and it is dirty and not a mmaped
   file we put it on swap, swap_allocate takes care of the rest.

   STACK - If we evict a stack page that's clean, we can just get a new
   page from thin air.  If we evict a dirty stack page, we write it to swap.

   EXECUTABLE - cannot write to executable, if we evict this we do nothing.

   MMAP - If we evict an mmapped page we write it back to the file system.   */

/* Evict a page from its frame and install this uaddr as the new
   page that is occuping the frame. Then returns the pointer to
   the kernel virtual address so that the user can install this
   kernel virtual address into its pagedirectory */
void *evict_page(void *uaddr){
	struct frame_entry *frame ;
	struct frame_entry *frame_to_clear;
	while((evict_hand + threshold) % frame_table_size() < clear_hand){
		/* Our clear hand is still at least theshold bits in front of us */
		frame= frame_at_position(evict_hand);
		evict_hand ++;

		ASSERT(frame != NULL);
		/*return the first page we find that has not been accesed */
		if(!pagedir_is_accessed(frame->cur_pagedir,frame->uaddr)
				&& !frame->pinned_to_frame){
			/*  evict page from frame moving it to the appropriate
				location and return the kernel virtual address of the
				physical page represented by the evict_hand in the bitmap*/
			return relocate_page(frame);
		}
	}

	/* in this case we need to move both hands simultaneously until the
       evict_hand finds a !accessed page */
	while(true){
		frame = frame_at_position(evict_hand);
		frame_to_clear = frame_at_position(clear_hand);

		evict_hand++;
		clear_hand++;

		pagedir_set_accessed(frame_to_clear->cur_pagedir, frame_to_clear->uaddr, false);

		if(!pagedir_is_accessed(frame->cur_pagedir, frame->uaddr)
				&& !frame->pinned_to_frame){
			return relocate_page(frame);
		}
	}
}

void evict_init(size_t threshold_set){
	threshold = threshold_set;
	evict_hand = 0;
	clear_hand = evict_hand + threshold;
}

/* Likely to be called from a timer interrupt*/
void clear_until_threshold(void){

}

static void *relocate_page (struct frame_entry *f){
	medium_t medium = pagedir_get_medium(f->cur_pagedir,f->uaddr);
	ASSERT(medium != PTE_AVL_ERROR);

	void *kaddr = palloc_get_kaddr_user_index(f->position_in_bitmap);

	bool needs_to_be_zeroed = true;

	if(pagedir_is_dirty(f->cur_pagedir, f->uaddr)){
		if(medium == PTE_AVL_STACK || medium == PTE_AVL_EXEC){
			/* Sets the memroy up for the user, so when it faults will
			   know where to look*/
			swap_write_out((uint32_t)f->cur_pagedir, f->uaddr);
		}else if(medium == PTE_AVL_MMAP){
			/* Sets the memroy up for the user, so when it faults will
			   know where to look*/
			mmap_write_out((uint32_t)f->cur_pagedir, f->uaddr);
		}else{
			PANIC("relocate_page called with dirty page of medium_t: %x", medium);
		}
	}else{
		if(medium == PTE_AVL_STACK){
			/* User has read a 0'd page they have not written to, delete the
	   	   	   page, return frame. */
			needs_to_be_zeroed = false;
			pagedir_clear_page(f->cur_pagedir, f->uaddr);
		}else if(medium == PTE_AVL_EXEC){
			/* this one should just set up on demand page again
			   so that the process will know just to read in from
			   disk again*/
			bool writable = pagedir_is_writable(f->cur_pagedir, f->uaddr);
			pagedir_setup_demand_page(f->cur_pagedir, f->uaddr,
						PTE_AVL_EXEC, f->uaddr, writable);
		}else if(medium == PTE_AVL_MMAP){
			/* this should also set up an on demand page
			   so that when the MMAP is page faulted it will find
			   it on disk again*/
			pagedir_setup_demand_page(f->cur_pagedir, f->uaddr,
									PTE_AVL_MMAP,f->uaddr , true);
		}else{
			PANIC("realocate_page called with clean page of medium_t: %x", medium);
		}
	}
	/* return the frame corresponding to evict_hand */

	if(needs_to_be_zeroed){
		/* Zero out the actual page so that the one returned to the user
	   	   has no valuable/sensitive/garbage data in it. Prevents security
	   	   problems*/
		memset(kaddr, 0, PGSIZE);
	}
}

