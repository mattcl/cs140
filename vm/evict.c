#include "evict.h"
#include <stdbool.h>
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "vm/swap.h"
#include "userprog/syscall.h"	/* MMAP */
#include <debug.h>
#include <string.h>

/* Both are protected by the frame table hash lock*/
static size_t evict_hand;
static size_t clear_hand;

/* Threshold can be set to respond to system
   conditions */

static size_t threshold;

static void *relocate_page (struct frame_entry *f, void * uaddr);
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
void *evict_page(struct frame_table *f_table, void *uaddr,
		enum palloc_flags flags){
//	printf("Evicting For uaddr %p\n", uaddr);
	struct frame_entry *frame ;
	struct frame_entry *frame_to_clear;


	/* A thread may have exited and freed a bunch of frames
	   between the invocation of this function and here so
	   recheck to see if there is a free frame*/
	frame = frame_first_free(flags, uaddr);
	if(frame != NULL){
		return palloc_kaddr_at_uindex(frame->position_in_bitmap);
	}

	lock_acquire(&f_table->frame_map_lock);

	/* in this case we need to move both hands simultaneously until the
       evict_hand finds a !accessed page */
	while(true){

		/* All frames are locked as is while the frame_map_lock is held
		   Now we can find all of the frames without having to worry
		   about other threads removing their data right now.
		   If we find one that we want to evict we set the pinned to
		   frame to true which will make the owning thread wait till
		   it is fully read out to swap/mmap */

		//printf("2 evict %u, clear %u\n", evict_hand % frame_table_size(), clear_hand % frame_table_size());
		frame = frame_at_position(evict_hand % frame_table_size());
		frame_to_clear = frame_at_position(clear_hand % frame_table_size());
		ASSERT(frame != NULL && frame_to_clear != NULL);
		evict_hand++;
		clear_hand++;

		ASSERT(pagedir_is_present(frame->cur_thread->pagedir, frame->uaddr));
		ASSERT(pagedir_is_present(frame_to_clear->cur_thread->pagedir, frame_to_clear->uaddr));

		pagedir_set_accessed(frame->cur_thread->pagedir, frame_to_clear->uaddr, false);

		if(!frame->pinned_to_frame && !pagedir_is_accessed(
				frame->cur_thread->pagedir, frame->uaddr)){
			/* Will make sure that the owning thread will
			   not remove its ish from the frame until we
			   are done relocating the data*/
			frame->pinned_to_frame = true;
			lock_release(&f_table->frame_map_lock);
			return relocate_page(frame, uaddr);
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

static void *relocate_page (struct frame_entry *f, void * uaddr){

	/* modifying the pagedir of another thread should be handled
	   with interrupts off, so that the dirty bit, AVL bits and
	   upper 20 bits.*/
	enum intr_level old_level = intr_disable();

	//printf("Relocate page , with evicthand %u and clear_hand %u\n", evict_hand % frame_table_size(), clear_hand % frame_table_size());
	medium_t medium = pagedir_get_medium(f->cur_thread->pagedir,f->uaddr);
	//printf("uaddr of frame we are evicting %x\n", f->uaddr);

	ASSERT(medium != PTE_AVL_ERROR);

	void *kaddr = palloc_kaddr_at_uindex(f->position_in_bitmap);

	bool needs_to_be_zeroed = true;

	if(pagedir_is_dirty(f->cur_thread->pagedir, f->uaddr)){
		if(medium == PTE_STACK || medium == PTE_EXEC){
			/* Sets the memroy up for the user, so when it faults will
			   know where to look*/
			swap_write_out(f->cur_thread, f->uaddr);
		}else if(medium == PTE_MMAP){
			/* Sets the memroy up for the user, so when it faults will
			   know where to look*/
			mmap_write_out(f->cur_thread, f->uaddr);
		}else{
			PANIC("relocate_page called with dirty page of medium_t: %x", medium);
		}
	}else{
		if(medium == PTE_STACK){
			/* User has read a 0'd page they have not written to, delete the
	   	   	   page, return frame. */
			needs_to_be_zeroed = false;
			pagedir_clear_page(f->cur_thread->pagedir, f->uaddr);
		}else if(medium == PTE_EXEC){
			/* this one should just set up on demand page again
			   so that the process will know just to read in from
			   disk again*/
			bool writable = pagedir_is_writable(f->cur_thread->pagedir, f->uaddr);
			pagedir_setup_demand_page(f->cur_thread->pagedir, f->uaddr,
						PTE_EXEC, (uint32_t)f->uaddr, writable);
		}else if(medium == PTE_MMAP){
			/* this should also set up an on demand page
			   so that when the MMAP is page faulted it will find
			   it on disk again*/
			pagedir_setup_demand_page(f->cur_thread->pagedir, f->uaddr,
						PTE_MMAP, (uint32_t)f->uaddr , true);
		}else{
			PANIC("realocate_page called with clean page of medium_t: %x", medium);
		}
	}

	intr_set_level(old_level);
	/* return the frame corresponding to evict_hand */

	if(needs_to_be_zeroed){
		/* Zero out the actual page so that the one returned to the user
	   	   has no valuable/sensitive/garbage data in it. Prevents security
	   	   problems*/
		memset(kaddr, 0, PGSIZE);
	}

	/* put user address and pgdir in the frame but leave the
	   rest of the data, such as position in bitmap as the
	   same*/
	f->uaddr = uaddr;
	f->cur_thread = thread_current();

	return kaddr;
}

