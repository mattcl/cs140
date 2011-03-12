#ifndef FRAME_H_
#define FRAME_H_

#include <bitmap.h>
#include "threads/palloc.h"
#include "threads/synch.h"
#include <stdint.h>

/* Globally accessible set by the timer interrupt
   Tells us that 4 ticks have elapsed and that we
   should now move the clear hand by one threshold
   if we are currently close to our threshold in
   front of the evict hand.*/
bool advance_clear_hand;

struct frame_table{

	/* A bitmap for the used frames */
	struct bitmap *used_frames;

	/* A lock on the bitmap */
	struct lock frame_table_lock;

	/* The base of user available memory */
	void *base;

	/* The size of user available memory */
	uint32_t size;

	/* The frame table entries that map uaddrs to
	   kaddr's and allow frames to be tracked and evicted
	   relatively easily*/
	struct frame_entry *entries;
};

struct frame_entry{
	/* Whether the frame entry is pinned down and not
	   allowed to be evicted */
	bool is_pinned;

	/* The current process that is owning this frame
	   entry right at this moment*/
	struct process *cur_owner;

	/* The pagedirectory of the current owner, put
	   here because putting only the thread pointer
	   is bad ju ju and the thread pointer will set
	   its pd* to NULL when it is deleting it which
	   will mess up everything because the frames will
	   still be held by the process but the pd would
	   be NULL*/
	uint32_t *pd;

	/* The user address that is currently inhabiting this
	   frame table entry*/
	void *uaddr;
};

void frame_init(void);
void *frame_get_page(enum palloc_flags flags, void *uaddr);
void frame_clear_page (void *kaddr);
void unpin_frame_entry(void *kaddr);
bool pin_frame_entry(void *kaddr);

#endif /* FRAME_H_ */
