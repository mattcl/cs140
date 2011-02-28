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
	struct bitmap *used_frames;
	struct lock frame_table_lock;
	void *base;
	uint32_t size;
	struct frame_entry *entries;
};

struct frame_entry{
	bool is_pinned;
	struct process *cur_owner;
	uint32_t *pd;
	void *uaddr;
};

void frame_init(void);
void *frame_get_page(enum palloc_flags flags, void *uaddr);
void frame_clear_page (void *kaddr);
void unpin_frame_entry(void *kaddr);
bool pin_frame_entry(void *kaddr);

#endif /* FRAME_H_ */
