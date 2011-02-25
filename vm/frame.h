#ifndef FRAME_H_
#define FRAME_H_

#include <bitmap.h>
#include "threads/palloc.h"
#include "threads/synch.h"
#include <stdint.h>

struct frame_table{
	struct bitmap *used_frames;
	struct lock frame_table_lock;
	void *base;
	uint32_t size;
	struct frame_entry *entries;
} f_table;

struct frame_entry{
	bool is_pinned;
	struct thread *cur_thread;
	void *uaddr;
	struct condition pin_condition;
};


void frame_init(void);
void *frame_get_page(enum palloc_flags flags, void *uaddr);
void frame_clear_page (void *kaddr);
void unpin_frame_entry(void *kaddr);


#endif /* FRAME_H_ */
