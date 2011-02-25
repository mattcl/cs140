#include <random.h>
#include <string.h>
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/interrupt.h"
#include "threads/pte.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "frame.h"
#include "swap.h"
#include "syscall.h"

static inline uint32_t frame_entry_pos(struct frame_entry *entry){
	return (((uint32_t)entry - (uint32_t)f_table.entries)
			/sizeof(struct frame_entry));
}

static inline void *entry_to_kaddr(struct frame_entry *entry){
	return f_table.base + frame_entry_pos(entry)*PGSIZE;
}

static inline struct frame_entry *frame_entry_at_pos(uint32_t pos){
	return f_table.entries + (pos * sizeof(struct frame_entry));
}

static inline struct frame_entry *frame_entry_at_kaddr (void *kaddr){
	return frame_entry_at_pos((((uint32_t)kaddr&PTE_ADDR)-
			(uint32_t)f_table.base)/PGSIZE);
}

static struct frame_entry *frame_first_free(enum palloc_flags flags, void *new_uaddr);
static void *evict_page(void *new_uaddr, bool zero_out);

static void evict_init(void){
	/* None yet */
}


void frame_init(void){
	f_table.size = palloc_number_user_pages();
	f_table.base = palloc_get_multiple(PAL_USER, f_table.size);
	ASSERT(f_table.base != NULL);
	f_table.used_frames = bitmap_create(f_table.size);
	ASSERT(f_table.used_frames != NULL);
	lock_init(&f_table.frame_table_lock);
	f_table.entries = calloc(f_table.size, sizeof(struct frame_entry));
	ASSERT(f_table.entries  != NULL);
	/* Initialize the condition variable in each frame to
	   guarantee that data will not leave the frame while
	   it is pinned*/
	struct frame_entry *start = f_table.entries;
	uint32_t i;
	for(i = 0; i < f_table.size; start ++, i++){
		cond_init(&start->pin_condition);
	}
	evict_init();
}

static void *evict_page(void *new_uaddr, bool zero_out){
	uint32_t frame_to_evict;
	enum intr_level old_level;
	struct frame_entry *entry;
	medium_t medium;
	uint32_t *pd;
	bool move_to_disk = false;
	/* Select random page and evict it */
	lock_acquire(&f_table.frame_table_lock);
	while(true){
		/* Must set the memory of another users page
       	   atomically othewise we may have inconsistent
       	   data in the PTE and the other process can
       	   fault and their ish will fail miserably*/
		old_level = intr_disable();
		frame_to_evict = random_ulong()%f_table.size;
		/* Eviction policy here, should run with interrupts
      	   disabled for same reason as above */
		entry = frame_entry_at_pos(frame_to_evict);
		if(entry->is_pinned) {
			intr_set_level(old_level);
			continue;
		}else{
			entry->is_pinned = true;
		}
		pd = entry->cur_thread->pagedir;
		medium = pagedir_get_medium(pd, entry->uaddr);
		if(pagedir_is_dirty(pd, entry->uaddr)){
			if(medium == PTE_STACK || medium == PTE_EXEC){
				pagedir_setup_demand_page(pd, entry->uaddr, PTE_SWAP_WAIT,
						((uint32_t)entry->uaddr & PTE_ADDR), true);
			}else if(medium == PTE_MMAP){
				pagedir_setup_demand_page(pd, entry->uaddr, PTE_MMAP_WAIT,
						((uint32_t)entry->uaddr & PTE_ADDR), true);
			}else{
				PANIC("realocate_page called with clean page of medium_t: %x", medium);
			}
			move_to_disk = true;
		}else{
			if(medium == PTE_STACK){
				pagedir_clean_page(pd, entry->uaddr);
			}else if(medium == PTE_EXEC){
				bool writable = pagedir_is_writable(pd, entry->uaddr);
				pagedir_setup_demand_page(pd, entry->uaddr, PTE_EXEC,
						((uint32_t)entry->uaddr & PTE_ADDR), writable);
			}else if(medium == PTE_MMAP){
				pagedir_setup_demand_page(pd, entry->uaddr, PTE_MMAP,
						((uint32_t)entry->uaddr & PTE_ADDR), true);
			}else{
				PANIC("realocate_page called with clean page of medium_t: %x", medium);
			}
		}
		intr_set_level(old_level);
	}

	entry->uaddr = new_uaddr;
	entry->cur_thread = thread_current();
	lock_release(&f_table.frame_table_lock);

	void *kaddr = entry_to_kaddr(entry);

	/* We set the user to fault and wait until the
     operation is complete, now we actually start
     moving the data from this frame out */
	if(move_to_disk){
		if(medium == PTE_STACK || medium == PTE_EXEC){
			swap_write_out(entry->cur_thread, entry->uaddr, kaddr, medium);
		}else if(medium == PTE_MMAP){
			mmap_write_out(entry->cur_thread, entry->uaddr, kaddr);
		}
	}

	if(zero_out){
		memset(kaddr, 0, PGSIZE);
	}

	return kaddr;
}

static struct frame_entry *frame_first_free(enum palloc_flags flags, void *new_uaddr){
	lock_acquire(&f_table.frame_table_lock);
	size_t frame_idx = bitmap_scan (f_table.used_frames, 0, 1 , false);
	if(frame_idx == BITMAP_ERROR){
		lock_release(&f_table.frame_table_lock);
		return NULL;
	}else{
		struct frame_entry *entry = frame_entry_at_position(frame_idx);
		ASSERT(entry->uaddr == NULL && entry->cur_thread == NULL);
		entry->uaddr = new_uaddr;
		entry->cur_thread = thread_current();
		entry->is_pinned = true;
		bitmap_set(f_table.used_frames, frame_idx, true);
		lock_release(&f_table.frame_table_lock);
	}
}

void *frame_get_page(enum palloc_flags flags, void *uaddr){
	ASSERT((flags & PAL_USER) != 0);
	struct frame_entry *entry = frame_first_free(flags, uaddr);
	if(entry){
		return entry_to_kaddr;
	}else{
		return evict_page(uaddr, (flags & PAL_ZERO) != 0);
	}
}

void frame_clear_page (void *kaddr){
	lock_acquire(&f_table.frame_table_lock);
	struct frame_entry *entry = frame_entry_at_kaddr(kaddr);

	ASSERT(thread_current() == entry->cur_thread);
	/* The thread is the same one that is in the frame
     now so it can release this*/

	while(entry->is_pinned){
		cond_wait(&entry->pin_condition, &f_table.frame_table_lock);
	}

	entry->uaddr = NULL;
	entry->cur_thread = NULL;
	entry->is_pinned = false;
	bitmap_set(f_table.used_frames, frame_entry_pos(entry), false);

	lock_release(&f_table.frame_table_lock);
}

/* Need to unpin after it is installed
   in the pagedir of your thread */
void unpin_frame_entry(void kaddr){
	lock_acquire(&f_table.frame_table_lock);
	struct frame_entry *entry = frame_entry_at_kaddr(kaddr);
	ASSERT(entry->is_pinned);
	entry->is_pinned = false;
	cond_signal(&entry->pin_condition, &f_table.frame_table_lock);
	lock_release(&f_table.frame_table_lock);
}

