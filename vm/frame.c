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
#include "userprog/syscall.h"

/* Given the frame entry pointer, returns its position in the
   frame table*/
static inline uint32_t frame_entry_pos(struct frame_entry *entry){
	return (((uint32_t)entry - (uint32_t)f_table.entries)
			/ sizeof(struct frame_entry));
}

/* Given the frame_entry pointer, returns the corresponding kernel
   virtual address that it corresponds to*/
static inline void *entry_to_kaddr(struct frame_entry *entry){
	return (uint8_t*)f_table.base + (frame_entry_pos(entry)*PGSIZE);
}

/* Given a position returns the frame_entry that it corresponds to
   utilizes pointer arithmetic*/
static inline struct frame_entry *frame_entry_at_pos(uint32_t pos){
	return f_table.entries + pos ;
}

/* Given the kernel virtual address, returns the corresponding frame table
   entry */
static inline struct frame_entry *frame_entry_at_kaddr (void *kaddr){
	ASSERT(((uint32_t)kaddr % PGSIZE) == 0);
	return frame_entry_at_pos(((uint32_t)kaddr-(uint32_t)f_table.base)/PGSIZE);
}

static struct frame_entry *frame_first_free(enum palloc_flags flags, void *new_uaddr);
static void *evict_page(void *new_uaddr, bool zero_out);

static void evict_init(void){
	/* None yet */
}

/* Initializes the frame table by first allocating all of the
   the user pool and creating a bitmap that corresponds to the
   free or used frames that we currently have. Also initializes
   a frame table lock and ensures that we only set individual
   frames is_pinned to true/false inside this lock. This is
   because we need to ensure that the frame we are looking at
   will only be changed by us at any moment. Synchronization
   could also work if we put a lock into each of the frames and
   acquired it before changing any of its data but we erred on the
   side of correctness and made sure that eviction on frames is done
   with the lock acquired. Each frame has a condition variable which
   will be used to synchronize frame_clear_page with eviction. If a
   frame is pinned then it should not ever have its data pulled out
   from underneath it. The condition variable ensures this.*/
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

/* Evicts a page from the frame table and sets its new
   uaddr and new thread to be the one passed in and the
   current running thread. returns the kernel virtual
   address of the memory which can then be installed in the
   pagedir of the current thread. We give back the kernel virtual
   address because this function is called from frame_get_page
   which is a virtual wrapper to palloc_get_page(PAL_USER) which
   also returns a kernel virtual address without mapping it to
   any pagedir*/
static void *evict_page(void *new_uaddr, bool zero_out){
	uint32_t frame_to_evict;
	enum intr_level old_level;
	struct frame_entry *entry;
	medium_t medium;
	uint32_t *pd;
	bool move_to_disk = false;
	/* Select page and evict it */
	lock_acquire(&f_table.frame_table_lock);
	while(true){
		/* Must set the memory of another users page
       	   atomically othewise we may have inconsistent
       	   data in the PTE and the other process can
       	   fault and their ish will fail miserably*/
		old_level = intr_disable();

		frame_to_evict = random_ulong() % f_table.size;
		entry = frame_entry_at_pos(frame_to_evict);
		if(entry->is_pinned) {
			intr_set_level(old_level);
			continue;
		}else{
			entry->is_pinned = true;
		}

		ASSERT(entry->is_pinned);

		/* Atomically set the pagedir of the passed in uaddr
		   to point to where it can find its memory and set
		   it's present bit to 0 */
		pd = entry->cur_thread->pagedir;
		medium = pagedir_get_medium(pd, entry->uaddr);
		if(pagedir_is_dirty(pd, entry->uaddr)){
			if(medium == PTE_STACK || medium == PTE_EXEC){
				pagedir_setup_demand_page(pd, entry->uaddr, PTE_SWAP_WAIT,
						pagedir_get_page(pd, entry->uaddr), true);
				move_to_disk = true;
			}else if(medium == PTE_MMAP){
				pagedir_setup_demand_page(pd, entry->uaddr, PTE_MMAP_WAIT,
						pagedir_get_page(pd, entry->uaddr), true);
				move_to_disk = true;
			}else{
				PANIC("realocate_page called with dirty page of medium_t: %x", medium);
			}
		}else{
			if(medium == PTE_STACK){
				pagedir_clear_page(pd, entry->uaddr);
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
		break;
	}

	printf("ousting %p\n", entry);

	lock_release(&f_table.frame_table_lock);



	void *kaddr = entry_to_kaddr(entry);

	/* We set the user to fault and wait until the move
	   to disk operation is complete, now we actually start
       moving the data from this frame out. Any attempt to access
       it from the original owners thread will fault and wait */
	if(move_to_disk){
		if(medium == PTE_STACK || medium == PTE_EXEC){
			swap_write_out(entry->cur_thread, entry->uaddr, kaddr, medium);
		}else if(medium == PTE_MMAP){
			mmap_write_out(entry->cur_thread, entry->uaddr, kaddr);
		}
	}

	lock_acquire(&f_table.frame_table_lock);
	entry->uaddr = new_uaddr;
	entry->cur_thread = thread_current();
	lock_release(&f_table.frame_table_lock);
	printf("ousted %p\n", entry);
	/* Clear out the page if PAL_ZERO was specified*/
	if(zero_out){
		memset(kaddr, 0, PGSIZE);
	}
	return kaddr;
}

/* Finds the first frame that is free and returns it, if the table
   is full then it will return NULL, in which case you should evict
   something */
static struct frame_entry *frame_first_free(enum palloc_flags flags, void *new_uaddr){
	lock_acquire(&f_table.frame_table_lock);
	size_t frame_idx = bitmap_scan (f_table.used_frames, 0, 1 , false);
	if(frame_idx == BITMAP_ERROR){
		lock_release(&f_table.frame_table_lock);
		return NULL;
	}else{
		/* Setup frame entry */
		struct frame_entry *entry = frame_entry_at_pos(frame_idx);
		ASSERT(entry->uaddr == NULL && entry->cur_thread == NULL);
		entry->uaddr = new_uaddr;
		entry->cur_thread = thread_current();
		entry->is_pinned = true;
		bitmap_set(f_table.used_frames, frame_idx, true);
		lock_release(&f_table.frame_table_lock);
		if((flags&PAL_ZERO) != 0){
			memset(entry_to_kaddr(entry), 0, PGSIZE);
		}
		return entry;
	}
}

/* If there are no frames that are free it will evict a frame
   and return that evicted frame to the user, otherwise it will
   return the first frame in the frame table that is free */
void *frame_get_page(enum palloc_flags flags, void *uaddr){
	ASSERT((flags & PAL_USER) != 0);
	struct frame_entry *entry = frame_first_free(flags, uaddr);
	if(entry){
		return entry_to_kaddr(entry);
	}else{
		return evict_page(uaddr, (flags & PAL_ZERO) != 0);
	}
}

/* Removes the data from the frame pointed to by the kaddr,
   if the frame that the kaddr is pointing to does not belong
   to the current thread will return with doing nothing. If the
   frame is currently pinned then we can not return from this
   function until it becomes unpinned*/
void frame_clear_page (void *kaddr){
	if((uint32_t)kaddr >= (uint32_t)f_table.base &&
			(uint32_t)kaddr  < ((uint32_t)f_table.base + (f_table.size * PGSIZE))){
		PANIC("kaddr %p, base %p end %p %size %u\n", kaddr, f_table.base,
				((uint32_t)f_table.base + (f_table.size * PGSIZE)), f_table.size);
	}
	lock_acquire(&f_table.frame_table_lock);
	struct frame_entry *entry = frame_entry_at_kaddr(kaddr);

	/* The thread is the same one that is in the frame
     now so it can release this*/
	printf("clearing %p\n", entry);
	while(entry->is_pinned ){
		printf("waiting won't clear %p \n", entry);
		/* new shit is being put in the frame, moving our shit out
		   so we need to wait until this entry->is_pinned is false */
		cond_wait(&entry->pin_condition, &f_table.frame_table_lock);
		/* it is possible that between the time that we were signaled
		   and we woke up another process has pinned down this frame.
		   In this case, howe		 */
		if(!entry->is_pinned || entry->cur_thread != thread_current()){
			printf("finally clearing %p\n", entry);
			lock_release(&f_table.frame_table_lock);
			return;
		}
	}
	printf("cleared %p\n", entry);
	/* Clear the entry */
	entry->uaddr = NULL;
	entry->cur_thread = NULL;
	entry->is_pinned = false;
	bitmap_set(f_table.used_frames, frame_entry_pos(entry), false);

	lock_release(&f_table.frame_table_lock);
}

/* Need to unpin after it is installed in the pagedir of your thread
   will unpin the frame*/
void unpin_frame_entry(void *kaddr){
	ASSERT(kaddr >= f_table.base &&
			(uint8_t*)kaddr  < (uint8_t*)f_table.base + (f_table.size * PGSIZE));
	lock_acquire(&f_table.frame_table_lock);
	struct frame_entry *entry = frame_entry_at_kaddr(kaddr);
	ASSERT(entry->is_pinned);
	printf("Unpinned %p\n", entry);
	entry->is_pinned = false;
	cond_signal(&entry->pin_condition, &f_table.frame_table_lock);
	lock_release(&f_table.frame_table_lock);
}

/* Returns if this frame was pinned, false if the
   current thread is not in the frame or if the frame
   is allready pinned */
bool pin_frame_entry(void *kaddr){
	ASSERT(kaddr >= f_table.base &&
			(uint8_t*)kaddr  < (uint8_t*)f_table.base + (f_table.size * PGSIZE));
	lock_acquire(&f_table.frame_table_lock);
	struct frame_entry *entry = frame_entry_at_kaddr(kaddr);
	if(entry->is_pinned){
		lock_release(&f_table.frame_table_lock);
		return false;
	}
	if(entry->cur_thread != thread_current()){
		lock_release(&f_table.frame_table_lock);
		return false;
	}
	entry->is_pinned = true;
	lock_release(&f_table.frame_table_lock);
	return true;
}
