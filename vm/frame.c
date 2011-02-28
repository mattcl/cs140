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

static struct frame_table f_table;

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
static struct frame_entry *choose_frame_to_evict_clock(void);
static struct frame_entry *choose_frame_to_evict_random(void);
static struct frame_entry *choose_frame_to_evict_lockstep(void);

/* variables for managing the clock algorithm */
static uint32_t evict_hand;
static uint32_t clear_hand;
static uint32_t threshold;

static void evict_init(void){
  threshold = f_table.size/4;
  evict_hand = 0;
  clear_hand = evict_hand + threshold;
}

/* Algorithm for choosing next frame to evict randomly*/
static struct frame_entry *choose_frame_to_evict_random(void){
	ASSERT(lock_held_by_current_thread(&f_table.frame_table_lock));
	struct frame_entry *entry;
       	uint32_t index;
	while(true){
		index = random_ulong() % f_table.size;
		entry = frame_entry_at_pos(index);
		if(!entry->is_pinned){
		    entry->is_pinned = true;
		    break;
		}
	}
	return entry;
}


/* clock algorithm for choosing next frame to evict.  We will have two
   hands, and evict hand and a clear hand.  The clear hand will always
   lead zeroing out accessed bits, while the evict hand will follow
   and evict the first page it finds that still has not been accessed.
   The clearing of the bits will happen only if the interrupt handler
   has ticked the appropriate number of ticks and we get a page fault
   to ensure that 1. our hands never cross and 2. We allow a reasonable
   amount of time for a page to be accessed before checking it's accessed
   bit again, we ensure that the two hands never come within threshold
   frames of each other, this has to be taken into consideration when 
   choosing a frame to evict */

/* Clears a threshold number of PTE's accessed bits from the current
   clear hand of our clock*/
static void clear_accessed_threshold(void){
	ASSERT(intr_get_level() == INTR_OFF);
	ASSERT(lock_held_by_current_thread(&f_table.frame_table_lock));

	if(f_table.size - (clear_hand - evict_hand) <= (threshold * 2)){
		/* If clear hand is way in front of evict hand don't clear
		   access bits*/
		return;
	}
	struct frame_entry *entry;
	uint32_t i;
	for(i = 0; i < threshold; i ++, clear_hand++){
		/* Check if the frame is occupied if so we know that
		   the thread that is in it is still alive because it
		   must have acquired the frame table lock to die*/
		entry = frame_entry_at_pos(clear_hand % f_table.size);
		if(entry->cur_owner != NULL){
			pagedir_is_accessed(entry->cur_owner->pagedir, entry->uaddr);
		}
	}

}

/* Implements the clock algorithm */
static struct frame_entry *choose_frame_to_evict_clock(void){
    ASSERT(lock_held_by_current_thread(&f_table.frame_table_lock));
    struct frame_entry *entry;
	enum intr_level old_level;

	old_level = intr_disable();
	if(advance_clear_hand){
		clear_accessed_threshold();
		advance_clear_hand = false;
	}
	intr_set_level(old_level);

    while((evict_hand + threshold) % f_table.size < clear_hand % f_table.size){
        entry = frame_entry_at_pos((evict_hand++)%f_table.size);
        old_level = intr_disable();
        if(!entry->is_pinned && !pagedir_is_accessed(entry->cur_owner->pagedir, entry->uaddr)){
        	intr_set_level(old_level);
        	entry->is_pinned = true;
        	return entry;
        }
        intr_set_level(old_level);

	}

    return choose_frame_to_evict_lockstep();
}

/* Choose a frame to evict but increment both hands so that
   our hands never cross */
static struct frame_entry *choose_frame_to_evict_lockstep(void){
    ASSERT(lock_held_by_current_thread(&f_table.frame_table_lock));
    struct frame_entry *entry;
    struct frame_entry *clear_entry;
	enum intr_level old_level;
    while(true){
        entry = frame_entry_at_pos((evict_hand++) % f_table.size);
        clear_entry = frame_entry_at_pos((clear_hand++) % f_table.size);
        old_level = intr_disable();
        pagedir_set_accessed(clear_entry->cur_owner->pagedir, clear_entry->uaddr, false);
		if(!entry->is_pinned && !pagedir_is_accessed(entry->cur_owner->pagedir, entry->uaddr)){
			intr_set_level(old_level);
			entry->is_pinned = true;
			return entry;
		}
		intr_set_level(old_level);
    }
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
   with the lock acquired. If a frame is pinned then it should not
   ever have its data pulled out from underneath it.*/
void frame_init(void){
	f_table.size = palloc_number_user_pages();
	f_table.base = palloc_get_multiple(PAL_USER, f_table.size);
	ASSERT(f_table.base != NULL);
	f_table.used_frames = bitmap_create(f_table.size);
	ASSERT(f_table.used_frames != NULL);
	lock_init(&f_table.frame_table_lock);
	f_table.entries = calloc(f_table.size, sizeof(struct frame_entry));
	ASSERT(f_table.entries  != NULL);
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
	enum intr_level old_level;
	struct frame_entry *entry;
	medium_t medium;
	uint32_t *pd;
	bool move_to_disk = false;

	void *kaddr;

	/* Select page and evict it */
	ASSERT(lock_held_by_current_thread(&f_table.frame_table_lock));

	entry = choose_frame_to_evict_random();
	kaddr = entry_to_kaddr(entry);
	ASSERT(entry->is_pinned);

	/* Must set the memory of another users page
       atomically othewise we may have inconsistent
       data in the PTE and the other process can
       fault and their ish will fail miserably*/
	old_level = intr_disable();

	/* Atomically set the pagedir of the passed in uaddr
	   to point to where it can find its memory and set
	   it's present bit to 0 */
	pd = entry->cur_owner->pagedir;
	medium = pagedir_get_medium(pd, entry->uaddr);
	if(pagedir_is_dirty(pd, entry->uaddr)){
		if(medium == PTE_STACK || medium == PTE_EXEC){
			pagedir_setup_demand_page(pd, entry->uaddr, PTE_SWAP_WAIT,
					((uint32_t)entry->uaddr & PTE_ADDR), true);
			move_to_disk = true;
		}else if(medium == PTE_MMAP){
			pagedir_setup_demand_page(pd, entry->uaddr, PTE_MMAP_WAIT,
					((uint32_t)entry->uaddr & PTE_ADDR), true);
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


	void * old_uaddr =  entry->uaddr;
	void * old_frame_thread = entry->cur_owner;
	pid_t old_process_id = entry->cur_owner->process->pid;
	entry->uaddr = new_uaddr;
	entry->cur_owner = thread_current();

	lock_release(&f_table.frame_table_lock);
	/* We set the user to fault and wait until the move
	   to disk operation is complete, now we actually start
       moving the data from this frame out. Any attempt to access
       it from the original owners thread will fault and wait */
	if(move_to_disk){
		if(medium == PTE_STACK || medium == PTE_EXEC){
			swap_write_out(old_frame_thread, old_process_id, old_uaddr, kaddr, medium);
		}else if(medium == PTE_MMAP){
			mmap_write_out(old_frame_thread, old_process_id, old_uaddr, kaddr);
		}
	}

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
		return frame_entry_at_kaddr(evict_page(new_uaddr, (flags & PAL_ZERO) != 0));
	}else{
		/* Setup frame entry */
		struct frame_entry *entry = frame_entry_at_pos(frame_idx);
		ASSERT(entry->uaddr == NULL && entry->cur_owner == NULL);
		entry->uaddr = new_uaddr;
		entry->cur_owner = thread_current();
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
	return entry_to_kaddr(entry);
}

/* Removes the data from the frame pointed to by the kaddr,
   if the frame that the kaddr is pointing to does not belong
   to the current thread will return with doing nothing. If the
   frame is currently pinned then we can not return from this
   function until it becomes unpinned*/
void frame_clear_page (void *kaddr){
	if((uint32_t)kaddr < (uint32_t)f_table.base ||
			(uint32_t)kaddr > ((uint32_t)f_table.base + (f_table.size * (PGSIZE-1)))){
		PANIC("kaddr %p, base %p end %u size %u\n", kaddr, f_table.base,
				((uint32_t)f_table.base + (f_table.size * PGSIZE)), f_table.size);
	}
	lock_acquire(&f_table.frame_table_lock);
	struct frame_entry *entry = frame_entry_at_kaddr(kaddr);

	if(entry->is_pinned ){
		/* The entry is pinned so this means that it is
		   currently being evicted so it is under the control
		   of another thread and doesn't need its frame table
		   entry updated here*/
		lock_release(&f_table.frame_table_lock);
		return;
	}

	/* Clear the entry */
	entry->uaddr = NULL;
	entry->cur_owner = NULL;
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

	entry->is_pinned = false;
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
	if(entry->cur_owner != thread_current()){
		lock_release(&f_table.frame_table_lock);
		return false;
	}
	entry->is_pinned = true;
	lock_release(&f_table.frame_table_lock);
	return true;
}
