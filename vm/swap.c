#include "swap.h"
#include "frame"
#include <bitmap.h>
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/block.h"


/* This bit map tracks used swap slots, each swap slot is
   4096 bytes large (I.E.) one page. When the bit is set to
   one it is allocated, otherwise it is not allocated*/
static struct bitmap* used_swap_slots;

/* Our secondary device, the SWAP, kinda like a swamp but not really
   because we can traverse it without getting wet thanks to our bitmap*/
static struct block *swap_device;

/* lock for the bitmap and swap to avoid race conditions */
static struct lock swap_slots_lock;

#define SECTORS_PER_SLOT 8

/* Note: Swap hash tables are in the individual processes */

/* Initializes the swap */
void swap_init (void){
	swap_device = block_get_role(BLOCK_SWAP);
	if(swap_device == NULL){
		PANIC("NO SWAP!!!!");
	}

	/* Calculate the number of swap slots supported
	   by our swap device  */
	uint32_t num_sectors = block_size(swap_device);

	uint32_t num_slots = num_sectors/SECTORS_PER_SLOT;

	used_swap_slots = bitmap_create(num_slots);

	if(used_swap_slots == NULL){
		PANIC("Couldn't allocat swap bitmap");
	}

	lock_init(&swap_slots_lock);
}


/* Takes the data from the page pointed to by kvaddr and moves that content
   to an available swap slot, if there is no swap slot currently available
   it returns false to indicate that there was a failure, whether this should
   panic the kernel is up to the caller*/
bool swap_allocate (void * kvaddr){

}

/* Takes the faulting addr and then reads the data back into main memory
   setting the pagedir to point to the new location, obtained using frame.h's
   frame_get_page function which might evict something else of the data that
   just got swapped back in */
bool swap_read_in (void *faulting_addr){
	struct thread cur = thread_current();
	struct process cur_process = cur->process;
	uint32_t vaddr = pagedir_get_aux(cur->pagedir, faulting_addr);
	size_t start_sector;
	uint8_t page_ptr, i;
	/* Lookup the corresponding swap slot that is holding this faulting
	   addresses data */
	struct swap_entry key;
	key.vaddr = vaddr;
	struct hash_elem *slot_result = hash_find(&cur_process->swap_table, &key.elem);
	if(slot_result == NULL){
		/* This only happens when we have inconsistency and we are trying to
		   read back into memory data that we have yet to swap out... PANIC
		   K-UNIT!!!!*/
		PANIC("See comment");
	}

	uint32_t swap_slot=hash_entry(slot_result, struct swap_entry, elem)->swap_slot;

	/* May evict a page to swap */
	uint32_t* free_page = frame_get_page(PAL_USER);

	lock_acquire(&swap_slots_lock);

	start_sector=swap_slot*SECTORS_PER_SLOT;
	page_ptr = free_page;

	/* Read the contents of this swap slot into memory */
	for(i=0; i<SECTORS_PER_SLOT; i++, start_sector++,
											page_ptr += BLOCK_SECTOR_SIZE){
		block_read(swap_device, start_sector, page_ptr );
	}

	/* Set this swap slot to usable*/
	bitmap_set(used_swap_slots, swap_slot, false);
	lock_release(&swap_slots_lock);

	/* Remove this swap slot from the processes swap table */
	struct hash_elem *deleted = hash_delete(&cur_process->swap_table, slot_result);

	if(deleted == NULL){
		PANIC("Element found in hash table but then not able to be deleted????");
	}

	/* Free the malloced swap entry */
	free(hash_entry(deleted, struct swap_entry, elem));

	pagedir_install_page(faulting_addr, free_page, true);
}

/* Function that hashes the individual elements in the swap hash table
   this function hashes the vaddr, because all virtual
   addresses are unique in each process we know that this will not
   produce collisions*/
unsigned swap_slot_hash_func (const struct hash_elem *a, void *aux UNUSED){
	return hash_bytes(&hash_entry(a, struct swap_entry, elem)->vaddr, sizeof (int));
}

/* Function to compare the individual swap hash table elements
   this function compares virtual addresses, because all virtual
   addresses are unique in each process we know that this will not
   produce collisions*/
bool swap_slot_compare (const struct hash_elem *a,
						 const struct hash_elem *b, void *aux UNUSED){
	ASSERT(a != NULL);
	ASSERT(b != NULL);
	return (hash_entry(a, struct swap_entry, elem)->vaddr <
			hash_entry(b, struct swap_entry, elem)->vaddr);
}

