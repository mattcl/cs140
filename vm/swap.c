#include "swap.h"
#include "frame.h"
#include <bitmap.h>
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "userprog/process.h"
#include "devices/block.h"
#include "threads/pte.h"
#include "threads/interrupt.h"
#include "devices/timer.h"

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

	uint32_t num_slots = num_sectors / SECTORS_PER_SLOT;

	//printf("%u size and %u slots\n", num_sectors*512, num_slots);
	used_swap_slots = bitmap_create(num_slots);

	ASSERT(used_swap_slots != NULL);

	if(used_swap_slots == NULL){
		PANIC("Couldn't allocat swap bitmap");
	}

	lock_init(&swap_slots_lock);
}

/* Takes the faulting addr and then reads the data back into main memory
   setting the pagedir to point to the new location, obtained using frame.h's
   frame_get_page function which might evict something else of the data that
   just got swapped back in. */
bool swap_read_in (void *faulting_addr){
	//printf("Swap read in %p \n", faulting_addr);
	struct thread *cur = thread_current();
	struct process *cur_process = cur->process;
	uint32_t *pd = cur->pagedir;
	uint32_t masked_uaddr = (uint32_t)faulting_addr & PTE_ADDR;
	size_t start_sector;
	uint8_t *kaddr_ptr;
	uint32_t i, swap_slot;
	medium_t org_medium;

	ASSERT(intr_get_level() == INTR_OFF);

	/* Wait while the data finishes moving to swap */
	while(pagedir_get_medium(pd, faulting_addr) != PTE_SWAP){
		printf("waiting\n");
		/* Wait for write to disk to complete*/
		intr_enable();
		timer_msleep (8000); /* The time of a disk write*/
		intr_disable();
	}

	intr_enable();

	ASSERT(pagedir_get_medium(pd, faulting_addr) == PTE_SWAP);

	/* May evict a page to swap, returns a kernel virtual address so
	   the dirty bit for this kernel address in the PTE*/
	void* kaddr = frame_get_page(PAL_USER, (void*)faulting_addr);

	lock_acquire(&swap_slots_lock);

	/* Lookup the corresponding swap slot that is holding this faulting
	   addresses data */
	struct swap_entry key;
	key.uaddr = masked_uaddr;
	struct hash_elem *slot_result = hash_find(&cur_process->swap_table,
			&key.elem);
	if(slot_result == NULL){
		/* This only happens when we have inconsistency and we are trying to
		   read back into memory data that we have yet to swap out... PANIC
		   K-UNIT!!!!*/
		PANIC("Inconsistency, expected inserted hash entry absent");
		/*return false*/
	}

	struct swap_entry *entry =
			hash_entry(slot_result, struct swap_entry, elem);

	swap_slot = entry->swap_slot;
	org_medium = entry->org_medium;

	ASSERT(kaddr != NULL);

	start_sector = swap_slot * SECTORS_PER_SLOT;
	kaddr_ptr = (uint8_t*)masked_uaddr; /* was kaddr*/

	/* Read the contents of this swap slot into memory */
	for(i = 0; i < SECTORS_PER_SLOT;
			i++, start_sector++,kaddr_ptr += BLOCK_SECTOR_SIZE){
		block_read(swap_device, start_sector, kaddr_ptr );
	}

	/* Set this swap slot to usable */
	bitmap_set(used_swap_slots, swap_slot, false);

	/* Remove this swap slot from the processes swap table */
	struct hash_elem *deleted = hash_delete(&cur_process->swap_table,
			slot_result);

	if(deleted == NULL){
		PANIC("Element found but then not able to be deleted???? Race is everywhere");
		/*return false;*/
	}

	/* Free the malloced swap entry */
	free(hash_entry(deleted, struct swap_entry, elem));

	lock_release(&swap_slots_lock);

	/*Disable interrupts while setting up memory */
	intr_disable();

	/* Set the page in our pagetable to point to our new frame
	   this will set the present bit back to 1*/
	bool success =
			pagedir_set_page (pd, (void*)masked_uaddr, kaddr, true);

	if(!success){
		PANIC("MEMORY ALLOCATION FAILURE");
		/*return false*/
	}

	/* indicate that this is in memorry */
	pagedir_set_medium(pd, (void*)masked_uaddr, org_medium);

	/* Make sure it is read back out to disk if faulted*/
	pagedir_set_dirty(pd, (void*)masked_uaddr, true);

	intr_enable();

	/* This page will be set to accessed after the page is read in
	   from swap so it is unnecessary to set it here*/
	unpin_frame_entry(kaddr);
	return true;
}

/* Its not going anywhere, the underlying frame will be here until
   the frame is no longer pinned*/
bool swap_write_out (struct thread *cur, void *uaddr, void *kaddr, medium_t medium){
	struct process *cur_process = cur->process;
	uint32_t *pd = cur->pagedir;
	printf("Swap out\n");
	/* We set the page to not present in memory in evict so assert it*/
	ASSERT(!pagedir_is_present(pd, uaddr));
	ASSERT(pagedir_get_medium(pd, uaddr) == PTE_SWAP_WAIT);
	ASSERT(kaddr != NULL);

	uint32_t i;
	uint32_t masked_uaddr = (((uint32_t)uaddr & PTE_ADDR));
	uint8_t *kaddr_ptr = (uint8_t*)masked_uaddr;/* was kaddr*/
	size_t swap_slot, start_sector;

	//printf("lock acquired\n");
	lock_acquire(&swap_slots_lock);

	/* Flip the first false bit to be true */
	swap_slot = bitmap_scan_and_flip(used_swap_slots, 0, 1, false);
	if(swap_slot == BITMAP_ERROR){
		PANIC("SWAP IS FULL BABY");
	}

	struct swap_entry *new_entry = calloc(1, sizeof(struct swap_entry));
	if(new_entry == NULL){
		PANIC("KERNEL OUT OF MEMORRY");
	}

	/* Set up the entry */
	new_entry->uaddr = masked_uaddr;
	new_entry->org_medium = medium;
	new_entry->swap_slot = swap_slot;

	struct hash_elem *returned  = hash_insert(&cur_process->swap_table,
			&new_entry->elem);
	if(returned != NULL){
		PANIC("COLLISION USING VADDR AS KEY IN HASH TABLE");
	}

	//printf("kvaddr of data this page points to %p\n", kaddr_ptr);

	start_sector = (swap_slot + 1) * SECTORS_PER_SLOT;

	//printf("swap slot %u, start sector %u\n", new_entry->swap_slot, start_sector);

	for(i = 0; i < SECTORS_PER_SLOT;
			i++, start_sector++, kaddr_ptr += BLOCK_SECTOR_SIZE){
		block_write(swap_device, start_sector, kaddr_ptr);
	}

	lock_release(&swap_slots_lock);

	//printf("Returned from writing block\n");

	/* Tell the process who just got this page evicted that the
	   can find it on swap*/
	if(!pagedir_setup_demand_page(pd, uaddr, PTE_SWAP,
				masked_uaddr, 0)){
		PANIC("Kernel out of memory");
	}

	printf("Swap out finished\n");

	return true;
}

/* Function that hashes the individual elements in the swap hash table
   this function hashes the vaddr, because all virtual
   addresses are unique in each process-- we know that this will not
   produce collisions*/
unsigned swap_slot_hash_func (const struct hash_elem *a, void *aux UNUSED){
	return hash_bytes(&hash_entry(a, struct swap_entry, elem)->uaddr,
			sizeof (int));
}

/* Function to compare the individual swap hash table elements
   this function compares virtual addresses, because all virtual
   addresses are unique in each process we know that this will not
   produce collisions*/
bool swap_slot_compare (const struct hash_elem *a,
		const struct hash_elem *b, void *aux UNUSED){
	ASSERT(a != NULL);
	ASSERT(b != NULL);
	return (hash_entry(a, struct swap_entry, elem)->uaddr <
			hash_entry(b, struct swap_entry, elem)->uaddr);
}

/* call all destructor for hash_destroy */
void swap_slot_destroy (struct hash_elem *e, void *aux UNUSED){
	/*File close needs to be called here */
	struct swap_entry *entry = hash_entry(e, struct swap_entry, elem);

	lock_acquire(&swap_slots_lock);
	/* Set this swap slot to usable*/
	bitmap_set(used_swap_slots, entry->swap_slot, false);
	lock_release(&swap_slots_lock);

	free(entry);
}

