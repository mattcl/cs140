

#include "swap.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include <bitmap.h>


static struct bitmap used_swap_slots;

/* Note: Swap hash tables are in the individual processes */

/* Initializes the swap */
void swap_init (void){

}


/* Takes the data from the page pointed to by kvaddr and moves that content
   to an available swap slot, if there is no swap slot currently available
   it returns false to indicate that there was a failure, whether this should
   panic the kernel is up to the caller*/
bool swap_allocate (void * kvaddr){

}

/* Takes the faulting addr and then reads the data back into main memory
   setting the pagedir to point to the new location of the data that just
   got swapped back in */
bool swap_read_in (void *faulting_addr){
	struct thread cur = thread_current();
	struct process cur_process = cur->process;
	uint32_t vaddr = pagedir_get_aux(cur->pagedir, faulting_addr);

	/* Lookup the corresponding swap slot that is holding this faulting
	   addresses data */
	struct swap_entry key;
	key.vaddr = vaddr;
	struct hash_elem *slot_result=hash_find(&cur_process->swap_table, &key.elem);
	if(slot_result == NULL){
		/* This only happens when we have inconsistency and we are trying to read
		   back into memory data that we have yet to swap out... PANIC
		   K-UNIT!!!!*/
		PANIC("See comment");
	}
	uint32_t swap_slot  = hash_entry(slot_result, struct swap_entry, elem)->swap_slot;

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

