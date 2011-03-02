
#ifndef SWAP_H_
#define SWAP_H_

#include <hash.h>
#include <stdint.h>
#include <debug.h>
#include "userprog/pagedir.h"
#include "userprog/process.h"

struct swap_entry{
	uint32_t uaddr; 		/* Key into the hash table*/
	uint32_t swap_slot; 	/* The swap slot that this vaddr's page
							   resides*/
	medium_t org_medium;	/* The original medium of the thing now on
							   disk */
	struct hash_elem elem;  /* The hash elem */
};

void destroy_swap_table(struct hash *to_destroy);
unsigned swap_slot_hash_func (const struct hash_elem *a, void *aux UNUSED);
bool swap_slot_compare (const struct hash_elem *a, const struct hash_elem *b,
															void *aux UNUSED);
void swap_slot_destroy (struct hash_elem *e, void *aux UNUSED);

void swap_init (void);

bool swap_read_in (void *faulting_addr);
bool swap_write_out (struct process *cur, uint32_t *pd, pid_t pid,
		void *uaddr, void *kaddr, medium_t medium);
#endif /* SWAP_H_ */
