
#ifndef SWAP_H_
#define SWAP_H_

#include <hash.h>
#include <stdint.h>

struct swap_hash_table_entry{
	uint32_t vaddr; 		/* Key into the hash table*/
	uint32_t swap_slot; 	/* The swap slot that this vaddr's page
							   resides*/
	struct hash_elem elem;  /* The hash elem */
};

unsigned swap_block_hash_func (const struct hash_elem *a, AUX);
bool swap_block_compare (HASH_ELEM *a, HASH_ELEM *b, AUX);


void swap_init(void);

#endif /* SWAP_H_ */
