

#include "swap.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include <bitmap.h>


static struct bitmap used_swap_slots;

/* Swap hash tables are in the individual processes */

/* Function that hashes the individual elements in the swap hash table
   this function hashes the vaddr*/
unsigned swap_block_hash_func (const struct hash_elem *a, AUX);

/* */
bool swap_block_compare (const struct hash_elem *a, const struct hash_elem *b, AUX);

void swap_init(void);

void swap_allocate(void * kvaddr);

