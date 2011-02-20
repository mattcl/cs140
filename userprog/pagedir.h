#ifndef USERPROG_PAGEDIR_H
#define USERPROG_PAGEDIR_H

#include <stdbool.h>
#include <stdint.h>

#define SWAP 1
#define DISK 0

typedef uint8_t medium_t;

uint32_t *pagedir_create (void);
void pagedir_destroy (uint32_t *pd);
bool pagedir_set_page (uint32_t *pd, void *upage, void *kpage, bool rw);
void *pagedir_get_page (uint32_t *pd, const void *upage);
void pagedir_clear_page (uint32_t *pd, void *upage);
bool pagedir_is_dirty (uint32_t *pd, const void *upage);
void pagedir_set_dirty (uint32_t *pd, const void *upage, bool dirty);
bool pagedir_is_accessed (uint32_t *pd, const void *upage);
void pagedir_set_accessed (uint32_t *pd, const void *upage, bool accessed);
void pagedir_activate (uint32_t *pd); 

/* functions for supplimentary page table */
void pagedir_set_storage_medium (uint32_t *pd, void *upage, medium_t medium);
medium_t  pagedir_get_storage_medium (uint32_t *pd, void *upage);
void pagedir_set_storage_location (uint32_t *pd, void *upage, uint32_t location);
uint32_t pagedir_get_storage_location (uint32_t *pd, void* upage);

#endif /* userprog/pagedir.h */
