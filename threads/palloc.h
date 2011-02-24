#ifndef THREADS_PALLOC_H
#define THREADS_PALLOC_H

#include <stddef.h>
#include <stding.h>

/* How to allocate pages. */
enum palloc_flags{
    PAL_ASSERT = 001,           /* Panic on failure. */
    PAL_ZERO = 002,             /* Zero page contents. */
    PAL_USER = 004              /* User page. */
};

#define MEMORY_DIVISION 2

void palloc_init (size_t user_page_limit);
void *palloc_get_page (enum palloc_flags);
void *palloc_get_multiple (enum palloc_flags, size_t page_cnt);
void palloc_free_page (void *);
void palloc_free_multiple (void *, size_t page_cnt);

/* Used for the frame allocator to know how many frames are available
   for the user*/
inline size_t palloc_number_user_pages(void);
inline size_t palloc_number_kernel_pages(void);
inline size_t palloc_get_user_page_index(void *kvaddr);
inline void * palloc_get_kaddr_user_index(uint32_t user_index);

#endif /* threads/palloc.h */
