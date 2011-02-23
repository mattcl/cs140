#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "filesys/file.h"
#include "threads/interrupt.h"
void syscall_init (void);

/* Also called from exception.c */
void system_exit (struct intr_frame *f, int status );
bool process_mmap_read_in(uint32_t *faulting_addr);

void save_dirty_pages(struct mmap_hash_entry *entry);

#endif /* userprog/syscall.h */
