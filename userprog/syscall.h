#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "filesys/file.h"
void syscall_init (void);

static struct lock filesys_lock;

void close_open_file (struct file *file);

#endif /* userprog/syscall.h */
