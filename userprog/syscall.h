#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

void close_open_file (struct file *file);

#endif /* userprog/syscall.h */
