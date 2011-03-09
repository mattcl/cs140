#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

/* Also called from exception.c */
void system_exit (struct intr_frame *f, int status );

#endif /* userprog/syscall.h */
