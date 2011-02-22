#ifndef USERPROG_EXCEPTION_H
#define USERPROG_EXCEPTION_H

/* Page fault error code bits that describe the cause of the exception.  */
#define PF_P 0x1    /* 0: not-present page. 1: access rights violation. */
#define PF_W 0x2    /* 0: read, 1: write. */
#define PF_U 0x4    /* 0: kernel, 1: user process. */

#define MAX_ASM_PUSH 32 /* The maximum amount of data that can be pushed
						   by a single assembly instruction. This exists
						   because 80x86 tries to dereference the memory
						   before actually decrementing the stack....
						   Which is completely counter intuitive....
						   Just sayin */

#define MAX_STACK_SIZE

void exception_init (void);
void exception_print_stats (void);

#endif /* userprog/exception.h */
