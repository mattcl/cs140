#ifndef THREADS_INIT_H
#define THREADS_INIT_H

#include <debug.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Page directory with kernel mappings only. */
extern uint32_t *init_page_dir;

#define DEFAULT_STACK_SIZE (1<<23) /* 8 MB is the default kernel stack size*/
#define MIN_STACK_SIZE (1<<12)     /* Min size of stack is one page*/
#define MAX_STACK_SIZE (1<<25)	   /* Absolute maximum size of stack is 32 MB */

/* Global Data */
extern uint32_t stack_size;

#endif /* threads/init.h */
