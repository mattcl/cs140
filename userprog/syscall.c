#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void syscall_init (void) {
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler (struct intr_frame *f){
	printf ("system call Vector number 0x%x!\n", f->vec_no);

	void *esp = f->esp;

	printf("syscall esp %p\n", esp);
	printf("System number %d\n", *((int *)esp+1));

	thread_exit ();
}
