#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void syscall_init (void) {
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

// arg with INT == 0 is the system call number
// params are start at INT == 1
#define arg(ESP, INT)((int *)ESP + INT)

static void syscall_handler (struct intr_frame *f){
	printf ("system call Vector number 0x%x!\n", f->vec_no);

	void *esp = f->esp;
	int sys_call_num = *(int*)arg(esp, 0);

	switch (sys_call_num){
		case SYS_HALT:
			break;
		case SYS_EXIT:
			break;
		case SYS_EXEC:
			break;
		case SYS_WAIT:
			break;
		case SYS_CREATE:
			break;
		case SYS_REMOVE:
			break;
		case SYS_OPEN:
			break;
		case SYS_FILESIZE:
			break;
		case SYS_READ:
			break;
		case SYS_WRITE:
			printf("%p",(char*)arg(esp, 2));
			break;
		case SYS_SEEK:
			break;
		case SYS_TELL:
			break;
		case SYS_CLOSE:
			break;
			// Project 3 Syscalls
		case SYS_MMAP:
			break;
		case SYS_MUNMAP:
			break;
			//Progect 4 Syscalls
		case SYS_CHDIR:
			break;
		case SYS_MKDIR:
			break;
		case SYS_READDIR:
			break;
		case SYS_ISDIR:
			break;
		case SYS_INUMBER:
			break;
		default:
			PANIC ("INVALID SYS CALL NUMBER %d\n", sys_call_num);
			break;
	}


	printf("syscall esp %p\n", esp);
	printf("System number %d\n",sys_call_num);

	thread_exit ();
}
