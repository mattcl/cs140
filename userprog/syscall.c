#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

static void system_halt (struct intr_frame *f UNUSED);
static void system_exit (struct intr_frame *f, int status UNUSED);
static void system_exec (struct intr_frame *f, const char *cmd_line UNUSED);
static void system_wait (struct intr_frame *f, tid_t pid UNUSED);
static void system_create (struct intr_frame *f, const char *file, unsigned int initial_size UNUSED);
static void system_remove(struct intr_frame *f, const char *file UNUSED);
static void system_open (struct intr_frame *f, const char *file UNUSED);
static void system_filesize(struct intr_frame *f, int fd UNUSED);
static void system_read(struct intr_frame *f, int fd , void *buffer, unsigned int size UNUSED);
static void system_write(struct intr_frame *f, int fd, const void *buffer, unsigned int size);
static void system_seek(struct intr_frame *f, int fd, unsigned int position UNUSED);
static void system_tell(struct intr_frame *f, int fd UNUSED);
static void system_close(struct intr_frame *f, int fd UNUSED);

void syscall_init (void) {
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

// arg with INT == 0 is the system call number
// params are start at INT == 1
#define arg(ESP, INT)((int *)ESP + INT)

static void syscall_handler (struct intr_frame *f){
	//printf ("system call Vector number 0x%x!\n", f->vec_no);

	void *esp = f->esp;
	int sys_call_num = *(int*)arg(esp, 0);

	//printf("syscall esp %p\n", esp);
	//printf("System Call number %d\n",sys_call_num);

	switch (sys_call_num){
		case SYS_HALT:
			printf("SYS_HALT called\n");
			break;
		case SYS_EXIT:
			printf("SYS_EXIT called\n");
			thread_exit ();
			break;
		case SYS_EXEC:
			printf("SYS_EXEC called\n");
			break;
		case SYS_WAIT:
			printf("SYS_WAIT called\n");
			break;
		case SYS_CREATE:
			printf("SYS_CREATE called\n");
			break;
		case SYS_REMOVE:
			printf("SYS_REMOVE called\n");
			break;
		case SYS_OPEN:
			printf("SYS_OPEN called\n");
			break;
		case SYS_FILESIZE:
			printf("SYS_FILESIZE called\n");
			break;
		case SYS_READ:
			printf("SYS_READ called\n");
			break;
		case SYS_WRITE:
			printf("SYS_WRITE called %d %s %d\n",*(int*)arg(esp, 1), *(char**)arg(esp, 2), *(int*)arg(esp,3));

			break;
		case SYS_SEEK:
			printf("SYS_SEEK called\n");
			break;
		case SYS_TELL:
			printf("SYS_TELL called\n");
			break;
		case SYS_CLOSE:
			printf("SYS_CLOSE called\n");
			break;
			// Project 3 Syscalls
		case SYS_MMAP:
			printf("SYS_MMAP called\n");
			break;
		case SYS_MUNMAP:
			printf("SYS_MUNMAP called\n");
			break;
			//Progect 4 Syscalls
		case SYS_CHDIR:
			printf("SYS_CHDIR called\n");
			break;
		case SYS_MKDIR:
			printf("SYS_MKDIR called\n");
			break;
		case SYS_READDIR:
			printf("SYS_READDIR called\n");
			break;
		case SYS_ISDIR:
			printf("SYS_ISDIR called\n");
			break;
		case SYS_INUMBER:
			printf("SYS_INUMBER called\n");
			break;
		default:
			PANIC ("INVALID SYS CALL NUMBER %d\n", sys_call_num);
			break;
	}
}
