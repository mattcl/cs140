#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "pagedir.h"

static void syscall_handler (struct intr_frame *);

void syscall_init (void) {
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

// arg with INT == 0 is the system call number
// params are start at INT == 1
#define arg(ESP, INT)((int *)ESP + INT)

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

static void *convert_user_pointer (void *user_ptr);

static void syscall_handler (struct intr_frame *f){
	printf ("system call Vector number 0x%x!\n", f->vec_no);

	void *esp = f->esp;
	int sys_call_num = *(int*)arg(esp, 0);

	printf("syscall esp %p\n", esp);
	printf("System number %d\n",sys_call_num);

	switch (sys_call_num){
		case SYS_HALT:
			system_halt(f);
			break;
		case SYS_EXIT:
			system_exit(f, *(int*)arg(esp, 1));
			break;
		case SYS_EXEC:
			system_exec(f, *(char**)arg(esp,1));
			break;
		case SYS_WAIT:
			system_wait(f, *(tid_t*)arg(esp,1));
			break;
		case SYS_CREATE:
			system_create(f, *(char**)arg(esp,1), *(unsigned int *)arg(esp,2));
			break;
		case SYS_REMOVE:
			system_remove(f, *(char**)arg(esp,1));
			break;
		case SYS_OPEN:
			system_open(f, *(char**)arg(esp,1));
			break;
		case SYS_FILESIZE:
			system_filesize(f, *(int*)arg(esp,1));
			break;
		case SYS_READ:
			system_read(f, *(int*)arg(esp,1), *(void**)arg(esp,2), *(unsigned int *)arg(esp,3) );
			break;
		case SYS_WRITE:{
			system_write(f, *(int*)arg(esp,1), *(void**)arg(esp,2), *(unsigned int *)arg(esp,3) );
			break;
		}
		case SYS_SEEK:
			system_seek(f, *(int*)arg(esp,1), *(unsigned int *)arg(esp,2) );
			break;
		case SYS_TELL:
			system_tell(f, *(int*)arg(esp,1));
			break;
		case SYS_CLOSE:
			system_close(f, *(int*)arg(esp,1));
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

/*
 * Takes a user program pointer and checks it, will return NULL if the pointer is invalid
 * Otherwise it will return the address that the kernel can use to access the appropriate data
 * Should be called before ever dereferencing a user pointer
 */
static void *convert_user_pointer (void *user_ptr UNUSED){

}

static void system_halt (struct intr_frame *f UNUSED){
	printf("SYS_HALT called\n");
}

static void system_exit (struct intr_frame *f, int satus UNUSED){
	printf("SYS_EXIT called\n");
	thread_exit ();
}

static void system_exec (struct intr_frame *f, const char *cmd_line UNUSED){
	printf("SYS_EXEC called\n");
}

static void system_wait (struct intr_frame *f, tid_t pid UNUSED){
	printf("SYS_WAIT called\n");
}
static void system_create (struct intr_frame *f, const char *file, unsigned int initial_size UNUSED){
	printf("SYS_CREATE called\n");
}
static void system_remove(struct intr_frame *f, const char *file UNUSED){
	printf("SYS_REMOVE called\n");
}
static void system_open (struct intr_frame *f, const char *file UNUSED){
	printf("SYS_OPEN called\n");
}
static void system_filesize(struct intr_frame *f, int fd UNUSED){
	printf("SYS_FILESIZE called\n");
}
static void system_read(struct intr_frame *f, int fd , void *buffer, unsigned int size UNUSED){
	printf("SYS_READ called\n");
}
static void system_write(struct intr_frame *f, int fd, const void *buffer, unsigned int size){
	struct thread *t = thread_current ();
	printf("SYS_WRITE called with args %d %s, %u\n",fd, buffer, size);
	//vtop(pagedir_get_page(t->pagedir, *(char**)arg(esp, 2))));
	f->eax = 4;
}

static void system_seek(struct intr_frame *f, int fd, unsigned int position UNUSED){
	printf("SYS_SEEK called\n");
}
static void system_tell(struct intr_frame *f, int fd UNUSED){
	printf("SYS_TELL called\n");
}
static void system_close(struct intr_frame *f, int fd UNUSED){
	printf("SYS_CLOSE called\n");
}
