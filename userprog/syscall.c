#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "pagedir.h"
#include "threads/vaddr.h"

typedef int pid_t;
#define PID_ERROR ((pid_t) -1)

static void syscall_handler (struct intr_frame *);

static void system_halt (struct intr_frame *f UNUSED);
static void system_exit (struct intr_frame *f, int status UNUSED);
static void system_exec (struct intr_frame *f, const char *cmd_line UNUSED);
static void system_wait (struct intr_frame *f, pid_t pid UNUSED);
static void system_create (struct intr_frame *f, const char *file_name, unsigned int initial_size UNUSED);
static void system_remove(struct intr_frame *f, const char *file_name UNUSED);
static void system_open (struct intr_frame *f, const char *file_name UNUSED);
static void system_filesize(struct intr_frame *f, int fd UNUSED);
static void system_read(struct intr_frame *f, int fd , void *buffer, unsigned int size UNUSED);
static void system_write(struct intr_frame *f, int fd, const void *buffer, unsigned int size);
static void system_seek(struct intr_frame *f, int fd, unsigned int position UNUSED);
static void system_tell(struct intr_frame *f, int fd UNUSED);
static void system_close(struct intr_frame *f, int fd UNUSED);

// returns a pointer that can be dereferenced given that
// the user_ptr points to valid memory, returns NULL if
// it does not
static inline void * user_ptr_to_kernel_ptr(void *user_ptr);

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

	void *user_ptr1;

	switch (sys_call_num){
		case SYS_HALT:{
			printf("SYS_HALT called\n");
			system_halt(f);
			break;
		}
		case SYS_EXIT:{
			printf("SYS_EXIT called\n");
			system_exit(f, *(int*)arg(esp, 1));
			thread_exit ();
			break;
		}
		case SYS_EXEC:{
			printf("SYS_EXEC called\n");
			if ((user_ptr1 = user_ptr_to_kernel_ptr(*(char**)arg(esp,1))) == NULL){
				//KILL PROCESS
			}
			system_exec(f, (char*)user_ptr1);
			break;
		}
		case SYS_WAIT:{
			printf("SYS_WAIT called\n");
			system_wait(f, *(pid_t*)arg(esp, 1));
			break;
		}
		case SYS_CREATE:{
			printf("SYS_CREATE called\n");
			if ((user_ptr1 = user_ptr_to_kernel_ptr(*(char**)arg(esp,1))) == NULL){
				//KILL PROCESS
			}
			system_create(f, (char*)user_ptr1, *(int*)arg(esp,2));
			break;
		}
		case SYS_REMOVE:{
			printf("SYS_REMOVE called\n");
			if ((user_ptr1 = user_ptr_to_kernel_ptr(*(char**)arg(esp,1))) == NULL){
				//KILL PROCESS
			}
			system_remove(f, (char*)user_ptr1);
			break;
		}
		case SYS_OPEN:{
			printf("SYS_OPEN called\n");
			if ((user_ptr1 = user_ptr_to_kernel_ptr(*(char**)arg(esp,1))) == NULL){
				//KILL PROCESS
			}
			system_open(f, (char*)user_ptr1);
			break;
		}
		case SYS_FILESIZE:{
			printf("SYS_FILESIZE called\n");
			system_filesize(f, *(int*)arg(esp, 1));
			break;
		}
		case SYS_READ:{
			printf("SYS_READ called\n");
			if((user_ptr1 = user_ptr_to_kernel_ptr(*(char**)arg(esp,2))) == NULL){
				//KILLLLLL PROCESS
			}
			system_read(f, *(int*)arg(esp, 1), user_ptr1, *(int*)arg(esp, 3));
			break;
		}
		case SYS_WRITE:{
			printf("SYS_WRITE called\n");
			if((user_ptr1 = user_ptr_to_kernel_ptr(*(char**)arg(esp,2))) == NULL){
				//KILLLLLL PROCESS
			}
			system_write(f,*(int*)arg(esp, 1), user_ptr1, *(int*)arg(esp, 3));
			break;
		}
		case SYS_SEEK:{
			printf("SYS_SEEK called\n");
			system_seek(f, *(int*)arg(esp, 1),*(int*)arg(esp, 2));
			break;
		}
		case SYS_TELL:{
			printf("SYS_TELL called\n");
			system_tell(f, *(int*)arg(esp, 1));
			break;
		}
		case SYS_CLOSE:{
			printf("SYS_CLOSE called\n");
			system_close(f, *(int*)arg(esp, 1));
			break;
		}
			// Project 3 Syscalls
		case SYS_MMAP:{
			printf("SYS_MMAP called\n");
			break;
		}
		case SYS_MUNMAP:{
			printf("SYS_MUNMAP called\n");
			break;
		}
			//Progect 4 Syscalls
		case SYS_CHDIR:{
			printf("SYS_CHDIR called\n");
			break;
		}
		case SYS_MKDIR:{
			printf("SYS_MKDIR called\n");
			break;
		}
		case SYS_READDIR:{
			printf("SYS_READDIR called\n");
			break;
		}
		case SYS_ISDIR:{
			printf("SYS_ISDIR called\n");
			break;
		}
		case SYS_INUMBER:{
			printf("SYS_INUMBER called\n");
			break;
		}
		default:{
			PANIC ("INVALID SYS CALL NUMBER %d\n", sys_call_num);
			break;
		}
	}
}

static void system_halt (struct intr_frame *f UNUSED){

}
static void system_exit (struct intr_frame *f, int status UNUSED){

}
static void system_exec (struct intr_frame *f, const char *cmd_line UNUSED){

}
static void system_wait (struct intr_frame *f, pid_t pid UNUSED){

}
static void system_create (struct intr_frame *f, const char *file_name, unsigned int initial_size UNUSED){

}
static void system_remove(struct intr_frame *f, const char *file_name UNUSED){

}
static void system_open (struct intr_frame *f, const char *file_name UNUSED){

}
static void system_filesize(struct intr_frame *f, int fd UNUSED){

}
static void system_read(struct intr_frame *f, int fd , void *buffer, unsigned int size UNUSED){

}
static void system_write(struct intr_frame *f, int fd, const void *buffer, unsigned int size){
	printf("SYS_WRITE called %d %s %d\n",fd, buffer, size);
}
static void system_seek(struct intr_frame *f, int fd, unsigned int position UNUSED){

}
static void system_tell(struct intr_frame *f, int fd UNUSED){

}
static void system_close(struct intr_frame *f, int fd UNUSED){

}

static inline void * user_ptr_to_kernel_ptr(void *user_ptr){

	return user_ptr;
}
