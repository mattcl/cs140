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

static int get_user(const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);

static unsigned int get_user_int(const uint32_t *uaddr, int *ERROR);

void syscall_init (void) {
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

// arg with INT == 0 is the system call number
// params are start at INT == 1
#define arg(ESP, INT)(((int *)ESP) + INT)

static void syscall_handler (struct intr_frame *f){
	printf ("system call Vector number 0x%x!\n", f->vec_no);

	void *esp = f->esp;
	if (!is_user_vaddr(esp)){
		//KILL Process
	}
	int sys_call_num = get_user(arg(esp, 0));

	//printf("syscall esp %p\n", esp);
	//printf("System Call number %d\n",sys_call_num);

	//TEST user access

	int ERROR = 0;
	unsigned int input = get_user_int((uint32_t*)0x2, &ERROR);
	if(ERROR < 0){
		printf("SEGFAULT!!!!!\n");
	} else {
		printf("DIDNT SEGFAULT THE REAL ERROR\n");
	}

	input = get_user_int((uint32_t*)esp, &ERROR);
	if(ERROR < 0){
		printf("SEGFAULT!!!!!REAL ERROR\n");
	} else {
		printf("DIDNT SEGFAULT :)\n");
	}

	//end test

	switch (sys_call_num){
		case SYS_HALT:{
				      printf("SYS_HALT called\n");
				      system_halt(f);
				      break;
			      }
		case SYS_EXIT:{
				      printf("SYS_EXIT called\n");
				      if (!is_user_vaddr(arg(esp,1))){
					      //KILL PROCESS
				      }
				      system_exit(f, *(int*)arg(esp,1));
				      thread_exit ();
				      break;
			      }
		case SYS_EXEC:{
				      printf("SYS_EXEC called\n");
				      if (!is_user_vaddr(arg(esp,1))){
					      //KILL PROCESS
				      }
				      system_exec(f, *(char**)arg(esp,1));
				      break;
			      }
		case SYS_WAIT:{
				      printf("SYS_WAIT called\n");
				      if (!is_user_vaddr(arg(esp,1))){
					      //KILL PROCESS
				      }
				      system_wait(f, *(pid_t*)arg(esp,1));
				      break;
			      }
		case SYS_CREATE:{
					printf("SYS_CREATE called\n");
					if (!is_user_vaddr(arg(esp,1)) || !is_user_vaddr(arg(esp,2))){
						//KILL PROCESS
					}
					system_create(f, (char*)arg(esp,1), *(int*)arg(esp,2));
					break;
				}
		case SYS_REMOVE:{
					printf("SYS_REMOVE called\n");
					if (!is_user_vaddr(arg(esp,1))){
						//KILL PROCESS
					}
					system_remove(f, (char*)arg(esp,1));
					break;
				}
		case SYS_OPEN:{
				      printf("SYS_OPEN called\n");
				      if (!is_user_vaddr(arg(esp,1))){
					      //KILL PROCESS
				      }
				      system_open(f, (char*)arg(esp,1));
				      break;
			      }
		case SYS_FILESIZE:{
					  printf("SYS_FILESIZE called\n");
					  if (!is_user_vaddr(arg(esp,1))){
						  //KILL PROCESS
					  }
					  system_filesize(f, *(int*)arg(esp,1));
					  break;
				  }
		case SYS_READ:{
				      printf("SYS_READ called\n");
				      if(!is_user_vaddr(arg(esp,1)) ||
						      !is_user_vaddr(arg(esp,2)) ||
						      !is_user_vaddr(arg(esp,3))){
					      //KILLLLLL PROCESS
				      }
				      system_read(f, *(int*)arg(esp,1), *(char**)arg(esp,2), *(int*)arg(esp,3));
				      break;
			      }
		case SYS_WRITE:{
				       printf("SYS_WRITE called\n");
				       if(!is_user_vaddr(arg(esp,1)) ||
						       !is_user_vaddr(arg(esp,2)) ||
						       !is_user_vaddr(arg(esp,3))){
					       //KILLLLLL PROCESS
				       }
				       system_write(f, *(int*)arg(esp,1), *(char**)arg(esp,2), *(int*)arg(esp,3));
				       break;
			       }
		case SYS_SEEK:{
				      printf("SYS_SEEK called\n");
				      if(!is_user_vaddr(arg(esp,1)) ||
						      !is_user_vaddr(arg(esp,2))){
					      //KILLLLLL PROCESS
				      }
				      system_seek(f, *(int*)arg(esp,1), *(unsigned int*)arg(esp,2));
				      break;
			      }
		case SYS_TELL:{
				      printf("SYS_TELL called\n");
				      if (!is_user_vaddr(arg(esp,1))){
					      //KILL PROCESS
				      }
				      system_tell(f, *(int*)arg(esp,1));
				      break;
			      }
		case SYS_CLOSE:{
				       printf("SYS_CLOSE called\n");
				       if (!is_user_vaddr(arg(esp,1))){
					       //KILL PROCESS
				       }
				       system_close(f, *(int*)arg(esp,1));
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
	printf("SYS_WRITE called %d %s %d\n",fd, (char*)buffer, size);
}
static void system_seek(struct intr_frame *f, int fd, unsigned int position UNUSED){

}
static void system_tell(struct intr_frame *f, int fd UNUSED){

}
static void system_close(struct intr_frame *f, int fd UNUSED){

}

/*
 * Returns a unsigned int if there was a segfault it will set
 * ERROR to negative 1
 */
static unsigned int get_user_int(const uint32_t *uaddr, int *ERROR){
	uint32_t returnValue = 0;
	uint8_t output [4];
	int i;
	for (i = 0; i < 4; i ++){
		int fromMemory = get_user((uint8_t*)uaddr);
		if (fromMemory == -1){
			*ERROR = -1;
			return 0;
		}
		output[i] = (uint8_t) fromMemory;
		(uint8_t*)uaddr ++;
	}

	for (i = 3; i >=0; i --){
		returnValue = ((returnValue << 8) + (uint8_t)output[i]);
	}
	*ERROR = 1;
	return returnValue;
}


static int get_user(const uint8_t *uaddr){
	int result;
	asm("movl $1f, %0; movzbl %1, %0; 1:"
			: "=&a" (result) : "m" (*uaddr));
	return result;
}

static bool put_user (uint8_t *udst, uint8_t byte){
	int error_code;
	asm("mov1 $1f, %0; movb %b2, %1; 1:"
			: "=&a" (error_code), "=m" (*udst) : "q" (byte));
	return error_code != -1;
}

