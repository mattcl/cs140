#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "process.h"
#include "pagedir.h"
#include "threads/vaddr.h"

static struct lock filesys_lock;

// THIS IS AN INTERNAL INTERRUPT HANDLER
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

bool verify_buffer (void * buffer, size_t size);

void syscall_init (void) {
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

// arg with INT == 0 is the system call number
// params are start at INT == 1
#define arg(ESP, INT)(((int *)ESP) + INT)

static void testMemoryAccess (void *esp){
	//printf("syscall esp %p\n", esp);
	//printf("System Call number %d\n",sys_call_num);

	//TEST user access

	int ERROR = 0;
	unsigned int input = get_user_int((uint32_t*)0x2, &ERROR);
	if (ERROR < 0){
		printf("SEGFAULT!!!!!\n");
	} else {
		printf("DIDNT SEGFAULT THE REAL ERROR\n");
	}


	input = get_user_int((uint32_t*)esp, &ERROR);
	if (ERROR < 0){
		printf("SEGFAULT!!!!!REAL ERROR\n");
	} else {
		printf("DIDNT SEGFAULT Should be system call %d:)\n", input);
	}

	input = get_user_int((uint32_t*)PHYS_BASE, &ERROR);
	if (ERROR < 0){
		printf("SEGFAULT!!!!!\n");
	} else {
		printf("DIDNT SEGFAULT THE REAL ERROR\n");
	}

	if(verify_buffer((char*)0x2, 300)){
		printf("Verify buffer failed\n");
	} else {
		printf("Verify buffer passed test 1\n");
	}

	if (verify_buffer((char*)0xbffffffb, 20)){
		printf("Verify buffer failed test 2\n");
	} else {
		printf("Verify buffer passed test 2\n");
	}

	if (!verify_buffer((char*)0xbfffffde, 6 )){
		printf("Verify buffer failed test 3\n");
	} else {
		printf("Verify buffer passed test 3\n");
	}

	if (verify_buffer((char*)0xbffffffb, 6)){
		printf("Verify buffer failed test 4\n");
	} else {
		printf("Verify buffer passed test 4\n");
	}


	//end test
}

//returns -1 on segfault
static int set_args(void *esp, int num, uint32_t argument[]){
	int i, ERR;
	for (i = 0; i < num; i++){
		//printf("Argument i pointer is %p", argument[i]);
		argument[i] = get_user_int((uint32_t*)arg(esp,(i+1)), &ERR);
		if (ERR < 0 ){
			return ERR;
		}
	}
	return 1;
}

static void syscall_handler (struct intr_frame *f){
	int ERROR = 0;

	void *esp = f->esp;

	int sys_call_num = get_user_int((uint32_t*)esp, &ERROR);
	if (ERROR < 0) system_exit(f, -1);

	testMemoryAccess(esp);

	uint32_t arg1 [3];

	switch (sys_call_num){
		case SYS_HALT:{
			system_halt(f);
			break;
		}
		case SYS_EXIT:{
			ERROR = set_args(esp, 1, arg1);
			if (ERROR < 0)system_exit(f, -1);
			system_exit(f, (int)arg1[0]);
			break;
		}
		case SYS_EXEC:{
			ERROR = set_args(esp, 1, arg1);
			if (ERROR < 0)system_exit(f, -1);
			system_exec(f, (char*)arg1[0]);
			break;
		}
		case SYS_WAIT:{
			ERROR = set_args(esp, 1, arg1);
			if (ERROR < 0)system_exit(f, -1);
			system_wait(f, (pid_t)arg1[0]);
			break;
		}
		case SYS_CREATE:{
			ERROR = set_args(esp, 2, arg1);
			if (ERROR < 0)system_exit(f, -1);
			system_create(f, (char*)arg1[0], (int)arg1[1]);
			break;
		}
		case SYS_REMOVE:{
			ERROR = set_args(esp, 1, arg1);
			if (ERROR < 0)system_exit(f, -1);
			system_remove(f, (char*)arg1[0]);
			break;
		}
		case SYS_OPEN:{
			ERROR = set_args(esp, 1, arg1);
			if (ERROR < 0)system_exit(f, -1);
			system_open(f, (char*)arg1[0]);
			break;
		}
		case SYS_FILESIZE:{
			ERROR = set_args(esp, 1, arg1);
			if (ERROR < 0)system_exit(f, -1);
			system_filesize(f, (int)arg1[0]);
			break;
		}
		case SYS_READ:{
			ERROR = set_args(esp, 3, arg1);
			if (ERROR < 0)system_exit(f, -1);
			system_read(f, (int)arg1[0], (char*)arg1[1], (int)arg1[2]);
			break;
		}
		case SYS_WRITE:{
			ERROR = set_args(esp, 3, arg1);
			if (ERROR < 0)system_exit(f, -1);
			system_write(f, (int)arg1[0], (char*)arg1[1], (int)arg1[2]);
			break;
		}
		case SYS_SEEK:{
			ERROR = set_args(esp, 2, arg1);
			if (ERROR < 0)system_exit(f, -1);
			system_seek(f, (int)arg1[0], (unsigned int)arg1[1]);
			break;
		}
		case SYS_TELL:{
			ERROR = set_args(esp, 1, arg1);
			if (ERROR < 0)system_exit(f, -1);
			system_tell(f, (int)arg1[0]);
			break;
		}
		case SYS_CLOSE:{
			ERROR = set_args(esp, 2, arg1);
			if (ERROR < 0)system_exit(f, -1);
			system_close(f, (int)arg1[0]);
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
	printf("SYS_HALT called\n");
}

//Finished
static void system_exit (struct intr_frame *f, int status UNUSED) {
	printf("exiting\n");
	thread_current()->process->exit_code = status;
	thread_exit();
	printf("done exiting \n");
}

static void system_exec (struct intr_frame *f, const char *cmd_line UNUSED){
	printf("SYS_EXEC called\n");
}

//Finished
static void system_wait (struct intr_frame *f, pid_t pid UNUSED){
	printf("SYS_WAIT called DONE\n");
	if (!pid_belongs_to_child(pid)){
		system_exit(f, -1);
	}
	f->eax = process_wait(tid_for_pid(pid));
}

static void system_create (struct intr_frame *f, const char *file_name, unsigned int initial_size UNUSED){
	printf("SYS_CREATE called\n");
}

static void system_remove(struct intr_frame *f, const char *file_name UNUSED){
	printf("SYS_REMOVE called\n");
}

static void system_open (struct intr_frame *f, const char *file_name UNUSED){
	printf("SYS_OPEN called\n");
}

static void system_filesize(struct intr_frame *f, int fd UNUSED){
	printf("SYS_FILESIZE called\n");
}

static void system_read(struct intr_frame *f, int fd , void *buffer, unsigned int size UNUSED){
	printf("SYS_READ called\n");
}

static void system_write(struct intr_frame *f, int fd, const void *buffer, unsigned int size){

	printf("SYS_WRITE called %d %s %d\n",fd, (char*)buffer, size);
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


bool verify_buffer (void * buffer, size_t size){
	uint8_t *uaddr = (uint8_t*)buffer;
	if (size < 0){
		return false;
	}
	if (!is_user_vaddr(uaddr)){
		return false;
	}
	if (get_user(uaddr) < 0){
		return false;
	}

	uaddr += size;

	if (get_user(uaddr) < 0){
		return false;
	}

	return true;
}

/*
 * Returns a unsigned int representing 4 bytes of data
 * if there was a segfault it will set
 * ERROR will be negative, positive otherwise
 */
static unsigned int get_user_int(const uint32_t *uaddr_in, int *ERROR){
	uint8_t *uaddr = (uint8_t*)uaddr_in;
	uint32_t returnValue = 0;
	uint8_t output [4];
	int i;
	for (i = 0; i < 4; i ++){
		if (!is_user_vaddr(uaddr)){
			*ERROR = -1;
			return 0;
		}
		int fromMemory = get_user(uaddr);
		if (fromMemory == -1){
			*ERROR = -1;
			return 0;
		}
		output[i] = (uint8_t) fromMemory;
		uaddr ++ ;
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
	asm("mov1 $1f, %0; movb %b2, %1; 1:" : "=&a" (error_code), "=m" (*udst) : "q" (byte));
	return error_code != -1;
}

