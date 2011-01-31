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
	//end test

}

//returns -1 on segfault
static int set_args(void *esp, int num, uint32_t *argument){
	int i;
	int ERR;
	for (i = 1; i <= num; i++){
		argument[i] = get_user_int(arg(esp,i),&ERR);
		if (ERR < 0 ){
			return -1;
		}
	}
	return 1;
}

static void syscall_handler (struct intr_frame *f){
	int ERROR = 0;

	void *esp = f->esp;

	int sys_call_num = get_user_int((uint32_t*)esp, &ERROR);
	if (ERROR < 0); //KILL USER PROCESS

	testMemoryAccess(esp);

	uint32_t arg1;
	uint32_t arg2;
	uint32_t arg3;

	switch (sys_call_num){
	case SYS_HALT:{
		printf("SYS_HALT called\n");
		system_halt(f);
		break;
	}
	case SYS_EXIT:{
		printf("SYS_EXIT called\n");

		arg1 = get_user_int(arg(esp,1), &ERROR);
		if (ERROR < 0);//KILL USER PROCESS
		system_exit(f, (int)arg1);
		thread_exit ();
		break;
	}
	case SYS_EXEC:{
		printf("SYS_EXEC called\n");
		arg1 = get_user_int(arg(esp,1), &ERROR);
		if (ERROR < 0); //KILL USER PROCESS
		system_exec(f, (char*)arg1);
		break;
	}
	case SYS_WAIT:{
		printf("SYS_WAIT called\n");
		arg1 = get_user_int(arg(esp,1), &ERROR);
		if (ERROR < 0); //KILL USER PROCESS

		system_wait(f, (pid_t)arg1);
		break;
	}
	case SYS_CREATE:{
		printf("SYS_CREATE called\n");
		arg1 = get_user_int(arg(esp,1), &ERROR);
		if (ERROR < 0); //KILL USER PROCESS
		arg2 = get_user_int(arg(esp,2), &ERROR);
		if (ERROR < 0); //KILL USER PROCESS
		system_create(f, (char*)arg1, (int)arg2);
		break;
	}
	case SYS_REMOVE:{
		printf("SYS_REMOVE called\n");
		arg1 = get_user_int(arg(esp,1), &ERROR);
		if (ERROR < 0); //KILL USER PROCESS

		system_remove(f, (char*)arg1);
		break;
	}
	case SYS_OPEN:{
		printf("SYS_OPEN called\n");
		arg1 = get_user_int(arg(esp,1), &ERROR);
		if (ERROR < 0); //KILL USER PROCESS
		system_open(f, (char*)arg1);
		break;
	}
	case SYS_FILESIZE:{
		printf("SYS_FILESIZE called\n");
		printf("SYS_OPEN called\n");
		arg1 = get_user_int(arg(esp,1), &ERROR);
		if (ERROR < 0); //KILL USER PROCESS
		system_filesize(f, (int)arg1);
		break;
	}
	case SYS_READ:{
		printf("SYS_READ called\n");
		arg1 = get_user_int(arg(esp,1), &ERROR);
		if (ERROR < 0); //KILL USER PROCESS
		arg2 = get_user_int(arg(esp,2), &ERROR);
		if (ERROR < 0); //KILL USER PROCESS
		arg3 = get_user_int(arg(esp,3), &ERROR);
		if (ERROR < 0); //KILL USER PROCESS

		system_read(f, (int)arg1, (char*)arg2, (int)arg3);
		break;
	}
	case SYS_WRITE:{
		printf("SYS_WRITE called\n");
		/*arg1 = get_user_int(arg(esp,1), &ERROR);
		if (ERROR < 0); //KILL USER PROCESS
		arg2 = get_user_int(arg(esp,2), &ERROR);
		if (ERROR < 0); //KILL USER PROCESS
		arg3 = get_user_int(arg(esp,3), &ERROR);
		if (ERROR < 0); //KILL USER PROCESS
*/
		//printf("Arg 1 %d, arg 2 %s, arg3 %d\n", arg1, (char*)arg2, arg3);

		ERROR = set_args(esp, 3, &arg1);

		printf("Arg 1 %d, arg 2 %s, arg3 %d\n", arg1, (char*)arg2, arg3);

		system_write(f, (int)arg1, (char*)arg2, (int)arg3);
		break;
	}
	case SYS_SEEK:{
		printf("SYS_SEEK called\n");
		arg1 = get_user_int(arg(esp,1), &ERROR);
		if (ERROR < 0); ;//KILL USER PROCESS
		arg2 = get_user_int(arg(esp,2), &ERROR);
		if (ERROR < 0);; //KILL USER PROCESS
		system_seek(f, (int)arg1, (unsigned int)arg2);
		break;
	}
	case SYS_TELL:{
		printf("SYS_TELL called\n");
		arg1 = get_user_int(arg(esp,1), &ERROR);
		if (ERROR < 0); ;//KILL USER PROCESS
		system_tell(f, (int)arg1);
		break;
	}
	case SYS_CLOSE:{
		printf("SYS_CLOSE called\n");
		arg1 = get_user_int(arg(esp,1), &ERROR);
		if (ERROR < 0); ;//KILL USER PROCESS
		system_close(f, (int)arg1);
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
static unsigned int get_user_int(const uint32_t *uaddr_in, int *ERROR){
	uint8_t *uaddr = (uint8_t*)uaddr_in;
	uint32_t returnValue = 0;
	uint8_t output [4];
	int i;
	for (i = 0; i < 4; i ++){
		//printf("get user called with %p\n",uaddr );
		if (!is_user_vaddr(uaddr)){
			*ERROR = -1;
			//printf("Error\n");
			return 0;
		}
		int fromMemory = get_user(uaddr);
		if (fromMemory == -1){
			*ERROR = -1;
			//printf("Error\n");
			return 0;
		}
		output[i] = (uint8_t) fromMemory;
		uaddr ++ ;
	}

	for (i = 3; i >=0; i --){
		//printf("%ul, %ul, %ul\n", returnValue , (returnValue << 8) , (uint8_t)output[i]);
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

