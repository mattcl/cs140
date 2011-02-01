#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "process.h"
#include "pagedir.h"
#include "threads/vaddr.h"
#include <console.h>
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/shutdown.h"

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

struct file *file_for_fd (int fd);

static unsigned int get_user_int(const uint32_t *uaddr, int *ERROR);
static bool verify_string(const char* str);

#define MAX_SIZE_PUTBUF 300

bool verify_buffer (const void * buffer, unsigned int size);

void syscall_init (void) {
	lock_init(&filesys_lock);
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

	if (verify_buffer((char*)0xbfffffde, 6 )){
		printf("Verify buffer passed test 3\n");
	} else {
		printf("Verify buffer failed test 3\n");
	}

	if (verify_buffer((char*)0xbffffffb, 6)){
		printf("Verify buffer failed test 4\n");
	} else {
		printf("Verify buffer passed test 4\n");
	}

	if (verify_buffer((char*)0x4ffffffb, 6)){
		printf("Verify buffer failed test 4\n");
	} else {
		printf("Verify buffer passed test 4\n");
	}
	
	//user string testing
	if(verify_string((char*) 0x2) ){
	  printf("NOoo, should have seg faulted at 0x2!!!");
	} else {
	  printf("yaa!, seg faluted at 0x2!!!");
	}
	
	if(verify_string((char*) PHYS_BASE)){
	  printf("Nooo, should have seg faulted at BASE!!!");
	} else {
	  printf("Yaaaa! seg faulted at base!");
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

	//testMemoryAccess(esp);

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

//FINISHED
static void system_halt (struct intr_frame *f UNUSED){
	shutdown_power_off();
}

//Finished
static void system_exit (struct intr_frame *f, int status UNUSED) {
	thread_current()->process->exit_code = status;
	thread_exit();
	PANIC("done exiting NEVER CALLED\n");
}

static void system_exec (struct intr_frame *f, const char *cmd_line UNUSED){
	printf("SYS_EXEC called\n");
}

//Finished
static void system_wait (struct intr_frame *f, pid_t pid UNUSED){
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
	//make sure to increment fdcount in process struct
}

static void system_filesize(struct intr_frame *f, int fd UNUSED){
	printf("SYS_FILESIZE called\n");
}

static void system_read(struct intr_frame *f, int fd , void *buffer, unsigned int size UNUSED){
	printf("SYS_READ called\n");
}

//FINISHED
static void system_write(struct intr_frame *f, int fd, const void *buffer, unsigned int size){
	if (!verify_buffer(buffer, size)){
		f->eax = -1;
		system_exit(f, -1);
	}
	if (fd == 0){
		f->eax = -1;
		system_exit(f, -1);
	}

	off_t bytes_written = 0;

	if (fd == 1){
		bytes_written = size;
		while (bytes_written > 0){
			if (bytes_written  > MAX_SIZE_PUTBUF){
				putbuf(buffer, MAX_SIZE_PUTBUF);
				bytes_written -= MAX_SIZE_PUTBUF;
				buffer += MAX_SIZE_PUTBUF;
			} else {
				putbuf(buffer, bytes_written);
				break;
			}
		}
		f->eax = size; // return size
		return;
	}

	struct file * open_file = file_for_fd(fd);

	if (open_file == NULL){
		system_exit (f, -1);
	}

	lock_acquire(&filesys_lock);
	bytes_written = file_write(open_file, buffer, size);
	lock_release(&filesys_lock);
	f->eax = bytes_written;
	//printf("SYS_WRITE called %d %s %d\n",fd, (char*)buffer, size);
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

//Returns the file or NULL if the fd is invalid
struct file *file_for_fd (int fd){
	struct process *process = thread_current()->process;
	struct fd_hash_entry key;
	key.fd = fd;

	struct hash_elem *fd_hash_elem = hash_find(&process->open_files, &key.elem);
	if (fd_hash_elem == NULL){
		return NULL;
	}

	return hash_entry(fd_hash_elem, struct fd_hash_entry, elem) ->open_file;
}


bool verify_buffer (const void * buffer, unsigned int size){
	uint8_t *uaddr = (uint8_t*)buffer;
	if (!is_user_vaddr(uaddr) || get_user(uaddr) < 0){
		return false;
	}

	uaddr += size;

	if (!is_user_vaddr(uaddr) || get_user(uaddr) < 0){
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

static bool verify_string(const char* str){

	char c;
	while (true){
		if (!is_user_vaddr(str) || (c = get_user((uint8_t*)str)) < 0){
			return false;
		}
		if (c == '\0'){
			return true;
		}
	}

}
