#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/thread.h"
#include "threads/synch.h"
#include "process.h"
#include "pagedir.h"
#include "threads/vaddr.h"
#include <console.h>
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/malloc.h"

/* THIS IS AN INTERNAL INTERRUPT HANDLER */
static void syscall_handler (struct intr_frame *);

static void system_halt (struct intr_frame *f );
static void system_exec (struct intr_frame *f, const char *cmd_line );
static void system_wait (struct intr_frame *f, pid_t pid );
static void system_create (struct intr_frame *f, const char *file_name, unsigned int initial_size );
static void system_remove(struct intr_frame *f, const char *file_name );
static void system_open (struct intr_frame *f, const char *file_name );
static void system_filesize(struct intr_frame *f, int fd );
static void system_read(struct intr_frame *f, int fd , void *buffer, unsigned int size );
static void system_write(struct intr_frame *f, int fd, const void *buffer, unsigned int size);
static void system_seek(struct intr_frame *f, int fd, unsigned int position );
static void system_tell(struct intr_frame *f, int fd );
static void system_close(struct intr_frame *f, int fd );

static bool buffer_is_valid (const void * buffer, unsigned int size);
static bool buffer_is_valid_writable (void * buffer, unsigned int size);
static bool string_is_valid(const char* str);

static unsigned int get_user_int(const uint32_t *uaddr, int *error);
static int get_user(const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);

static struct file *file_for_fd (int fd);
static struct fd_hash_entry * fd_to_fd_hash_entry (int fd);

/* Maximum size of output to to go into the putbuf command*/
#define MAX_SIZE_PUTBUF 300

/* Standard file descriptors.  */
#define	STDIN_FILENO	0	/* Standard input.  */
#define	STDOUT_FILENO	1	/* Standard output.  */

/*  arg with INT == 0 is the system call number
	Macro to easily get the n'th argument passed to
	the system call. INT is the argument you want.
	0 is the system call number and 1 - n are the
	arguments */
#define arg(ESP, INT)(((int *)ESP) + INT)

void syscall_init (void){
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* returns -1 on segfault */
static int set_args(void *esp, int num, uint32_t argument[]){
	int i, err;
	for(i = 0; i < num; i++){
		argument[i] = get_user_int((uint32_t*)arg(esp,(i+1)), &err);
		if(err < 0 ){
			return err;
		}
	}
	return 1;
}
/* Verifies the stack pointer, and calls set_args to 
   load up the arugments for the sys_call into the 
   buffer arg1.  Note that arg1 is initialized to 4
   the maximum number of arguments a SYS_CALL */
static void syscall_handler (struct intr_frame *f){
	int error = 0;

	/* verify esp */
	get_user_int(f->esp, &error);
	if(error < 0) system_exit(f, -1);

	void *esp = f->esp;

	/* get verified system call */
	int sys_call_num = get_user_int((uint32_t*)esp, &error);
	if(error < 0) system_exit(f, -1);

	/* arguments for each system call */
	uint32_t arg1 [4];

	switch (sys_call_num){
		case SYS_HALT:{
			system_halt(f);
			break;
		}
		case SYS_EXIT:{
			error = set_args(esp, 1, arg1);
			if(error < 0) system_exit(f, -1);
			system_exit(f, (int)arg1[0]);
			break;
		}
		case SYS_EXEC:{
			error = set_args(esp, 1, arg1);
			if(error < 0)system_exit(f, -1);
			system_exec(f, (char*)arg1[0]);
			break;
		}
		case SYS_WAIT:{
			error = set_args(esp, 1, arg1);
			if(error < 0)system_exit(f, -1);
			system_wait(f, (pid_t)arg1[0]);
			break;
		}
		case SYS_CREATE:{
			error = set_args(esp, 2, arg1);
			if(error < 0)system_exit(f, -1);
			system_create(f, (char*)arg1[0], (int)arg1[1]);
			break;
		}
		case SYS_REMOVE:{
			error = set_args(esp, 1, arg1);
			if(error < 0)system_exit(f, -1);
			system_remove(f, (char*)arg1[0]);
			break;
		}
		case SYS_OPEN:{
			error = set_args(esp, 1, arg1);
			if(error < 0)system_exit(f, -1);
			system_open(f, (char*)arg1[0]);
			break;
		}
		case SYS_FILESIZE:{
			error = set_args(esp, 1, arg1);
			if(error < 0)system_exit(f, -1);
			system_filesize(f, (int)arg1[0]);
			break;
		}
		case SYS_READ:{
			error = set_args(esp, 3, arg1);
			if(error < 0)system_exit(f, -1);
			system_read(f, (int)arg1[0], (char*)arg1[1], (int)arg1[2]);
			break;
		}
		case SYS_WRITE:{
			error = set_args(esp, 3, arg1);
			if(error < 0)system_exit(f, -1);
			system_write(f, (int)arg1[0], (char*)arg1[1], (int)arg1[2]);
			break;
		}
		case SYS_SEEK:{
			error = set_args(esp, 2, arg1);
			if(error < 0)system_exit(f, -1);
			system_seek(f, (int)arg1[0], (unsigned int)arg1[1]);
			break;
		}
		case SYS_TELL:{
			error = set_args(esp, 1, arg1);
			if(error < 0)system_exit(f, -1);
			system_tell(f, (int)arg1[0]);
			break;
		}
		case SYS_CLOSE:{
			error = set_args(esp, 2, arg1);
			if(error < 0)system_exit(f, -1);
			system_close(f, (int)arg1[0]);
			break;
		}
		/* Project 3 Syscalls */
		case SYS_MMAP:{
			printf("SYS_MMAP called\n");
			break;
		}
		case SYS_MUNMAP:{
			printf("SYS_MUNMAP called\n");
			break;
		}
		/* Progect 4 Syscalls */
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
	shutdown_power_off();
}


void system_exit (struct intr_frame *f UNUSED, int status){
	struct process * proc = thread_current()->process;
	printf("%s: exit(%d)\n", proc->program_name, status);
	proc->exit_code = status;
	thread_exit();
	NOT_REACHED();
}


static void system_exec (struct intr_frame *f, const char *cmd_line ){
	if(!string_is_valid(cmd_line)){
		f->eax = -1;
		return;
	}
	tid_t returned = process_execute(cmd_line);
	if(returned == TID_ERROR){
		f->eax = -1;
		return;
	}
	pid_t ret =  child_tid_to_pid(returned);
	if(ret == PID_ERROR){
		f->eax = -1;
		return;
	}else{
		f->eax = ret;
	}
}

static void system_wait (struct intr_frame *f, pid_t pid){
	tid_t child_tid;
	if((child_tid = child_pid_to_tid(pid)) == PID_ERROR){
		f->eax = -1;
		return;
	}

	f->eax = process_wait(child_tid);
}

static void system_create (struct intr_frame *f, const char *file_name, unsigned int initial_size){
	if(!string_is_valid(file_name)){
		system_exit(f, -1);
	}
	lock_acquire(&filesys_lock);
	f->eax = filesys_create(file_name, initial_size);
	lock_release(&filesys_lock);
}

static void system_remove(struct intr_frame *f, const char *file_name){
	if(!string_is_valid(file_name)){
		system_exit(f, -1);
	}
	lock_acquire(&filesys_lock);
	f->eax = filesys_remove(file_name);
	lock_release(&filesys_lock);
}

static void system_open (struct intr_frame *f, const char *file_name){
	if(!string_is_valid(file_name)){
		system_exit(f, -1);
	}
	struct file *opened_file;
	lock_acquire(&filesys_lock);
	opened_file = filesys_open(file_name);
	lock_release(&filesys_lock);
	if(opened_file  == NULL){
		f->eax = -1;
		return;
	}

	struct process *process = thread_current()->process;

	struct fd_hash_entry *fd_entry = calloc(1, sizeof(struct fd_hash_entry));
	if(fd_entry == NULL){
		f->eax = -1;
		return;
	}

	fd_entry->fd = ++(process->fd_count);
	fd_entry->open_file = opened_file;

	struct hash_elem *returned = hash_insert(&process->open_files, &fd_entry->elem);

	if(returned != NULL){
		/* We have just tried to put the fd of an identical fd into the hash
		 Table this is a problem with the hash table and should fail the kernel
		 Cause our memory has been corrupted somehow */
		PANIC("ERROR WITH HASH IN PROCESS EXIT!!");
	}

	f->eax = fd_entry->fd;
}

static void system_filesize(struct intr_frame *f, int fd){
	struct file *open_file = file_for_fd(fd);
	if(open_file == NULL){
		f->eax = -1;
		return;
	}

	lock_acquire(&filesys_lock);
	f->eax = file_length(open_file);
	lock_release(&filesys_lock);
}

static void system_read(struct intr_frame *f , int fd , void *buffer, unsigned int size){
	if(!buffer_is_valid_writable(buffer, size)){
		system_exit(f, -1);
	}

	if(fd == STDOUT_FILENO){
		f->eax = 0;
		return;
	}

	unsigned int bytes_read ;

	char *charBuffer = (char*) buffer;

	if(fd == STDIN_FILENO){
		for( bytes_read = 0; bytes_read <  size ; ++bytes_read){
			charBuffer[bytes_read]= input_getc();
		}
		f->eax = bytes_read;
		return;
	}

	struct file * file = file_for_fd(fd);

	if(file == NULL){
		f->eax = 0;
		return;
	}

	lock_acquire(&filesys_lock);
	bytes_read = file_read(file, buffer, size);
	lock_release(&filesys_lock);
	f->eax = bytes_read;
}

static void system_write(struct intr_frame *f, int fd, const void *buffer, unsigned int size){
	if(!buffer_is_valid(buffer, size)){
		system_exit(f, -1);
	}
	if(fd == STDIN_FILENO){
		system_exit(f, -1);
	}

	off_t bytes_written = 0;

	if(fd == STDOUT_FILENO){
		bytes_written = size;
		while(bytes_written > 0){
			if(bytes_written  > MAX_SIZE_PUTBUF){
				putbuf(buffer, MAX_SIZE_PUTBUF);
				bytes_written -= MAX_SIZE_PUTBUF;
				buffer += MAX_SIZE_PUTBUF;
			}else{
				putbuf(buffer, bytes_written);
				break;
			}
		}
		f->eax = size; /* return size*/
		return;
	}

	struct file * open_file = file_for_fd(fd);

	if(open_file == NULL){
		f->eax = 0;
		return;
	}

	lock_acquire(&filesys_lock);
	bytes_written = file_write(open_file, buffer, size);
	lock_release(&filesys_lock);
	f->eax = bytes_written;
}

static void system_seek(struct intr_frame *f, int fd, unsigned int position){
	struct file *file = file_for_fd(fd);
	if(file == NULL){
		f->eax = -1;
		return;
	}

	if(fd == STDIN_FILENO){
		f->eax = -1;
		return;
	}

	lock_acquire(&filesys_lock);
	off_t f_size = file_length(file);
	lock_release(&filesys_lock);

	if(f_size < 0){
		f->eax = -1;
		return;
	}

	if((unsigned int) f_size < position){
		f->eax = -1;
		return;
	}

	lock_acquire(&filesys_lock);
	file_seek(file, position);
	lock_release(&filesys_lock);

	f->eax = -1;
}

static void system_tell(struct intr_frame *f, int fd){
	struct file *open_file = file_for_fd(fd);
	if(open_file == NULL){
		f->eax = -1;
		return;
	}

	lock_acquire(&filesys_lock);
	f->eax = file_tell(open_file);
	lock_release(&filesys_lock);
}

static void system_close(struct intr_frame *f UNUSED, int fd ){
	struct fd_hash_entry *entry =fd_to_fd_hash_entry(fd);
	if(entry == NULL){
		return;
	}

	/* if fd was stdin or stdout it CAN'T be in the fd table
	   so it won't get here if STDIN or STDOUT  is passed in*/
	lock_acquire(&filesys_lock);
	file_close(entry->open_file);
	lock_release(&filesys_lock);

	struct hash_elem *returned = hash_delete(&thread_current()->process->open_files, &entry->elem);
	if(returned == NULL){
		/* We have just tried to delete a fd that was not in our fd table....
		   This Is obviously a huge problem so system KILLLLLLL!!!! */
		PANIC("ERROR WITH HASH IN PROCESS EXIT!! CLOSE");
	}

	free(entry);
}

/* Returns the file or NULL if the fd is invalid */
static struct file *file_for_fd (int fd){
	struct fd_hash_entry *hash_elem = fd_to_fd_hash_entry (fd);
	if(hash_elem == NULL){
		return NULL;
	}
	return  hash_elem->open_file;
}

static struct fd_hash_entry * fd_to_fd_hash_entry (int fd){
	struct process *process = thread_current()->process;
	struct fd_hash_entry key;
	key.fd = fd;
	struct hash_elem *fd_hash_elem = hash_find(&process->open_files, &key.elem);
	if(fd_hash_elem == NULL){
		return NULL;
	}
	return hash_entry(fd_hash_elem, struct fd_hash_entry, elem);
}

static bool buffer_is_valid (const void * buffer, unsigned int size){
	uint8_t *uaddr = (uint8_t*)buffer;
	if(!is_user_vaddr(uaddr) || get_user(uaddr) < 0){
		return false;
	}
	if(size > 1){
		uaddr += size;
		if(!is_user_vaddr(uaddr) || get_user(uaddr) < 0){
			return false;
		}
		return true;
	}
}

static bool buffer_is_valid_writable (void * buffer, unsigned int size){
	uint8_t *uaddr = (uint8_t*)buffer;
	printf("Buffer_is_valid_writable\n");
	int byte;
	if(!is_user_vaddr(uaddr) || (byte = get_user(uaddr)) < 0 || put_user(uaddr, 1) < 0){
		return false;
	}
	put_user(uaddr, byte);
	if(size > 1){
		uaddr += size;
		if(!is_user_vaddr(uaddr) || (byte = get_user(uaddr)) < 0 || put_user(uaddr, 1) < 0){
			return false;
		}
		put_user(uaddr, byte);
	}
	return true;
}


 /* Returns a unsigned int representing 4 bytes of data
    if there was a segfault it will set
    ERROR will be negative, positive otherwise*/
static unsigned int get_user_int(const uint32_t *uaddr_in, int *error){
	uint8_t *uaddr = (uint8_t*)uaddr_in;
	uint32_t returnValue = 0;
	uint8_t output [4];
	int i;
	for(i = 0; i < 4; i ++){
		if(!is_user_vaddr(uaddr)){
			*error = -1;
			return 0;
		}
		int fromMemory = get_user(uaddr);
		if(fromMemory == -1){
			*error = -1;
			return 0;
		}
		output[i] = (uint8_t) fromMemory;
		uaddr ++ ;
	}

	for(i = 3; i >=0; i --){
		returnValue = ((returnValue << 8) + (uint8_t)output[i]);
	}
	*error = 1;
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
	asm("movl $1f, %0; movb %b2, %1; 1:" : "=&a" (error_code), "=m" (*udst) : "q" (byte));
	return error_code != -1;
}

static bool string_is_valid(const char* str){
	int c;
	while(true){
		if(!is_user_vaddr(str) || (c = get_user((uint8_t*)str)) < 0){
			return false;
		}
		if((char)c == '\0'){
			break;
		}
		str ++;
	}
	return true;
}
