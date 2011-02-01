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
#include "devices/input.c"
#include "threads/malloc.h"
#include <unistd.h>

// THIS IS AN INTERNAL INTERRUPT HANDLER
static void syscall_handler (struct intr_frame *);

static void system_halt (struct intr_frame *f );
static void system_exit (struct intr_frame *f, int status );
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
static bool string_is_valid(const char* str);

static unsigned int get_user_int(const uint32_t *uaddr, int *ERROR);
static int get_user(const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);

static struct file *file_for_fd (int fd);
static struct fd_hash_entry * fd_to_fd_hash_entry (int fd);

#define MAX_SIZE_PUTBUF 300

// arg with INT == 0 is the system call number
// params are start at INT == 1
#define arg(ESP, INT)(((int *)ESP) + INT)

void syscall_init (void) {
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

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

	if(buffer_is_valid((char*)0x2, 300)){
		printf("Verify buffer failed\n");
	} else {
		printf("Verify buffer passed test 1\n");
	}

	if (buffer_is_valid((char*)0xbffffffb, 20)){
		printf("Verify buffer failed test 2\n");
	} else {
		printf("Verify buffer passed test 2\n");
	}

	if (buffer_is_valid((char*)0xbfffffde, 6 )){
		printf("Verify buffer passed test 3\n");
	} else {
		printf("Verify buffer failed test 3\n");
	}

	if (buffer_is_valid((char*)0xbffffffb, 6)){
		printf("Verify buffer failed test 4\n");
	} else {
		printf("Verify buffer passed test 4\n");
	}

	if (buffer_is_valid((char*)0x4ffffffb, 6)){
		printf("Verify buffer failed test 4\n");
	} else {
		printf("Verify buffer passed test 4\n");
	}

	//user string testing
	if(string_is_valid((char*) 0x2) ){
		printf("NOoo, should have seg faulted at 0x2!!!");
	} else {
		printf("yaa!, seg faluted at 0x2!!!");
	}

	if(string_is_valid((char*) PHYS_BASE)){
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
	int error = 0;

	void *esp = f->esp;

	int sys_call_num = get_user_int((uint32_t*)esp, &error);
	if (error < 0) system_exit(f, -1);

	//testMemoryAccess(esp);

	uint32_t arg1 [3];

	switch (sys_call_num){
	case SYS_HALT:{
		system_halt(f);
		break;
	}
	case SYS_EXIT:{
		error = set_args(esp, 1, arg1);
		if (error < 0)system_exit(f, -1);
		system_exit(f, (int)arg1[0]);
		break;
	}
	case SYS_EXEC:{
		error = set_args(esp, 1, arg1);
		if (error < 0)system_exit(f, -1);
		system_exec(f, (char*)arg1[0]);
		break;
	}
	case SYS_WAIT:{
		error = set_args(esp, 1, arg1);
		if (error < 0)system_exit(f, -1);
		system_wait(f, (pid_t)arg1[0]);
		break;
	}
	case SYS_CREATE:{
		error = set_args(esp, 2, arg1);
		if (error < 0)system_exit(f, -1);
		system_create(f, (char*)arg1[0], (int)arg1[1]);
		break;
	}
	case SYS_REMOVE:{
		error = set_args(esp, 1, arg1);
		if (error < 0)system_exit(f, -1);
		system_remove(f, (char*)arg1[0]);
		break;
	}
	case SYS_OPEN:{
		error = set_args(esp, 1, arg1);
		if (error < 0)system_exit(f, -1);
		system_open(f, (char*)arg1[0]);
		break;
	}
	case SYS_FILESIZE:{
		error = set_args(esp, 1, arg1);
		if (error < 0)system_exit(f, -1);
		system_filesize(f, (int)arg1[0]);
		break;
	}
	case SYS_READ:{
		error = set_args(esp, 3, arg1);
		if (error < 0)system_exit(f, -1);
		system_read(f, (int)arg1[0], (char*)arg1[1], (int)arg1[2]);
		break;
	}
	case SYS_WRITE:{
		error = set_args(esp, 3, arg1);
		if (error < 0)system_exit(f, -1);
		system_write(f, (int)arg1[0], (char*)arg1[1], (int)arg1[2]);
		break;
	}
	case SYS_SEEK:{
		error = set_args(esp, 2, arg1);
		if (error < 0)system_exit(f, -1);
		system_seek(f, (int)arg1[0], (unsigned int)arg1[1]);
		break;
	}
	case SYS_TELL:{
		error = set_args(esp, 1, arg1);
		if (error < 0)system_exit(f, -1);
		system_tell(f, (int)arg1[0]);
		break;
	}
	case SYS_CLOSE:{
		error = set_args(esp, 2, arg1);
		if (error < 0)system_exit(f, -1);
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
	printf("SYS_HALT called\n");
	shutdown_power_off();
}

//Finished
static void system_exit (struct intr_frame *f, int status) {
	printf("SYS_EXIT\n");
	thread_current()->process->exit_code = status;
	thread_exit();
	NOT_REACHED();
}

//FINISHED
static void system_exec (struct intr_frame *f, const char *cmd_line ){
	printf("SYS_EXEC called\n");
	if (!string_is_valid(cmd_line)){
		system_exit(f, -1);
	}
	struct process* cur = thread_current()->process;
	lock_acquire(&cur->child_pid_lock);
	tid_t returned = process_execute(cmd_line);
	if (returned == TID_ERROR){
		f->eax = -1;
		return;
	}
	//wait until the child process is set up or fails
	// the pid_t will be in child_waiting_on
	cond_wait(&cur->pid_cond, &cur->child_pid_lock);
	lock_release(&cur->child_pid_lock);
	f->eax = cur->child_waiting_on;
}

//Finished
static void system_wait (struct intr_frame *f, pid_t pid){
	if (!pid_belongs_to_child(pid)){
		system_exit(f, -1);
	}
	f->eax = process_wait(tid_for_pid(pid));
}

//FinISHED
static void system_create (struct intr_frame *f, const char *file_name, unsigned int initial_size){
	if(!string_is_valid(file_name)){
		system_exit(f, -1);
	}
	lock_acquire(&filesys_lock);
	f->eax = filesys_create(file_name, initial_size);
	lock_release(&filesys_lock);
}

//FINISHED
static void system_remove(struct intr_frame *f, const char *file_name) {
	if(!string_is_valid(file_name)){
		system_exit(f, -1);
	}
	lock_acquire(&filesys_lock);
	f->eax = filesys_remove(file_name);
	lock_release(&filesys_lock);
}

//finished
static void system_open (struct intr_frame *f, const char *file_name){
	printf("SYS_OPEN called\n");
	if (!string_is_valid(file_name)){
		system_exit(f, -1);
	}
	struct file *opened_file;
	lock_acquire(&filesys_lock);
	opened_file = filesys_open(file_name);
	lock_release(&filesys_lock);
	if (opened_file  == NULL){
		f->eax = -1;
		return;
	}

	struct process *process = thread_current()->process;

	struct fd_hash_entry *fd_entry = calloc(1, sizeof(struct fd_hash_entry));
	if (fd_entry == NULL){
		f->eax = -1;
		return;
	}

	struct hash_elem *returned = hash_insert(&process->open_files, &fd_entry->elem);
	if (returned != NULL){
		// We have just tried to put the fd of an identical fd into the hash
		// Table this is a problem with the hash table and should fail the kernel
		// Cause our memory has been corrupted somehow
		PANIC("ERROR WITH HASH IN PROCESS EXIT!!");
	}

	fd_entry->fd =++ process->fd_count;
	fd_entry->open_file = opened_file;
	f->eax = fd_entry->fd;
}

//FINISHED
static void system_filesize(struct intr_frame *f, int fd){
	printf("SYS_FILESIZE called\n");
	struct file *open_file = file_for_fd(fd);
	if (open_file == NULL){
		f->eax = -1;
	}

	lock_acquire(&filesys_lock);
	f->eax = file_length(open_file);
	lock_release(&filesys_lock);
}

static void system_read(struct intr_frame *f , int fd , void *buffer, unsigned int size){
	printf("SYS_READ called\n");
	if(!buffer_is_valid(buffer, size)) {
		system_exit(f, -1);
	}

	if(fd == STDOUT_FILENO){
		system_exit(f, -1);
	}

	off_t bytes_read ;

	char charBuffer = (char*) buffer;

	if(fd == STDIN_FILENO) {

		for( bytes_read = 0; bytes_read <  size ; ++bytes_read){
			charBuffer[bytes_read]= input_getc();
		}

		f->eax = bytes_read;
		return;
	}


	struct file * file = file_for_fd(fd);

	if (file == NULL){
		f->eax = -1;
		return;
	}

	lock_acquire(&filesys_lock);
	bytes_read = file_read(file, buffer, size);
	lock_release(&filesys_lock);
	f->eax = bytes_read;


}

//FINISHED
static void system_write(struct intr_frame *f, int fd, const void *buffer, unsigned int size){
	//printf("SYS_WRITE called\n");
	if (!buffer_is_valid(buffer, size)){
		system_exit(f, -1);
	}
	if (fd == STDIN_FILENO){
		system_exit(f, -1);
	}

	off_t bytes_written = 0;

	if (fd == STDOUT_FILENO){
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
		f->eax = -1;
		return;
	}

	lock_acquire(&filesys_lock);
	bytes_written = file_write(open_file, buffer, size);
	lock_release(&filesys_lock);
	f->eax = bytes_written;
}

static void system_seek(struct intr_frame *f, int fd, unsigned int position){
	printf("SYS_SEEK called\n");
	struct file *file = file_for_fd(fd);
	if(file == NULL){
		f->eax = -1;
		return;
	}


	lock_acquire(&filesys_lock);
	off_t f_size = file_length(file);
	lock_release(&filesys_lock);

	if(f_size < position) {
		f->eax = -1;
		return;
	}

	lock_acquire(&filesys_lock);
	f->eax = file_seek(file, position);
	lock_release(&filesys_lock);
}

//FINISHED
static void system_tell(struct intr_frame *f, int fd){
	printf("SYS_TELL called\n");
	struct file *open_file = file_for_fd(fd);
	if (open_file == NULL){
		f->eax = -1;
		return;
	}

	lock_acquire(&filesys_lock);
	f->eax = file_tell(open_file);
	lock_release(&filesys_lock);
}

//FINISHED
static void system_close(struct intr_frame *f, int fd ){
	printf("SYS_CLOSE called\n");

	struct fd_hash_entry *entry =fd_to_fd_hash_entry(fd);
	if (entry == NULL){
		return;
	}

	lock_acquire(&filesys_lock);
	file_close(entry->open_file);
	lock_release(&filesys_lock);

	struct hash_elem *returned = hash_delete(&thread_current()->process->open_files, &entry->elem);
	if (returned == NULL){
		/* We have just tried to delete a fd that was not in our fd table....
		 * This Is obviously a huge problem so system KILLLLLLL!!!! */
		PANIC("ERROR WITH HASH IN PROCESS EXIT!! CLOSE");
	}

	free(entry);
}

//Returns the file or NULL if the fd is invalid
static struct file *file_for_fd (int fd){
	struct fd_hash_entry *hash_elem = fd_to_fd_hash_entry (fd);
	if (hash_elem == NULL){
		return NULL;
	}
	return  hash_elem->open_file;
}

static struct fd_hash_entry * fd_to_fd_hash_entry (int fd){
	struct process *process = thread_current()->process;
	struct fd_hash_entry key;
	key.fd = fd;
	struct hash_elem *fd_hash_elem = hash_find(&process->open_files, &key.elem);
	if (fd_hash_elem == NULL){
		return NULL;
	}
	return hash_entry(fd_hash_elem, struct fd_hash_entry, elem);
}

static bool buffer_is_valid (const void * buffer, unsigned int size){
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

static bool string_is_valid(const char* str){
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
