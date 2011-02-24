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
#include "threads/palloc.h"
#include "threads/init.h"
#include "vm/frame.h"
#include <string.h>

/* THIS IS AN INTERNAL INTERRUPT HANDLER */
static void syscall_handler (struct intr_frame *);

static void system_halt (struct intr_frame *f );
static void system_exec (struct intr_frame *f, const char *cmd_line );
static void system_wait (struct intr_frame *f, pid_t pid );
static void system_create (struct intr_frame *f, const char *file_name, unsigned int initial_size );
static void system_remove (struct intr_frame *f, const char *file_name );
static void system_open (struct intr_frame *f, const char *file_name );
static void system_filesize (struct intr_frame *f, int fd );
static void system_read (struct intr_frame *f, int fd , void *buffer, unsigned int size );
static void system_write (struct intr_frame *f, int fd, const void *buffer, unsigned int size);
static void system_seek (struct intr_frame *f, int fd, unsigned int position );
static void system_tell (struct intr_frame *f, int fd );
static void system_close (struct intr_frame *f, int fd );
static void system_mmap (struct intr_frame *f, int fd, void *uaddr);
static void system_munmap (struct intr_frame *f, mapid_t map_id);

static struct mmap_hash_entry *mapid_to_hash_entry(mapid_t mid);
static bool buffer_is_valid (const void * buffer, unsigned int size);
static bool buffer_is_valid_writable (void * buffer, unsigned int size);
static bool string_is_valid(const char* str);

static unsigned int get_user_int(const uint32_t *uaddr, int *error);
static int get_user(const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);

static struct file *file_for_fd (int fd, bool mmap);
static struct fd_hash_entry * fd_to_fd_hash_entry (int fd);
static void mmap_save_all(struct mmap_hash_entry *entry);
static void mmap_hash_entry_destroy (struct hash_elem *e, void *aux UNUSED);

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
		error = set_args(esp, 2, arg1);
		if(error < 0)system_exit(f, -1);
		system_mmap(f, (int)arg1[0], (void*)arg1[1]);
		break;
	}
	case SYS_MUNMAP:{
		error = set_args(esp, 1, arg1);
		if(error < 0)system_exit(f, -1);
		system_munmap(f, (int)arg1[0]);
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
		BSOD ("INVALID SYS CALL NUMBER %d\n", sys_call_num);
		break;
	}
	}
}

/* General note: if the user passes in a pointer to memory
   that is not valid and would have page faulted the process
   will get killed. For other errors the function will just
   fail silently */

/* Halts the system*/
static void system_halt (struct intr_frame *f UNUSED){
	shutdown_power_off();
}

/* Exits the currently running process freeing the mmapped
   hash table */
void system_exit (struct intr_frame *f UNUSED, int status){
	struct process * proc = thread_current()->process;
	printf("%s: exit(%d)\n", proc->program_name, status);
	proc->exit_code = status;
	/* Must be done before destroying the page dir which will lose all
	   of the data from the mmapped files and before we dissable interrupts
	   because moving dirty pages to disk takes a loooooonnnnggggg time*/
	hash_destroy(&proc->mmap_table, &mmap_hash_entry_destroy);
	thread_exit();
	NOT_REACHED();
}

/* Starts a new child process with the given file name
   returns -1 if the process could not start, kills if
   cmd_line points to invalid memory*/
static void system_exec (struct intr_frame *f, const char *cmd_line ){
	if(!string_is_valid(cmd_line)){
		system_exit(f, -1);
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

/* Waits on the given pid to finish and returns that pid's
   exit code upon completion. Returns -1 if the pid isn't
   a valid child or if this pid has already been waited on
   once. But we still have the exit code so we could actually
   return the exit code again if it wouldn't fail a test */
static void system_wait (struct intr_frame *f, pid_t pid){
	tid_t child_tid;
	if((child_tid = child_pid_to_tid(pid)) == PID_ERROR){
		f->eax = -1;
		return;
	}

	f->eax = process_wait(child_tid);
}

/* Creates a new file by the name of filename. It doesn't open
   the file though. The error code from the filesystem is passed
   back. Kills if file_name points to invalid memory*/
static void system_create (struct intr_frame *f, const char *file_name, unsigned int initial_size){
	if(!string_is_valid(file_name)){
		system_exit(f, -1);
	}
	lock_acquire(&filesys_lock);
	f->eax = filesys_create(file_name, initial_size);
	lock_release(&filesys_lock);
}

/* removes a file by the name of file name returns the value from
   the filesystem. Kills if file_name points to invalid memory*/
static void system_remove(struct intr_frame *f, const char *file_name){
	if(!string_is_valid(file_name)){
		system_exit(f, -1);
	}
	lock_acquire(&filesys_lock);
	f->eax = filesys_remove(file_name);
	lock_release(&filesys_lock);
}

/* Opens the file by the name of file_name returns -1 if the file
   wasn't opened. Kills if the file_name refers to invalid memory*/
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
	fd_entry->is_closed = false;
	fd_entry->num_mmaps = 0;
	struct hash_elem *returned = hash_insert(&process->open_files, &fd_entry->elem);

	if(returned != NULL){
		/* We have just tried to put the fd of an identical fd into the hash
		 Table this is a problem with the hash table and should fail the kernel
		 Cause our memory has been corrupted somehow */
		BSOD("ERROR WITH HASH IN PROCESS EXIT!!");
	}

	f->eax = fd_entry->fd;
}

/* Returns the size of the file for the fd, or -1 if the fd
   is invalid */
static void system_filesize(struct intr_frame *f, int fd){
	struct file *open_file = file_for_fd(fd, false);
	if(open_file == NULL){
		f->eax = -1;
		return;
	}

	lock_acquire(&filesys_lock);
	f->eax = file_length(open_file);
	lock_release(&filesys_lock);
}

/* Reads size bytes into buffer an returns the number of bytes
   actually written. Kills if the buffer refers to invalid memory
   or if the buffer refers to memory that is read only. Checks to make
   sure that buffer is contiguous*/
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

	struct file * file = file_for_fd(fd, false);

	if(file == NULL){
		f->eax = 0;
		return;
	}

	lock_acquire(&filesys_lock);
	bytes_read = file_read(file, buffer, size);
	lock_release(&filesys_lock);
	f->eax = bytes_read;
}

/* Writes size bytes from buffer to the fd. Returns the number of bytes written
   to the fd. If the buffer does not refer to contiguous valid memory then this
   will kill the process.*/
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

	struct file * open_file = file_for_fd(fd, false);

	if(open_file == NULL){
		f->eax = 0;
		return;
	}

	lock_acquire(&filesys_lock);
	bytes_written = file_write(open_file, buffer, size);
	lock_release(&filesys_lock);
	f->eax = bytes_written;
}

/* Seeks to the position in the file described by fd. If the offset is
   larger than the size of the file it will return -1. If the fd is invalid
   it will return -1. if it completes the seek it will return 1. But seek
   is a void funciton so these numbers are actually meaningless
 */
static void system_seek(struct intr_frame *f, int fd, unsigned int position){
	struct file *file = file_for_fd(fd, false);
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

	f->eax = 1;
}

/* Returns the position of the file described by fd, or
   -1 if the fd is not valid */
static void system_tell(struct intr_frame *f, int fd){
	struct file *open_file = file_for_fd(fd, false);
	if(open_file == NULL){
		f->eax = -1;
		return;
	}

	lock_acquire(&filesys_lock);
	f->eax = file_tell(open_file);
	lock_release(&filesys_lock);
}

/* Closes the file described by fd and removes fd from the list of open
   files for this process. Does nothing if fd is invalid*/
static void system_close(struct intr_frame *f UNUSED, int fd ){
	struct fd_hash_entry *entry =fd_to_fd_hash_entry(fd);
	/* Can't close something that is already closed */
	if(entry == NULL || entry->is_closed){
		f->eax = -1;
		return;
	}

	/* if fd was stdin or stdout it CAN'T be in the fd table
	   so it won't get here if STDIN or STDOUT  is passed in.
	   If this fd is not mmapped then we can actually delete
	   it and remove it from the hash, otherwise we will mark
	   it as closed but not really close it. This will be called
	   again on system munmap, which will set both flags to false
	   so that it will actually remove the file.*/
	if(entry->num_mmaps == 0){
		lock_acquire(&filesys_lock);
		file_close(entry->open_file);
		lock_release(&filesys_lock);
		struct hash_elem *returned = hash_delete(&thread_current()->process->open_files, &entry->elem);
		if(returned == NULL){
			/* We have just tried to delete a fd that was not in our fd table....
				   This Is obviously a huge problem so system KILLLLLLL!!!! */
			BSOD("ERROR WITH HASH IN PROCESS EXIT!! CLOSE");
		}

		free(entry);

	}else{
		entry->is_closed = true;
	}
}

static struct mmap_hash_entry *uaddr_to_mmap_entry(
	struct thread *cur, void *uaddr){
	struct hash_iterator i;
	struct hash_elem *e;
	hash_first (&i, &cur->process->mmap_table);
	while((e = hash_next(&i)) != NULL){
		struct mmap_hash_entry *test =
				hash_entry(e, struct mmap_hash_entry, elem);
		if((uint32_t)uaddr < test->end_addr &&
				(uint32_t)uaddr >= test->begin_addr){
			return test;
		}
	}
	return NULL;
}

static struct mmap_hash_entry *mapid_to_hash_entry(mapid_t mid){
	struct process *process = thread_current()->process;
	struct mmap_hash_entry key;
	key.mmap_id = mid;
	struct hash_elem *map_hash_elem = hash_find(&process->mmap_table, &key.elem);
	if(map_hash_elem == NULL){
		return NULL;
	}
	return hash_entry(map_hash_elem, struct mmap_hash_entry, elem);
}

static void system_mmap (struct intr_frame *f, int fd, void *uaddr){
	printf("map\n");
	struct fd_hash_entry *entry =fd_to_fd_hash_entry(fd);
	/* Can't mmap a closed file. Fd to hash_entry also implicitly
	   verifies the fd*/
	if(entry == NULL || entry->is_closed){
		f->eax = -1;
		return;
	}
	/* verify the virtual addr */
	if( ((uint32_t)uaddr % PGSIZE) != 0 || uaddr == NULL
			|| !is_user_vaddr(uaddr)){
		f->eax = -1;
		return;
	}

	/* Bounds checking */
	lock_acquire(&filesys_lock);
	int32_t length = file_length(entry->open_file);
	lock_release(&filesys_lock);
	if(length < 1){
		f->eax = -1;
		return;
	}

	/*Number of pages to allocate*/
	uint32_t num_pages = length / PGSIZE;
	if(length % PGSIZE != 0){
		num_pages ++;
	}

	/* If the end of the mmap would collide with the maximum size of the stack
	   or go into userspace then we can't map this ish. These two quatities
	   may be equal because that means we will have 0 fragmentation between
	   the stack and the mmapped segment. This also means that the user may
	   actually grow the stack larger than the max size by cleverly mmapping
	   files*/
	if((uint32_t)uaddr + (num_pages * PGSIZE) >
			(uint32_t)PHYS_BASE - (stack_size)){
		f->eax = -1;
		return;
	}

	struct thread *cur = thread_current();
	struct process *process = cur->process;
	uint32_t *pd = cur->pagedir;
	/* Here we passed the simple ish so now we are going to check if
	   any of the memory requested is already mapped in the virtual
	   address space*/
	uint8_t *temp_ptr = (uint8_t*)uaddr;
	uint32_t i;
	for(i = 0; i < num_pages; i ++, temp_ptr += PGSIZE){
		if(pagedir_is_mapped(pd, temp_ptr)){
			/* if this virtual address is mapped then we can't create
			   this mmap */
			f->eax = -1;
			return;
		}
	}

	/* All of the pages that are being requested are not mapped if we get
	   here, including other mmapped files that this user has so set up
	   pages.*/

	/* Try to setup all of the pages. Will only fail when kernel out of
	   memory*/
	for(i = 0, temp_ptr = (uint8_t*)uaddr; i < num_pages;
			i ++, temp_ptr += PGSIZE){
		ASSERT(((uint32_t)temp_ptr % PGSIZE) == 0);
		if(!pagedir_setup_demand_page(pd, temp_ptr, PTE_AVL_MMAP,
				(uint32_t)temp_ptr, true)){
			/* This virtual address cannot be allocated so we have an error...
			   Clear the addresses that have been set*/
			pagedir_clear_pages(pd, uaddr, i);
			f->eax = -1;
			return;
		}
	}

	/* If we get here all pages are on demand and ready to be faulted in*/

	entry->num_mmaps ++;

	struct mmap_hash_entry *mmap_entry =
			calloc(1, sizeof(struct mmap_hash_entry));
	if(mmap_entry == NULL){
		/* Can't be allocated, KERNEL OUT OF MEMORY
		   unmap all our PTE's*/
		pagedir_clear_pages(pd, uaddr, num_pages);
		f->eax = -1;
		return;
	}

	mmap_entry->begin_addr = (uint32_t)uaddr;
	mmap_entry->end_addr  =  (uint32_t)uaddr + (num_pages*PGSIZE);
	mmap_entry->fd = entry->fd;
	mmap_entry->mmap_id = process->mapid_counter++;
	mmap_entry->num_pages = num_pages;

	struct hash_elem *returned =
			hash_insert(&process->mmap_table, &mmap_entry->elem);

	if(returned != NULL){
		/* We have just tried to put the mmap of an identical mmap into the hash
		   Table this is a problem with the hash table and should fail the kernel
		   Cause our memory has been corrupted somehow. Or our hash function isn't
		   working appropriately */
		BSOD("ERROR WITH HASH IN PROCESS EXIT!!");
	}

	f->eax = mmap_entry->mmap_id;
	printf("mapend\n");
}

/* Called from process exit because it can never kill and we need to make
   sure all of the changes to the mmapped regions are saved to disk.*/
static void system_munmap (struct intr_frame *f, mapid_t map_id){
	printf("un\n");
	struct mmap_hash_entry *entry = mapid_to_hash_entry(map_id);
	if(entry == NULL){
		f->eax = -1;
		return;
	}

	struct fd_hash_entry *fd_entry = fd_to_fd_hash_entry(entry->fd);
	struct thread * cur = thread_current();
	uint32_t *pd = cur->pagedir;

	mmap_save_all(entry);
	pagedir_clear_pages(pd, (uint32_t*)entry->begin_addr, entry->num_pages);

	struct hash_elem *returned =
			hash_delete(&cur->process->mmap_table, &entry->elem);
	if(returned == NULL){
		/* We have just tried to delete a fd that was not in our fd table....
		   This Is obviously a huge problem so system KILLLLLLL!!!! */
		BSOD("ERROR WITH HASH IN munmap!! CLOSE");
	}

	free(entry);

	if(fd_entry->num_mmaps == 0  && fd_entry->is_closed){
		fd_entry->is_closed = false;
		system_close(f, fd_entry->fd);
	}
	printf("un end\n");
}

/* Read in the appropriate file block from disk
   We know that the current thread is the only one that
   can call this function, when it was trying to access
   memory*/
bool mmap_read_in(void *faulting_addr){
	printf("readin\n");
	struct thread *cur = thread_current();

	/* Get the key into the hash, AKA the uaddr of this page*/
	uint32_t uaddr = pagedir_get_aux(cur->pagedir, faulting_addr);

	/* Get hash entry if it exists */
	struct mmap_hash_entry *entry = uaddr_to_mmap_entry(cur, (uint32_t*)uaddr);
	if(entry == NULL){
		return false;
	}

	uint32_t offset = uaddr - entry->begin_addr;

	/* Accessed through kernel memory the user PTE will not be
	   marked as accessed or dirty !!! */
	uint32_t *kaddr = frame_get_page(PAL_USER, (uint32_t*)uaddr);

	struct fd_hash_entry *fd_entry = fd_to_fd_hash_entry(entry->fd);
	ASSERT(fd_entry != NULL);

	/* The actual reading in from the block always tries to read PGSIZE
	   bytes even though the last page may have many zeros that don't
	   belong to the file. This is because it leverages the fact that
	   file_read will only read up untill the end of the file and
	   never more so we know we will only read the appropriate amount
	   of data into our zero page*/
	lock_acquire(&filesys_lock);
	off_t original_spot = file_tell(fd_entry->open_file);
	file_seek(fd_entry->open_file, offset);
	off_t amount_read = file_read(fd_entry->open_file, kaddr, PGSIZE);
	if(amount_read < PGSIZE){
		memset(kaddr+amount_read, 0, PGSIZE - amount_read);
	}
	file_seek(fd_entry->open_file, original_spot);
	lock_release(&filesys_lock);

	bool success =
			pagedir_install_page((void*)uaddr, (void*)kaddr, true);

	/* Make sure that we stay consistent with our naming scheme
	   of memory*/
	pagedir_set_medium(cur->pagedir, (void*)uaddr, PTE_AVL_MMAP);

	frame_unpin(kaddr);

	printf("in end\n");
	/*"Kernel out of memory! if false;"*/
	return success;
}

/* uaddr is expected to be page aligned, pointing to a page
   that is used for this mmapped file */
bool mmap_write_out(struct thread *cur, void *uaddr){
	printf("mmap out\n");
	ASSERT(((uint32_t)uaddr % PGSIZE) == 0);
	if(!pagedir_is_present(cur->pagedir, uaddr)){
		/* Can't read back to disk if the memory isn't
		   actually present*/
		return false;
	}

	struct mmap_hash_entry *entry = uaddr_to_mmap_entry(cur, uaddr);
	if(entry == NULL){
		return false;
	}

	struct fd_hash_entry *fd_entry = fd_to_fd_hash_entry(entry->fd);

	/* The file should never be closed as long as there is a
	   mmapping to it */
	ASSERT(entry != NULL);

	lock_acquire(&filesys_lock);
	uint32_t offset = (uint32_t) uaddr - entry->begin_addr;
	file_seek(fd_entry->open_file, offset);
	/* If this is the last page only read the appropriate number of bytes*/
	uint32_t write_bytes = (entry->end_addr - (uint32_t)uaddr) / PGSIZE == 1 ?
			file_length(fd_entry->open_file) % PGSIZE : PGSIZE;
	file_write(fd_entry->open_file, uaddr, write_bytes);
	lock_release(&filesys_lock);

	/* Clear this page so that it can be used, and set this PTE
	   back to on demand status*/
	if(!pagedir_setup_demand_page(cur->pagedir, uaddr, PTE_AVL_MMAP,
			(uint32_t)uaddr, true)){
		/* This virtual address cannot be allocated so we have an error*/
		return false;
	}
	printf("mmap out end\n");
	return true;
}

/* System call helpers */

/* Saves all of the pages that are dirty for the given mmap_hash_entry */
static void mmap_save_all(struct mmap_hash_entry *entry){
	printf("saveall\n");
	struct thread * cur = thread_current();
	uint32_t *pd = cur->pagedir;
	struct fd_hash_entry *fd_entry = fd_to_fd_hash_entry(entry->fd);

	/* The file should never be closed as long as there is a
	   mmapping to it */
	ASSERT(fd_entry != NULL);

	fd_entry->num_mmaps --;
	/* Write all of the files out to disk */
	uint8_t* pg_ptr = (uint8_t*)entry->begin_addr;
	uint32_t j;
	lock_acquire(&filesys_lock);
	uint32_t original_position = file_tell(fd_entry->open_file);
	for(j = 0; j < entry->num_pages; j++, pg_ptr += PGSIZE){
		if(pagedir_is_present(pd, pg_ptr) && pagedir_is_dirty(pd, pg_ptr)){
			uint32_t offset = (uint32_t) pg_ptr - entry->begin_addr;
			file_seek(fd_entry->open_file, offset);
			uint32_t write_bytes = (entry->num_pages -1 == j) ?
					file_length(fd_entry->open_file) % PGSIZE : PGSIZE;
			file_write(fd_entry->open_file, pg_ptr, write_bytes);
		}
	}
	file_seek(fd_entry->open_file, original_position);
	lock_release(&filesys_lock);
	printf("saveall exit\n");
}

/* Returns the file or NULL if the fd is invalid.
   If the file is closed, but needs to be held to
   read in for mmapping files then we need to return
   NULL to functions that are not related to mmap
   functions*/
static struct file *file_for_fd (int fd, bool mmap){
	struct fd_hash_entry *hash_elem = fd_to_fd_hash_entry (fd);
	if(hash_elem == NULL){
		return NULL;
	}
	if(!mmap && hash_elem->is_closed){
		return NULL;
	}
	return  hash_elem->open_file;
}

/* Returns the corresponding fd_hash_entry for the fd
   may return null, in which case we know that the fd
   is invalid soooo..... */
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

/* call all destructor for hash_destroy */
void mmap_hash_entry_destroy (struct hash_elem *e, void *aux UNUSED){
	/*File close needs to be called here */
	mmap_save_all(hash_entry(e, struct mmap_hash_entry, elem));
	free(hash_entry(e, struct mmap_hash_entry, elem));
}

/* This function validates the buffer to make sure that we can read
   the full extent of the buffer. Touches every page to make sure that
   it is readable */
static bool buffer_is_valid (const void * buffer, unsigned int size){
	uint8_t *uaddr = (uint8_t*)buffer;
	if(!is_user_vaddr(uaddr) || get_user(uaddr) < 0){
		return false;
	}
	if(size > 1){
		while(size != 0){
			uint32_t increment = (size > PGSIZE) ? PGSIZE : size;
			uaddr += increment;
			if(!is_user_vaddr(uaddr) || get_user(uaddr) < 0){
				return false;
			}
			size -= increment;
		}
	}
	return true;
}

/* Makes sure that the full exetent of the buffer is valid to be read
   and written to. This function will return true if the buffer is valid
   or false if this buffer is not mapped in the user vaddr space or if it
   is read only segment. Touches every page in buffer to make sure it is
   writable */
static bool buffer_is_valid_writable (void * buffer, unsigned int size){
	uint8_t *uaddr = (uint8_t*)buffer;
	int byte;
	if(!is_user_vaddr(uaddr) || (byte = get_user(uaddr)) < 0 || !put_user(uaddr, 1)){
		return false;
	}
	put_user(uaddr, byte);
	if(size > 1){
		while(size != 0){
			/* Touch every page in the buffer to make sure it
			   is valid and touch the last address in the buffer*/
			uint32_t increment = (size > PGSIZE) ? PGSIZE : size;

			uaddr += increment;
			if(!is_user_vaddr(uaddr) || (byte = get_user(uaddr)) < 0 || !put_user(uaddr, 1)){
				return false;
			}
			/* put the data back*/
			put_user(uaddr, byte);

			size -= increment;
		}
	}
	return true;
}


/* Returns a unsigned int representing 4 bytes of data
    if there was a segfault it will set
    error to be negative, positive otherwise*/
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

/* Attempts to get a byte from the user address
   returns -1 on segfault */
static int get_user(const uint8_t *uaddr){
	int result;
	asm("movl $1f, %0; movzbl %1, %0; 1:"
			: "=&a" (result) : "m" (*uaddr));
	return result;
}

/* Attempts to write one byte to the user address
   returns true if the address was written to and
   false if a page fault occured*/
static bool put_user (uint8_t *udst, uint8_t byte){
	int error_code;
	asm("movl $1f, %0; movb %b2, %1; 1:" : "=&a" (error_code), "=m" (*udst) : "q" (byte));
	return error_code != -1;
}

/* Verifies that the string pointer passed in is a valid
   string character, this function will look at every address
   of the string until it finds a terminating character if the
   user passes in a bad pointer but it doesn't page fault then
   the string will be used anyway and may result in undefined
   behavior*/
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
