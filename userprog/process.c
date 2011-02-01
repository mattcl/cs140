#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <list.h>
#include <hash.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"

static struct hash processes;			 /*A hash of all created processes*/
static struct lock processes_hash_lock;  /*A lock on that hash table*/
static struct lock pid_lock;			 /*A lock needed to increment it*/


static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);


static struct process *parent_process_from_child (struct process* child_process);

//HASH table functions
static unsigned file_hash_func (const struct hash_elem *e, void *aux UNUSED);
static bool file_hash_compare (const struct hash_elem *a,
						 const struct hash_elem *b,
						 void *aux UNUSED);
static void fd_hash_entry_destroy (struct hash_elem *e, void *aux UNUSED);


static unsigned process_hash_func (const struct hash_elem *a, void *aux UNUSED);
static bool process_hash_compare  (const struct hash_elem *a,
						     const struct hash_elem *b,
		                     void *aux UNUSED);
static void process_hash_entry_destroy (struct hash_elem *e, void *aux UNUSED);


typedef bool is_equal (struct child_list_entry *cle, void *c_tid);
static bool is_equal_func_1 (struct child_list_entry *cle, void *c_tid){
	return ((list_entry(cle,struct child_list_entry,elem))->child_tid==*(tid_t*)c_tid);
}
static bool is_equal_func_2 (struct child_list_entry *cle, void *c_pid){
	return ((list_entry(cle,struct child_list_entry,elem))->child_pid==*(pid_t*)c_pid);
}

void process_init(void){
	hash_init(&processes, &process_hash_func, &process_hash_compare, NULL);
	lock_init(&processes_hash_lock);
	lock_init(&pid_lock);

	lock_init(&filesys_lock);

	//CREATE the GLOBAL process
	struct process *global = calloc(1, sizeof(struct process));
	if (global == NULL){
		// We can't allocate the global process, this is bad
		PANIC("We can't Allocate the global process");
	}
	global->pid = 0;

	thread_current()->process = global;

	// Initializes this process with the parent process ID
	// of 0
	if (!initialize_process(global, thread_current())){
		PANIC("ERROR initialzing the global process");
	}

}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t process_execute (const char *file_name) {
	char *fn_copy;
	tid_t tid;

	/* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL){
		return TID_ERROR;
	}
	strlcpy (fn_copy, file_name, PGSIZE);
	/*probably want to copy the rest of the argument here.  We also
	  need to make sure the stack pointer is correct. */
	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (file_name, PRI_DEFAULT, start_process, fn_copy);
	if (tid == TID_ERROR){
		palloc_free_page (fn_copy);
	}
	return tid;
}

static pid_t allocate_pid(void){
	static pid_t next_pid = 1;
	pid_t pid;
	lock_acquire (&pid_lock);
	pid = next_pid++;
	lock_release (&pid_lock);

	return pid;
}

/* called by thread create and process_init
 * Must be run with interrupts off
 * Initializes the process and sets the process pointer
 * In the thread that is being created with a parent_id
 * Equal to the pid of creator thread
 */
bool initialize_process (struct process *p, struct thread *our_thread){
	p->pid = allocate_pid();
	p->parent_id = thread_current()->process->pid;
	p->fd_count = 2;
	bool success = hash_init(&p->open_files, &file_hash_func, &file_hash_compare, NULL);
	if (!success){
		return false;
	}

	sema_init(&p->waiting_semaphore, 0);

	list_init(&p->children_list);

	lock_init(&p->child_pid_tid_lock);
	cond_init(&p->pid_cond);

	p->child_waiting_on_pid = 0;
	our_thread->process = p;
	p->exit_code = 0;

	lock_acquire(&processes_hash_lock);
	struct hash_elem *process = hash_insert(&processes, &p->elem);
	lock_release(&processes_hash_lock);

	// returns something if it wasn't inserted of NULL if it
	// was inserted. Go Figure. If process == NULL all is good
	// otherwise bad times;
	if (process != NULL){
		hash_destroy(&p->open_files, NULL);
		return false;
	}
	return true;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process (void *file_name_) {
	struct thread *cur = thread_current();
	struct process *cur_process = cur->process;

	// Get parent process. We know that it is waiting on a
	// signal if it called exec
	lock_acquire(&processes_hash_lock);
	struct process *parent = parent_process_from_child(cur_process);
	lock_release(&processes_hash_lock);

	// Parent hasn't exited yet so we can grab their lock
	// so that they wait until set up is done
	if (parent != NULL){
		lock_acquire(&parent->child_pid_tid_lock);
	}

	char *file_name = file_name_;
	struct intr_frame if_;
	bool success;

	/* Initialize interrupt frame and load executable. */
	memset (&if_, 0, sizeof if_);
	if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
	if_.cs = SEL_UCSEG;
	if_.eflags = FLAG_IF | FLAG_MBS;
	success = load (file_name, &if_.eip, &if_.esp);

	/* If load failed, quit. */
	palloc_free_page (file_name);

	if (!success) {
		//BAD TIMES
		if (parent != NULL){
			//communicate error with parent
			parent->child_waiting_on_pid= PID_ERROR;
			cond_signal(&parent->pid_cond, &parent->child_pid_tid_lock);
			lock_release(&parent->child_pid_tid_lock);
		}
		// Calls process Exit to clean up process and set error
		// code for the parent to retrieve
		cur_process->exit_code = PID_ERROR;
		thread_exit ();
	}
	//printf("Finished loading\n");

	if (parent != NULL){
		struct child_list_entry *cle = calloc(1, sizeof(struct child_list_entry));
		if(cle != NULL){
			cle->child_pid = cur_process->pid;
			cle->child_tid = cur->tid;
			list_push_front(&parent->children_list, &cle->elem);
			parent->child_waiting_on_pid = cur_process->pid;
		} else {
			//Failed to allocate a handle on the child
			parent->child_waiting_on_pid = PID_ERROR;
		}
		cond_signal(&parent->pid_cond, &parent->child_pid_tid_lock);
		lock_release(&parent->child_pid_tid_lock);

		if (cle == NULL){
			cur_process->exit_code = PID_ERROR;
			thread_exit();
		}
	}

	/* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
	asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
	NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait (tid_t child_tid){
	struct child_list_entry *child_entry = child_list_entry_tid(child_tid);
	if (child_entry == NULL){
		// not one of our children
		return PID_ERROR;
	}

	printf("WAITING ON %u\n", child_tid);

	struct process *cur = thread_current()->process;

	//Doing this with interrupts disabled because
	// the child thread could begin thread exit in between
	// if it wasn't. Disable interrupts itself, and then
	// bring us back to hear and then we would be dereferencing
	// freed memory
	enum intr_level old_level = intr_disable();

	// Needs interrupts off
	struct thread* childthread = thread_find(child_tid);

	if(childthread != NULL) {
		printf("Waiting on child\n");
		cur->child_waiting_on_pid = childthread->process->pid;
		printf("SHOULD BE BLOCKING %u process %d\n", child_tid, child_pid);
		sema_down(&cur->waiting_semaphore);
		printf("SHOULD BE BLOCKING %u process %d\n", child_tid, child_pid);
	}
	intr_set_level (old_level);

	//retrieve exit code now, should be in the updated
	// child_entry
	lock_acquire(&cur->child_pid_tid_lock);
	int exit_code = list_entry(child_entry, struct child_list_entry, elem)->exit_code;
	lock_release(&cur->child_pid_tid_lock);
	return exit_code;
}


/* Free the current process's resources.
 * And signals the parent that it has finished,
 * if the parent still exists and is waiting*/
void process_exit (void){
	struct thread *cur = thread_current ();
	struct process *cur_process = cur->process;
	printf("Exiting process %u\n", cur->process->pid);
	uint32_t *pd;

	/* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
	pd = cur->pagedir;
	if (pd != NULL) {
		/* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
		cur->pagedir = NULL;
		pagedir_activate (NULL);
		pagedir_destroy (pd);
	}

	//We are no longer viable processes and are being removed from the
	// list of processes. The lock here also ensures that our parent
	// has either exited or hasn't exited while we update information
	lock_acquire(&processes_hash_lock);
	struct hash_elem *deleted = hash_delete(&processes, &cur_process->elem);

	struct process *parent = parent_process_from_child(cur_process);

	if (parent != NULL){
		printf("Parent not null\n");

		//Get our list entry
		struct list_entr *our_entry =
				child_list_entry_gen(parent, &cur_process->pid, &is_equal_func_2);
		if (our_entry != NULL){
			lock_acquire(&parent->child_pid_tid_lock);
			struct child_list_entry *entry = list_entry(our_entry,
					struct child_list_entry, elem);
			entry->exit_code = cur_process->exit_code;
			lock_release(&parent->child_pid_tid_lock);
		}

		if (parent->child_waiting_on_pid == cur->process->pid){
			printf("Waking parent\n");
			sema_up(&parent->waiting_semaphore);
		} else {
			//Debuging for deadlock
			printf("not waking parent\n");
		}
	}

	lock_release(&processes_hash_lock);

	if( deleted != &cur_process->elem){
		// We pulled out a different proccess with the same pid... uh oh
		PANIC("WEIRD SHIT WITH HASH TABLE!!!");
	}

	// Free all open files
	hash_destroy(&cur_process->open_files, &fd_hash_entry_destroy);

	// We have already been removed from the list of processes and
	// thus can't be found by our children. The locking here isn't
	// necessary but doesn't hurt correctness
	lock_acquire(&cur_process->child_pid_tid_lock);
	while (!list_empty (&cur_process->children_list)){
	       struct list_elem *e = list_pop_front (&cur_process->children_list);
	       free (list_entry(e, struct child_list_entry, elem));
	}
	lock_release(&cur_process->child_pid_tid_lock);

	free(cur_process);

}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void process_activate (void){
	struct thread *t = thread_current ();

	/* Activate thread's page tables. */
	pagedir_activate (t->pagedir);

	/* Set thread's kernel stack for use in processing
     interrupts. */
	tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr{
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr{
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

static bool setup_stack_args(void **esp, char *f_name, char *token, char *save_ptr);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load (const char *file_name, void (**eip) (void), void **esp) {
	struct thread *t = thread_current ();
	struct Elf32_Ehdr ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	// --------- BEGIN CHANGES -------- //
	char arg_buffer[MAX_ARG_LENGTH];
	size_t len = strnlen(file_name, MAX_ARG_LENGTH) + 1;
	strlcpy(arg_buffer, file_name, len);
	

	char *f_name, *token, *save_ptr;
	
	// extract the filename from the args
	f_name = strtok_r(arg_buffer, " ", &save_ptr);
	token = strtok_r(NULL, " ", &save_ptr);

	// ---------- END CHANGES ----------//

	/* Allocate and activate page directory. */
	t->pagedir = pagedir_create ();
	if (t->pagedir == NULL) {
		goto done;
	}
	process_activate ();

	/* Open executable file. */
	lock_acquire(&filesys_lock);
	file = filesys_open (f_name);
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}

	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 3
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
			|| ehdr.e_phnum > 1024){

		printf ("load: %s: error loading executable\n", file_name);
		goto done;

	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++){
		struct Elf32_Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file)){
			goto done;
		}
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr){
			goto done;
		}
		file_ofs += sizeof phdr;
		switch (phdr.p_type){
		case PT_NULL:
		case PT_NOTE:
		case PT_PHDR:
		case PT_STACK:
		default:
			/* Ignore this segment. */
			break;
		case PT_DYNAMIC:
		case PT_INTERP:
		case PT_SHLIB:
			goto done;
		case PT_LOAD:
			if (validate_segment (&phdr, file)){
				bool writable = (phdr.p_flags & PF_W) != 0;
				uint32_t file_page = phdr.p_offset & ~PGMASK;
				uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
				uint32_t page_offset = phdr.p_vaddr & PGMASK;
				uint32_t read_bytes, zero_bytes;
				if (phdr.p_filesz > 0){
					/* Normal segment.
                     Read initial part from disk and zero the rest. */
					read_bytes = page_offset + phdr.p_filesz;
					zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
							- read_bytes);
				} else {
					/* Entirely zero.
                     Don't read anything from disk. */
					read_bytes = 0;
					zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
				}
				if (!load_segment (file, file_page, (void *) mem_page,
						read_bytes, zero_bytes, writable)){
					goto done;
				}

			}else{
				goto done;
			}
			break;
		}
	}

	/* Set up stack. */
	if (!setup_stack (esp)){
		goto done;
	}
	
	/* Start address. */
	*eip = (void (*) (void)) ehdr.e_entry;

	success = setup_stack_args(esp, f_name, token, save_ptr);

	done:
	/* We arrive here whether the load is successful or not. */
	file_close (file);
	lock_release(&filesys_lock);
	return success;
}

static inline void push_4_byte_data(void ** esp, void *data){
	*(uint32_t*)esp -= sizeof(uint32_t);
	**((uint32_t **) esp) = (uint32_t)data;
}

static inline void adjust_stack_ptr(void **esp, size_t length){
	*(char**)esp -= length;
}


static bool setup_stack_args(void **esp, char *f_name, char *token, char *save_ptr){
	//printf("Setup stack\n");
	void *strPtrs[128];
	int count = 0;
	int i = 0;

	size_t fn_len = strlen(f_name) + 1;

	//make space for filename
	adjust_stack_ptr(esp, fn_len);

	//puts filename on stack
	strlcpy(*esp, f_name, fn_len);

	strPtrs[0] = *esp;
	//printf("ESP %p %s %s\n", *esp, *(char**)esp, f_name);

	// pushes arguments onto stack
	for(; token != NULL; token = strtok_r(NULL, " ", &save_ptr)) {
		size_t arg_len = strlen(token) + 1;

		//make room for the argument
		adjust_stack_ptr(esp, arg_len);

		//put stuff into the stack
		strlcpy(*esp, token, arg_len);
		//printf("ESP %p %s %s\n", *esp, *(char**)esp, token);
		strPtrs[++count] = *esp;

	}

	// word align
	adjust_stack_ptr(esp, ((unsigned int)*esp) % 4);
	//printf("ESP %p\n", *esp);

	// sets argv[argc] = NULL
	push_4_byte_data(esp , NULL);
	//printf("ESP %p, %d\n", *esp, **(int**)esp);

	// set argv elements
	for(i = count; i >= 0; i--) {
		push_4_byte_data(esp, strPtrs[i]);
		//printf("ESP %p %p %s %p %s (argv[%d])\n", *esp, **(char***)esp, **(char***)esp, strPtrs[i], (char*)strPtrs[i], i);
	}

	// set argv
	char *beginning = *esp;
	push_4_byte_data(esp, beginning);
	//printf("ESP %p, %p (argv)\n", *esp, **(char***)esp);

	// set argc (Count was an index but needs to be the number of args including filename)
	push_4_byte_data(esp, (void*)(count+1));

	//printf("ESP %p, %d (argc)\n", *esp, **(int**)esp);

	//push return address
	push_4_byte_data(esp , NULL);
	//printf("ESP %p, %d (return address)\n", *esp, **(int**)esp);

	//printf("Returning from setting up stack %p\n", *esp);
	return true;

}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment (const struct Elf32_Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) {
		return false;
	}
	/* p_offset must point within FILE. */
	if (phdr->p_offset > (Elf32_Off) file_length (file)){
		return false;
	}

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz){
		return false;
	}
	/* The segment must not be empty. */
	if (phdr->p_memsz == 0){
		return false;
	}
	/* The virtual memory region must both start and end within the
     user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr)){
		return false;
	}
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz))){
		return false;
	}

	/* The region cannot "wrap around" across the kernel virtual
     address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr){
		return false;
	}
	/* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE){
		return false;
	}
	/* It's okay. */
	return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
             uint32_t read_bytes, uint32_t zero_bytes, bool writable){

	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0){
		/* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL){
			return false;
		}

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes){
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)){
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack (void **esp){
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);

	if (kpage != NULL){
		success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
		if (success){
			*esp = PHYS_BASE;
		}else{
			palloc_free_page (kpage);
		}
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
     address, then map our page there. */
	return (pagedir_get_page (t->pagedir, upage) == NULL
			&& pagedir_set_page (t->pagedir, upage, kpage, writable));
}

/*
 * Returns a process * or NULL
 * MUST BE CALLED WITH THE procces_hash_lock HELD!!!
 */
static struct process *parent_process_from_child (struct process* our_process){
	struct process key;
	key.pid = our_process->parent_id;
	struct hash_elem *parent_process = hash_find(&processes, &key.elem);
	if (parent_process != NULL){
		return hash_entry(parent_process, struct process, elem);
	} else {
		return NULL;
	}
}

static struct list_elem *child_list_entry_gen(struct process *process,								void *c_tid, bool tid,is_equal *func){
	lock_acquire(&process->child_pid_tid_lock);
	struct list_elem *h, *n;
	h = list_begin(&process->children_list);
	while ((n= list_next(h)) != list_end(&process->children_list)){
		if(func(h, c_tid)){
			lock_release(&process->child_pid_tid_lock);
			return n;
		}
		h = n;
	}
	lock_release(&process->child_pid_tid_lock);
	return NULL;
}

static struct child_list_entry *child_list_entry_tid (tid_t c_tid){
	struct process *cur_process = thread_current()->process;
	return list_entry(
			child_list_entry_gen(cur_process, &c_tid, &is_equal_func_1),
			struct child_list_entry,
			elem);
}

static struct child_list_entry *child_list_entry_pid(pid_t c_pid){
	struct process *cur_process = thread_current()->process;
	return list_entry(
			child_list_entry_gen(cur_process, &c_pid, &is_equal_func_2),
			struct child_list_entry,
			elem);
}

/* Takes a tid and returns the corresponding pid
 * if it was a child, PID_ERROR otherwise*/
static pid_t child_tid_to_pid (tid_t c_tid){
	struct list_elem *child_entry = child_list_entry_tid(c_tid);
	if (child_entry != NULL){
		return list_entry(child_entry,struct child_list_entry,elem)->child_pid;
	}
	return PID_ERROR;
}

/* Takes a pid and returns the corresponding tid
 * if it was a child, TID_ERROR otherwise*/
static tid_t child_pid_to_tid (pid_t c_pid){
	struct list_elem *child_entry = child_list_entry_pid(c_pid);
	if (child_entry != NULL){
		return list_entry(child_entry,struct child_list_entry,elem)->child_tid;
	}
	return PID_ERROR;
}

static bool file_hash_compare (const struct hash_elem *a,
						 const struct hash_elem *b,
						 void *aux UNUSED){
	ASSERT(a != NULL);
	ASSERT(b != NULL);
	return (hash_entry(a, struct fd_hash_entry, elem)->fd <
			hash_entry(b, struct fd_hash_entry, elem)->fd);
}

static unsigned file_hash_func (const struct hash_elem *e, void *aux UNUSED){
	return hash_int(hash_entry(e, struct fd_hash_entry, elem)->fd);
}

static void fd_hash_entry_destroy (struct hash_elem *e, void *aux UNUSED){
	//File close needs to be called here
	lock_acquire(&filesys_lock);
	file_close(hash_entry(e, struct fd_hash_entry, elem)->open_file);
	lock_release(&filesys_lock);
	free(hash_entry(e, struct fd_hash_entry, elem));
}

static bool process_hash_compare  (const struct hash_elem *a,
						     const struct hash_elem *b,
		                     void *aux UNUSED){
	ASSERT(a != NULL);
	ASSERT(b != NULL);
	return (hash_entry(a, struct process, elem)->pid <
			hash_entry(b, struct process, elem)->pid);
}

static unsigned process_hash_func (const struct hash_elem *a, void *aux UNUSED){
	pid_t pid = hash_entry(a, struct process, elem)->pid;
	return hash_bytes(&pid, (sizeof(pid_t)));
}

static void process_hash_entry_destroy (struct hash_elem *e UNUSED, void *aux UNUSED){
	//Auxilary data may need to be destroyed left it here just in case
}

