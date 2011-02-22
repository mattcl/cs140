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
#include "vm/frame.h"
#include "vm/swap.h"

static struct hash processes;			 /*A hash of all created processes*/
static struct lock processes_hash_lock;  /*A lock on that hash table*/
static struct lock pid_lock;			 /*A lock needed to increment it*/

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

static struct process *parent_process_from_child (struct process* child_process);
static struct process *process_lookup (pid_t pid);

/* Shortcuts for lots of typing and possible type errors */
#define HASH_ELEM const struct hash_elem
#define AUX void *aux UNUSED

/* HASH table functions*/
static unsigned file_hash_func (HASH_ELEM *e, AUX);
static bool file_hash_compare (HASH_ELEM *a, HASH_ELEM *b, AUX);
static void fd_hash_entry_destroy (struct hash_elem *e, AUX);

static unsigned process_hash_func (HASH_ELEM *a, AUX);
static bool process_hash_compare  (HASH_ELEM *a, HASH_ELEM *b, AUX);

typedef bool is_equal (struct list_elem *cle, void *c_tid);
static bool is_equal_func_tid (struct list_elem *cle, void *c_tid){
	return ((list_entry(cle,struct child_list_entry,elem))->child_tid==*(tid_t*)c_tid);
}
static bool is_equal_func_pid (struct list_elem *cle, void *c_pid){
	return ((list_entry(cle,struct child_list_entry,elem))->child_pid==*(pid_t*)c_pid);
}

static struct list_elem *child_list_entry_gen(
		struct process *process, void *c_tid, is_equal *func);

static struct child_list_entry *child_list_entry_pid(pid_t c_pid);
static struct child_list_entry *child_list_entry_tid(tid_t c_tid);

void process_init(void){
	hash_init(&processes, &process_hash_func, &process_hash_compare, NULL);
	lock_init(&processes_hash_lock);
	lock_init(&pid_lock);

	lock_init(&filesys_lock);

	/* CREATE the GLOBAL process*/
	struct process *global = calloc(1, sizeof(struct process));
	if(global == NULL){
		/* We can't allocate the global process, this is bad*/
		PANIC("We can't Allocate the global process");
	}
	global->pid = 0;

	thread_current()->process = global;

	/* Initializes this process with the parent process ID of 0 */
	if(!initialize_process(global, thread_current())){
		PANIC("ERROR initialzing the global process");
	}
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
   Must be run with interrupts off
   Initializes the process and sets the process pointer
   In the thread that is being created */
bool initialize_process (struct process *p, struct thread *our_thread){
	p->pid = allocate_pid();
	p->parent_id = thread_current()->process->pid;
	p->fd_count = 2;
	bool success = hash_init(&p->open_files, &file_hash_func, &file_hash_compare, NULL);

	if(!success){
		return false;
	}

	success = hash_init(&p->swap_table, &swap_slot_hash_func, &swap_slot_compare, NULL);

	if(!success){
		return false;
	}

	sema_init(&p->waiting_semaphore, 0);
	list_init(&p->children_list);
	lock_init(&p->child_pid_tid_lock);
	cond_init(&p->pid_cond);

	p->child_waiting_on_pid = -1;
	p->child_pid_created = false;
	our_thread->process = p;
	p->exit_code = -1;

	lock_acquire(&processes_hash_lock);
	struct hash_elem *process = hash_insert(&processes, &p->elem);
	lock_release(&processes_hash_lock);

	/* returns something if it wasn't inserted of NULL if it
	   was inserted. Go Figure. If process == NULL all is good
	   otherwise bad times;*/
	if(process != NULL){
		hash_destroy(&p->open_files, NULL);
		return false;
	}
	return true;
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t process_execute (const char *file_name){
	char *fn_copy;
	tid_t tid;

	/* Make a copy of FILE_NAME.
       Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if(fn_copy == NULL){
		return TID_ERROR;
	}
	strlcpy (fn_copy, file_name, PGSIZE);

	struct process *cur_process = thread_current()->process;

	/* make sure that the new process signals us that it has set up */
	lock_acquire(&cur_process->child_pid_tid_lock);

	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (file_name, PRI_DEFAULT, start_process, fn_copy);

	if(tid == TID_ERROR){
		palloc_free_page (fn_copy);
		lock_release(&cur_process->child_pid_tid_lock);
		return TID_ERROR;
	}

	/* wait until the child process is set up or fails. Must
	   be after we know the thread is running that we wait on the
	   lock. Our cur_process->child_pid_created field will contain
	   whether it was successful or not */
	cond_wait(&cur_process->pid_cond, &cur_process->child_pid_tid_lock);

	/* Check to see if it set up correcly */
	if(cur_process->child_pid_created == false){
		lock_release(&cur_process->child_pid_tid_lock);
		return TID_ERROR;
	}

	/* If it set up correctly the tid will be in the list
	   of children for this thread */
	cur_process->child_pid_created = false;
	lock_release(&cur_process->child_pid_tid_lock);

	return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process (void *file_name_){
	struct thread *cur = thread_current();
	struct process *cur_process = cur->process;

	/* Get parent process. We know that it is waiting on a
	   signal if it called exec */
	lock_acquire(&processes_hash_lock);
	struct process *parent = parent_process_from_child(cur_process);
	lock_release(&processes_hash_lock);

	/* Parent hasn't exited yet so we can grab their lock
	   so that they wait until set up is done and so we can
	   signal them when set up is finished
	   Every process that is exec'd has a parent waiting on
	   it to be initialized */
	if(parent != NULL){
		/* Signaling and releasing this lock will resume
		   parent execution in process_execute */
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

	palloc_free_page (file_name);

	if(!success){
		/* BAD TIMES Calls process Exit to clean up process and set error
		   code for the parent to retrieve */
		cur_process->exit_code = PID_ERROR;

		if(parent != NULL){
			/* communicate error with parent */
			parent->child_pid_created= false;
			cond_signal(&parent->pid_cond, &parent->child_pid_tid_lock);
			lock_release(&parent->child_pid_tid_lock);
		}
		thread_exit ();
		NOT_REACHED ();
	}

	if(parent != NULL){
		struct child_list_entry *cle = calloc(1, sizeof(struct child_list_entry));
		if(cle != NULL){
			cle->child_pid = cur_process->pid;
			cle->child_tid = cur->tid;
			list_push_front(&parent->children_list, &cle->elem);
			parent->child_pid_created = true;
			cond_signal(&parent->pid_cond, &parent->child_pid_tid_lock);
			lock_release(&parent->child_pid_tid_lock);
		}else{
			/* Failed to allocate a handle on the child*/
			parent->child_pid_created = false;
			cur_process->exit_code = -1;
			cond_signal(&parent->pid_cond, &parent->child_pid_tid_lock);
			lock_release(&parent->child_pid_tid_lock);
			thread_exit();
			NOT_REACHED ();
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
	struct process *cur = thread_current()->process;
	/* Find pid and see if the process still exists. I.E.
	   it hasn't removed itself from the processes hash
	   if it has we know that it is dead and we can just
	   retrieve its exit code. This prevents race conditions
	   with the child process exiting */
	lock_acquire(&processes_hash_lock);

	struct child_list_entry *child_entry = child_list_entry_tid(child_tid);
	if(child_entry == NULL){
		/*  not one of our children */
		lock_release(&processes_hash_lock);
		return PID_ERROR;
	}

	struct process *child = process_lookup(child_entry->child_pid);

	/*We know that the process can't exit untill it acquires the process
	 lock so set the waiting pid to its process pid so that it will
	 signal us when it is done exiting*/

	/* Wait for process to signal us
	   If child == NULL it has already exited */
	if(child != NULL){
		cur->child_waiting_on_pid = child->pid;
		lock_release(&processes_hash_lock);
		sema_down(&cur->waiting_semaphore);
	}else{
		lock_release(&processes_hash_lock);
	}

	/* Lock's really aren't required here either because if we
	   get to this point we know that the thread has already
	   completely exited and set the exit code in the appropriate
	   entry but I put them here just in case*/
	lock_acquire(&cur->child_pid_tid_lock);
	cur->child_waiting_on_pid = -1; /* NOT WAITING ON ANYTHING*/
	int exit_code = child_entry->exit_code;

	/* This is lame I think that keeping the exit code for the process
	   is so much more useful, sigh */
	child_entry->exit_code = -1;
	lock_release(&cur->child_pid_tid_lock);

	return exit_code;
}


/* Free the current process's resources.
   And signals the parent that it has finished,
   if the parent still exists and is waiting*/
void process_exit (void){
	struct thread *cur = thread_current ();
	struct process *cur_process = cur->process;
	uint32_t *pd;
	/* Destroy the current process's page directory and switch back
       to the kernel-only page directory. */
	pd = cur->pagedir;
	if(pd != NULL){
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

	/* We are no longer viable processes and are being removed from the
	   list of processes. The lock here also ensures that our parent
	   has either exited or hasn't exited while we update information
	   Lock prevents a parent from waiting on this process if we get to
	   the lock first. This ensures that a waiting parent will be woken up*/
	lock_acquire(&processes_hash_lock);
	struct hash_elem *deleted = hash_delete(&processes, &cur_process->elem);

	if( deleted != &cur_process->elem){
		/* We pulled out a different proccess with the same pid... uh oh */
		PANIC("WEIRD SHIT WITH HASH TABLE!!!");
	}

	struct process *parent = parent_process_from_child(cur_process);

	if(parent != NULL){
		/* Get our list entry */
		struct list_elem *our_entry =
				child_list_entry_gen(parent, &cur_process->pid, &is_equal_func_pid);
		lock_acquire(&parent->child_pid_tid_lock);
		if(our_entry != NULL){
			struct child_list_entry *entry =
					list_entry(our_entry, struct child_list_entry, elem);
			entry->exit_code = cur_process->exit_code;
		}

		lock_release(&parent->child_pid_tid_lock);
		/*Wake parent up with this if */
		if(parent->child_waiting_on_pid == cur_process->pid){
			sema_up(&parent->waiting_semaphore);
		}
	}
	lock_release(&processes_hash_lock);

	/* Free all open files Done without exterior locking
	   each file will close with the filesys lock held */
	hash_destroy(&cur_process->open_files, &fd_hash_entry_destroy);

	/* We do not need to lock this because all children of
 	   this process need to go through acquiring a handle
	   for this process through the all process hash table
	   but our process is not in it so it won't be found and
	   thus updates can not occur to the list after this
	   process has finally released the all process lock.
	   Plus the only way to add things to the list is to create
	   a new process. And this thread can't be exiting and creating
	   simultaneously */
	while(!list_empty (&cur_process->children_list)){
	       struct list_elem *e = list_pop_front (&cur_process->children_list);
	       free (list_entry(e, struct child_list_entry, elem));
	}

	free(cur_process->program_name);

	/*close our executable allowing write access again */
	lock_acquire(&filesys_lock);
	file_close(cur_process->executable_file);
	lock_release(&filesys_lock);
	free(cur_process);
}

/* Sets up the CPU for running user code in the current thread.
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
        uint32_t read_bytes, uint32_t zero_bytes, bool writable);

static bool setup_stack_args(void **esp, char *f_name, char *token, char *save_ptr);

static bool read_elf_headers(struct file *file, struct Elf32_Ehdr *ehdr,
							 struct process *cur_process, struct thread* t);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load (const char *file_name, void (**eip) (void), void **esp){
	struct thread *t = thread_current ();
	struct process *cur_process = t->process;
	struct Elf32_Ehdr ehdr;
	struct file *file = NULL;
	bool success = false;

	/* Acquire the lock in advance just incase we need to break */
	lock_acquire(&filesys_lock);

	char arg_buffer[MAX_ARG_LENGTH];
	size_t len = strnlen(file_name, MAX_ARG_LENGTH) + 1;
	strlcpy(arg_buffer, file_name, len);
	
	char *f_name, *token, *save_ptr;
	
	/* extract the filename from the args */
	f_name = strtok_r(arg_buffer, " ", &save_ptr);
	token = strtok_r(NULL, " ", &save_ptr);

	size_t fn_len = strlen(f_name) + 1;
	cur_process->program_name = calloc( fn_len , sizeof(char));

	if(cur_process->program_name == NULL){
		/* failure */
		goto done;
	}

	strlcpy(cur_process->program_name, f_name , fn_len);

	/* Allocate and activate page directory. */
	t->pagedir = pagedir_create ();
	if(t->pagedir == NULL){
		goto done;
	}
	process_activate ();

	/* Open executable file. */
	file = filesys_open (f_name);
	if(file == NULL){
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}

	if(!read_elf_headers(file, &ehdr, cur_process, t)){
		goto done;
	}

	/* Set up stack. */
	if(!setup_stack (esp)){
		printf("failed to setup stack\n");
		goto done;
	}

	/* Start address. */
	*eip = (void (*) (void)) ehdr.e_entry;

	/*Push args*/
	success = setup_stack_args(esp, f_name, token, save_ptr);

done:
	/* We arrive here whether the load is successful or not. */
	lock_release(&filesys_lock);
	return success;
}

static bool read_elf_headers(struct file *file, struct Elf32_Ehdr *ehdr,
							 struct process *cur_process, struct thread* t){
	off_t file_ofs;
	uint32_t i = 0, j = 0, k = 0;
	/* Read and verify executable header. */
	if(file_read (file, ehdr, sizeof(struct Elf32_Ehdr))!=sizeof(struct Elf32_Ehdr)
			|| memcmp (ehdr->e_ident, "\177ELF\1\1\1", 7)
			|| ehdr->e_type != 2
			|| ehdr->e_machine != 3
			|| ehdr->e_version != 1
			|| ehdr->e_phentsize != sizeof (struct Elf32_Phdr)
			|| ehdr->e_phnum > 1024){

		//printf ("load: %s: error loading executable\n", file_name);
		return false;

	}

	cur_process->executable_file = file;
	file_deny_write(cur_process->executable_file);

	/* Read program headers. */
	file_ofs = ehdr->e_phoff;

	/* An array that contains the max number of headers
	   will eventually only store the number of loadable
	   headers in it and be malloced */
	struct exec_page_info head[ehdr->e_phnum];

	//printf("base %p size %u %u\n", head, sizeof(struct exec_page_info), ehdr.e_phnum);

	if(head == NULL){
		PANIC("KERNEL OUT OF MEMORY");
	}

	for(i = 0; i < ehdr->e_phnum; i++){
		struct Elf32_Phdr phdr;

		if(file_ofs < 0 || file_ofs > file_length (file)){
			return false;
		}

		file_seek (file, file_ofs);

		if(file_read (file, &phdr, sizeof phdr) != sizeof phdr){
			return false;
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
			/* Implementation for shared/dynamic libraries*/
			return false;
		case PT_LOAD:
			if(validate_segment (&phdr, file)){
				uint32_t page_offset = phdr.p_vaddr & PGMASK;
				//printf("page offset %u\n", page_offset);
				head[k].file_page = phdr.p_offset & ~PGMASK;
				head[k].mem_page = phdr.p_vaddr & ~PGMASK;
				head[k].writable = (phdr.p_flags & PF_W) != 0;

				if(phdr.p_filesz > 0){
					/* Normal segment.
                     Read initial part from disk and zero the rest. */
					head[k].read_bytes = page_offset + phdr.p_filesz;
					head[k].zero_bytes =
							(ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
							- head[k].read_bytes);
				}else{
					/* Entirely zero.
                     Don't read anything from disk. */
					head[k].read_bytes = 0;
					head[k].zero_bytes =
							ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
				}

				/* Setup demand paging for all of the executable pages */
				uint32_t num_pages=(head[k].read_bytes+head[k].zero_bytes)/PGSIZE;
				head[k].end_addr =
						head[k].read_bytes + head[k].zero_bytes + head[k].mem_page;

				for(j = 0; j < num_pages; j ++){
					uint8_t* uaddr = ((uint8_t*)head[k].mem_page) + (PGSIZE*j);
					//printf("user address %p\n", uaddr);
					pagedir_setup_demand_page(t->pagedir, (uint32_t*)uaddr,
								PTE_AVL_EXEC, (uint32_t)uaddr, head[k].writable);
				}
				//printf("Data for this vaddr fpage %u, mempage %p read_bytes %u zero_bytes %u end_addr %p\n", exec_pages[load_i].file_page, exec_pages[load_i].mem_page, exec_pages[load_i].read_bytes, exec_pages[load_i].zero_bytes, exec_pages[load_i].end_addr);
				k ++;
			}else{
				return false;
			}
			break;
		}
	}

	/* Save all of our infor so that we can handle page_faults */
	cur_process->exec_info = calloc (k, sizeof(struct exec_page_info));
	if(cur_process->exec_info == NULL){
		PANIC("KERNEL OUT OF MEMORY!!!!");
	}
	memcpy (cur_process->exec_info, head, k*sizeof(struct exec_page_info));
	cur_process->num_exec_pages = k;

	return true;
}

/* Pushes 4 bytes of data onto the buffer represented by
   esp. (Pushes 4 bytes of data onto the stack) */
static inline void push_4_byte_data(void ** esp, void *data){
	*(uint32_t*)esp -= sizeof(uint32_t);
	**((uint32_t **) esp) = (uint32_t)data;
}

/* Increments the pointer esp by length bytes */
static inline void adjust_stack_ptr(void **esp, size_t length){
	*(char**)esp -= length;
}

/* Sets up the stack arguments so that they are all correctly on the stack
   for main to read.*/
static bool setup_stack_args(void **esp, char *f_name, char *token, char *save_ptr){
	void *strPtrs[MAX_ARG_LENGTH/2];
	int count = 0;
	int i = 0;

	size_t fn_len = strlen(f_name) + 1;

	/* make space for filename */
	adjust_stack_ptr(esp, fn_len);

	/* puts filename on stack */
	strlcpy(*esp, f_name, fn_len);

	strPtrs[0] = *esp;

	/* pushes arguments onto stack */
	for(; token != NULL; token = strtok_r(NULL, " ", &save_ptr)){
		size_t arg_len = strlen(token) + 1;

		/* make room for the argument */
		adjust_stack_ptr(esp, arg_len);

		/* put stuff into the stack */
		strlcpy(*esp, token, arg_len);
		strPtrs[++count] = *esp;

	}

	/* word align */
	adjust_stack_ptr(esp, ((unsigned int)*esp) % 4);

	/* sets argv[argc] = NULL*/
	push_4_byte_data(esp , NULL);

	/* set argv[i] elements */
	for(i = count; i >= 0; i--){
		push_4_byte_data(esp, strPtrs[i]);
	}

	/* set argv char** */
	char *beginning = *esp;
	push_4_byte_data(esp, beginning);

	/* set argc (Count was an index but needs to be the number of args including filename) */
	push_4_byte_data(esp, (void*)(count+1));

	/* push return address */
	push_4_byte_data(esp , NULL);
	return true;
}

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment (const struct Elf32_Phdr *phdr, struct file *file){
	/* p_offset and p_vaddr must have the same page offset. */
	if((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)){
		return false;
	}
	/* p_offset must point within FILE. */
	if(phdr->p_offset > (Elf32_Off) file_length (file)){
		return false;
	}

	/* p_memsz must be at least as big as p_filesz. */
	if(phdr->p_memsz < phdr->p_filesz){
		return false;
	}
	/* The segment must not be empty. */
	if(phdr->p_memsz == 0){
		return false;
	}
	/* The virtual memory region must both start and end within the
     user address space range. */
	if(!is_user_vaddr ((void *) phdr->p_vaddr)){
		return false;
	}
	if(!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz))){
		return false;
	}

	/* The region cannot "wrap around" across the kernel virtual
       address space. */
	if(phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr){
		return false;
	}
	/* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
	if(phdr->p_vaddr < PGSIZE){
		return false;
	}
	/* It's okay. */
	return true;
}

bool process_exec_read_in(uint32_t *faulting_addr){
	struct thread *cur = thread_current();
	struct process *cur_process = cur->process;
	uint32_t vaddr = ((uint32_t)faulting_addr & ~(uint32_t)PGMASK);
	struct exec_page_info *info = NULL;
	uint32_t i;

	for(i = 0; i < cur_process->num_exec_pages; i++){
		//printf("beginning %p end %p vaddr %p\n",  cur_process->exec_info[i].mem_page, cur_process->exec_info[i].end_addr, vaddr);
		if(vaddr >= cur_process->exec_info[i].mem_page &&
		   vaddr < cur_process->exec_info[i].end_addr){
			info = &cur_process->exec_info[i];
			break;
		}
	}
	if(info == NULL){
		/* We have inconsistency, we are loading a page from
		   the process executable but we don't have the info
		   for it that should have been set in process load
		   EXEC bit shouldn't be set unless the corresponding
		   data can be found in the exec_info array*/
		PANIC("INCONSISTENCY IN EXCEPTION.C");
		/*return false;*/
	}

	/* The way this works is it calculates the number of bytes that need to be
	   read in for this particular page. It does this by looking at the number
	   of full pages that the header describes. This is done by taking the
	   total number of read_bytes and dividing by PGSIZE then we use the
	   offset from the page that the faulting address is in to the beginning
	   of the segment that is described by the header of the segment. Then
	   we take this offset and divide by PGSIZE to get our "entry" into the
	   array of pages. calculating zero bytes for this page
	   falls out nicely after that*/
	uint32_t full_pages = info->read_bytes / PGSIZE;
	uint32_t offset_seg_start = ((uint32_t)vaddr) - ((uint32_t)info->mem_page);
	uint32_t entry = (offset_seg_start) / PGSIZE;
	uint32_t zero_bytes;
	if(entry == full_pages){
		zero_bytes = info->zero_bytes % PGSIZE;
	}else if(entry < full_pages){
		zero_bytes = 0;
	}else{
		zero_bytes = PGSIZE;
	}

	/* read_bytes is always going to make up the difference
	   between zero_bytes and PGSIZE */
	uint32_t read_bytes = PGSIZE - zero_bytes;

	/* The file_page (offset into the ELF file) will be the regular page
	   offset for the header plus the offset between the faulting address
	   and the beginning of this segments memory. We are only going to read
	   into memory one page */
	uint32_t file_page = info->file_page + offset_seg_start;


	printf("File page after converting to single %u, read_bytes %u zero_bytes %u\n", file_page, read_bytes, zero_bytes);

	bool success = load_segment(cur_process->executable_file,
						file_page, (uint8_t*)vaddr, read_bytes,
						zero_bytes, info->writable);
	return success;
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

	lock_acquire(&filesys_lock);

	file_seek (file, ofs);

	/* This loop only executed once per call it isn't changed because
	   it doesn't need to be changed*/
	while(read_bytes > 0 || zero_bytes > 0){
		//printf("upage %p\n", upage);
		/* Calculate how to fill this page.
           We will read PAGE_READ_BYTES bytes from FILE
           and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = frame_get_page(PAL_USER);
		if(kpage == NULL){
			lock_release(&filesys_lock);
			printf("couldn't allocate frame %p %u %u %u\n", upage, ofs, read_bytes, zero_bytes);
			return false;
		}

		/* Load this page. */
		if(file_read (file, kpage, page_read_bytes) != (int) page_read_bytes){
			frame_clear_page (kpage);
			lock_release(&filesys_lock);
			printf("file read failed %p %u %u %u\n", upage, ofs, read_bytes, zero_bytes);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. But only if that
		   virtual address doesn't already have something mapped to it,
		   I.E. the present bit is on*/
		if(!pagedir_install_page (upage, kpage, writable)){
			frame_clear_page(kpage);
			lock_release(&filesys_lock);
			printf("couldn't install the page %p %u %u %u\n", upage, ofs, read_bytes, zero_bytes);
			return false;
		}

		/* Make sure that if this page is evicted and is readonly that it will
		   be deleted outright instead of put on swap */
		pagedir_set_medium(thread_current()->pagedir, upage, PTE_AVL_EXEC);

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	lock_release(&filesys_lock);
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack (void **esp){
	uint8_t *kpage;
	bool success = false;

	kpage = frame_get_page(PAL_USER | PAL_ZERO);

	if(kpage != NULL){
		success = pagedir_install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
		if(success){
			*esp = PHYS_BASE;
		}else{
			frame_clear_page (kpage);
		}
	}
	return success;
}

/* Returns a process * or NULL if the parent has already exited
   MUST BE CALLED WITH THE procces_hash_lock HELD!!!*/
static struct process *parent_process_from_child (struct process* our_process){
	return process_lookup(our_process->parent_id);
}

/* Must be called with process_hash_lock HELD
   looks up a process in the process_hash_table without
   acquiring the lock*/
static struct process *process_lookup (pid_t pid){
	struct process key;
	key.pid = pid;
	struct hash_elem *process_result = hash_find(&processes, &key.elem);
	if(process_result != NULL){
		return hash_entry(process_result, struct process, elem);
	}else{
		return NULL;
	}
}


 /* Generic, returns a list_elem corresponding to the
    process, tid/pid and an is_equal function to return
    the list_elem that corresponds to the child with the
    given tid/pid */
static struct list_elem *child_list_entry_gen(
		struct process *process, void *c_tid, is_equal *func){

	lock_acquire(&process->child_pid_tid_lock);
	struct list_elem *h;
	h = list_head(&process->children_list);
	while((h = list_next(h)) != list_end(&process->children_list)){
		if(func(h, c_tid)){
			lock_release(&process->child_pid_tid_lock);
			return h;
		}
	}
	lock_release(&process->child_pid_tid_lock);
	return NULL;
}

/* Returns the child_list_entry for the tid
   or null if the tid isn't one of our children*/
static struct child_list_entry *child_list_entry_tid (tid_t c_tid){
	struct process *cur_process = thread_current()->process;
	struct list_elem *temp = child_list_entry_gen(cur_process, &c_tid, &is_equal_func_tid);
	if( temp != NULL){
		return list_entry( temp, struct child_list_entry,elem);
	}
	return NULL;
}

/* Returns the child_list_entry for the pid
   or null if the pid isn't one of our children */
static struct child_list_entry *child_list_entry_pid(pid_t c_pid){
	struct process *cur_process = thread_current()->process;
	struct list_elem *temp = child_list_entry_gen(cur_process, &c_pid, &is_equal_func_pid);
	if( temp != NULL){
		return list_entry( temp, struct child_list_entry,elem);
	}
	return NULL;
}

/* Takes a tid and returns the corresponding pid
   if it was a child, PID_ERROR otherwise*/
pid_t child_tid_to_pid (tid_t c_tid){
	struct child_list_entry *child_entry = child_list_entry_tid(c_tid);
	if(child_entry != NULL){
		return child_entry->child_pid;
	}
	return PID_ERROR;
}

/* Takes a pid and returns the corresponding tid
   if it was a child, TID_ERROR otherwise*/
tid_t child_pid_to_tid (pid_t c_pid){
	struct child_list_entry *child_entry = child_list_entry_pid(c_pid);
	if(child_entry != NULL){
		return child_entry->child_tid;
	}
	return PID_ERROR;
}

/* Compare for open file hashes */
static bool file_hash_compare (HASH_ELEM *a, HASH_ELEM *b, AUX){
	ASSERT(a != NULL);
	ASSERT(b != NULL);
	return (hash_entry(a, struct fd_hash_entry, elem)->fd <
			hash_entry(b, struct fd_hash_entry, elem)->fd);
}

/* open file hash functions */
static unsigned file_hash_func (HASH_ELEM *e, AUX){
	return hash_bytes(&hash_entry(e, struct fd_hash_entry, elem)->fd, sizeof(int));
}

/* call all destructor for hash_destroy */
static void fd_hash_entry_destroy (struct hash_elem *e, AUX){
	/*File close needs to be called here */
    lock_acquire(&filesys_lock);
	file_close(hash_entry(e, struct fd_hash_entry, elem)->open_file);
	lock_release(&filesys_lock);

	free(hash_entry(e, struct fd_hash_entry, elem));
}

/* comparison of processes in all_process hash */
static bool process_hash_compare  (HASH_ELEM *a, HASH_ELEM *b, AUX){
	ASSERT(a != NULL);
	ASSERT(b != NULL);
	return (hash_entry(a, struct process, elem)->pid <
			hash_entry(b, struct process, elem)->pid);
}

/* process hash function */
static unsigned process_hash_func (HASH_ELEM *a, AUX){
	pid_t pid = hash_entry(a, struct process, elem)->pid;
	return hash_bytes(&pid, (sizeof(pid_t)));
}

#undef HASH_ELEM
#undef AUX

