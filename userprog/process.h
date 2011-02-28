#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
#include <list.h>
#include <hash.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include <stdint.h>
#include <stdbool.h>

/* define a limit on the argument length */
#define MAX_ARG_LENGTH 256

typedef int32_t pid_t;
#define PID_ERROR ((pid_t)-1)          /* Error value for tid_t. */

/* You can not acquire this lock and acquire memory
   using frame_get_page (user memory) because frame_get_page
   may try to evict a page to disk and also try to acquire
   this lock */
struct lock filesys_lock;

typedef uint32_t mapid_t;

struct process {
	/* This processes ID. Also hash key */
	pid_t pid;
	pid_t parent_id;

	/* The element in the processes hash*/
	struct hash_elem elem;

	struct list children_list;

	/*The thread which this process is running on*/
	struct thread *owning_thread;

	/* only this process can access open_files
	 so no locks are included */

	/*A hash of open file descriptors */
	struct hash open_files;

	/* The current count of file descriptors*/
	int fd_count;

	/* The exit code of this process.
	   MUST BE SET BEFORE thread_exit IS CALLED*/
	int exit_code;

	/* Program name malloced */
	char *program_name;
	struct file *executable_file;


	/* The particular pid this thread is waiting on
	   If this pid exits it will increment the waiting
	   semaphore. Only used for process wait/exit*/
	pid_t child_waiting_on_pid;

	/* A semaphore that allows us to wait for child pid to exit
	   only used in wait/exit*/
	struct semaphore waiting_semaphore;

	/* Whether the child pid was successfully created or not
	   only used for only used in processExecute/start_process*/
	bool child_pid_created;

	/* The condition of whether a process created with exec finished
	   loading
	   only used for only used in processExecute/start_process*/
	struct condition pid_cond;

	/* The child process can't complete its creation until
	   it acquires this lock given that it exists I.E. that the parent
	   exists still. USED wherever any of the last 4 objects are used*/
	struct lock child_pid_tid_lock;


	/* Swap hash. This structure allows us to put pages at virtual
	   addresses onto the swap device and retrieve them. The swap
	   table is per process to allow us to use the virtual address
	   for the process as an index into the table. .*/
	struct hash swap_table;

	/* Lock for this processes swap table */
	struct lock swap_table_lock;


	/* The exec_info is a pointer to an array of ELF program
	   header information this information is used to determine
	   where on disk the particular missing page is located.
	   the information that it stores is for the entire header,
	   each header is an entire segment so the size of this
	   struct will be less than 5 * sizeof(exec_page_info).
	   The only loadable segments right now are the code
	   segment and the data segment with the global and static
	   data.*/
	struct exec_page_info *exec_info;
	uint32_t num_exec_pages;

	/* A hash table that stores the necessary information to
	   map a file into the address space and to lazily load
	   the information from the file */
	struct hash mmap_table;
	mapid_t mapid_counter;

	/* As with the swap table, the mmap table can also be
	   accessed from multiple threads via eviction so it too
	   must be locked down so reading and writing to the table
	   while the owning process creates or destroyes mmaps can
	   be synchronized*/
	struct lock mmap_table_lock;

};

/* An entry into the list of children that a particular process
   has. This includes all the information needed by the parent
   process to determine the run status of a child and its exit
   code */
struct child_list_entry{
	pid_t child_pid;      /*pid of a child process*/
	tid_t child_tid;	  /*tid of a child process*/
	int exit_code;		  /*The exit code of this process*/
	struct list_elem elem;/*list elem for child process list*/
};

/* An entry into the open file hash of a process
   It allows us to accurately and quickly tell if the process
   currently owns a fd. And get its underlying file*/
struct fd_hash_entry{
	int fd;				    /* hash key and File Descriptor*/
	struct file *open_file; /* Open file associated with this FD */
	struct hash_elem elem;  /* hash elem for this fd entry*/
	bool is_closed;			/* bool to prevent a file from being closed
							   if mmaped, but prevent it from being
							   accessed by other syscalls*/
	uint32_t num_mmaps;		/* number of referencing maps if > 0
							   this fd must be saved.*/
};

/* This is the struct that describes the necessary ELF
   program header information that is needed to read
   in the executable on a page fault. It does this by
   taking the faulting addresses most significant 20
   bits and seeing if it is in this particular entries
   bounds (mem_page and end_addr). Then it takes this
   offset from the faulting address and mem_page and
   adds it to the file_offset of the elf file and then
   reads in the appropriate amounts of data by calculating
   the appropriate read_bytes and zero_bytes.
   NOTE: the segment is not constrained to be only one page */
struct exec_page_info{
	uint32_t mem_page;		/* The starting address in virtual memory
							   of this segment*/
	uint32_t end_addr;      /* The address one byte past the end of this
							   headers segment*/
	uint32_t file_offset;	/* The offset into the executable file for
							   this particular segment*/
	uint32_t read_bytes;    /* The number of bytes to read from this
							   segment*/
	uint32_t zero_bytes;    /* The number of bytes that are zero at the
							   end of this segment. MAY BE MORE THAN ONE
							   page worth of zero bytes*/
	bool writable;   		/* Whether this segment is read/write or read only*/
};

struct mmap_hash_entry{
	mapid_t mmap_id;     	/* Key into the hash table*/
	uint32_t begin_addr;	/* start address of this mmapping*/
	uint32_t end_addr;		/* While we can calculate this from the filesize
							   accessing the disk in any way is too slow so just
							   keep it stored in memory*/
	int fd;					/* FD for this mapping*/
	uint32_t num_pages;		/* Number of pages so I don't have to think*/
	struct hash_elem elem;  /* hash elem*/
};

void process_init(void);

/* methods for dealing with pid's and tid's */
tid_t child_pid_to_tid (pid_t c_pid);
pid_t child_tid_to_pid (tid_t c_tid);

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

bool initialize_process (struct process *p, struct thread *our_thread);
bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
        uint32_t read_bytes, uint32_t zero_bytes, bool writable);

bool process_lock(pid_t pid, struct lock *lock_to_grab);

/* Called by exception.c */
bool process_exec_read_in(void *faulting_addr);
#endif /* userprog/process.h */
