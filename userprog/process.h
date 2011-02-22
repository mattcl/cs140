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

struct lock filesys_lock;

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
	   for the process as an index into the table. Only the code in
	   swap.c will put objects into this table. And we will only
	   remove things when we read the page back into memory from
	   swap.*/
	struct hash swap_table;


	/* This is data that is stored to easily find the data for the
	   executable when we page fault on the executable. I.E. we need
	   to read the executable from disk. To do so we need the data that
	   is stored in the elf file for this particular virtual address. We
	   save this data in an array that is the number of pages of the
	   executable. This is an array to save space and avoid the overhead
	   of a data structure such as an hash table that maps from virtual
	   addresses to the data for the executable's page. Each entry is
	   21 bytes. So an executable with a data segment that is 2^20 bytes
	   large will only incur an overhead of 4320 bytes to find the different
	   segments of the executable. Similaraly if the data segment is all 4 GB
	   large then we only need 21 MB to find all of the different segments of
	   the executable*/
	struct exec_page_info *exec_info;
	uint32_t num_exec_pages;
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
};

/* Implicitly calculate the number of zero bytes by subtracting
   it from PGSIZE. this structure is 17 bytes large*/
struct exec_page_info{
	uint32_t mem_page;
	uint32_t end_addr;
	uint32_t file_page;
	uint32_t read_bytes;
	uint32_t zero_bytes;
	bool writable;
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

/* Called by exception.c */
bool process_exec_read_in(uint32_t *faulting_addr);

#endif /* userprog/process.h */
