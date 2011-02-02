#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
#include <list.h>
#include <hash.h>
#include "filesys/file.h"
#include "filesys/filesys.h"

// define a limit on the argument length
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

	/* The Id of the process that created it*/
	//pid_t parent_id;

	struct list children_list;

	/*The thread which this process is running on*/
	struct thread *owning_thread;

	// only this process can access open_files
	// so no locks are included

	/*A hash of open file descriptors */
	struct hash open_files;

	/* The current count of file descriptors*/
	int fd_count;

	/* The exit code of this process.
	 * MUST BE SET BEFORE thread_exit IS CALLED*/
	int exit_code;

	/*Program name malloced*/
	char *program_name;
	struct file *executable_file;

	/* The particular pid this thread is waiting on
	 * If this pid exits it will increment the waiting
	 * semaphore. Only used for process wait/exit*/
	pid_t child_waiting_on_pid;

	/*A semaphore that allows us to wait for child pid to exit
	 * only used in wait/exit*/
	struct semaphore waiting_semaphore;

	/* Whether the child pid was successfully created or not
	 * only used for only used in processExecute/start_process*/
	bool child_pid_created;

	/* The condition of whether a process created with exec finished
	   loading
	   only used for only used in processExecute/start_process*/
	struct condition pid_cond;

	/* The child process can't complete its creation until
	 * it acquires this lock given that it exists I.E. that the parent
	 * exists still. USED wherever any of the last 4 objects are used*/
	struct lock child_pid_tid_lock;

};

struct child_list_entry{
	pid_t child_pid;
	tid_t child_tid;
	int exit_code;
	bool has_exited;
	struct list_elem elem;
};

struct fd_hash_entry {
	/* hash key and File Descriptor*/
	int fd;

	/* Open file associated with this FD */
	struct file *open_file;

	/* hash elem for this fd entry*/
	struct hash_elem elem;
};

void process_init(void);

//methods for dealing with pid's and tid's
tid_t child_pid_to_tid (pid_t c_pid);
pid_t child_tid_to_pid (tid_t c_tid);

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

bool initialize_process (struct process *p, struct thread *our_thread);

#endif /* userprog/process.h */
