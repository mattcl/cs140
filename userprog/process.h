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

typedef uint32_t pid_t;

struct process {
	pid_t pid; 			   /* This processes ID. Also hash key */
	struct hash_elem elem; /* The element in the processes hash*/

	pid_t parent_id;       /* The Id of the process that created it*/

	struct thread *owning_thread;

	// only this process can access these
	// fields so no locking is needed
	struct hash open_files; /*A hash of open file descriptors */
	int fd_count;			/* The current count of file descriptors*/

	int exit_code;

	//Accessed with interrupts turned off
	// These two are used when this process
	// waits on a living child process
	pid_t child_waiting_on;
	struct semaphore waiting_semaphore;

	//These two are accessed whenever a child
	// process finishes
	struct hash children_exit_codes;
	struct lock children_exit_codes_lock;
};

struct fd_hash_entry {
	int fd; 				  /* hash key and File Descriptor*/
	struct file *open_file;   /* Open file associated with this FD */
	struct hash_elem elem;    /* hash elem for this fd entry*/
};

struct process_return_hash_entry{
	int exit_code;
	pid_t child_pid;
	tid_t child_tid;
	struct hash_elem elem;
};

void process_init(void);

bool pid_belongs_to_child(pid_t child);
tid_t tid_for_pid(pid_t pid);

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

bool initialize_process (struct process *p, struct thread *our_thread);

#endif /* userprog/process.h */
