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
	pid_t pid;
	struct list_elem elem;

	//only this process can access these
	// fields so no locking is needed
	struct hash open_files;
	int fdcount;
};

struct fdHashEntry {
	int fd; // hash key
	struct file *open_file;
	struct hash_elem elem;
};


tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
