#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/buffer-cache.h"

/* debug*/
#include "threads/thread.h"
#include "userprog/process.h"
/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init (bool format){
	fs_device = block_get_role (BLOCK_FILESYS);
	if(fs_device == NULL){
		PANIC ("No file system device found, can't initialize file system.");
	}

	inode_init ();
	free_map_init ();
	dir_init();

	if(format){
		do_format ();
	}

	free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done (void){
	bcache_flush();
	free_map_close ();
	printf("Filesys done\n");
}

static inline bool file_is_self(char *file_name){
	return file_name != NULL && ((strlen(file_name) == 2 && !strcmp(file_name, '..')) ||
			(strlen(file_name) == 1 && *file_name =='.'));
}

static inline bool file_is_root(char *file_name, struct dir *dir){
	return (dir != NULL && dir->sector == ROOT_DIR_SECTOR && file_name != NULL
			&& (file_is_self(file_name) || *file_name == '/'));
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create (const char *path, off_t initial_size){
	block_sector_t inode_sector = 0;
	const char *file_name;
	struct dir *dir = dir_open_path (path, &file_name);

	/* You don't create the root directory.. ever */
	if(file_is_root(file_name, dir)){
		dir_close(dir);
		return false;
	}

	/* debug variables */
	bool s1 = false;
	bool s2 = false;
	bool s3 = false;

	printf("Creating filename %s at path %s \n", file_name, path);
	bool success = (dir != NULL
			&& (s1 = free_map_allocate (1, &inode_sector))
			&& (s2 = inode_create (inode_sector, initial_size, false))
			&& (s3 = dir_add (dir, file_name, inode_sector)));


	if(!success){
		printf("dir null %u, freemap alloc %u, inode create %u, dir add %u\n", dir == NULL, s1, s2, s3);
	}

	if(!success && inode_sector != 0){
		free_map_release (inode_sector, 1);
	}

	dir_close (dir);

	return success;
}

/* Creates an empty directory! At the path name handed in*/
bool filesys_create_dir(const char *path){
	block_sector_t inode_sector = 0;
	const char *file_name ;
	struct dir *dir = dir_open_path (path, &file_name);
	printf("creating a directory %s at path %s\n", file_name, path);

	/* special consideration for creating /, we don't allow it sorry! :)*/
	if(file_is_root(file_name, dir)){
		dir_close(dir);
		return false;
	}

	/* debug variables */
	bool s1 = false;
	bool s2 = false;
	bool s3 = false;


	bool success = (dir != NULL
			&& (s1 = free_map_allocate (1, &inode_sector))
			&& (s2 = dir_create (inode_sector, dir_get_inode(dir)->sector))
			&& (s3 = dir_add (dir, file_name, inode_sector)));

	if(!success){
		printf("dir null %u, freemap alloc %u, inode create %u, dir add %u\n", dir == NULL, s1, s2, s3);
	}


	if(!success && inode_sector != 0){
		free_map_release (inode_sector, 1);
	}

	dir_close (dir);
	return success;
}

/* Opens the file with the given path.
   Returns the new file if successful or a null pointer
   otherwise. Fails if no file named NAME exists,
   or if an internal memory allocation fails, or the path
   leading up to the leaf was invalid. */
struct file * filesys_open (const char *path){
	const char *file_name = NULL;
	struct dir *dir = dir_open_path (path, &file_name);

	/* special consideration for opening / because
	   / is not actually in the directory. */
	if(file_is_root(file_name, dir)){
		dir_close(dir);
		return file_open(inode_open(ROOT_DIR_SECTOR));
	}

	struct inode *inode = NULL;
	printf("filesys open dir_path %s file_name is %s\n",path, file_name);
	printf("dir null %u, dir sector %u vs root sector %u\n",dir == NULL, dir->sector, ROOT_DIR_SECTOR);
	printf("process pid %u\n", thread_current()->process->pid);


	if(dir != NULL){
		dir_lookup (dir, file_name, &inode);
	}

	dir_close (dir);

	return file_open (inode);
}

/* Deletes the file named by path.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists, or the path
   leading up to the leaf of the path is an invalid path
   or if an internal memory allocation fails. */
bool filesys_remove (const char *path){
	const char *file_name = NULL;
	struct dir *dir = dir_open_path (path, &file_name);

	/* special consideration for removing / or . or .. we don't
	   allow deleting them sorry! :)*/
	if(file_is_self(file_name) || file_is_root(file_name, dir)){
		dir_close(dir);
		return false;
	}

	bool success = (dir != NULL) && dir_remove (dir, file_name);
	dir_close (dir);

	return success;
}

/* Formats the file system. */
static void do_format (void){
	printf ("Formatting file system...\n");
	free_map_create ();
	if(!dir_create (ROOT_DIR_SECTOR, ROOT_DIR_SECTOR)){
		PANIC ("root directory creation failed");
	}
	free_map_close ();
}
