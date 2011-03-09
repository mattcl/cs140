#ifndef FILESYS_DIRECTORY_H
#define FILESYS_DIRECTORY_H

#include <stdbool.h>
#include <stddef.h>
#include <hash.h>
#include "devices/block.h"
#include "threads/synch.h"
#include "off_t.h"

/* Maximum length of a file name component.
   This is the traditional UNIX maximum length.
   After directories are implemented, this maximum length may be
   retained, but much longer full path names must be allowed. */
#define NAME_MAX 14

struct inode;

/* A directory. */
struct dir{
	struct inode *inode;         /* Backing store. */
	block_sector_t sector;		 /* Sector of this dir used as hash key*/
	struct hash_elem e;			 /* Elem in the dirs hash*/
	struct lock dir_lock;		 /* Access to the directory only
								    handled by one thread at a time*/
	int open_cnt;                       /* Number of openers. */
};

/* A single directory entry. */
struct dir_entry{
	block_sector_t inode_sector;        /* Sector number of header. */
	char name[NAME_MAX + 1];            /* Null terminated file name. */
	bool in_use;                        /* In use or free? */
};


void dir_init(void);

/* Opening and closing directories. */
bool dir_create (block_sector_t sector, block_sector_t parent);
struct dir *dir_open_path(const char *path, char **file_name);
struct dir *dir_open (struct inode *inode);
struct dir *dir_open_root (void);
struct dir *dir_reopen (struct dir *dir);
void dir_close (struct dir *dir);
struct inode *dir_get_inode (struct dir * dir);

/* Reading and writing. */
bool dir_lookup (const struct dir *dir, const char *name, struct inode **);
bool dir_add (struct dir *dir, const char *name, block_sector_t);
bool dir_remove (struct dir *dir, const char *name);
bool dir_readdir (struct dir *dir, char *name, off_t *off);
uint32_t dir_file_count(struct dir *dir);

#endif /* filesys/directory.h */
