#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/block.h"
#include <stdint.h>
#include "threads/synch.h"
#include <list.h>

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* The different break down of block
   pointers in our inode */
#define NUM_REG_BLK 122
#define NUM_IND_BLK 1
#define NUM_DBL_BLK 1
#define NUM_TRP_BLK 1
#define PTR_PER_BLK (BLOCK_SECTOR_SIZE/sizeof(uint32_t))

#define INODE_IS_DIR 1


struct indirect_block{
	uint32_t ptrs[PTR_PER_BLK];
};

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long.
   For conciseness in space the i suffix/prefix signifies an indirect block
   a d signifies a double indirect block and a t signifies a triply
   indirect block */
struct disk_inode{
	off_t file_length;               	/* File size in bytes. */
	uint32_t flags;						/* Flags */
	uint32_t magic;                     /* Magic number. */

	/* Our design allows for changing the constants and experimenting
	   with the benifits of different amount of indirection*/
	uint32_t block_ptrs[NUM_REG_BLK];   /* The first X sectors of the file
	 	 	 	 	 	 	 	 	 	   can be accessed directly*/
	uint32_t i_ptrs[NUM_IND_BLK];		/* The indirect pointers in the inode*/
	uint32_t d_ptrs[NUM_DBL_BLK];		/* The double indirect pointers inode*/
	uint32_t t_ptrs[NUM_TRP_BLK];		/* The trp indirect pointers*/
};

/* In-memory inode. */
struct inode{
	block_sector_t sector;              /* Sector number of disk location. */
	int open_cnt;                       /* Number of openers. */
	bool removed;                       /* True if deleted, false otherwise. */
	int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
	off_t cur_length;					/* The current length of the file */
	struct lock writer_lock;			/* Needed to extend the file */
	struct lock reader_lock;			/* Needed to change or write cur_length*/
	struct lock meta_data_lock;			/* A lock for open count */
	struct list_elem elem;              /* Element in inode list. */
};


void inode_init (void);
bool inode_create (block_sector_t sector, off_t size, bool is_dir);
struct inode *inode_open (block_sector_t sector);
struct inode *inode_reopen (struct inode *inode);
block_sector_t inode_get_inumber (const struct inode *inode);
void inode_close (struct inode *inode);
void inode_remove (struct inode *inode);
off_t inode_read_at (struct inode *inode, void *buf, off_t size, off_t offset);
off_t inode_write_at (struct inode *inode, const void *buf, off_t size, off_t offset);
void inode_deny_write (struct inode *inode);
void inode_allow_write (struct inode *inode);
off_t inode_length (struct inode *inode);
bool inode_is_dir(struct inode *inode);

bool inode_remove_unopened(struct inode *inode);

#endif /* filesys/inode.h */
