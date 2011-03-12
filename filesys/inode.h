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
   pointers in our inode. They are defined
   so that we can easily change the composition
   of our inode with minimal work. The total of
   these numbers must be 125 */
#define NUM_REG_BLK 122
#define NUM_IND_BLK 1
#define NUM_DBL_BLK 1
#define NUM_TRP_BLK 1

/* The number of blk pointers in any type of indirect block*/
#define PTR_PER_BLK (BLOCK_SECTOR_SIZE/sizeof(uint32_t))

#define INODE_IS_DIR 1

/* The structure of an indirect block just contains an array
   of block pointers which may point to other indirect blocks
   or directly to data depending on the context*/
struct indirect_block{
	uint32_t ptrs[PTR_PER_BLK];
};

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long.
   For conciseness in space the i suffix/prefix signifies an indirect block
   a d signifies a double indirect block and a t signifies a triply
   indirect block */
struct disk_inode{
	/* File size in bytes. */
	off_t file_length;

	/* Flags */
	uint32_t flags;

	/* Magic number. */
	uint32_t magic;

	/* Our design allows for changing the constants and experimenting
	   with the benifits of different amount of indirection*/

	/* The first X sectors of the file can be accessed directly*/
	uint32_t block_ptrs[NUM_REG_BLK];

	/* The indirect pointers in the inode*/
	uint32_t i_ptrs[NUM_IND_BLK];

	/* The double indirect pointers inode*/
	uint32_t d_ptrs[NUM_DBL_BLK];

	/* The trp indirect pointers*/
	uint32_t t_ptrs[NUM_TRP_BLK];
};

/* In-memory inode. Used to access and control the flow of data
   to and from disk. */
struct inode{
	 /* Sector number of disk location. */
	block_sector_t sector;

	 /* Number of openers. */
	int open_cnt;

	/* True if deleted, false otherwise. */
	bool removed;

	 /* 0: writes ok, >0: deny writes. */
	int deny_write_cnt;

	/* The current length of the file */
	off_t cur_length;

	/* Needed to extend the file */
	struct lock writer_lock;

	/* Needed to change or write cur_length*/
	struct lock reader_lock;

	/* A lock for open count */
	struct lock meta_data_lock;

	/* Element in inode list. */
	struct list_elem elem;
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
bool inode_remove_dir(struct inode *inode);

#endif /* filesys/inode.h */
