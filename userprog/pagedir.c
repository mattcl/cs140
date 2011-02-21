
#include "userprog/pagedir.h"
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "threads/init.h"
#include "threads/pte.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "vm/frame.h"

/* masks to isolate bit corresponding to constants in pagedir.h */
#define PTE_SWAP 0x00000200
#define PTE_EXECUTABLE 0x00000400
#define PTE_MMAP 0x00000800

static uint32_t *active_pd (void);
static void invalidate_pagedir (uint32_t *);

/* Creates a new page directory that has mappings for kernel
   virtual addresses, but none for user virtual addresses.
   Returns the new page directory, or a null pointer if memory
   allocation fails. */
uint32_t *pagedir_create (void){
	uint32_t *pd = palloc_get_page (0);
	if(pd != NULL){
		memcpy (pd, init_page_dir, PGSIZE);
	}
	return pd;
}

/* Destroys page directory PD, freeing all the pages it
   references. */
void pagedir_destroy (uint32_t *pd){
	uint32_t *pde;

	if(pd == NULL){
		return;
	}

	ASSERT (pd != init_page_dir);
	for(pde = pd; pde < pd + pd_no (PHYS_BASE); pde++){
		if(*pde & PTE_P){
			uint32_t *pt = pde_get_pt (*pde);
			uint32_t *pte;

			for(pte = pt; pte < pt + PGSIZE / sizeof *pte; pte++){
				if(*pte & PTE_P){
					frame_clear_page(pte_get_page (*pte));
				}
			}
			palloc_free_page (pt);
		}
	}
	palloc_free_page (pd);
}

/* Returns the address of the page table entry for virtual
   address VADDR in page directory PD.
   If PD does not have a page table for VADDR, behavior depends
   on CREATE.  If CREATE is true, then a new page table is
   created and a pointer into it is returned.  Otherwise, a null
   pointer is returned. */
static uint32_t *lookup_page (uint32_t *pd, const void *vaddr, bool create){
	uint32_t *pt, *pde;

	ASSERT (pd != NULL);

	/* Shouldn't create new kernel virtual mappings. */
	ASSERT (!create || is_user_vaddr (vaddr));

	/* Check for a page table for VADDR.
       If one is missing, create one if requested. */
	pde = pd + pd_no (vaddr);
	if(*pde == 0){
		if(create){
			pt = palloc_get_page (PAL_ZERO);
			if(pt == NULL){
				return NULL;
			}

			*pde = pde_create (pt);
		}else{
			return NULL;
		}
	}

	/* Return the page table entry. */
	pt = pde_get_pt (*pde);
	return &pt[pt_no (vaddr)];
}

/* Adds a mapping in page directory PD from user virtual page
   uaddr to the physical frame identified by kernel virtual
   address kaddr.
   uaddr must not already be mapped.
   kaddr should probably be a page obtained from the user pool
   with palloc_get_page().
   If WRITABLE is true, the new page is read/write;
   otherwise it is read-only.
   Returns true if successful, false if memory allocation
   failed. */
bool pagedir_set_page (uint32_t *pd, void *uaddr, void *kaddr, bool writable){
	uint32_t *pte;

	ASSERT (pg_ofs (uaddr) == 0);
	ASSERT (pg_ofs (kaddr) == 0);
	ASSERT (is_user_vaddr (uaddr));
	ASSERT (vtop (kaddr) >> PTSHIFT < init_ram_pages);
	ASSERT (pd != init_page_dir);

	pte = lookup_page (pd, uaddr, true);

	if(pte != NULL){
		ASSERT ((*pte & PTE_P) == 0);
		*pte = pte_create_user (kaddr, writable);
		return true;
	}else{
		return false;
	}
}

/* Looks up the physical address that corresponds to user virtual
   address UADDR in PD.  Returns the kernel virtual address
   corresponding to that physical address, or a null pointer if
   UADDR is unmapped. */
void *pagedir_get_page (uint32_t *pd, const void *uaddr){
	uint32_t *pte;

	ASSERT (is_user_vaddr (uaddr));

	pte = lookup_page (pd, uaddr, false);
	if(pte != NULL && (*pte & PTE_P) != 0){
		return pte_get_page (*pte) + pg_ofs (uaddr);
	}else{
		return NULL;
	}
}

/* Marks user virtual page uaddr "not present" in page
   directory PD.  Later accesses to the page will fault.  Other
   bits in the page table entry are preserved.
   uaddr need not be mapped. */
void pagedir_clear_page (uint32_t *pd, void *uaddr){
	uint32_t *pte;

	ASSERT (pg_ofs (uaddr) == 0);
	ASSERT (is_user_vaddr (uaddr));

	pte = lookup_page (pd, uaddr, false);
	if(pte != NULL && (*pte & PTE_P) != 0){
		*pte &= ~PTE_P;
		invalidate_pagedir (pd);
	}
}

/* Returns true if the PTE for virtual page uaddr in PD is dirty,
   that is, if the page has been modified since the PTE was
   installed.
   Returns false if PD contains no PTE for uaddr. */
bool pagedir_is_dirty (uint32_t *pd, const void *uaddr){
	uint32_t *pte = lookup_page (pd, uaddr, false);
	return pte != NULL && (*pte & PTE_D) != 0;
}

/* Set the dirty bit to DIRTY in the PTE for virtual page uaddr
   in PD. */
void pagedir_set_dirty (uint32_t *pd, const void *uaddr, bool dirty){
	uint32_t *pte = lookup_page (pd, uaddr, false);
	if(pte != NULL){
		if(dirty){
			*pte |= PTE_D;
		}else{
			*pte &= ~(uint32_t) PTE_D;
			invalidate_pagedir (pd);
		}
	}
}

/* Returns true if the PTE for virtual page uaddr in PD has been
   accessed recently, that is, between the time the PTE was
   installed and the last time it was cleared.  Returns false if
   PD contains no PTE for uaddr. */
bool pagedir_is_accessed (uint32_t *pd, const void *uaddr){
	uint32_t *pte = lookup_page (pd, uaddr, false);
	return pte != NULL && (*pte & PTE_A) != 0;
}

/* Sets the accessed bit to ACCESSED in the PTE for virtual page
   uaddr in PD. */
void pagedir_set_accessed (uint32_t *pd, const void *uaddr, bool accessed){
	uint32_t *pte = lookup_page (pd, uaddr, false);
	if(pte != NULL){
		if(accessed){
			*pte |= PTE_A;
		}else{
			*pte &= ~(uint32_t) PTE_A;
			invalidate_pagedir (pd);
		}
	}
}

/* Loads page directory PD into the CPU's page directory base
   register. */
void pagedir_activate (uint32_t *pd){
	if(pd == NULL){
		pd = init_page_dir;
	}

	/* Store the physical address of the page directory into CR3
       aka PDBR (page directory base register).  This activates our
       new page tables immediately.  See [IA32-v2a] "MOV--Move
       to/from Control Registers" and [IA32-v3a] 3.7.5 "Base
       Address of the Page Directory". */
	asm volatile ("movl %0, %%cr3" : : "r" (vtop (pd)) : "memory");
}

/* Returns the currently active page directory. */
static uint32_t *active_pd (void){
	/* Copy CR3, the page directory base register (PDBR), into
       `pd'.
       See [IA32-v2a] "MOV--Move to/from Control Registers" and
       [IA32-v3a] 3.7.5 "Base Address of the Page Directory". */
	uintptr_t pd;
	asm volatile ("movl %%cr3, %0" : "=r" (pd));
	return ptov (pd);
}

/* Seom page table changes can cause the CPU's translation
   lookaside buffer (TLB) to become out-of-sync with the page
   table.  When this happens, we have to "invalidate" the TLB by
   re-activating it.

   This function invalidates the TLB if PD is the active page
   directory.  (If PD is not active then its entries are not in
   the TLB, so there is no need to invalidate anything.) */
static void invalidate_pagedir (uint32_t *pd){
	if(active_pd () == pd){
		/* Re-activating PD clears the TLB.  See [IA32-v3a] 3.12
           "Translation Lookaside Buffers (TLBs)". */
		pagedir_activate (pd);
	}
}

/* Currently these are notes for how we will use the page table
   to contain the information we need for the supplementary page
   table.

   Memory
   ------
   We do not have to handle this case since we will not get a page fault.
   Because the OS zeros PTE_AVL we can assert that these are not zero 
   whenever we do anything with this area.

   31                                 12 11                  PTE_P 
   +----------------------------------+---+---------------------+
   |         Physical Address         |000|      Flags     | 1  |
   +----------------------------------+---+---------------------+

   Swap
   ___
   We use the 20 bits alloted to store a virtual address.  The 
   virtual adress will then be a key into a swap table-a hash that 
   is stored per process.  The values in that hash will be a 32 bit
   integer that says what swap slot the page is stored in.

   31                                 12 11                  PTE_P 
   +----------------------------------+---+---------------------+
   |         Virtual Address          |001|      Flags     | 0  |
   +----------------------------------+---+---------------------+

   Disk Executable
   --------------
   We use the 20 bits to store the offset into the executable that 
   the process is running.  Because each process has a pointer to
   its executable we can ask the current process for it's executable.
   Note that because we know we will be reading page size chunks out
   of the file we only need 20 bits.

   31                                 12 11                  PTE_P 
   +----------------------------------+---+---------------------+
   |         Virtual Address          |010|      Flags     | 0  |
   +----------------------------------+---+---------------------+

   Disk MMap
   ---------
   We use the 20 bits to store the id of the mmapped
   file that page faulted.  We use that as a key into a hash
   that the current process holds, and combine the starting virtual
   address of that file to get an offset into the mmaped file  

   31                                 12 11                  PTE_P 
   +----------------------------------+---+---------------------+
   |         mmapid_t                 |100|      Flags     | 0  |
   +----------------------------------+---+---------------------+
*/

/* Sets the medium as mentioned above. */
void pagedir_set_medium (uint32_t *pd, void *uaddr, medium_t medium){
	/* get the page table out of the page directory */
	uint32_t *pte = lookup_page (pd, uaddr, false);


	if(pte != NULL){
	  /* These functions asssume these 3 bits are zeroed */
	  ASSERT(*pte && PTE_AVL == MEMORY);		
	  
		if(medium == SWAP){
			*pte |= PTE_SWAP;
		}else if(medium == DISK_EXCECUTABLE){
			*pte |= PTE_EXECUTABLE;
		}else if(medium == DISK_MMAP){
		        *pte |= PTE_MMAP;
		}else{
		  PANIC("pagedir_set_medium called with unexpected medium");
		}
	}

	PANIC("pagedir_set_medium called on a page table entry that is not initialized");
}

medium_t pagedir_get_medium (uint32_t *pd, void *uaddr){
	/*get the page table out of the page directory*/
	uint32_t *pte = lookup_page (pd, uaddr, false);
	

	if(pte != NULL){
	    if((*pte & (uint32_t)PTE_AVL) == SWAP){
	        return SWAP;
	    }else if(*pte & (uint32_t)PTE_AVL == DISK_EXCECUTABLE){
		return DISK_EXCECUTABLE;
	    }else if(*pte & (uint32_t)PTE_AVL == DISK_MMAP){
	        return DISK_MMAP;
	    }else{
	      PANIC("pagedir_get_medium called with unexpected medium");
	    }
	}

	PANIC("pagedir_get_medium called on a page table entry that is not initialized");
}

void pagedir_set_aux (uint32_t *pd, void *uaddr, uint32_t location){
	uint32_t *pte = lookup_page(pd, uaddr, false);

	if(pte != NULL){
		*pte |= (location);
	}
	PANIC("pagedir_set_aux");
}

uint32_t pagedir_get_aux (uint32_t *pd, void *uaddr){
	uint32_t *pte = lookup_page(pd, uaddr, false);

	if(pte == NULL) return 0;

	return *pte & PTE_ADDR;
}

/* Adds a mapping from user virtual address uaddr to kernel
   virtual address kaddr to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   uaddr must not already be mapped.
   kaddr should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if uaddr is already mapped or
   if memory allocation fails. */
bool install_page (void *uaddr, void *kaddr, bool writable){
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
       address, then map our page there. */
	return (pagedir_get_page (t->pagedir, uaddr) == NULL
			&& pagedir_set_page (t->pagedir, uaddr, kaddr, writable));
}

