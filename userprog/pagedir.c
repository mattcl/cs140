
#include "userprog/pagedir.h"
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "threads/init.h"
#include "threads/pte.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "vm/frame.h"

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
				} else {
					/* if its in the swap we need to "free"
				     it's swap memory */
					/* Swap slots are recovered when we free
					   the swap hash table. Using the hash
					   do all*/
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

/* Marks user virtual page uaddr- "not present" in page
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

/* Returns whether the present bit is set, and returns true if the
   bit is set or false if the PTE has yet to be allocated or if the
   page is missing */
bool pagedir_is_present (uint32_t *pd, const void *uaddr){
	uint32_t *pte = lookup_page (pd, uaddr, false);
	return pte != NULL && (*pte & PTE_P) != 0;
}

bool pagedir_is_writable (uint32_t *pd, const void *uaddr){
	uint32_t *pte = lookup_page (pd, uaddr, false);
	return pte != NULL && (*pte & PTE_W) != 0;
}

/* Returns true if the uaddr has any mapping, this doesn't mean
   that it has to be in memory, it can also be on swap/disk*/
bool pagedir_is_mapped (uint32_t *pd, const void *uaddr){
	uint32_t *pte = lookup_page(pd, uaddr, false);
	return 	pte != NULL && ((*pte & PTE_P) != 0 ||
			(*pte & (uint32_t)PTE_AVL) != PTE_AVL_ERROR);
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
uint32_t *active_pd (void){
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

/* Sets the medium that this uaddr originated from, this will be used
   by eviction and then read by the page fault handler. */
void pagedir_set_medium (uint32_t *pd, void *uaddr, medium_t medium){
	/* get the page table out of the page directory */
	uint32_t *pte = lookup_page (pd, uaddr, false);

	if(pte != NULL){
		/* This function makes sure that these 3 bits are zeroed
		   before manipulating anything */
		//ASSERT(*pte && PTE_AVL == PTE_AVL_MEMORY);
		*pte &= ~(uint32_t)PTE_AVL;
		if(medium == PTE_AVL_SWAP || medium == PTE_AVL_EXEC ||
				medium == PTE_AVL_MMAP ||medium == PTE_AVL_STACK ||
				medium == PTE_AVL_ERROR){
			*pte |= medium;
		}else{
			PANIC("pagedir_set_medium called with unexpected medium");
		}
	}else{
		PANIC("pagedir_set_medium called on a page table entry that is not initialized");
	}
	//PANIC("medium set to %u. %u set for pte %p", (*pte & (uint32_t)PTE_AVL), medium, uaddr);
}

/* Gets the type of medium that this uaddr came from
   this is used by the page fault handler to determine
   where to look for data when it has been evicted, or
   lazily loaded*/
medium_t pagedir_get_medium (uint32_t *pd, const void *uaddr){
	/*get the page table entry out of the page directory*/
	uint32_t *pte = lookup_page (pd, uaddr, false);

	if(pte != NULL){
		medium_t medium = (*pte & (uint32_t)PTE_AVL);
		if(medium == PTE_AVL_SWAP || medium == PTE_AVL_EXEC||
				medium == PTE_AVL_MMAP || medium == PTE_AVL_STACK){
			return medium;
		}
	}
	/* It is not currently mapped or is an invalid medium so we
	   can return error*/
	return PTE_AVL_ERROR;
}

void pagedir_set_aux (uint32_t *pd, void *uaddr, uint32_t aux_data){
	uint32_t *pte = lookup_page(pd, uaddr, false);
	/* The last 12 bits should be zero */
	ASSERT((aux_data & ~(uint32_t)PTE_ADDR) == 0);

	/* Set the bottom 12 bits to 0, more usable form of the
	   function I believe, avoids asserting something. Use
	   after done debugging
	aux_data &= ~(uint32_t)PTE_ADDR;
	 */

	if(pte != NULL){
		*pte |= aux_data;
	}else{
		PANIC("pagedir_set_aux called on a page table entry that is not initialized");
	}
}

uint32_t pagedir_get_aux (uint32_t *pd, const void *uaddr){
	uint32_t *pte = lookup_page(pd, uaddr, false);

	if(pte != NULL){
		return *pte & PTE_ADDR;
	}else{
		//PANIC("pagedir_get_aux called on a page table entry that is not initialized");
		return 0;
	}
}

/* Adds a mapping from user virtual address uaddr to kernel
   virtual address kaddr to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   kaddr should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if uaddr is already mapped or
   if memory allocation fails. */
bool pagedir_install_page (void *uaddr, void *kaddr, bool writable){
	struct thread *t = thread_current ();

	/* Verify that there's not already a page present at that virtual
       address, then map our page there. */
	return (!pagedir_is_present (t->pagedir, uaddr)
			&& pagedir_set_page (t->pagedir, uaddr, kaddr, writable));
}

/* Sets up a PTE that is not present but that has the neccessary information
   to be loaded when a page fault occurs. This will map the most significant
   top 20 bits to be something that will be useful for the page fault handler.
   The data for the top 20 bits will be passed in as a uint32_t and have the
   lower 12 bits masked off. Also sets the appropriate bits for medium type*/
bool pagedir_setup_demand_page(uint32_t *pd, void *uaddr, medium_t medium ,
		uint32_t data, bool writable){

	//printf("setting %p's page to be medium type %u with auxilary data %p  and present bit %u\n", uaddr, medium, data, pagedir_is_present(pd, uaddr));

	/* Ensure the PTE exists because the following functions won't create it.*/
	uint32_t *pte = lookup_page(pd, uaddr, true);

	if(pte == NULL){
		return false;
	}

	/*Set writable bit */
	*pte |= (writable ? PTE_W : 0);

	/* Set the aux data*/
	pagedir_set_aux(pd, uaddr, data);

	/* Set the appropriate medium */
	pagedir_set_medium(pd, uaddr, medium);

	/*Clear the present bit and clear the TLB*/
	pagedir_clear_page(pd, uaddr);

	return true;
}

/* Clears all of the PTE's starting at base and going to
   num_pages. Clear means that it will clear its page, set its
   medium bits to error and set it to not present.*/
void pagedir_clear_pages(uint32_t* pd, void *base, uint32_t num_pages){
	uint8_t* rm_ptr = (uint8_t*)base;
	uint32_t j;
	for(j = 0; j < num_pages; j++, rm_ptr += PGSIZE){
		if(pagedir_is_present(pd, rm_ptr)){
			frame_clear_page(pagedir_get_page(pd, rm_ptr));
		}
		pagedir_set_medium(pd, rm_ptr, PTE_AVL_ERROR);
		pagedir_clear_page(pd, rm_ptr);
	}
}

