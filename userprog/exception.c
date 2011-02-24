#include <inttypes.h>
#include <stdio.h>
#include "gdt.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h" /* PHYS_BASE */
#include "threads/pte.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "exception.h"
#include "process.h"
#include "syscall.h"
#include "userprog/process.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "threads/init.h"

/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void exception_init (void){
	/* These exceptions can be raised explicitly by a user program,
       e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
       we set DPL==3, meaning that user programs are allowed to
       invoke them via these instructions. */
	intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
	intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
	intr_register_int (5, 3, INTR_ON, kill,
			"#BR BOUND Range Exceeded Exception");

	/* These exceptions have DPL==0, preventing user processes from
       invoking them via the INT instruction.  They can still be
       caused indirectly, e.g. #DE can be caused by dividing by
       0.  */
	intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
	intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
	intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
	intr_register_int (7, 0, INTR_ON, kill,
			"#NM Device Not Available Exception");
	intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
	intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
	intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
	intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
	intr_register_int (19, 0, INTR_ON, kill,
			"#XF SIMD Floating-Point Exception");

	/* Most exceptions can be handled with interrupts turned on.
       We need to disable interrupts for page faults because the
       fault address is stored in CR2 and needs to be preserved. */
	intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void exception_print_stats (void){
	printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */

static void kill (struct intr_frame *f){
	/* This interrupt is one (probably) caused by a user process.
       For example, the process might have tried to access unmapped
       virtual memory (a page fault).  For now, we simply kill the
       user process.  Later, we'll want to handle page faults in
       the kernel.  Real Unix-like operating systems pass most
       exceptions back to the process via signals, but we don't
       implement them. */

	/* The interrupt frame's code segment value tells us where the
       exception originated. */
	switch (f->cs){
	case SEL_UCSEG:
		/* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
		printf ("%s: dying due to interrupt %#04x (%s).\n",
				thread_name (), f->vec_no, intr_name (f->vec_no));
		intr_dump_frame (f);

		system_exit(f, -1);

	case SEL_KCSEG:
		/* Kernel's code segment, which indicates a kernel bug.
           Kernel code shouldn't throw exceptions.  (Page faults
           may cause kernel exceptions--but they shouldn't arrive
           here.)  Panic the kernel to make the point.  */
		intr_dump_frame (f);
		PANIC ("Kernel bug - unexpected interrupt in kernel");

	default:
		/* Some other code segment?  Shouldn't happen.  Panic the
           kernel. */
		printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
				f->vec_no, intr_name (f->vec_no), f->cs);
		system_exit(f, -1);
	}
}

/* Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to project 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void page_fault (struct intr_frame *f){
	bool not_present;  /* True: not-present page, false: writing r/o page. */
	bool write;        /* True: access was write, false: access was read. */
	bool user;         /* True: access by user, false: access by kernel. */
	void *fault_addr;  /* Fault address. */
	void *pd = active_pd(); 	   /* The page directory used to obtain the fault */

	/* Obtain faulting address, the virtual address that was
       accessed to cause the fault.  It may point to code or to
       data.  It is not necessarily the address of the instruction
       that caused the fault (that's f->eip).
       See [IA32-v2a] "MOV--Move to/from Control Registers" and
       [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
       (#PF)". */
	asm ("movl %%cr2, %0" : "=r" (fault_addr));

	/* Turn interrupts back on (they were only off so that we could
     be assured of reading CR2 before it changed). */
	intr_enable ();

	/* Count page faults. */
	page_fault_cnt++;

	/* Determine cause. */
	not_present = (f->error_code & PF_P) == 0;
	write = (f->error_code & PF_W) != 0;
	user = (f->error_code & PF_U) != 0;

	/* This section implements virtual memory from the fault
	     handlers prospective. */

	//printf("fault_addr %p, esp %x \n", fault_addr, ((uint32_t)f->esp - 32));
	if(not_present){
		/* We got a page fault for a not-present error.  We need to
	       either 1) Read in the page from the appropriate place,
	       2) try to grow the stack, or 3) kill them */

		/* Check the medium bits and IF any of them are set
		   we read in the data from the appropriate location
		   ELSE medium_t is PTE_AVL_MEMORY (i.e. it isn't EXEC, SWAP, or MMAP),
		   and it is not present so this process is either growing the
		   stack or accessing invalid memory and must be killed*/
		medium_t type = pagedir_get_medium(pd, fault_addr);

		/* Get the page address of the faulting address, masks off
		   the lower 12 bits and makes it a byte pointer so that
		   we can increment it easily*/
		uint8_t *uaddr = (uint8_t*)(((uint32_t)fault_addr & PTE_ADDR));

		if(type == PTE_AVL_SWAP){
			/* Data is not present but on swap read it in
							   then return so that dereference becomes valid*/
			if(!swap_read_in(uaddr)){
				printf("COULDN't read in from swap!!!!\n");
				kill(f);
			}
		}else if(type == PTE_AVL_EXEC){
			/* Data is not present but is on disk still so
			   read it in and then derefernece becomes valid*/
			if(!process_exec_read_in(uaddr)){
				printf("COULDN'T load the executable segment, KILLL\n");
				kill(f);
			}
		}else if(type == PTE_AVL_MMAP){
			if(!mmap_read_in(uaddr)){
				printf("Couldn't load page from mmaped file\n");
				kill(f);
			}
		}else if(type == PTE_AVL_STACK){
			/* read in zero page */
			/* Get new frame and install it at the faulting addr*/
			uint32_t* kaddr  = frame_get_page(PAL_USER | PAL_ZERO, uaddr);

			/* it will be set to dirty or accessed on the retry*/
			pagedir_install_page(uaddr, kaddr, true);

		}else if(type == PTE_AVL_ERROR){
			if(user){

				if(fault_addr < PHYS_BASE &&
					(uint32_t)fault_addr >= ((uint32_t)f->esp - MAX_ASM_PUSH) &&
					(uint32_t)PHYS_BASE -(stack_size) <= ((uint32_t)f->esp - PGSIZE)){
					  /* For explanation of (f->esp - MAX_ASM_PUSH) see
					     note on MAX_ASM_PUSH */

					/* Trying to grow the stack segment?*/
					/* While the page is not present and supposed to be in memory */
					while(!pagedir_is_present(pd, uaddr) &&
							pagedir_get_medium(pd, uaddr) == PTE_AVL_ERROR){

						/* Put a demand stack page in the page table*/
						pagedir_setup_demand_page(pd, uaddr,
								PTE_AVL_STACK,0 , true);

						/* move to the next higher page size */
						uaddr += PGSIZE;
					}
				}else{
					/* This is invalid reference to memory, kill it K-UNIT style
					   It wasn't trying to grow the stack segment*/
					//printf("kill1\n");
					kill(f);
				}
			}else{
				/* We don't allow for growing the stack in kernel code.
				   Plus you really can't grow the stack because if you
				   passed a pointer to a buffer on the stack, esp must
				   have already been decremented. And when the user pushed
				   the pointer for us to read they would have page faulted
				   and already grown the stack. So it is safe to just return -1
				   to the kernel code*/
				//printf("kernel 1 write %u\n", write);
				f->eip = (void*)f->eax;
				f->eax = 0xffffffff;
			}
		}else{
		    PANIC("unrecognized medium in page fault, check exception.c");
		}
	}else{
		/* The page is present and we got a page fault so this means that
		   we tried to write to read only memory. This will kill a user
		   process or return -1 to kernel code*/
		if(user){
			//printf("kill2\n");
			kill(f);
		}else{
			//printf("kernel 2 write %u\n", write);
			f->eip = (void*)f->eax;
			f->eax = 0xffffffff;
		}
	}
	/* Page was read in or the return value was set for kernel code
	   so the memory access will try again and succeed or we will kill
	   the process or fail silently from the kernel code that faulted */
}
