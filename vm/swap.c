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
   |         Offset                   |010|      Flags     | 0  |
   +----------------------------------+---+---------------------+

   Disk MMap
   ---------
   We use the 20 bits to store the virtual address of the mmapped
   file that page faulted.

   31                                 12 11                  PTE_P 
   +----------------------------------+---+---------------------+
   |         Virtual Address          |100|      Flags     | 0  |
   +----------------------------------+---+---------------------+
*/

#include "swap.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include <bitmap.h>


static struct bitmap used_swap_slots;
