#include "page.h"
#include <stdint.h>
#include <stdbool.h>
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include <debug.h>
/* returns the key to the frame that is now available, use the entry
   to install this page into the pagedir of the evicting thread that
   is asking for memory
   Eviction policy algorithm goes here */
void *evict_page(void){
	return 0;
}
