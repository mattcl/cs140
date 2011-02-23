#include "evict.h"
#include <stdint.h>
#include <stdbool.h>
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "vm/frame.h"
#include <debug.h>

static size_t evict_hand;
static size_t clear_hand;
static size_t threshold;

/* returns the key to the frame that is now available, use the entry
   to install this page into the pagedir of the evicting thread that
   is asking for memory.   

   
   MEMORY - If we try to evict a page, it's medium should say that it is
   in memory or it does not make sense that we are evicting it.

   SWAP - If we evict something in memory and it is dirty and not a mmaped
   file we put it on swap, swap_allocate takes care of the rest.

   STACK - If we evict a stack page that's clean, we can just get a new
   page from thin air.  If we evict a dirty stack page, we write it to swap.

   EXECUTABLE - cannot write to executable, if we evict this we do nothing.
   MMAP - If we evict an mmapped page we write it back to the file system.
n   */
void *evict_page(struct frame_table * f_table){
  
    struct bitmap *bmap = f_table->used_frames;
  
    while(evict_hand + threshold % NUM_FRAMES < clear_hand){
    /* Our clear hand is still at least theshold bits in front of us */
      
    if(!pagedir_is_accesed(
			  ;
      
  }
      

}

void evict_init(){
  evict_hand = 0;
  clear_hand = 0;
  threshold = 1;
  
}

void *get_least_recently_used_page (){
  

    while(true){
      struct frame_hash_entry *frame = elem_to_frame(hash_next(iter));
      ASSERT(elem != NULL);
      
      if(pagedir_is_accessed(frame->current_page_dir,frame->page)){
	  return frame_evict(frame);
      }
      if(iter == clock_hand){
	  break;
      }
    }
}
       
void *frame_evict (frame_hash_entry * frame){
    medium_t medium = pagedir_get_medium(frame->page);
    /*  not sure about this */
    ASSERT(medium != PTE_AVL_MEMORY);

    if(pagedir_is_dirty(upage)){
      if(medium == PTE_AVL_MMAP){
	/* must write to file system */
      }else if(medium == PTE_AVL_SWAP){
	/* put on swap */
      } else{
	PANIC("John doesn't get how eviction works o_O");
      }
    }else{
      /* we should be able to overwrite the data here */
      frame_ha
    }
}

