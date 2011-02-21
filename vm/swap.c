#include "swap.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include <bitmap.h>


static struct bitmap used_swap_slots;
