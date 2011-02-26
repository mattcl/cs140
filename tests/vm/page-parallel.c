/* Runs 4 child-linear processes at once. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

#define CHILD_CNT 4

void
test_main (void)
{
  pid_t children[CHILD_CNT];
  int i;

  for (i = 0; i < CHILD_CNT; i++) 
    CHECK ((children[i] = exec ("child-linear")) != -1,
           "exec \"child-linear\"");

  printf("----------------- started waiting-------------------------------------------\n");
  for (i = 0; i < CHILD_CNT; i++){
	  printf("wait child %d", i);
      CHECK (wait (children[i]) == 0x42, "wait for child %d", i);
  }
}
