#ifndef THREADS_SYNCH_H
#define THREADS_SYNCH_H

#include <list.h>
#include <stdbool.h>

/* A counting semaphore. */
struct semaphore{
    unsigned value;             /* Current value. */
    struct list waiters;        /* List of waiting threads. */
};

void sema_init (struct semaphore *, unsigned value);
void sema_down (struct semaphore *);
bool sema_try_down (struct semaphore *);
void sema_up (struct semaphore *);
void sema_self_test (void);

//========== Begin Changes =========//

/* Lock. No longer layered over a semaphore
 * It has a holder, a boolean value telling
 * whether it is held or not, and a list of waiters,
 * The lock_priority. */
struct lock {
    struct thread *holder;      /* Thread holding lock . */
    struct list_elem elem;		/* element in a held locks list */
    bool held;					/* Whether this lock is held */
    struct list waiters;		/* List of waiting threads */
	int lock_priority; 			/* The priority which is max over
							     * all threads which are waiting on this
							     * Will be the priority that that thread
							     * Which is holding the lock must have */
};

//========== End Changes ===========//

void lock_init (struct lock *);
void lock_acquire (struct lock *);
bool lock_try_acquire (struct lock *);
void lock_release (struct lock *);
bool lock_held_by_current_thread (const struct lock *);

// --------- Begin Changes -------- //
void update_temp_priority(struct thread *t);

// --------- End Changes ----------//


/* Condition variable. */
struct condition {
    struct list waiters;        /* List of waiting threads. */
};

void cond_init (struct condition *);
void cond_wait (struct condition *, struct lock *);
void cond_signal (struct condition *, struct lock *);
void cond_broadcast (struct condition *, struct lock *);

/* Optimization barrier.

   The compiler will not reorder operations across an
   optimization barrier.  See "Optimization Barriers" in the
   reference guide for more information.*/
#define barrier() asm volatile ("" : : : "memory")

#endif /* threads/synch.h */
