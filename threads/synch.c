/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
*/

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"


//========= Begin Changes ======//

bool lockCompare (const struct list_elem *a,
					const struct list_elem *b,
					void *aux UNUSED);

bool condCompare (const struct list_elem *a,
			      const struct list_elem *b,

			      void *aux UNUSED);
/* Returns the maximum priority lock out of this list of locks */
static inline struct lock *max_lock(struct list *locks){
	return list_entry(list_max(locks, &lockCompare, NULL),
					  struct lock,  elem);
}
/* Returns the maximum priority thread out of this list of threads */
static inline struct thread *max_thread(struct list *threads){
	return list_entry(list_max(threads, &threadCompare, NULL),
					  struct thread, elem);
}
//======== End Changes ========//


/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
     decrement it.

   - up or "V": increment the value (and wake up one waiting
     thread, if any). */
void sema_init (struct semaphore *sema, unsigned value){
	ASSERT (sema != NULL);

	sema->value = value;
	list_init (&sema->waiters);
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. */
void sema_down (struct semaphore *sema){
	enum intr_level old_level;

	ASSERT (sema != NULL);
	ASSERT (!intr_context ());

	old_level = intr_disable ();
	while (sema->value == 0) {
		list_push_back (&sema->waiters, &thread_current ()->elem);
		thread_block ();
	}
	sema->value--;
	intr_set_level (old_level);
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool sema_try_down (struct semaphore *sema){
	enum intr_level old_level;
	bool success;

	ASSERT (sema != NULL);

	old_level = intr_disable ();
	if (sema->value > 0){
	  sema->value--;
	  success = true;
	} else {
		success = false;
	}

	intr_set_level (old_level);

	return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
void sema_up (struct semaphore *sema){
	enum intr_level old_level;

	ASSERT (sema != NULL);

	old_level = intr_disable ();
	if (!list_empty (&sema->waiters)) {
		struct list_elem *highest = remove_list_max(&sema->waiters, &threadCompare);
		ASSERT(highest != NULL);
		// Pop off only the highest priority waiter
		thread_unblock (list_entry (highest, struct thread, elem));
	}
	sema->value++;
	intr_set_level (old_level);
	thread_preempt();
}

static void sema_test_helper (void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void sema_self_test (void){
	struct semaphore sema[2];
	int i;

	printf ("Testing semaphores...");
	sema_init (&sema[0], 0);
	sema_init (&sema[1], 0);
	thread_create ("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
	for (i = 0; i < 10; i++){
		sema_up (&sema[0]);
		sema_down (&sema[1]);
	}
	printf ("done.\n");
}

/* Thread function used by sema_self_test(). */
static void sema_test_helper (void *sema_) {
	struct semaphore *sema = sema_;
	int i;

	for (i = 0; i < 10; i++){
		sema_down (&sema[0]);
		sema_up (&sema[1]);
	}
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void lock_init (struct lock *lock){
	ASSERT (lock != NULL);
	lock->holder = NULL;
	lock->lock_priority = -1;
	list_init (&lock->waiters);
}

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void lock_acquire (struct lock *lock) {
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (!lock_held_by_current_thread (lock));


	enum intr_level old_level;
	struct thread *t = thread_current();

	old_level = intr_disable ();
	t->lockWaitedOn = lock;
	while (lock->holder != NULL) {
		list_push_back (&lock->waiters, &t->elem);

		// Update temp because this will bubble all the way to the first
		// thread that has a lock that t is dependent on and give it the
		// highest priority
		update_temp_priority(t);
		thread_block ();
	}

	t->lockWaitedOn = NULL;

	// These must be done atomically because otherwise in the pathological
	// case we could re-enable interrupts then immediately get preempted
	// In this case we won't be holding the lock and if there is a max
	// priority thread waiting on this lock then we won't be able to
	// update our temp priority
	lock->holder = t;
	list_push_back(&t->held_locks, &lock->elem);

	intr_set_level (old_level);

	// update the temp priority because acquiring this lock may have
	// also acquired the group of people waiting on this lock which
	// may have higher priority than t
	//update_temp_priority(t);
}

/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool lock_try_acquire (struct lock *lock) {
	bool success;
	struct thread *t = thread_current ();

	ASSERT (lock != NULL);
	ASSERT (!lock_held_by_current_thread (lock));

	enum intr_level old_level;

	old_level = intr_disable ();

	if (lock->holder != NULL){
		success = false;
	} else {
		success = true;
		lock->holder = t;
		// not atomically because we are only updating thread specific data
		list_push_back(&t->held_locks, &lock->elem);
		// update the temp priority because acquiring this lock may have
		// also acquired the group of people waiting on this lock which
		// may have higher priority than t
		update_temp_priority(t);
	}

	intr_set_level (old_level);

	return success;
}

/* Releases *lock, which must be owned by the current thread.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
void lock_release (struct lock *lock){
	ASSERT (lock != NULL);
	ASSERT (lock_held_by_current_thread (lock));
	ASSERT (!intr_context ());

	// turn off interrupts to atomically remove from list
	enum intr_level old_level = intr_disable ();
	if (!list_empty (&lock->waiters)) {

		//Remove the thread with highest priority O(n) in threads
		// waiting on this lock
		struct list_elem *highest =
				remove_list_max(&lock->waiters, &threadCompare);
		ASSERT(highest != NULL);

		//The thread that is still waiting with the highest priority
		if(!list_empty(&lock->waiters)){
			// Reset the lock priority to the next highest priority waiting on
			// the lock So that the next acquisition will be raised if necessary
			lock->lock_priority = max_thread(&lock->waiters)->tmp_priority;
		}
		// Change here to be able to pop off only the highest priority waiter
		thread_unblock (list_entry (highest, struct thread, elem));
	}

	//Needs to be with interrupts disabled because it is used
	//by many other threads when they update their tmp priority
	// if it is not null it will cause recursion to occur
	lock->holder = NULL;

	// may be reset immediately after re enabling interrupts then when
	// this thread gets resumed will cause the lock to be removed from
	// its correct list, all bad
	list_remove(&lock->elem);

	// Revert back to whatever donated priority was acquired
	// before acquiring this lock
	update_temp_priority(thread_current());

	intr_set_level (old_level);

	//schedule highest priority thread
	thread_preempt();
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racey.) */
bool lock_held_by_current_thread (const struct lock *lock){
	ASSERT (lock != NULL);
	return lock->holder == thread_current();
}

/* One semaphore in a list. */
struct semaphore_elem {
    struct list_elem elem;              /* List element. */
    struct semaphore semaphore;         /* This semaphore. */

    /* The thread that waits on this semaphore to become
     * available. */
    struct thread *thread;
};

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void cond_init (struct condition *cond){
	ASSERT (cond != NULL);

	list_init (&cond->waiters);
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void cond_wait (struct condition *cond, struct lock *lock){
	struct semaphore_elem waiter;

	waiter.thread = thread_current();

	ASSERT (cond != NULL);
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (lock_held_by_current_thread (lock));

	sema_init (&waiter.semaphore, 0);
	list_push_back (&cond->waiters, &waiter.elem);
	lock_release (lock);
	sema_down (&waiter.semaphore);
	lock_acquire (lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void cond_signal (struct condition *cond, struct lock *lock){
	ASSERT (cond != NULL);
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (lock_held_by_current_thread (lock));

	if (!list_empty (&cond->waiters)){
		//------ Begin Changes -----//
		// We are only going to unblock the thread with the
		// highest priority.
		struct list_elem *e = remove_list_max(&cond->waiters, &condCompare);
		ASSERT(e != NULL);
		sema_up (&list_entry (e, struct semaphore_elem, elem)->semaphore);
		//------ End Changes-------//
	}
}
/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void cond_broadcast (struct condition *cond, struct lock *lock){
	ASSERT (cond != NULL);
	ASSERT (lock != NULL);

	while (!list_empty (&cond->waiters)){
		cond_signal (cond, lock);
	}
}

//----- Begin Changes ------//

/**
 * This function takes as parameters list_elem *a, which is a memeber of a
 * lock and list_elem *b which is a member of a lock and return true
 * if lock A has priority LESS than that of lock b. Could be more efficient
 * To get the max priority through a priority queue
 */
bool lockCompare (const struct list_elem *a,
					const struct list_elem *b,
					void *aux UNUSED){

	return ((list_entry(a, struct lock, elem)->lock_priority) <
		    (list_entry(b, struct lock, elem)->lock_priority));
}

/**
 * This function takes as parameters list_elem *a which is a member of a
 * semaphore_elem and *b which is similar and then goes to the thread that
 * is waiting on this semaphore (Because this is a conditional) and returns
 * if the first element's thread's priority is less than the second element's
 * thread's priority
 */
bool condCompare (const struct list_elem *a,
			      const struct list_elem *b,
			      void *aux UNUSED){

	return ((list_entry(a, struct semaphore_elem, elem)->thread->tmp_priority)<
		    (list_entry(b, struct semaphore_elem, elem)->thread->tmp_priority));
}

/*Must Be run with interrupts off because it will create race conditions
 * otherwise in the priority donation process.
 *
 * update_temp_priority takes as its value the starting thread
 * That needs its tmp_priority updated.
 * Because This value has effect on other threads which are holding
 * locks that this thread may be dependent on, it will also update
 * those threads tmp_priority values as well.
 *
 * This function is used by both thread.c and sync.c. It is completely
 * hidden from the client. It works by updating the tmp priority which
 * is the maximum value of the priorities of all of this threads held locks.
 *
 * The lock priority value, in turn, is the maximum priority of all threads
 * that are waiting on this lock.
 * This function will recursively update all threads which hold a lock
 * on which this thread is dependent giving the appropriate priority to
 * each one.
 *
 * The recursion needs to be done with interrupt's disabled because
 * We need to donate priority atomically or we will have odd race conditions
 */
void update_temp_priority(struct thread *t){

	ASSERT (intr_get_level () == INTR_OFF);

	if(t == NULL)return;
	if(list_empty(&t->held_locks)){
		t->tmp_priority = t->priority;
	} else {
		// Set the priority of this thread to the highest priority
		// of all the threads waiting on any of the locks that this
		// thread currently holds

		t->tmp_priority = max(max_lock(&t->held_locks)->lock_priority,
							  t->priority);

	}

	// Update all the neccessary threads that this thread depends.
	if(t->lockWaitedOn != NULL){
		// This lock needs to be updated to reflect the change of this threads
		// priority update
		t->lockWaitedOn->lock_priority =
				max(t->lockWaitedOn->lock_priority, t->tmp_priority);
		update_temp_priority(t->lockWaitedOn->holder);
	}
}

// ------ End Changes ------//
