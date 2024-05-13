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

/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
   decrement it.

   - up or "V": increment the value (and wake up one waiting
   thread, if any). */
void
sema_init (struct semaphore *sema, unsigned value) {
    // project01[scheduling] - Initialize semaphore to the given value
	ASSERT (sema != NULL);

	sema->value = value;
	list_init (&sema->waiters);
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. This is
   sema_down function. */
void
sema_down (struct semaphore *sema) {
    // project01[scheduling] - Request the semaphore. If it acquired the semaphore, decrease the value by 1
	enum intr_level old_level;

	ASSERT (sema != NULL);
	ASSERT (!intr_context ());

	old_level = intr_disable ();

	while (sema->value == 0) {
        list_insert_ordered(&sema->waiters, &thread_current ()->elem, compare_priority, NULL);
		thread_block ();
	}

    sema->value--;
	intr_set_level (old_level);
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool
sema_try_down (struct semaphore *sema) {
	enum intr_level old_level;
	bool success;

	ASSERT (sema != NULL);

	old_level = intr_disable ();
	if (sema->value > 0)
	{
		sema->value--;
		success = true;
	}
	else
		success = false;
	intr_set_level (old_level);

	return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
void
sema_up (struct semaphore *sema) {
    // project01[scheduling] - Release the semaphore and increase the value by 1

	ASSERT (sema != NULL);

    enum intr_level old_level;
	old_level = intr_disable ();

	if (!list_empty (&sema->waiters)) {
        list_sort(&sema->waiters, compare_priority, NULL);
        thread_unblock(list_entry(list_pop_front(&sema->waiters), struct thread, elem));
    }
	sema->value++;

	intr_set_level (old_level);
}

static void sema_test_helper (void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void
sema_self_test (void) {
	struct semaphore sema[2];
	int i;

	printf ("Testing semaphores...");
	sema_init (&sema[0], 0);
	sema_init (&sema[1], 0);
	thread_create ("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
	for (i = 0; i < 10; i++)
	{
		sema_up (&sema[0]);
		sema_down (&sema[1]);
	}
	printf ("done.\n");
}

/* Thread function used by sema_self_test(). */
static void
sema_test_helper (void *sema_) {
	struct semaphore *sema = sema_;
	int i;

	for (i = 0; i < 10; i++)
	{
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
void
lock_init (struct lock *lock) {
    // project01[scheduling] - Initialize the lock data structure

	ASSERT (lock != NULL);

	lock->holder = NULL;
	sema_init (&lock->semaphore, 1);
}

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
lock_acquire (struct lock *lock) {
    /*
     * project01[scheduling] - Request the lock
     *      If the lock is not available, store address of the lock.
     *      Store the current priority and maintain donated threads on list(multiple donation)
     *      Donate priority
    */
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (!lock_held_by_current_thread (lock));


	sema_down (&lock->semaphore);           // 해당 lock에 대한 semaphore를 획득

    struct thread *curr = thread_current ();
    lock->holder = curr;                          // 해당 lock에 스레드 접근

    int highest_priority = list_entry(list_max(&lock->semaphore.waiters, compare_priority, NULL), struct thread, elem)->priority;
    if (highest_priority > curr->priority) {
        curr->priority = highest_priority;
    }
}

/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool
lock_try_acquire (struct lock *lock) {
	bool success;

	ASSERT (lock != NULL);
	ASSERT (!lock_held_by_current_thread (lock));

	success = sema_try_down (&lock->semaphore);
	if (success)
		lock->holder = thread_current ();
	return success;
}

/* Releases LOCK, which must be owned by the current thread.
   This is lock_release function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
void
lock_release (struct lock *lock) {
    /* project01[scheduling] - Release the lock
            When the lock is released, remove the thread that holds the lock on donation list and set priority properly
     */
	ASSERT (lock != NULL);
	ASSERT (lock_held_by_current_thread (lock));

    // 먼저 donations 에서 해제하는 lock을 기다리는 thread 삭제
//    struct thread *origin_locked_thread = lock->holder;
//    struct list *donation_list = &origin_locked_thread->donations;


	lock->holder = NULL;
	sema_up (&lock->semaphore);
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool
lock_held_by_current_thread (const struct lock *lock) {
	ASSERT (lock != NULL);

	return lock->holder == thread_current ();
}

/* One semaphore in a list. */
struct semaphore_elem {
	struct list_elem elem;              /* List element. */
	struct semaphore semaphore;         /* This semaphore. */
};

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void
cond_init (struct condition *cond) {
    // project01[scheduling] - Initialize the condition variable data structure

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
void
cond_wait (struct condition *cond, struct lock *lock) {
    // project01[scheduling] - Wait for signal by the condition variable

	struct semaphore_elem waiter;

	ASSERT (cond != NULL);
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (lock_held_by_current_thread (lock));

	sema_init (&waiter.semaphore, 0);
    list_insert_ordered(&cond->waiters, &waiter.elem, compare_priority, NULL);
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
void
cond_signal (struct condition *cond, struct lock *lock UNUSED) {
    // project01[scheduling] - Send a signal to thread of the highest priority waiting in condition variable.

	ASSERT (cond != NULL);
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (lock_held_by_current_thread (lock));

	if (!list_empty (&cond->waiters)) {
        list_sort(&cond->waiters, compare_priority, NULL);
        sema_up(&list_entry(list_pop_front(&cond->waiters), struct semaphore_elem, elem)->semaphore);
    }

}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_broadcast (struct condition *cond, struct lock *lock) {
    // project01[scheduling] - Send a signal to all threads waiting in the condition variable.

	ASSERT (cond != NULL);
	ASSERT (lock != NULL);

	while (!list_empty (&cond->waiters))
		cond_signal (cond, lock);
}

void multiple_donation(struct lock *unlocked_lock) {
    struct thread *origin_locked_thread = unlocked_lock->holder;

    // 먼저 donations 에서 해제하는 lock을 기다리는 thread 삭제
    struct list *donation_list = &origin_locked_thread->donations;

    struct list_elem *temp_elem = list_begin(donation_list);
    while (temp_elem != list_end(donation_list)) {
        struct thread *temp_thread = list_entry(temp_elem, struct thread, elem);
        if (temp_thread->wait_on_lock == unlocked_lock) {
            temp_elem = list_remove(temp_elem);
            break;
        }
        temp_elem = list_next(temp_elem);
    }

    // donations 에서의 최대 priority 추출
    int highest_priority = list_max(donation_list, compare_priority, NULL);

    // 해제할려는 lock의 기다리는 thread 를 찾고 wait_on_lock 연결해제 및 lock_holder를 가리키도록함
    struct thread *new_locked_thread = list_entry(list_pop_front(&unlocked_lock->semaphore.waiters), struct thread, elem);
    if (new_locked_thread != NULL) {
        new_locked_thread->wait_on_lock = NULL;
        unlocked_lock->holder = new_locked_thread;
    }
}

void nested_donation(struct lock *wanted_lock, struct thread *curr) {
    curr->wait_on_lock = wanted_lock;

    struct lock *temp_lock = wanted_lock;
    while(temp_lock != NULL) {
        struct thread *next_thread = temp_lock->holder;
        if (next_thread->priority < curr->priority) {       // 들어온 것만으로 체크를 하는데 이래도 될려나? -> 나중에 바꾸긴해야할듯
            next_thread->priority = curr->priority;
        }
        temp_lock = &next_thread->wait_on_lock;
    }
}

void priority_donation(struct lock *lock) {
    struct list wait_list = lock->semaphore.waiters;
    int highest_priority = list_entry(list_max(&wait_list, compare_priority, NULL) , struct thread, elem)->priority;
    lock->holder->priority = highest_priority;
}