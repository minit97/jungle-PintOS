/* Tests that the highest-priority thread waiting on a semaphore
   is the first to wake up. */

#include <stdio.h>
#include "tests/threads/tests.h"
#include "threads/init.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "devices/timer.h"

static thread_func priority_sema_thread;
static struct semaphore sema;

void
test_priority_sema (void) 
{
  int i;
  
  /* This test does not work with the MLFQS. */
  ASSERT (!thread_mlfqs);

  sema_init (&sema, 0);
  thread_set_priority (PRI_MIN);    // 0
  for (i = 0; i < 10; i++)
    {
      int priority = PRI_DEFAULT - (i + 3) % 10 - 1;    // 27 26 25 24 23 22 21 30 29 28
      char name[16];
      snprintf (name, sizeof name, "priority %d", priority);
      thread_create (name, priority, priority_sema_thread, NULL);
    }

  for (i = 0; i < 10; i++) 
    {
      sema_up (&sema);
      msg ("Back in main thread.");
    }
}

static void
priority_sema_thread (void *aux UNUSED) 
{
  sema_down (&sema);                            // 처음 들어온 27번이 yield()를 통해 schedule을 호출하지만 sema_down에서 block 상태가 되버린다.
  msg ("Thread %s woke up.", thread_name ());
}
