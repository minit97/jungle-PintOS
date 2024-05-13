# 1. Alarm Clock
- thread_yield() : yield the cpu and insert thread to ready_list
  - thread_current() : Return the current thread.
  - intr_disabled() : Disable the interrupt and return previous interrupt state
  - intr_set_level(old_level) : Set a state of interrupt to the state passed to parameter and return previous interrupt state
  - schedule() : Do context switch
- timer_ticks() : return the value of the current tick
- timer_elased() : return how many ticks have passed since the start

---
# 2. Prority Scheduling
- thread_set_priority(int new_priority) : Change priority of the current thread to new_priority
- int thread_get_priority(void) : Return priority of the current thread.  
- the synchronization primitives
  - Lock
    - FIFO lock/unlock in priority-less Pintos : Lock is acquired by FIFO order in waiters list, ignoring priority.
    - When threads try to acquire semaphore, sort waiters list in order of priority
      - Modify sema_down() / cond_wait()
    - void lock_init(struct lock *lock) : Initialize the lock data structure
    - void lock_acquire(struct lock *lock) : Request the lock
    - void lock_release(struct lock *lock) : Release the lock
  - Semaphore
    - void sema_init(struct semaphore *sema, unsigned value) : Initialize semaphore to the given value
    - void sema_down(struct semaphore *sema) : Request the semaphore. If it acquired the semaphore, decrease the value by 1
    - void sema_up(struct semaphore *sema) : Release the semaphore and increase the value by 1
  - Condition variables
    - void cond_init(struct condition *cond) : Initialize the condition variable data structure.
    - void cond_wait(struct condition *cond, struct lock *lock) : Wait for signal by the condition variable
    - void cond_signal(struct condition *cond, struct lock *lock UNUSED) : Send a signal to thread of the highest priority waiting in the condition variable 
    - void con_broadcast(struct condition *cond, struct lock *lock) : Send a signal to all threads waiting in the condition variable 
- Priority Inversion
  - Priority Donation 
    - Donating Priority to the lock holder we avoid priority inversion
      - Request lock and inherit its priority to the lock holder
  - Nested Donation
  - Multiple Donation
--- 
# 3. Advanced Scheduler (BSD)

---
# etc..  
### - Schedule()
- Schedule a new process
  - Get the currently running process
  - Get the next process to run
  - Switch contetxt from current to next
- Who calls schedule()?
  - exit, block, yield
  - Or pre-empted, (when the time quantum expires...)
- Before calling schedule
  - Disable interrupt
  - Change the state of the running thread from running to something else

### - User stack vs Kernel Stack
- excuting in user mode : user stack
- excuting in kernel mode : kernel stack
- system call
  - switch from user stack to kernel stack
  - raise privilege level

### - Summary
- schedule()
  - Called in exit, yield and block
  - Get the new process to the CPU
- Context switch
  - Save the context of the currently running thread to the stack
  - Save the current stack top at the currently running struct thread
  - Restore the stack top of the next thread to esp register
  - Restore the context from the stack of the next thread to run
- Change the state of the next process to running and frees the memory from the dying process