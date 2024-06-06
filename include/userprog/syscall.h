#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <debug.h>
#include <stddef.h>

void syscall_init (void);

void halt (void);
void exit (int status);
int exec (const char *cmd_line);
//int kernel_fork (const char *thread_name, struct intr_frame *f);
int wait (int pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

void check_address(void *addr);

struct lock filesys_lock;
struct semaphore filesys_sema;
#endif /* userprog/syscall.h */
