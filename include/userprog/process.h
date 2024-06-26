#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include <stdbool.h>
#include "threads/thread.h"
#include "filesys/off_t.h"

// Project 3: Lazy Load
struct container {
    struct file *file;
    off_t offset;
    size_t read_bytes;
};

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

void argument_stack(char **argv, int argc, void **rsp);

struct thread *get_child_process (int pid);
void remove_child_process (struct thread *cp);

bool lazy_load_segment(struct page *page, void *aux);
#endif /* userprog/process.h */
