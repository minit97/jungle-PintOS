#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "include/filesys/file.h"
#include "include/filesys/filesys.h"
#include "include/lib/stdio.h"
#include "include/userprog/process.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/thread.h"
#include "userprog/gdt.h"
#include "userprog/process.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
void check_address(void *addr);
void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file_name);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
tid_t fork(const char *thread_name, struct intr_frame *f);
int exec(const char *cmd_line);
int wait(int pid);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void) {
  write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG)
                                                               << 32);
  write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

  /* The interrupt service rountine should not serve any interrupts
   * until the syscall_entry swaps the userland stack to the kernel
   * mode stack. Therefore, we masked the FLAG_FL. */
  write_msr(MSR_SYSCALL_MASK,
            FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED) {
  switch (f->R.rax) {
    case SYS_EXIT:
      exit(f->R.rdi);
      break;
    case SYS_WRITE:
      f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
      break;
  }
  // print("system call!") thread_exit();
}

void check_address(void *addr) {
  if (addr == NULL) exit(-1);
  // 유저 영역의 주소인지 확인
  if (!is_user_vaddr(addr)) exit(-1);
  // 할당된 영역인지 확인
  if (pml4_get_page(thread_current()->pml4, addr) == NULL) exit(-1);
}

int write(int fd, const void *buffer, unsigned size) {
  if (fd == STDIN_FILENO) {
    return -1;
  }

  if (fd == STDOUT_FILENO) {
    putbuf(buffer, size);
    return size;
  }

  struct file *file = process_get_file(fd);
  if (file == NULL) {
    return -1;
  }

  return (int)file_write(file, buffer, size);
}

void exit(int status) {
  struct thread *curr = thread_current();
  // curr->exit_status = status;
  printf("%s: exit(%d)\n", curr->name, status);
  thread_exit();
}