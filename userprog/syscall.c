#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "include/filesys/file.h"
#include "include/filesys/filesys.h"
#include "include/lib/stdio.h"
#include "include/threads/palloc.h"
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

int fork(const char *thread_name, struct intr_frame *f);

struct lock filesys_lock;  // 파일 점유 시 필요한 락

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
  lock_init(&filesys_lock);
}

/* The main system call interface */
void syscall_handler(
    struct intr_frame *f
        UNUSED) {  // user level에서의 프로세스 실행 정보(intr_frame)
  switch (f->R.rax) {
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      exit(f->R.rdi);
      break;
    case SYS_FORK:
      f->R.rax = fork(f->R.rdi, f);
      break;
    case SYS_EXEC:
      f->R.rax = exec(f->R.rdi);
      break;
    case SYS_WAIT:
      f->R.rax = wait(f->R.rdi);
      break;
    case SYS_CREATE:
      f->R.rax = create(f->R.rdi, f->R.rsi);
      break;
    case SYS_REMOVE:
      f->R.rax = remove(f->R.rdi);
      break;
    case SYS_OPEN:
      f->R.rax = open(f->R.rdi);
      break;
    case SYS_FILESIZE:
      f->R.rax = filesize(f->R.rdi);
      break;
    case SYS_READ:
      f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
      break;
    case SYS_WRITE:
      f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
      break;
    case SYS_SEEK:
      seek(f->R.rdi, f->R.rsi);
      break;
    case SYS_TELL:
      f->R.rax = tell(f->R.rdi);
      break;
    case SYS_CLOSE:
      close(f->R.rdi);
      break;
    default:
      exit(-1);
      break;
  }
}

void check_address(void *addr) {
  if (addr == NULL) exit(-1);
  // 유저 영역의 주소인지 확인
  if (!is_user_vaddr(addr)) exit(-1);
  // 할당된 영역인지 확인
  if (pml4_get_page(thread_current()->pml4, addr) == NULL) exit(-1);
}

int write(int fd, const void *buffer, unsigned size) {
  int write_bytes = 0;
  check_address(buffer);

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
  lock_acquire(&filesys_lock);
  write_bytes = (int)file_write(file, buffer, size);
  lock_release(&filesys_lock);

  return write_bytes;
}

void exit(int status) {
  struct thread *curr = thread_current();
  curr->exit_code =
      status;  // 이 값을 통해 부모 프로세스는 자식 프로세스가 종료되었는지 확인
  printf("%s: exit(%d)\n", curr->name, status);
  thread_exit();
}

void halt(void) { power_off(); }

bool create(const char *file, unsigned initial_size) {
  check_address(file);

  if (file == NULL || initial_size < 0) {
    exit(-1);
  }

  return filesys_create(file, initial_size);
}

bool remove(const char *file) {
  check_address(file);

  if (file == NULL) {
    exit(-1);
  }

  return filesys_remove(file);
}

int filesize(int fd) {
  struct file *file = process_get_file(fd);

  if (file == NULL) {
    return -1;
  }
  return file_length(file);
}

/*
fd로 지정된 열린 파일에서 다음 읽기나 쓰기 작업을 시작할 위치를 변경
position : 파일의 시작점으로부터의 오프셋을 바이트 단위로 나타냄
*/
void seek(int fd, unsigned position) {
  struct file *open_file = process_get_file(fd);
  if (open_file == NULL) {
    return;
  }

  file_seek(open_file, position);
}

/*
다음 읽기나 쓰기 작업이 발생할 위치 반환
파일의 시작점으로부터 오프셋을 바이트 단위로 나타낸다
*/
unsigned tell(int fd) {
  struct file *open_file = process_get_file(fd);
  if (open_file = NULL) {
    return;
  }

  return file_tell(open_file);
}

/*
파일의 현 위치에서 데이터를 읽는다
*/
int read(int fd, void *buffer, unsigned size) {
  int read_bytes = 0;
  check_address(buffer);

  if (fd == STDIN_FILENO) {
    return input_getc();
  }

  struct file *open_file = process_get_file(fd);
  if (open_file == NULL) {
    return -1;
  }
  lock_acquire(&filesys_lock);
  read_bytes = file_read(open_file, buffer, size);
  lock_release(&filesys_lock);

  return read_bytes;
}

int open(const char *file_name) {
  check_address(file_name);

  lock_acquire(&filesys_lock);
  struct file *open_file = filesys_open(file_name);
  if (open_file == NULL) {
    lock_release(&filesys_lock);
    return -1;
  }

  int fd = process_add_file(open_file);
  if (fd == -1) file_close(open_file);
  lock_release(&filesys_lock);
  return fd;
}

void close(int fd) {
  struct file *open_file = process_get_file(fd);

  if (open_file == NULL) exit(-1);
  file_close(open_file);
  process_close_file(fd);
}

tid_t fork(const char *thread_name,
           struct intr_frame *f) {  // 유저 영역 인터럽트 프레임
  return process_fork(thread_name, f);
}

int wait(int pid) { return process_wait(pid); }

int exec(const char *cmd_line) {
  check_address(cmd_line);

  if (process_exec(cmd_line) == -1) {
    exit(-1);
  }

  NOT_REACHED();  // exec 성공 시 해당 코드는 실행될 수 없다
}