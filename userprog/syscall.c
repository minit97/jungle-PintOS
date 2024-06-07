#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "intrinsic.h"

#include "lib/stdio.h"              // STDIN_FILENO, STDOUT_FILENO
#include "lib/string.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/synch.h"          // lock_init()
#include "threads/palloc.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "kernel/stdio.h"           // putbuf
#include "vm/file.h"


void syscall_entry (void);
void syscall_handler (struct intr_frame *);
int kernel_fork (const char *thread_name, struct intr_frame *f);
void *mmap (void *addr, size_t length, int writable, int fd, off_t offset);

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

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

    sema_init(&filesys_sema, 1);
}

/* The main system call interface */
void syscall_handler (struct intr_frame *f UNUSED) {
    /**
     * 1. Make system call handler call system call using system call number
     * 2. Check validation of the pointers in parameter list
     *      - These pointers must point to user area, not kernel area
     *      - If these pointers don't point the valid address, it is page fualt
     * 3. Copy arguments on the user stack to the kernel
     * 4. Save return value of system call at rax register
     */
//    uint64_t arg1 = f->R.rdi;
//    uint64_t arg2 = f->R.rsi;
//    uint64_t arg3 = f->R.rdx;
//    uint64_t arg4 = f->R.r10;
//    uint64_t arg5 = f->R.r8;
//    uint64_t arg6 = f->R.r9;
    thread_current()->rsp_stack = f->rsp;

    uint64_t system_call_num = f->R.rax;
    switch (system_call_num) {
        case SYS_HALT:
            halt();
            break;
        case SYS_EXIT:
            exit(f->R.rdi);
            break;
        case SYS_FORK:
            f->R.rax = kernel_fork(f->R.rdi, f);
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
        /**
         * project 3
         */
        case SYS_MMAP:
            f->R.rax = mmap(f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
            break;
        case SYS_MUNMAP:
            munmap(f->R.rdi);
            break;
        default:
            thread_exit ();
            break;
    }
}

/**
 * process syscall
 */
void halt (void) {
    /**
     * - Shutdown pintos
     * - Use void shutdonw_power_off(void)
     */
    power_off();
}

void exit (int status) {
    /**
     * - Exit process
     * - Use void thread_exit(void)
     * - It should print message "Name of process: exit(status)".
     */
    struct thread *cur = thread_current();
    cur->exit_status = status;

    printf("%s: exit(%d)\n", cur->name, status);
    thread_exit();
}

int exec (const char *cmd_line) {
    /**
     * process_execute() 함수를 호출하여 자식 프로세스 생성
     * 생성된 자식 프로세스의 프로세스 디스크립터를 검색
     * 자식 프로세스의 프로그램이 적재될 때까지 대기
     * 프로그램 적재 실패 시 -1, 성공 시 자식 프로세스의 pid 리턴
     */
    char *cmd_line_copy = palloc_get_page(0);
    if (cmd_line_copy == NULL) exit(-1);			// 메모리 할당 실패 시 status -1로 종료한다.
    strlcpy(cmd_line_copy, cmd_line, PGSIZE);           // cmd_line을 복사한다.

    // 스레드의 이름을 변경하지 않고 바로 실행한다.
    return process_exec(cmd_line_copy);
}

int kernel_fork (const char *thread_name, struct intr_frame *f) {
    return process_fork(thread_name, f);
}


int wait (int pid) {
    /**
     * - Wait for termination of child process whose process id is pid
     *
     * - Wait for a child process pid to exit and retrieve the child's exit status
     * - If pid is alive, wait till it terminates. Returns the status that pid passed to exit
     * - If pid did nt call exit, but was terminated by the kernel, return -1
     * - A parent process can call wait for the child process that the terminated. -> return exit status of the terminated child process
     * - After the child terminates, the parent should deallocate its process descriptor
     * - wait fails and return -1 if
     *      - pid does not refer to a direct child of the calling process
     *      - The process that calls wait has already called wait on pid
     */
    return process_wait(pid);
}



/**
 * file syscall
 */
bool create (const char *file, unsigned initial_size) {
    sema_down(&filesys_sema);
    check_address(file);
    bool result = filesys_create(file, initial_size);
    sema_up(&filesys_sema);

    return result;
}

bool remove (const char *file) {
    check_address(file);
    return filesys_remove(file);
}

int open (const char *file) {
    /**
     * returns fd
     */
    check_address(file);
    sema_down(&filesys_sema);

    struct file *opened_file = filesys_open (file);
    if (opened_file == NULL) {
        sema_up(&filesys_sema);
        return -1;
    }

    struct thread *curr = thread_current();
    struct file **fdt = curr->fdt;
    while(curr->next_fd <= 130){
        if (fdt[curr->next_fd] == NULL) {
            fdt[curr->next_fd] = opened_file;
            sema_up(&filesys_sema);
            return curr->next_fd;
        }
        curr->next_fd++;
    }

    file_close(opened_file);
    sema_up(&filesys_sema);
    return -1;
}

int filesize (int fd) {
    if (fd < 2 || fd > 130) return -1;

    struct thread *curr = thread_current();
    struct file **fdt = curr->fdt;
    struct file *file = fdt[fd];
    if (file == NULL) return -1;

    return file_length(file);
}

int read (int fd, void *buffer, unsigned size) {
    /**
     * 구현 사항
     * 1. fd == 0 : call input_getc
     * 2. fd != 1 and fd < 2 : return -1
     * 3. others : file find by fd and call file_read
     */
    check_address(buffer);

    sema_down(&filesys_sema);

    if (fd == STDIN_FILENO) {
        input_getc();
        sema_up(&filesys_sema);
        return size;
    }
    if (fd < 2 || fd > 130) {
        sema_up(&filesys_sema);
        return -1;
    }

    struct thread *curr = thread_current();
    struct file **fdt = curr->fdt;
    struct file *file = fdt[fd];
    if (file == NULL) {
        sema_up(&filesys_sema);
        return -1;
    }

    // project3 : pt-write-code2 test
    struct page *page = spt_find_page(&thread_current()->spt, buffer);
    if (page && !page->writable) {
        sema_up(&filesys_sema);
        exit(-1);
    }

    int result = file_read(file, buffer, size);
    sema_up(&filesys_sema);

    return result;
}

int write (int fd, const void *buffer, unsigned size) {
    /**
     * 구현 사항
     * 1. fd == 1 : call putbuf and return size
     * 2. fd != 1 and fd < 2 : return -1
     * 3. others : file find by fd and call file_write
     */
    check_address(buffer);

    sema_down(&filesys_sema);

    int result;
    if (fd == STDOUT_FILENO) {
        putbuf(buffer, size);
        sema_up(&filesys_sema);
        return size;
    }

    if (fd < 2 || fd > 130) {
        sema_up(&filesys_sema);
        return -1;
    }

    struct thread *curr = thread_current();
    struct file **fdt = curr->fdt;
    struct file *file = fdt[fd];
    if (file == NULL) {
        sema_up(&filesys_sema);
        return -1;
    }

    result = file_write(file, buffer, size);
    sema_up(&filesys_sema);

    return result;
}

void seek (int fd, unsigned position) {
    /**
     * Changes the next byte to be read or written in open file fd to position
     */
    if (fd < 2 || fd > 130) return;

    struct thread *curr = thread_current();
    struct file **fdt = curr->fdt;
    struct file *file = fdt[fd];
    if (file == NULL) return;

    file_seek(file, position);
}

unsigned tell (int fd) {
    /**
     * Return the position of the next byte to be read or written in open file fd
     */
    if (fd < 2 || fd > 130) return -1;

    struct thread *curr = thread_current();
    struct file **fdt = curr->fdt;
    struct file *file = fdt[fd];
    if (file == NULL) return;

    return file_tell(file);
}

void close (int fd) {
    /**
     * set 0 at file descriptor entry at index fd
     */
    if (fd < 2 || fd > 130) return;

    struct thread *curr = thread_current();
    struct file **fdt = curr->fdt;
    struct file *file = fdt[fd];
    if (file == NULL) return;

    file_close(file);
    fdt[fd] = NULL;
}

void check_address(void *addr) {
    /**
     * 주소 값이 유저 영역에서 사용하는 주소 값인지 확인하는 함수
     * PintOS에서는 시스템 콜이 접근할 수 있는 주소를 0x8048000 ~ 0xc0000000으로 제한함
     * 유저 영역을 벗어난 영역일 경우 프로세스 종료 exit(-1)
     */
    if (addr == NULL)
        exit(-1);
    // 포인터가 가리키는 주소가 유저영역의 주소인지 확인
    if (!is_user_vaddr(addr))
        exit(-1);
    // 해당 페이지맵은 커널 가상 주소에 대한 매핑을 가지고 있지만, 사용 주소에 대한 매핑은 없다.
//    if (pml4_get_page(thread_current()->pml4, addr) == NULL)
//        exit(-1);
}

/**
* project3
*/
// fd로 열린 파일을 offset 바이트로부터 프로세스의 가상 주소 공간의 addr에 length 바이트만큼 매핑한다.
void *mmap (void *addr, size_t length, int writable, int fd, off_t offset) {
    if (addr == NULL || addr != pg_round_down(addr)) return NULL;                   // 주소값이 NULL or 시작 주소값이 아니라면
    if (is_kernel_vaddr(addr) || is_kernel_vaddr(addr + length)) return NULL;       // 주소값이 커널 영역 or 길이가 저장값이 아니라서 유저 영역을 벗어난다면
    if (offset != pg_round_down(offset)) return NULL;                               // offset 값이 페이지의 시작점이 아니라면

    if (spt_find_page(&thread_current()->spt, addr)) return NULL;                   // addr에 할당된 페이지가 이미 존재하는 경우
    if (fd == 0 || fd == 1) return NULL;                                            // 콘솔 입력 및  출력을 나타내는 파일 디스크립터는 매핑할 수 없다.

    struct file *found_file = find_file_by_fd(fd);
    if (found_file == NULL) return NULL;
    if (file_length(found_file) == 0 || (int)length <= 0) return NULL;              // mmap 호출은 fd로 열린 파일의 길이가 0 바이트 경우 실패할 수 있다.

    return do_mmap(addr, length, writable, found_file, offset);                     // 파일이 매핑된 가상 주소 반환
}

void munmap (void *addr) {
    do_munmap(addr);
}

struct file *find_file_by_fd (int fd) {
    if (fd < 0 || fd > 130){
        return NULL;
    }

    struct thread *curr = thread_current();
    return curr->fdt[fd];
}