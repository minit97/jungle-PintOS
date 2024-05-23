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

#include "kernel/stdio.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

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
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
    /**
     * 1. Make system call handler call system call using system call number
     * 2. Check validation of the pointers in parameter list
     *      - These pointers must point to user area, not kernel area
     *      - If these pointers don't point the valid address, it is page fualt
     * 3. Copy arguments on the user stack to the kernel
     * 4. Save return value of system call at rax register
     */
    uint64_t system_call_num = f->R.rax;
    uint64_t arg1 = f->R.rdi;
    uint64_t arg2 = f->R.rsi;
    uint64_t arg3 = f->R.rdx;
    uint64_t arg4 = f->R.r10;
    uint64_t arg5 = f->R.r8;
    uint64_t arg6 = f->R.r9;

//    printf("박현민 1. 시스템콜 rdi : %d\n" , arg1);    // 첫 번째 인자를 전달
//    printf("박현민 2. 시스템콜 rsi : %s\n" , arg2);    // 두 번째 인자를 전달
//    printf("박현민 3. 시스템콜 rdx : %d\n" , arg3);    // 반환 값 저장

    switch (system_call_num) {
        case SYS_HALT:
            halt();
            break;
        case SYS_EXIT:
            exit(arg1);
            break;
//        case SYS_FORK:
//            f->R.rax = fork(f->R.rsi, f);
//            break;
//        case SYS_EXEC:
//            f->R.rax = exec(f->R.rsi);
//            break;
//        case SYS_WAIT:
//            wait();
//            break;
//        case SYS_CREATE:
//            f->R.rax = create(arg1, arg2);
//            break;
//        case SYS_REMOVE:
//            remove();
//            break;
//        case SYS_OPEN:
//            open();
//            break;
//        case SYS_FILESIZE:
//            filesize();
//            break;
//        case SYS_READ:
//            read();
//            break;
        case SYS_WRITE:
            f->R.rax = write(arg1, arg2, arg3);
            break;
//        case SYS_SEEK:
//            seek();
//            break;
//        case SYS_TELL:
//            tell();
//            break;
//        case SYS_CLOSE:
//            close();
//            break;
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

int exec (const char *file) {
    /**
     * - Create child process and execute program corresponds to cmd_line on it
     *
     * - Run program which execute cmd_line
     * - Create thread and run. exec() in pintos is equivalent to fork() + exec() in Unix
     * - Pass the arguments to the program to be executed
     * - Return pid of the new child process
     * - If it fails to load the program or to create a process, return -1
     * - Parent process calling exec should wait until child process is created  and loads the executable completely
     */

}

int fork (const char *thread_name, struct intr_frame *f) {
    return process_fork(thread_name, f);
}

//
//int wait (pid_t pid) {
//    /**
//     * - Wait for termination of child process whose process id is pid
//     *
//     * - Wait for a child process pid to exit and retrieve the child's exit status
//     * - If pid is alive, wait till it terminates. Returns the status that pid passed to exit
//     * - If pid did nt call exit, but was terminated by the kernel, return -1
//     * - A parent process can call wait for the child process that the terminated. -> return exit status of the terminated child process
//     * - After the child terminates, the parent should deallocate its process descriptor
//     * - wait fails and return -1 if
//     *      - pid does not refer to a direct child of the calling process
//     *      - The process that calls wait has already called wait on pid
//     */
//
//    return -1;
//}
//
//

//
/**
 * file syscall
 */
bool create (const char *file, unsigned initial_size) {

    return false;
}

bool remove (const char *file) {

    return false;
}

int open (const char *file) {
    /**
     * returns fd
     */
     return 1;
}

int filesize (int fd) {
    return 1;
}

int read (int fd, void *buffer, unsigned length) {
    return 1;
}

int write (int fd, const void *buffer, unsigned size) {
    if (fd == 1) {
        putbuf(buffer, size);
        return size;
    }
    return -1;
}

void seek (int fd, unsigned position) {

}

unsigned tell (int fd) {

}

void close (int fd) {
    /**
     * set 0 at file descriptor entry at index fd
     */
}

//int dup2(int oldfd, int newfd) {
//
//}