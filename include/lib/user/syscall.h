#ifndef __LIB_USER_SYSCALL_H
#define __LIB_USER_SYSCALL_H

#include <stdbool.h>
#include <debug.h>
#include <stddef.h>

/* Process identifier. */
typedef int pid_t;
#define PID_ERROR ((pid_t) -1)

/* Map region identifier. */
typedef int off_t;
#define MAP_FAILED ((void *) NULL)

/* Maximum characters in a filename written by readdir(). */
#define READDIR_MAX_LEN 14

/* Typical return values from main() and arguments to exit(). */
#define EXIT_SUCCESS 0          /* Successful execution. */
#define EXIT_FAILURE 1          /* Unsuccessful execution. */

/* Projects 2 and later. */
/* pintos를 종료한다 */
void halt (void) NO_RETURN;
/* 
현 동작중인 유저 프로그램을 종료한다.
종료 status를 커널에 반환한다.

status = 0 : 성공
status != 0 : 에러
*/
void exit (int status) NO_RETURN;
/*

*/
pid_t fork (const char *thread_name);
/*
현재 프로세스의 메모리 공간을 새로운 프로그램의 메모리로 덮어씌운다.
즉 PID는 변하지 않지만 실행 중인 프로그램만 바뀐다.
파일 디스크립터도 변하지 않는다.
*/
int exec (const char *file);
int wait (pid_t);
/*
파일 이름, 파일 사이즈를 기반으로 파일을 생성한다
*/
bool create (const char *file, unsigned initial_size);
/*
파일을 삭제한다. file 인자는 제거할 파일의 이름 및 경로 정보
성공 : true
실패 : false
*/
bool remove (const char *file);
/*
파일을 열 때 사용
성공 : fd 반환
실패 : -1 반환
*/
int open (const char *file);
/*
파일의 크기를 알려주는 시스템 콜
*/
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

int dup2(int oldfd, int newfd);

/* Project 3 and optionally project 4. */
void *mmap (void *addr, size_t length, int writable, int fd, off_t offset);
void munmap (void *addr);

/* Project 4 only. */
bool chdir (const char *dir);
bool mkdir (const char *dir);
bool readdir (int fd, char name[READDIR_MAX_LEN + 1]);
bool isdir (int fd);
int inumber (int fd);
int symlink (const char* target, const char* linkpath);

static inline void* get_phys_addr (void *user_addr) {
	void* pa;
	asm volatile ("movq %0, %%rax" ::"r"(user_addr));
	asm volatile ("int $0x42");
	asm volatile ("\t movq %%rax, %0": "=r" (pa));
	return pa;
}

static inline long long
get_fs_disk_read_cnt (void) {
	long long read_cnt;
	asm volatile ("movq $0, %rdx");
	asm volatile ("movq $1, %rcx");
	asm volatile ("int $0x43");
	asm volatile ("\t movq %%rax, %0": "=r" (read_cnt));
	return read_cnt;
}

static inline long long
get_fs_disk_write_cnt (void) {
	long long write_cnt;
	asm volatile ("movq $0, %rdx");
	asm volatile ("movq $1, %rcx");
	asm volatile ("int $0x44");
	asm volatile ("\t movq %%rax, %0": "=r" (write_cnt));
	return write_cnt;
}

#endif /* lib/user/syscall.h */
