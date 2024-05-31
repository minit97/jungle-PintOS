#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"
#endif
#include "userprog/syscall.h"

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);
static bool duplicate_pte (uint64_t *pte, void *va, void *aux);

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {  // process_execute()
	char *fn_copy;
	tid_t tid;

	/* Make a copy of FILE_NAME. Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);

    /** PHM
     * 1. Parse the string of file_name
     * 2. Forward first token as name of new process to thread_create() function
     */
    char *thread_name, *next_file_ptr;
    thread_name = strtok_r (file_name, " ", &next_file_ptr);

	/* Create a new thread to execute FILE_NAME. */
	tid = thread_create (thread_name, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init ();

	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();                             // #define NOT_REACHED() PANIC ("executed an unreachable statement");
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_) {
	/* Clone current thread to new thread.*/
    struct thread *cur = thread_current();
    memcpy(&cur->parent_if, if_, sizeof(struct intr_frame));

    tid_t pid = thread_create (name, PRI_DEFAULT, __do_fork, cur);
    if (pid == TID_ERROR) return TID_ERROR;

    // 자식이 로드될 때까지 대기하기 위해서 방금 생성한 자식 스레드를 찾는다.
    struct thread *child = get_child_process(pid);

    // 생성만 완료, 생성 후 ready_list에 들어가고 실행될 때 __do_fork가 실행
    // __do_fork 함수가 실행되어 로드가 완료될 때까지 부모는 대기
    sema_down(&child->load_sema);

	return pid;
}

/* A thread function that copies parent's execution context.                                    // 부모의 실행 컨텍스트를 복사하는 스레드 함수이다.
 * Hint) parent->tf does not hold the userland context of the process.                          // 힌트) parent->tf는 프로세스의 사용자 및 컨텍스트를 보유하지 않는다.
 *       That is, you are required to pass second argument of process_fork to this function.    // 즉, prcess_fork의 두번째 인수를 이 함수에 전달해야
 */
static void
__do_fork (void *aux) {
    struct intr_frame if_;
    struct thread *parent = (struct thread *) aux;
    struct thread *current = thread_current ();

    /* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
    struct intr_frame *parent_if = &parent->parent_if;
    bool succ = true;

    /* 1. Read the cpu context to local stack. */
    memcpy (&if_, parent_if, sizeof (struct intr_frame));
    if_.R.rax = 0;  // 자식 프로세스의 리턴값은 0

    /* 2. Duplicate PT */
    current->pml4 = pml4_create();
    if (current->pml4 == NULL)
        goto error;

    process_activate (current);
#ifdef VM
    supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
    if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
        goto error;
#endif

    /* TODO: Your code goes here.
     * TODO: Hint) To duplicate the file object, use `file_duplicate`
     * TODO:       in include/filesys/file.h. Note that parent should not return
     * TODO:       from the fork() until this function successfully duplicates
     * TODO:       the resources of parent.*/
    current->fdt[0] = parent->fdt[0];
    current->fdt[1] = parent->fdt[1];
    for (int i = 2; i <= 130; i++) {
        struct file *file = parent->fdt[i];
        if (file == NULL) continue;
        current->fdt[i] = file_duplicate(file);
    }

    current->next_fd = parent->next_fd;
    sema_up(&current->load_sema);   // 로드가 완료될 때까지 기다리고 있던 부모 대기 해제

    process_init ();

    /* Finally, switch to the newly created process. */
    if (succ)
        do_iret (&if_);
    error:
        current->exit_status = TID_ERROR;
        sema_up(&current->load_sema);
        exit(TID_ERROR);
//        thread_exit ();
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
    if (is_kernel_vaddr(va)) return true;

	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);
    if (parent_page == NULL) return false;

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
    newpage = palloc_get_page(PAL_USER | PAL_ZERO);
    if (newpage == NULL) return false;

	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
    memcpy(newpage, parent_page, PGSIZE);
    writable = is_writable(pte);

	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
        return false;
	}
	return true;
}
#endif



/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int process_exec (void *f_name) {   // start_process()
	char *file_name = f_name;
	bool success;

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
	process_cleanup ();

    /** PHM
     * 1. Parse file_name
     */
    char *token, *save_ptr;
    char *argv[130];
    int argc = 0;
    for (token = strtok_r(file_name, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ", &save_ptr)) {
        argv[argc++] = token;
    }

	/* And then load the binary */
    // file_name : program name | &if_.rip : Function entry point | &if_.rsp : Stack top(user stack)
    lock_acquire(&filesys_lock);
//    printf("load 전 \n");
    success = load (argv[0], &_if);
//    printf("load 후 \n");
    lock_release(&filesys_lock);

    /** PHM
     * 2. Save tokens on user stack of new process
     */
    argument_stack(argv, argc, &_if.rsp);
    _if.R.rdi = argc;               // argc: main함수가 받은 인자의 수
    _if.R.rsi = _if.rsp + 8;        // argv: main 함수가 받은 각각의 인자들

    /**
    * 메모리 적재 완료 시 부모 프로세스 다시 진행 (세마포어 이용)
    */
	/* If load failed, quit. */
	palloc_free_page (file_name);
    // sema_up(&global_sema);

	if (!success)
        return -1;
	/* Start switched process. */
	do_iret (&_if);
	NOT_REACHED ();
}


/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid UNUSED) {     // The OS quits without waiting for the process to finish!
    struct thread *child = get_child_process(child_tid);
    if (child == NULL) return -1;

    // 자식 종료 대기
    sema_down(&child->wait_sema);
    list_remove(&child->child_elem);

    // 자식 종료 후 스케줄링을 위해 자식에 signal 전달
    sema_up(&child->exit_sema);

    return child->exit_status;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */
    for (int i = 2; i <= 130; i++)
        close(i);

    palloc_free_multiple(curr->fdt, 3);
    file_close(curr->running);      // 현재 실행 중인 파일을 닫는다.
    process_cleanup ();

    sema_up(&curr->wait_sema);      // 자식 종료를 대기하고 있는 부모에게 signal 전달
    sema_down(&curr->exit_sema);    // 부모의 signal 대기, 대기가 풀리면 do_schedule(THREAD_DYING) 후 다른 스레드 실행
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.          * FILE_NAME에서 ELF 실행 파일을 현재 스레드로 로드합니다.
 * Stores the executable's entry point into *RIP                            * 실행 파일의 진입 지점을 *RIP에 저장하고
 * and its initial stack pointer into *RSP.                                 * 초기 스택 포인터를 *RSP에 저장합니다.
 * Returns true if successful, false otherwise.                             * 성공하면 true를 반환하고, 그렇지 않으면 false를 반환합니다. */
static bool
load (const char *file_name, struct intr_frame *if_) {
    /* Load a ELF file
     * - Create page table (2 level paging)
     * - Open the file, read the ELF header
     * - Parse the file, load the 'data' to the data segment
     * - Create user stack and initialize it
     */

	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
    /**
     * create page directory
     * 유저 프로세스의 페이지 테이블 생성
     * 페이지 디렉토리 생성
     */
	t->pml4 = pml4_create();
	if (t->pml4 == NULL)
		goto done;
    /**
     * set cr3 register
     * PDBR(cr3) 레지스터 값을 실행중인 스레드의 페이지 테이블 주소로 변경
     * 페이지 테이블 활성화
     */
	process_activate (thread_current ());

	/* Open executable file. */
	file = filesys_open (file_name);    // 프로그램 파일 open
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}
    t->running = file;          // 스레드가 삭제될 때 파일을 닫을 수 있게 구조체에 파일을 저장해둔다.
//    file_deny_write(file);      // 현재 실행중인 파일은 수정할 수 없게 막는다.

	/* Read and verify executable header. */
    /**
     * ELF 파일의 헤더 정보를 읽어와 저장
     */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
        /**
         * 배치 정보를 읽어와 저장
         */
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
                    // load the executable file
                    /**
                     * 배치정보를 통해 파일을 메모리에 적재
                     */
					if (!load_segment (file, file_page, (void *) mem_page, read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	/* Set up stack. */
	if (!setup_stack (if_))     // initializing use stack, rsp : 스택 포인터 주소
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;    // initialize entry point, rip : text 세그먼트 시작 주소

	success = true;

done:
	/* We arrive here whether the load is successful or not. */
//	file_close (file);      // 파일을 여기서 닫지 않고 스레드가 삭제될 때 process_exit에서 닫는다.
	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	return success;
}
#endif /* VM */


void argument_stack(char **argv, int argc, void **rsp) {  // User Stack 저장
    char *argv_address[argc];
    uint8_t size = 0;

    // argv 문자열
    for (int i = argc - 1; i >= 0; i--) {
        *rsp -= (strlen(argv[i]) + 1);                 // string length + 1byte(\n) - null pointer sentinel
        memcpy(*rsp, argv[i], strlen(argv[i]) + 1);
        size += strlen(argv[i]) + 1;
        argv_address[i] = *rsp;
    }

    // word-align : 첫 번째 push 이전에 스택 포인터를 8의 배수로 내림하여 정렬
    if(size % 8) {
        int padding = 8 - (size % 8);
        *rsp -= padding;
        memset(*rsp, 0, padding);
    }

    // 배열의 끝을 나타내기 위해 null pointer sentinel 추가
    *rsp -= 8;
    memset(*rsp, 0, 8);

    // argv 주소
    for (int i = argc - 1; i >= 0; i--) {
        *rsp -= 8;                                      // 포인터니깐 8byte
        memcpy(*rsp, &argv_address[i], 8);
    }

    // return address(fake)
    *rsp -= 8;
    memset(*rsp, 0, 8);
}


struct thread *get_child_process (int pid) {
    /**
     * 자식 리스트에 접근하여 프로세스 디스크립터 검색
     * 해당 pid가 존재하면 프로세스 디스크립터 반환
     * 리스트에 존재하지 않으면 NULL 리턴
     */
     struct thread *cur = thread_current();
     struct list *child_list = &cur->child_list;
     for (struct list_elem *e = list_begin(child_list); e != list_end(child_list); e = list_next(e)) {
         struct thread *t = list_entry(e, struct thread, child_elem);
         if (t->tid == pid) {
             return t;
         }
     }
     return NULL;
}

void remove_child_process (struct thread *cp) {
    /**
     * 자식 리스트에서 제거
     * 프로세스 디스크립터 메모리 해제
     */
}