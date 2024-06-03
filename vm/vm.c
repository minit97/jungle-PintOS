/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "vm/file.h"

#include "threads/vaddr.h"



struct list frame_table;

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
    list_init(&frame_table);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable, vm_initializer *init, void *aux) {
    // 타입에 따라 적절한 이니셜라이져를 가져와 uninit_new를 호출하는 함수

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* Create the page, fetch the initialier according to the VM type,
		 * and then create "uninit" page struct by calling uninit_new. You
		 * should modify the field after calling the uninit_new. */
        struct page* page = (struct page*)malloc(sizeof(struct page));

        bool (*initializer)(struct page *, enum vm_type, void *);
        switch(VM_TYPE(type)) {
            case VM_ANON:
                initializer = anon_initializer;
                break;
            case VM_FILE:
                initializer = file_backed_initializer;
                break;
        }

        // uninit_new를 호출해 "uninit" 페이지 구조체를 생성
        uninit_new(page, upage, init, type, aux, initializer);
        page->writable = writable;

		/* Insert the page into the spt. */
        return spt_insert_page(spt, page);
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
    // spt_find_page: spt에서 va가 있는지를 찾는 함수, hash_find() 사용


    struct page *page = (struct page *)malloc(sizeof(struct page));
    // pg_round_down: 해당 va가 속해 있는 page의 시작 주소를 얻는 함수
    page->va = pg_round_down(va);

    // hash_find: Dummy page의 빈 hash_elem을 넣어주면, va에 맞는 hash_elem을 리턴해주는 함수 (hash_elem 갱신)
    struct hash_elem *e = hash_find(&spt->spt_hash, &page->hash_elem);

    free(page);

    return e == NULL ? NULL : hash_entry(e, struct page, hash_elem);
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page (struct supplemental_page_table *spt UNUSED, struct page *page UNUSED) {
    return hash_insert(&spt->spt_hash, &page->hash_elem) == NULL ? true : false; // 존재하지 않을 경우에만 삽입
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
    /**
     * palloc_get_page 호출하여 새 Frame를 가져오는 함수
     * 성공적으로 가져오면 프레임을 할당하고 멤버를 초기화한 후 반환
     */

    struct frame *frame = (struct frame*)malloc(sizeof(struct frame));

    //PAL_USER: 커널 풀 대신 유저 풀에서 메모리를 할당 받기 위함
    frame->kva = palloc_get_page(PAL_USER);

    if (frame->kva == NULL) {
        frame = vm_evict_frame();
        frame->page = NULL;

        return frame;
    }

    list_push_back (&frame_table, &frame->frame_elem);
    frame->page = NULL;

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);

	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED, bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;

	/* Validate the fault */
    if (addr == NULL || is_kernel_vaddr(addr)) return false;
    if (!not_present) return false;
    if (vm_claim_page(addr)) return true;

    struct thread *curr = thread_current();
    void *rsp_stack = is_kernel_vaddr(f->rsp) ? curr->rsp_stack : f->rsp;
    /*
        프레임 할당에 실패했을 때, 주소의 범위가 유효한지 확인하고 스택을 키움
        핀토스는 스택 사이즈 1MB로 제한함, 그 사이에 있어야 함
    */
    if (rsp_stack - 8 <= addr && USER_STACK - 0x100000 <= addr && addr <= USER_STACK) {
        vm_stack_growth(curr->stack_bottom - PGSIZE);
        return true;
    }
    return false;

}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
    // 프레임을 페이지에 할당하는 함수

	struct page *page = spt_find_page(&thread_current()->spt, va);
    if (page == NULL) false;

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool vm_do_claim_page (struct page *page) {
    // 실제로 프레임을 페이지에 할당하는 함수

	struct frame *frame = vm_get_frame ();
    if (frame == NULL) return false;

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* Insert page table entry to map page's VA to frame's PA. */
    struct thread *curr = thread_current();
    bool success = (pml4_get_page (curr->pml4, page->va) == NULL && pml4_set_page (curr->pml4, page->va, frame->kva, page->writable));

    return success ? swap_in(page, frame->kva) : false;
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
    hash_init (&spt->spt_hash, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED, struct supplemental_page_table *src UNUSED) {
    // scr에서 dst로 SPT을 복사하는 함수

    struct hash_iterator iterator;
    hash_first(&iterator, &src->spt_hash);

    while (hash_next(&iterator)) {
        // hash_cur: 현재 elem을 리턴하거나, table의 끝인 null 포인터를 반환하거나
        struct page *parent_page = hash_entry(hash_cur(&iterator), struct page, hash_elem);

        enum vm_type type = page_get_type(parent_page);
        void *upage = parent_page->va;
        bool writable = parent_page->writable;

        vm_initializer *init = parent_page->uninit.init;
        void *aux = parent_page->uninit.aux;

        if (parent_page->uninit.type & VM_MARKER_0) {
            struct thread *curr = thread_current();
            setup_stack(&curr->tf);
        } else if (parent_page->operations->type == VM_UNINIT) {    // 부모의 페이지 타입이 uninit인 경우
            if (!vm_alloc_page_with_initializer(type, upage, writable, init, aux)) {
                return false;
            }
        } else {                                                    // 부모의 페이지 타입이 uninit이 아니면 spt 추가만
            if (!vm_alloc_page(type, upage, writable) || !vm_claim_page(upage)) {
                return false;
            }
        }

        if (parent_page->operations->type != VM_UNINIT) {
            struct page* child_page = spt_find_page(dst, upage);
            memcpy(child_page->frame->kva, parent_page->frame->kva, PGSIZE);
        }
    }

    return true;
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* Destroy all the supplemental_page_table hold by thread and
	 * writeback all the modified contents to the storage. */

    struct hash_iterator iterator;
    hash_first(&iterator, &spt->spt_hash);

    while (hash_next(&iterator)) {
        // hash_cur: 현재 elem을 리턴하거나, table의 끝인 null 포인터를 반환하거나
        struct page *page = hash_entry(hash_cur(&iterator), struct page, hash_elem);

        if (page->operations->type == VM_FILE) {
            do_munmap(page->va);
        }
        free(page);
    }
    hash_destroy(&spt->spt_hash, spt_destroy);
}


/**
* Custom Func
*/
unsigned page_hash (struct hash_elem *elem, void *aux UNUSED) {
    // hash_entry: 해당 hash_elem을 가지고 있는 page를 리턴하는 함수
    struct page *page = hash_entry(elem, struct page, hash_elem);

    // hash_bytes: 해당 page의 가상 주소를 hashed index로 변환하는 함수
    return hash_bytes(&page->va, sizeof(page->va));
}

bool page_less (struct hash_elem *elema, struct hash_elem *elemb, void *aux UNUSED) {
    // page_less: 두 page의 주소값을 비교하여 왼쪽 값이 작으면 True 리턴하는 함수

    struct page *pagea = hash_entry(elema, struct page, hash_elem);
    struct page *pageb = hash_entry(elemb, struct page, hash_elem);

    return pagea->va < pageb->va;
}

void spt_destroy (struct hash_elem *e, void *aux UNUSED) {
    struct page *page = hash_entry(e, struct page, hash_elem);

    free(page);
}