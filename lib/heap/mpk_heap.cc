#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <mutex>
#include <thread>
#include <mpt/mpt.h>
#include "mpk_heap.h"

#define LOGGING 1
#define __SOURCEFILE__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#define rlog(format, ...) { \
    if( LOGGING ) { \
        fprintf(stderr, "[smv] " format, ##__VA_ARGS__); \
        fflush(NULL);   \
    }\
}

FILE* fp;

struct mpk_metadata_struct *mpk[MAX_MEMDOM];
int cnt = 0;
std::mutex so_mutex;

static int mid;
static int central_pkey;
/* Create memory domain and return it to user */
int mpk_create(){
    int mpk_id;
    /*
    srand(time(0));
    std::unique_lock<std::mutex> lock(so_mutex);
    if (cnt < MAX_MEMDOM)
      mpk_id = ++cnt;
    else
      mpk_id = rand() % MAX_MEMDOM;
    lock.unlock();
    */
    std::unique_lock<std::mutex> lock(so_mutex);
    central_pkey = pkey_alloc(0, 1);
    mpk_id = central_pkey;
    rlog("central_pkey : %d\n", central_pkey);
    lock.unlock();
    /* Allocate metadata to hold mpk info */
#ifdef INTERCEPT_MALLOC
#undef malloc
#endif
    mpk[mpk_id] = (struct mpk_metadata_struct*) malloc(sizeof(struct mpk_metadata_struct));
#ifdef INTERCEPT_MALLOC
#define malloc(sz) mpk_alloc(mpk_private_id(), sz)
#endif
    mpk[mpk_id]->mpk_id = mpk_id;
    mpk[mpk_id]->start = NULL; // mpk_alloc will do the actual mmap
    mpk[mpk_id]->total_size = 0;
    mpk[mpk_id]->free_list_head = NULL;
    mpk[mpk_id]->free_list_tail = NULL;
    pthread_mutex_init(&mpk[mpk_id]->mlock, NULL);
    mid = mpk_id;
    return mpk_id;
}

/* Remove memory domain mpk from kernel */
int mpk_kill(int mpk_id){
    int rv = 0;
    char buf[50];
    struct free_list_struct *free_list;

    /* Bound checking */
    if( mpk_id > MAX_MEMDOM ) {
		fprintf(stderr, "mpk_kill(%d) failed\n", mpk_id);
        return -1;
    }

    /* Free mmap */
    if( mpk[mpk_id]->start ) {
        rv = munmap(mpk[mpk_id]->start, mpk[mpk_id]->total_size);
        if( rv != 0 ) {
            fprintf(stderr, "mpk munmap failed, start: %p, sz: 0x%lx bytes\n", mpk[mpk_id]->start, mpk[mpk_id]->total_size);
        }
    }

    /* Free all free_list_struct in this mpk */
    free_list = mpk[mpk_id]->free_list_head;
    while( free_list ) {
        struct free_list_struct *tmp = free_list;
        free_list = free_list->next;
        rlog("freeing free_list addr: %p, size: 0x%lx bytes\n", tmp->addr, tmp->size);
#ifdef INTERCEPT_MALLOC
#undef free
#endif
        free(tmp);
#ifdef INTERCEPT_MALLOC
#define free(addr) mpk_free(addr)
#endif
    }

    /* Free mpk metadata */
#ifdef INTERCEPT_MALLOC
#undef free
#endif
    free(mpk[mpk_id]);
#ifdef INTERCEPT_MALLOC
#define free(addr) mpk_free(addr)
#endif
    
    return rv;
}

/* mmap memory in mpk 
 * Caller should hold mpk lock
 */
void *mpk_mmap(int mpk_id,
                  unsigned long addr, unsigned long len, 
                  unsigned long prot, unsigned long flags, 
                  unsigned long fd, unsigned long pgoff){
    void *base = NULL;
    int rv = 0;
    char buf[50];

    /* Call the actual mmap with mpk flag */
    fp = fopen("/home/soyeon/log/log", "a+"); 
    mpk_create();
    base = (void*) mmap(NULL, len, prot, flags, fd, pgoff);
    std::unique_lock<std::mutex> lock(so_mutex);
    pkey_mprotect(base, len, prot, central_pkey); 
    lock.unlock();
    if( base == MAP_FAILED ) {
        perror("mpk_mmap: ");
        return NULL;
    }
    mpk[mpk_id]->start = base;
    mpk[mpk_id]->total_size = len;
    rlog("Memdom ID %d mmaped at %p\n", mpk_id, base);

    rlog("[%s] mpk %d mmaped 0x%lx bytes at %p\n", __func__, mpk_id, len, base);
    return base;
}



/* Get calling thread's defualt mpk id */
int mpk_private_id(void){
    int rv = 0;
    char buf[1024];
    rv= 1;

    rlog("private mpk id: %d\n", rv);    
    return rv;
}

void dumpFreeListHead(int mpk_id){
    struct free_list_struct *walk = mpk[mpk_id]->free_list_head;
    while ( walk ) {
        rlog("[%s] mpk %d free_list addr: %p, sz: 0x%lx\n", 
                __func__, mpk_id, walk->addr, walk->size);
        walk = walk->next;
    }
}

/* Insert a free list struct to the head of mpk free list 
 * Reclaimed chunks are inserted to head
 */
void free_list_insert_to_head(int mpk_id, struct free_list_struct *new_free_list){
    int rv;
    struct free_list_struct *head = mpk[mpk_id]->free_list_head;
    if( head ) {
        new_free_list->next = head;
    }
    mpk[mpk_id]->free_list_head = new_free_list;
    rlog("[%s] mpk %d inserted free list addr: %p, size: 0x%lx\n", __func__, mpk_id, new_free_list->addr, new_free_list->size);
}

/* Initialize free list */
void free_list_init(int mpk_id){
    struct free_list_struct *new_free_list;

    /* The first free list should be the entire mmap region */
#ifdef INTERCEPT_MALLOC
#undef malloc
#endif
    new_free_list = (struct free_list_struct*) malloc (sizeof(struct free_list_struct));
#ifdef INTERCEPT_MALLOC
#define malloc(sz) mpk_alloc(mpk_private_id(), sz)
#endif
    new_free_list->addr = mpk[mpk_id]->start;
    new_free_list->size = mpk[mpk_id]->total_size;   
    new_free_list->next = NULL;
    mpk[mpk_id]->free_list_head = NULL;   // reclaimed chunk are inserted to head   
    mpk[mpk_id]->free_list_tail = new_free_list; 
    rlog("[%s] mpk %d: free_list addr: %p, size: 0x%lx bytes\n", __func__, mpk_id, new_free_list->addr, new_free_list->size);
}

/* Round up the number to the nearest multiple */
unsigned long round_up(unsigned long numToRound, int multiple){
    int remainder = 0;
    if( multiple == 0 ) {
        return 0;
    }
    remainder = numToRound % multiple;
    if( remainder == 0 ) {
        return numToRound;
    }
    return numToRound + multiple - remainder;
}

void* mpk_malloc(unsigned long sz) {
  mpk_alloc(mpk_private_id(), sz);
}

/* Allocate memory in memory domain mpk */
void *mpk_alloc(int mpk_id, unsigned long sz) {
    char *memblock = NULL;
    struct free_list_struct *free_list = NULL;
    struct free_list_struct *prev = NULL;
    
    /* Memdom 0 is in global mpk, Memdom -1 when defined THREAD_PRIVATE_STACK, use malloc */
    if(mpk_id == 0){
#ifdef INTERCEPT_MALLOC
#undef malloc
#endif
    sz = round_up ( sz + sizeof(struct block_header_struct), CHUNK_SIZE);
        memblock = (char*) malloc(sz);   
#ifdef INTERCEPT_MALLOC
#define malloc(sz) mpk_alloc(mpk_private_id(), sz)
#endif
//        return memblock;
          goto out;
    }



    /* First time this mpk allocates memory */
    if( mpk[mpk_id] == NULL || !mpk[mpk_id]->start ) {
        /* Call mmap to set up initial memory region */
        memblock = (char*) mpk_mmap(mpk_id, 0, MEMDOM_HEAP_SIZE, 
                                       PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
        if( memblock == MAP_FAILED ) {
            fprintf(stderr, "Failed to mpk_alloc using mmap for mpk %d\n", mpk_id);
            memblock = NULL;
            goto out;
        }
      mem_start[mpk_id] = memblock;
      pthread_mutex_lock(&mpk[mpk_id]->mlock);
        /* Initialize free list */
        free_list_init(mpk_id);
    }
    else {
      pthread_mutex_lock(&mpk[mpk_id]->mlock);
    }
    rlog("[%s] mpk %d allocating sz 0x%lx bytes(%p)\n", __func__, mpk_id, sz, pthread_self());
    pkey_set_real(make_pkru(mpk_id, PKEY_ENABLE_ALL), mpk_id);

    /* Round up size to multiple of cache line size: 64B 
     * Note that the size of should block_header + the actual data
     * --------------------------------------
     * | block header |      your data       |
     * --------------------------------------
     */
    sz = round_up ( sz + sizeof(struct block_header_struct), CHUNK_SIZE);
    rlog("[%s] request rounded to 0x%lx bytes\n", __func__, sz);

    /* Get memory from the tail of free list, if the last free list is not available for allocation,
     * start searching the free list from the head until first fit is found.
     */
    free_list = mpk[mpk_id]->free_list_tail;
    if(!free_list) {
        rlog("[%s] free_list is NULL\n", __func__);
        free_list_init(mpk_id);
    }

    /* Allocate from tail: 
     * check if the last element in free list is available, 
     * allocate memory from it */
    rlog("[%s] mpk %d search from tail for 0x%lx bytes\n", __func__, mpk_id, sz);     
    rlog("[%s] free_list size: %d\n", free_list->size);
    if ( free_list && sz <= free_list->size ) {
        memblock = (char*)free_list->addr;

        /* Adjust the last free list addr and size*/
        free_list->addr = (char*)free_list->addr + sz;
        free_list->size = free_list->size - sz;

        rlog("[%s] mpk %d last free list available, free_list addr: %p, remaining sz: 0x%lx bytes\n", 
                __func__, mpk_id, free_list->addr, free_list->size);
        /* Last chunk is now allocated, tail is not available from now */
        if( free_list->size == 0 ) {
#ifdef INTERCEPT_MALLOC
#undef free
#endif
            free(free_list);
#ifdef INTERCEPT_MALLOC
#define free(addr) mpk_free(addr)
#endif
            mpk[mpk_id]->free_list_tail = NULL;
            rlog("[%s] free_list size is 0, freed this free_list_struct, the next allocate should request from free_list_head\n", __func__);
        }
        goto out;
    }

    /* Allocate from head: 
     * ok the last free list is not available, 
     * let's start searching from the head for the first fit */
    rlog("[%s] mpk %d search from head for 0x%lx bytes\n", __func__, mpk_id, sz);     
    dumpFreeListHead(mpk_id);
    free_list = mpk[mpk_id]->free_list_head;
    while (free_list) {
        if( prev ) {
            rlog("[%s] mpk %d prev->addr %p, prev->size 0x%lx bytes\n", __func__, mpk_id, prev->addr, prev->size);
        }
        if( free_list ) {
            rlog("[%s] mpk %d free_list->addr %p, free_list->size 0x%lx bytes\n", __func__, mpk_id, free_list->addr, free_list->size);
        }
        
        /* Found free list! */
        if( sz <= free_list->size ) {

            /* Get memory address */
            memblock = (char*)free_list->addr;

            /* Adjust free list:
             * if the remaining chunk size if greater then CHUNK_SIZE
             */
            if( free_list->size - sz >= CHUNK_SIZE ) {
                char *ptr = (char*)free_list->addr;
                ptr = ptr + sz;
                free_list->addr = (void*)ptr;
                free_list->size = free_list->size - sz;
                rlog("[%s] Adjust free list to addr %p, sz 0x%lx\n", 
                        __func__, free_list->addr, free_list->size);
            }
            /* Remove this free list struct: 
             * since there's no memory to allcoate from here anymore 
             */
            else{                
                if ( free_list == mpk[mpk_id]->free_list_head ) {
                    mpk[mpk_id]->free_list_head = mpk[mpk_id]->free_list_head->next;
                    rlog("[%s] mpk %d set free_list_head to free_list_head->next\n", __func__, mpk_id);
                }
                else {
                    prev->next = free_list->next;
                    rlog("[%s] mpk %d set prev->next to free_list->next\n", __func__, mpk_id);
                }
#ifdef INTERCEPT_MALLOC
#undef free
#endif
                free(free_list);
#ifdef INTERCEPT_MALLOC
#define free(addr) mpk_free(addr)
#endif

                rlog("[%s] mpk %d removed free list\n", __func__, mpk_id);
            }
            goto out;
        }

        /* Move pointer forward */
        prev = free_list;
        free_list = free_list->next;
    }   
   
out:   
    if( !memblock ) {
        fprintf(stderr, "mpk_alloc failed: no memory can be allocated in mpk %d\n", mpk_id);
    }
    else{    
        /* Record allocated memory in the block header for free to use later */
        struct block_header_struct header;
        header.addr = (void*)memblock;
        header.mpk_id = mpk_id;
        header.size = sz;
        //rlog("[%s] pkru : %p\n", __func__, rdpkru());
        memcpy(memblock, &header, sizeof(struct block_header_struct));
        memblock = memblock + sizeof(struct block_header_struct);
        rlog("[%s] header: addr %p, allocated 0x%lx bytes and returning data addr %p\n", __func__, header.addr, sz, memblock);
    }
    pthread_mutex_init(&mprotect_mutex[mpk_id], NULL);
    pkey_set_real(make_pkru(mpk_id, PKEY_DISABLE_ACCESS), mpk_id);
    pthread_mutex_unlock(&mpk[mpk_id]->mlock);
    return (void*)memblock;
}

/* Deallocate data in memory domain mpk */
void mpk_free(void* data){
    struct block_header_struct header;
    char *memblock = NULL;
    int mpk_id = -1;

    /* Read the header stored ahead of the actual data */
    memblock = (char*) data - sizeof(struct block_header_struct);
    memcpy(&header, memblock, sizeof(struct block_header_struct));
    mpk_id = header.mpk_id;
    //rlog("[%s] block addr: %p, header addr: %p, freeing 0x%lx bytes in mpk %d (%p)\n", __func__, memblock, header.addr, header.size, header.mpk_id, pthread_self());
    if(mpk_id == 0) {
#ifdef INTERCEPT_MALLOC
#undef free
#endif
      free(memblock);
#ifdef INTERCEPT_MALLOC
#define free(addr) mpk_free(addr)
#endif
      return;
    }
    if(mpk_id < 0 || mpk_id > MAX_MEMDOM)
      assert(!mpk_id);

    pthread_mutex_lock(&mpk[mpk_id]->mlock);
 
    /* Free the memory */
    memset(memblock, 0, header.size);

    /* Create a new free list node */
#ifdef INTERCEPT_MALLOC
#undef malloc
#endif
    struct free_list_struct *free_list = (struct free_list_struct *) malloc(sizeof(struct free_list_struct));
#ifdef INTERCEPT_MALLOC
#define malloc(sz) mpk_alloc(mpk_private_id(), sz)
#endif
    free_list->addr = memblock;
    free_list->size = header.size;
    free_list->next = NULL;

    /* Insert the block into free list head */
    free_list_insert_to_head(header.mpk_id, free_list);   

    pthread_mutex_unlock(&mpk[mpk_id]->mlock);
}

