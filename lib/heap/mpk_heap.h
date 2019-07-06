#ifndef MEMDOM_LIB_H
#define MEMDOM_LIB_H

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/mman.h>
#include "pkey.h"

/* Permission */
#define MEMDOM_READ             0x00000001
#define MEMDOM_WRITE            0x00000002
#define MEMDOM_EXECUTE          0x00000004
#define MEMDOM_ALLOCATE         0x00000008

/* MMAP flag for mpk protected area */
#define MAP_MEMDOM	0x00800000	

/* Maximum heap size a mpk can use: 1GB */
#define MEMDOM_HEAP_SIZE 0x40000000
//#define MEMDOM_HEAP_SIZE 0x1000

/* Maximum number of mpks a thread can have: 1024*/
#define MAX_MEMDOM 16

/* Minimum size of bytes to allocate in one chunk */
#define CHUNK_SIZE 64

//#define INTERCEPT_MALLOC
#ifdef INTERCEPT_MALLOC
#define malloc(sz) mpk_alloc(mpk_private_id(), sz)
#define calloc(a,b) mpk_alloc(mpk_private_id(), a*b)
#define free(addr) mpk_free(addr)
#endif

/* Free list structure
 * A free list struct records a block of memory available for allocation.
 * mpk_alloc() allocates memory from the tail of the free list (usually the largest available block).
 * mpk_free() inserts free list to the head of the free list
 */
struct free_list_struct {
    void *addr;
    unsigned long size;
    struct free_list_struct *next;
};

/* Every allocated chunk of memory has this block header to record the required
 * metadata for the allocator to free memory
 */
struct block_header_struct {
    void *addr;
    int mpk_id;
    unsigned long size;    
};

/* Memory domain metadata structure
 * A memory domain is an anonymously mmap-ed memory area.
 * mmap() is called when mpk_alloc is called the first time for a given mpk 
 * Subsequent allocation does not invoke mmap(), instead, it allocates memory from the mmaped
 * area and update related metadata fields. 
 */
struct mpk_metadata_struct {
    int mpk_id;
    void *start;    // start of this mpk's addr (inclusive)
    unsigned long total_size; // the total memory size of this mpk
    struct free_list_struct *free_list_head;
    struct free_list_struct *free_list_tail;
    pthread_mutex_t mlock;  // protects this mpk in sn SMP environment
};
extern int cnt;
void* mem_start[3];
pthread_mutex_t mprotect_mutex[3];
extern struct mpk_metadata_struct *mpk[MAX_MEMDOM];

#ifdef __cplusplus
extern "C" {
#endif

/* Create memory domain and return it to user */
int mpk_create(void);

/* Remove memory domain mpk from kernel */
int mpk_kill(int mpk_id);

/* Allocate memory region in memory domain mpk */
void *mpk_mmap(int mpk_id, 
                  unsigned long addr, unsigned long len, 
                  unsigned long prot, unsigned long flags, 
                  unsigned long fd, unsigned long pgoff);

/* Allocate npages pages in memory domain mpk */
void *mpk_alloc(int mpk_id, unsigned long nbytes);
void *mpk_malloc(unsigned long nbytes);

/* Deallocate npages pages in memory domain mpk */
void mpk_free(void* data);

/* Get the calling thread's defualt mpk id */
int mpk_private_id(void);

#ifdef __cplusplus
}
#endif

#endif
