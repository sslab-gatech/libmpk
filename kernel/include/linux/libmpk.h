
#ifndef _LINUX_LIBMPK
#define _LINUX_LIBMPK

#include <linux/slab.h>

typedef struct _mpt_node {
  void* buf;
  size_t len;
  int prot;
  int pkey;
  int id;
  struct _mpt_node* next;
  /* 
  _mpt_node(void* b, size_t l, int p) {
    buf = b;
    len = l;
    prot = p;
    pkey = -1; 
    next = NULL;
  } */
  //std::atomic_int cnt;
} mpt_node;

#define TABLE_SIZE 0x4000
typedef struct _HashEntry {
	int key;
	mpt_node value;
} HashEntry;

extern char *table;
extern int *pkey_arr;
extern HashEntry *mmap_table;

void alloc_hash(void); 
   
mpt_node* hash_get(int key);    

void hash_put(int key, mpt_node* value);



#endif
