#include "headers/pkey.h"
#include "headers/mpt.h"
#include <iostream>
#include <cstdio>
#include <climits>
//#include <map>
#include "headers/hash.h"
#include <atomic>
#include <string>
#include <thread>
#include <mutex>
#include <list>
#include <fcntl.h>
#include <cstring>
#include <map>

#define DEVICE_FILENAME "/dev/libmpk"  
#define DEBUG 0 
#define llog(format, ...) { \
    if( DEBUG ) { \
        fprintf(stdout, "[mpt] " format, ##__VA_ARGS__); \
        fflush(NULL);   \
    }\
}
 
static std::atomic_int cnt;

typedef struct _mpt_node {
  void* buf;
  size_t len;
  int prot;
  int pkey;
  int id;
  struct _mpt_node* next;
   _mpt_node(void* b, size_t l, int p) {
    buf = b;
    len = l;
    prot = p;
    pkey = -1;
    next = NULL;
  } 
  //std::atomic_int cnt;
} mpt_node;

struct _HashEntry {
  int key;
  mpt_node value;
};

typedef struct _stack_node {
  struct _stack_node* prev;
  struct _stack_node* next;
  int pkey;
  _stack_node(int id) {
    prev = NULL; next = NULL; pkey = id;
  }
} stack_node;

// Shared data structures

int* pkey_arr;

static int exec_pkey = -1;
static int threshold = 0;
static std::atomic_int n_pkey; 
static std::atomic_int n_mmap;
static struct _HashEntry *mmap_table;
static HashMap<stack_node*> stack;
static std::mutex stack_mutex;
static std::mutex protect_mutex;
static uint16_t pkey_indomain_map;
static uint16_t all_pkeys_mask = ((1U << 16) - 1);
// XXX do we need head?
static stack_node* head, *tail;
#define MPT_BIT(prot) (prot & (PROT_READ | PROT_WRITE))

mpt_node* hash_get(int key) {
	int hash = (key % TABLE_SIZE);
	while (mmap_table[hash].key != -1 && mmap_table[hash].key != key)
		hash = (hash + 1) % TABLE_SIZE;
	if (mmap_table[hash].key == -1)
		return NULL;
	else
		return &mmap_table[hash].value;
}

void hash_put(int key, mpt_node* value) {
	int hash = (key % TABLE_SIZE);
	while (mmap_table[hash].key != -1 && mmap_table[hash].key != key)
		hash = (hash + 1) % TABLE_SIZE;
/*	
 *	if (table[hash].key != -1) {
		table[hash].key = -1;
		table[hash].value = NULL;
	}	
  */
	mmap_table[hash].key = key;
  memcpy(&mmap_table[hash].value, value, sizeof(mpt_node));
//	table[hash].value = value;
}
static __always_inline unsigned long ffz(unsigned long word)
{
  asm("rep; bsf %1,%0"
      : "=r" (word)
      : "r" (~word));
  return word;
}

static inline int
pkey_set_mpt(int pkru, int pkey) 
{
  register int eax, edx;
  asm volatile(".byte 0x0f, 0x01, 0xee\n\t"
      : "=a" (eax), "=d" (edx) : "c" (0));
  asm volatile(".byte 0x0f, 0x01, 0xef\n\t"
      : : "a" ((eax & ~(0x3 << (pkey * 2))) | pkru), "c" (0), "d" (edx));
  return 0;
}

static inline int mpt_update(int pkey, int prot, bool synch) {
  unsigned int pkru = -1;
  if(prot & PROT_WRITE) {
    pkru = make_pkru(pkey, PKEY_ENABLE_ALL); 
  }
  else if(prot & PROT_READ) {
    pkru = make_pkru(pkey, PKEY_DISABLE_WRITE);
  }
  else {
    pkru = make_pkru(pkey, PKEY_DISABLE_ACCESS);
  }
  pkey_set_mpt(pkru, pkey);
  if(synch)
    pkey_sync();
  return 0;
}

static inline int mpt_find(bool domain) {
  for(int i = START_PKEY ; i < MAX_PKEY; i++) {
    llog("pkey_arr[%d] : %d\n", i, pkey_arr[i]);
    if(pkey_arr[i] == -1) {
      stack_mutex.lock();
      stack.put(i, new stack_node(i));
      stack_mutex.unlock();
      return i;
    }
  }

  if(true) {
    cnt.fetch_add(1, std::memory_order_relaxed);
    if(cnt < threshold) {
      return -1;
    }

    int i = tail->prev->pkey;
    mpt_node* mn = hash_get(pkey_arr[i]);
    
    if(domain) {
      //check bitmap and change i
      if((pkey_indomain_map &= (1 << i))) {
        if(pkey_indomain_map == all_pkeys_mask) {
          return -1;
          // every pkey is used in domain.
        }
        else {
          i = ffz(pkey_indomain_map);
        }
      }
      // evict
      syscall(337, mn->buf, mn->len, PROT_NONE, 0, pkey_arr[i]);
    }
    else {
      // evict
      syscall(337, mn->buf, mn->len, mn->prot, 0, pkey_arr[i]);
    }
    // pkey_arr[i] = -1;
    cnt = 0;
    return i;
  }

  //evict... but it should be unreachable
  mpt_node* mn = hash_get(pkey_arr[15]);
  syscall(337, mn->buf, mn->len, mn->prot, 0, pkey_arr[15]);
  return 15;
}

int mpt_init(int evict_rate)
{
  for(int i = START_PKEY; i < MAX_PKEY; i++) {
    pkey_alloc(0, 0);
  }
  threshold = evict_rate + 1;
  head = new stack_node(-1); tail = new stack_node(-1);
  head->next = tail;
  tail->prev = head;
  // 0 index is always allocated.
  pkey_indomain_map = 1;
  n_mmap = 0; cnt = 0;
  int fd = open(DEVICE_FILENAME, O_RDWR | O_NDELAY);
  char* p;
  if(fd >= 0) {
    p = (char *)mmap(0, 0x1000 + TABLE_SIZE * sizeof(struct _HashEntry), PROT_READ, MAP_SHARED, fd, 0);
  }
  pkey_arr = (int *) p;
  mmap_table = (struct _HashEntry*)( p + 0x1000);


  return 0;
}

int mpt_mmap(void** addr, size_t length, int prot, int flags) 
{
  
  static std::atomic_int m_cnt;
  int id = m_cnt.fetch_add(1, std::memory_order_relaxed);
  void* r_addr = (void *)syscall(335, NULL, length, prot, flags | MAP_ANONYMOUS | MAP_PRIVATE, id);
  //mpt_node* mn = hash_get(id); //new mpt_node(r_addr, length, prot);
  //hash_put(id, mn);
  *addr = r_addr;
  n_mmap.fetch_add(1, std::memory_order_relaxed);

  return id;
}

inline int do_mpt_mprotect(mpt_node* mn, int prot, int grouping_key, bool domain, int id) 
{
  int ret = 2;

  void* buf = mn->buf;
  size_t len = mn->len;
  int pkey = mn->pkey;
  // I will save is_exec instead of mn->prot
  int mn_prot = mn->prot;
  
  if(grouping_key == -1) {
    if(pkey == -1) {
      ret = 1;
      pkey = mpt_find(domain);
      if(pkey == -1 && !domain) {
        mprotect(buf, len, prot);
        llog("mprotect\n");
        return 0;
      }
      else if(pkey == -1 && domain) {
        llog("already MAX_PKEY\n");
        return -1;
      }
      if(prot == PROT_EXEC && exec_pkey == -1) {
        exec_pkey = pkey;
      }

      syscall(336, buf, len, (DEFAULT_PROT | prot), pkey, id);
    }
    else {
      // existing entry
      if (!domain && (mn_prot == PROT_EXEC) && (prot != PROT_EXEC)) {
        // previous permission was exec-only, but current permission is not
        mpt_node* cur = hash_get(pkey_arr[pkey]);
        mpt_node* prev = NULL;
        if(!cur->next) {
          // this is last exec-only page 
          exec_pkey = -1;
        } 
        else {
          // still has exec-only
          int tmp_pkey = pkey;
          pkey = mpt_find(domain);
          if(pkey == -1 && !domain) {
            syscall(340, buf, len, prot, tmp_pkey);
            llog("mprotect\n");
            return 0;
          }
          else if(pkey == -1 && domain) {
            llog("already MAX_PKEY\n");
            return -1;
          }
//          mn->pkey = pkey;
//          pkey_arr[pkey] = id;
        }
      }
      // previous permission had exec, but current permission is not, or vice versa
      if (((mn_prot | PROT_EXEC) && !(prot | PROT_EXEC)) || (!(mn_prot | PROT_EXEC) && (prot | PROT_EXEC) ) ) {
        syscall(339, buf, len, (DEFAULT_PROT | prot), pkey, id);
//        pkey_mprotect_exec(buf, len, (DEFAULT_PROT | prot), pkey);
      }
    }
    // only non domain (mpt_mprotect) need synch 
    mpt_update(pkey, prot, !domain);
  }
  else {
    syscall(338, buf, len, (DEFAULT_PROT | prot), grouping_key, id);
    //
    mpt_update(grouping_key, prot, !domain);
  }

  if(!(prot == PROT_EXEC && !domain)) {
    stack_mutex.lock();
    stack_node* cur = stack.get(pkey);
    mn;
    if(cur->prev)
      cur->prev->next = cur->next;
    if(cur->next)
      cur->next->prev = cur->prev;
    if(head->next) {
      cur->next = head->next;
      head->next->prev = cur;
    }
    cur->prev = head;
    head->next = cur;
    stack_mutex.unlock();
  }
// I can remove this because prot has to be changed only when it includes EXEC permission.
//  mn->prot = prot;
//
  return ret;
}

// synch
int mpt_mprotect(int id, int prot) {
  if(id == -1)
    return -1;
  mpt_node* mn = hash_get(id);
  if(mn == NULL)
    return -1;
  int grouping_key = -1;
  if (prot == PROT_EXEC) {
    if(exec_pkey != -1) {
      grouping_key = exec_pkey;
    }
  }
  return do_mpt_mprotect(mn, prot, grouping_key, false, id);
}

int mpt_begin(int id, int prot) {
  if(id == -1)
    return -1;
  mpt_node* mn = hash_get(id);
  if(mn == NULL)
    return -1;
  pkey_indomain_map |= (1 << mn->pkey);
  return do_mpt_mprotect(mn, prot, -1, true, id);
}

int mpt_end(int id) {
  if(id == -1)
    return -1;
  mpt_node* mn = hash_get(id);
  if(mn == NULL)
    return -1;
  pkey_indomain_map &= ~(1 << mn->pkey);
  return do_mpt_mprotect(mn, PROT_NONE, -1, true, id);
}

int mpt_destroy(int id)
{
  n_mmap.fetch_sub(1, std::memory_order_relaxed);
  mpt_node* mn = hash_get(id);
  if(mn == NULL) {
    llog("already destroy\n");
    return -1;
  }

  void* buf = mn->buf;
  size_t len = mn->len;
  int pkey = mn->pkey;

  // if(pkey != -1)
  //   pkey_arr[pkey].pkey = -1;
  //delete mn;
  //hash_put(id, NULL);
  syscall(341, buf, len, id);
  //
  return 0;
}

