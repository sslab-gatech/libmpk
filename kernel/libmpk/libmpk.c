#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/sched.h>
#include <linux/mman.h>
#include<linux/syscalls.h>
#include<linux/libmpk.h>

char *table;
HashEntry* mmap_table;
int *pkey_arr;

SYSCALL_DEFINE3(mpk_munmap, unsigned long, addr, size_t, len, int, id)
{
  mpt_node *mn = hash_get(id);
  memset(mn, 0, sizeof(mpt_node));
  //if(pkey_arr[mn->pkey] != -1)
  pkey_arr[mn->pkey] = -1;
  mn->pkey = -1;
  //printk("mpk_munmap\n");
  return sys_munmap(addr, len);
}

SYSCALL_DEFINE5(mpk_mmap, unsigned long, addr, unsigned long, len,
    unsigned long, prot, unsigned long, flags,
    int, id) {

  long raddr = sys_mmap_pgoff(addr, len, prot, flags, -1, 0);
  mpt_node mn = {.buf = (void*)raddr, .len = len, .prot = prot, .pkey = -1, .next = NULL, .id = id};
  hash_put(id, &mn);
  //printk("mpk_mmap\n");
  return raddr;
}

SYSCALL_DEFINE5(pkey_mprotect_set, unsigned long, start, unsigned long, len,
    unsigned long, prot, int, pkey,
    int, id) {
  pkey_arr[pkey] = id;
  mpt_node *mn = hash_get(id);
  mn->pkey = pkey;
  mn->prot = prot;
  //printk("pkey_mprotect_set\n");
  return sys_pkey_mprotect(start, len, prot, pkey);
}

SYSCALL_DEFINE5(pkey_mprotect_evict, unsigned long, start, unsigned long, len,
    unsigned long, prot, int, pkey,
    int, id) {
  mpt_node *mn = hash_get(id);
  mn->pkey = -1;
  //printk("pkey_mprotect_evict\n");
  return sys_pkey_mprotect(start, len, prot, pkey);
}
SYSCALL_DEFINE4(mprotect_exec, unsigned long, start, unsigned long, len,
    unsigned long, prot, int, pkey) {
  mpt_node* cur = hash_get(pkey_arr[pkey]);
  mpt_node* prev = NULL;

  // still has exec-only
  while(cur) {
    if(cur->buf == start) {
      if(!prev) {
        pkey_arr[pkey] = cur->next->id;
      }
      else if(cur->next) {
        prev->next = cur->next->next;
      }
      cur->pkey = -1;
      break;
    }
    prev = cur;
    cur = cur->next;
  }
  //printk("mprotect_exec\n");
  return sys_pkey_mprotect(start, len, prot, -1);
}

SYSCALL_DEFINE5(pkey_mprotect_exec, unsigned long, start, unsigned long, len,
    unsigned long, prot, int, pkey,
    int, id) {
  mpt_node *mn = hash_get(id);
  if(mn->prot == PROT_EXEC && prot != PROT_EXEC) {
    mpt_node* cur = hash_get(pkey_arr[mn->pkey]);
    mpt_node* prev = NULL;
    if(!cur->next) {
      // this is last exec-only page 
    } 
    else {
      // still has exec-only
      //PORT how to handle this case?
      while(cur) {
        if(cur->buf == start) {
          if(!prev) {
            pkey_arr[mn->pkey] = cur->next->id;
          }
          else if(cur->next) {
            prev->next = cur->next->next;
          }
          cur->pkey = -1;
          break;
        }
        prev = cur;
        cur = cur->next;
      }
    }
  }
  pkey_arr[pkey] = id;
  mn->pkey = pkey;
  mn->prot = prot;
  //printk("pkey_mprotect_exec\n");
  return sys_pkey_mprotect(start, len, prot, pkey);
}

SYSCALL_DEFINE5(pkey_mprotect_grouping, unsigned long, start, unsigned long, len,
    unsigned long, prot, int, grouping_key,
    int, id) {
  // TODO it's single link list now, but I will change to tree for binary search
  mpt_node* cur = hash_get(pkey_arr[grouping_key]);
  mpt_node *mn = hash_get(id);
  if (!cur->next) {
    cur->next = mn;
  }
  else {
    while (cur) {
      if(!cur->next) {
        cur->next = mn;
        break;
      }
      cur = cur->next;
    }
  }
  mn->pkey = grouping_key;

  //printk("pkey_mprotect_grouping\n");
  return sys_pkey_mprotect(start, len, prot, grouping_key);
}

void alloc_hash(void) {
  int i = 0;
	table = kzalloc(TABLE_SIZE * sizeof(HashEntry), GFP_KERNEL);
  memset(table, -1, 0x1000);
  pkey_arr = (int *) table;
  mmap_table = (HashEntry *)(table + 0x1000);
	for(i = 0; i < TABLE_SIZE; i++) {
		mmap_table[i].key = -1;
		memset(&mmap_table[i].value, 0, sizeof(mpt_node));
    mmap_table[i].value.pkey = -1;
  }
}
   
mpt_node* hash_get(int key) {
	int hash = (key % TABLE_SIZE);
  //printk("key : %d, %d\n", mmap_table[hash].key, key);
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

