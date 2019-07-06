#ifndef PKEY_H
#define PKEY_H

#include <unistd.h>

#define PKEY_ENABLE_ALL 0x0
#define PKEY_DISABLE_ACCESS 0x1
#define PKEY_DISABLE_WRITE 0x2
#define SYS_pkey_mprotect 0x149
#define SYS_pkey_alloc 0x14a
#define SYS_pkey_free 0x14b
#define __NR_mpt_mprotect 333
#define __NR_pkey_sync 334

#define make_pkru(pkey, rights) ((rights) << (2 * pkey))
struct mprot {
    void* start;
    size_t len;
    unsigned long prot;
    int pkey;
  };
static inline void 
wrpkru(unsigned int pkru) 
{ 
//unsigned int eax = pkru; 
//unsigned int ecx = 0; 
//unsigned int edx = 0;

asm volatile(".byte 0x0f,0x01,0xef\n\t" 
: : "a" (pkru), "c" (0), "d" (0)); 
}

static inline int
rdpkru() {
  register int eax, edx;
  asm volatile(".byte 0x0f, 0x01, 0xee\n\t"
      : "=a" (eax), "=d" (edx) : "c" (0));
  return eax;
}

static inline int
pkey_set(int pkru) 
{ 
asm volatile(".byte 0x0f,0x01,0xef\n\t" 
: : "a" (pkru), "c" (0), "d" (0)); 
return 0;
}

static inline int
pkey_set_real(int pkru, int pkey) 
{
  register int eax, edx;
  asm volatile(".byte 0x0f, 0x01, 0xee\n\t"
      : "=a" (eax), "=d" (edx) : "c" (0));
  asm volatile(".byte 0x0f, 0x01, 0xef\n\t"
      : : "a" ((eax & ~(0x3 << (pkey * 2))) | pkru), "c" (0), "d" (edx));
  //printf("%d\n", eax);
  return 0;
}

#ifdef __cplusplus
extern "C" {
#endif
int pkey_read(int idx);
int pkey_mprotect(void *ptr, size_t size, unsigned long orig_prot, unsigned long pkey) ;
int pkey_alloc(int, int);
int pkey_free(unsigned long pkey);

int evict_mprotect(struct mprot* m1, struct mprot* m2);
int pkey_sync(void);
#ifdef __cplusplus
}
#endif

#endif
