#ifndef PKEY_H
#define PKEY_H

#include <unistd.h>
#include <stdio.h>

#define PKEY_ENABLE_ALL 0x0
#define PKEY_DISABLE_ACCESS 0x1
#define PKEY_DISABLE_WRITE 0x2
#define SYS_pkey_mprotect 0x149
#define SYS_pkey_alloc 0x14a
#define SYS_pkey_free 0x14b
#define __NR_pkey_sync 334

#define make_pkru(pkey, rights) ((rights) << (2 * pkey))

#define LOGGING 0
#define __SOURCEFILE__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#define rlog(format, ...) { \
    if( LOGGING ) { \
        FILE *fp = fopen("/home/soyeon/log/log2", "a"); \
        fprintf(fp, "[smv] " format, ##__VA_ARGS__); \
        fflush(NULL);   \
        fclose(fp); \
    }\
}
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

static int
pkey_set_real(int pkru, int pkey) 
{
  register int eax, edx;
  asm volatile(".byte 0x0f, 0x01, 0xee\n\t"
      : "=a" (eax), "=d" (edx) : "c" (0));
  asm volatile(".byte 0x0f, 0x01, 0xef\n\t"
      : : "a" ((eax & ~(0x3 << (pkey * 2))) | pkru), "c" (0), "d" (edx));
  //printf("%d\n", eax);
  //rlog("pkru : 0x%x, pkey : %d\n", pkru, pkey);
  return 0;
}

int pkey_read(int idx);
int pkey_mprotect(void *ptr, size_t size, unsigned long orig_prot, unsigned long pkey) ;
int pkey_alloc(int flag, int permit);
int pkey_free(unsigned long pkey);
#ifdef __cplusplus
extern "C" {
#endif
int pkey_sync(void);
#ifdef __cplusplus
}
#endif


#endif
