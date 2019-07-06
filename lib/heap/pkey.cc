#include <unistd.h>
#include <stdint.h>
#include "pkey.h"

int
pkey_read(int idx) 
{
  int eax = rdpkru();
  return (eax >> (idx * 2)) & 3;
}

int 
pkey_mprotect(void *ptr, size_t size, unsigned long orig_prot, 
unsigned long pkey) 
{ 
return syscall(SYS_pkey_mprotect, ptr, size, orig_prot, pkey); 
}

int 
pkey_alloc(int flag, int permit) 
{ 
return syscall(SYS_pkey_alloc, flag, permit); 
}

int 
pkey_free(unsigned long pkey) 
{ 
return syscall(SYS_pkey_free, pkey); 
}

int pkey_sync()
{
  return syscall(__NR_pkey_sync, rdpkru());
}

/*
#ifndef NOINLINE
#define NOINLINE __attribute__ ((noinline))
#endif
unsigned int NOINLINE 
have_pkru (void)
{
  unsigned int eax, ebx, ecx, edx;

  if (!__get_cpuid (1, &eax, &ebx, &ecx, &edx))
    return 0;

  if ((ecx & bit_OSXSAVE) == bit_OSXSAVE)
    {
      if (__get_cpuid_max (0, NULL) < 7)
	return 0;

      __cpuid_count (7, 0, eax, ebx, ecx, edx);

      if ((ecx & bit_PKU) == bit_PKU)
	return 1;
      else
	return 0;
    }
  return 0;
}
*/

