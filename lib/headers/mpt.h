#include <stdbool.h>
#include <sys/mman.h>
#define MAX_PKEY 16
#define START_PKEY 1
#define DEFAULT_PROT (PROT_READ | PROT_WRITE)
#define CCOMP extern "C"

typedef struct _mpt_data {
  void* addr;
  size_t size;
} mpt_data;


// Public API
#ifdef __cplusplus
extern "C" {
#endif
int mpt_init(int evict_rate);
int mpt_mmap(void** addr,size_t length, int prot, int flags);
// for quick permission change
int mpt_mprotect(int id, int prot);
// for domain-based isolation
int mpt_begin(int id, int prot);
int mpt_end(int id);

int mpt_destroy(int id);
#ifdef __cplusplus
}
#endif
