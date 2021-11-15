# libmpk (a software abstraction for MPK)

libmpk, a software abstraction for MPK, virtualizes the hardware protection keys to eliminate the protection-key-use-after-free problem while providing accesses to an unlimited number of virtualized keys. To support legacy applications, it also provides a lazy inter-thread key synchronization. To enhance the security of MPK itself, libmpk restricts unauthorized writes to its metadata. We apply libmpk to three real-world applications: OpenSSL, JavaScript JIT compiler, and Memcached for memory protection and isolation.

This repository has the modified Linux kernel and related library. The kernel source is already applied to later version ofthe mainline, so all you have to do is apply the library. The source codes in the 'lib' is provided under the terms of the MIT license.

## Build and install the kernel

      - libmpk was developed on Linux 4.14.2. (Ubuntu 16.04)
      - The Linux kernel source is available in ./kernel
      - Enable memory protection keys when compiling the kernel.
      - Build and install the kernel.
      
## Build library

### Build general library

```
$ cd lib
$ ./install.sh
```

### Build heap-related library

```
$ cd lib/heap
$ ./install.sh
```

## Reference 
https://www.usenix.org/conference/atc19/presentation/park-soyeon
```
@inproceedings {234966,
author = {Soyeon Park and Sangho Lee and Wen Xu and HyunGon Moon and Taesoo Kim},
title = {libmpk: Software Abstraction for Intel Memory Protection Keys (Intel {MPK})},
booktitle = {2019 {USENIX} Annual Technical Conference ({USENIX} {ATC} 19)},
year = {2019},
isbn = {978-1-939133-03-8},
address = {Renton, WA},
pages = {241--254},
url = {https://www.usenix.org/conference/atc19/presentation/park-soyeon},
publisher = {{USENIX} Association},
month = jul,
}
```

## Contacts
- Soyeon Park <soyeon@gatech.edu>
- Sangho Lee <Sangho.Lee@microsoft.com>
- Wen Xu <wen.xu@gatech.edu>
- Hyungon Moon <hyungon@unist.ac.kr>
- Taesoo Kim <taesoo@gatech.edu>
