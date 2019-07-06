export SYSLIB=/usr/lib
export SYSINC=/usr/include

# compile smv userspace API library
echo "================= Compiling user space library ================="
cmake .
make clean
make

# Copy library and header files to local machine
echo "================= Copying smv header files to: $SYSINC ================="
sudo cp mpk_heap.h /usr/include
sudo cp pkey.h /usr/include

echo "================= Copying smv library to system folder: $SYSLIB ================="
sudo cp libmpk_heaplib.so /usr/lib
sudo cp libmpk_heaplib.so /usr/lib/x86_64-linux-gnu/
sudo cp libmpk_heaplib.so /lib/x86_64-linux-gnu/

echo "================= Installation copmleted ==============================="
