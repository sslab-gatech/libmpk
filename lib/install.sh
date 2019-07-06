SYSLIB=/usr/lib
SYSINC=/usr/include

# compile smv userspace API library
echo "================= Compiling user space library ================="
make clean
make

# Copy library and header files to local machine
echo "================= Copying smv header files to: $SYSINC ================="
sudo cp libmpt.so /usr/local/lib/
sudo cp libmpt.so /usr/lib/
sudo mkdir -p /usr/include/mpt
sudo cp headers/*.h /usr/include/mpt/
echo "================= Installation copmleted ==============================="
