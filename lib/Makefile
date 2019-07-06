all: mpt #mpt2 

mpt: 
	g++ -std=c++11 -fPIC -c pkey.cc -g -O5
	g++ -std=c++11 -fPIC -c mpt.cc -g -O5
	g++ -std=c++11 -shared -Wl,-soname,libmpt.so -o libmpt.so mpt.o pkey.o -g
	ar rcs libmpt.a mpt.o pkey.o

mpt2:
	g++ -std=c++11 -fPIC -c pkey.cc -g
	g++ -std=c++11 -fPIC -c mpt2.cc -g
	g++ -std=c++11 -shared -Wl,-soname,libmpt2.so -o libmpt2.so mpt2.o pkey.o -g
	ar rcs libmpt2.a mpt2.o pkey.o

install:
	cp libmpt.so /usr/local/lib/
	cp libmpt.so /usr/lib/
	mkdir -p /usr/include/mpt	
	cp headers/*.h /usr/include/mpt/

clean:
	rm -f pkey.o mpt.o libmpt.so libmpt.a mpt2.o libmpt2.so libmpt2.a
	
