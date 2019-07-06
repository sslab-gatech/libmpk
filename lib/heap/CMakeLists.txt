cmake_minimum_required(VERSION 2.6)
project(smv_api)

#set(CMAKE_BUILD_TYPE "Debug")
#set(CMAKE_C_FLAGS "-O0 -g")

if(APPLE)
	set(CMAKE_OSX_ARCHITECTURES i386 x86_64)
endif()
##set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32 -g")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -g")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -g -std=c++11")
#set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(mpk_heaplib SHARED mpk_heap.cc pkey.cc)

target_link_libraries(mpk_heaplib pthread) 
##INSTALL(FILES mpk_heap.h
##  DESTINATION include)
##INSTALL(TARGETS mpk_heaplib 
##  LIBRARY DESTINATION lib
##)
