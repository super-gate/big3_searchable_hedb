# HElib requires at least 3.11 cmake
CMAKE_MINIMUM_REQUIRED ( VERSION 3.11)
 
# project name
PROJECT ( "HDB_supergate" )
SET ( PROJECT_VERSION_MAJOR 0 )
SET ( PROJECT_VERSION_MINOR 1 )

# Build type and Makefile config
SET (CMAKE_BUILD_TYPE Release)
SET ( CMAKE_VERBOSE_MAKEFILE true )
 
# Compiler
SET ( CMAKE_C_COMPILER "c" )
 
# Change the compliler...
SET (CMAKE_C_COMPILER             "/usr/bin/c")
SET (CMAKE_C_FLAGS                "-Wall -std=c++17 ")


SET (CMAKE_C_FLAGS                "-Wall")
SET (CMAKE_C_FLAGS_DEBUG          "-g")
SET (CMAKE_C_FLAGS_MINSIZEREL     "-Os -DNDEBUG")
SET (CMAKE_C_FLAGS_RELEASE        "-O4 -DNDEBUG")
SET (CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g")
SET (CMAKE_CXX_COMPILER             "/usr/bin/c++")
SET (CMAKE_CXX_FLAGS                "-Wall")
SET (CMAKE_CXX_FLAGS_DEBUG          "-g")
SET (CMAKE_CXX_FLAGS_MINSIZEREL     "-Os -DNDEBUG")
SET (CMAKE_CXX_FLAGS_RELEASE        "-O4 -DNDEBUG")
SET (CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g")
SET (CMAKE_LINKER  "/usr/bin/llvm-ld")
SET (CMAKE_NM      "/usr/bin/llvm-nm")
SET (CMAKE_OBJDUMP "/usr/bin/llvm-objdump")

SET(CMAKE_CXX_STANDARD 17)
SET(CMAKE_CXX_STANDARD_REQUIRED ON)

# shared compile options
ADD_COMPILE_OPTIONS ( -g -Wall )
# In MAC, static option should be removed
#SET ( CMAKE_EXE_LINKER_FLAGS "-static -Wl,--gc-sections" )

# shared header files

INCLUDE_DIRECTORIES (${CMAKE_SOURCE_DIR}/include)

INCLUDE_DIRECTORIES (${CMAKE_SOURCE_DIR}/include)

INCLUDE_DIRECTORIES (/usr/local/include)


# shared linked libraries (-l)
find_package(helib REQUIRED)
include_directories(${PROJECT_SOURCE_DIR})


LINK_LIBRARIES(helib)


# shared link library directory (-L)
LINK_DIRECTORIES ( /usr/lib )
LINK_DIRECTORIES (/usr/local/lib)
 

# sources and headers
SET( SOURCESS 
    ${CMAKE_SOURCE_DIR}/src/HDB_supergate.cpp
    ${CMAKE_SOURCE_DIR}/src/HDB_supergate_server.cpp
    ${CMAKE_SOURCE_DIR}/src/HDB_supergate_user.cpp
    )

SET( HEADERSS
    ${CMAKE_SOURCE_DIR}/include/HDB_supergate.hpp
    ${CMAKE_SOURCE_DIR}/include/HDB_supergate_server.hpp
    ${CMAKE_SOURCE_DIR}/include/HDB_supergate_user.hpp
    )

# Make Library 
ADD_LIBRARY(HDB_supergate_lib STATIC ${SOURCESS})


INSTALL(TARGETS HDB_supergate_lib
    DESTINATION ${CMAKE_SOURCE_DIR}/../lib_HDB/bin
)

INSTALL(FILES ${HEADERSS} 
    DESTINATION ${CMAKE_SOURCE_DIR}/../lib_HDB/include)

#cmake command to build (change PATH below to local helib install directory)
#cmake -Dhelib_DIR=/home/smhan/Documents/helib_install/helib_pack/share/cmake/helib ..