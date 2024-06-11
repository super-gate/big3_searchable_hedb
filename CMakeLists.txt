# 요구 CMake 최소 버전
CMAKE_MINIMUM_REQUIRED ( VERSION 3.11)
 
# 프로젝트 이름 및 버전
PROJECT ( "searchable_hedb" )
SET ( PROJECT_VERSION_MAJOR 0 )
SET ( PROJECT_VERSION_MINOR 1 )

SET (CMAKE_BUILD_TYPE Release)
SET (CMAKE_VERBOSE_MAKEFILE false )


# 공통 컴파일러
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

# 공통 컴파일 옵션, 링크 옵션
ADD_COMPILE_OPTIONS ( -g -Wall )

# 공통 헤더 파일 Include 디렉토리 (-I)
INCLUDE_DIRECTORIES (${CMAKE_SOURCE_DIR}/HDB_comparison_library/include)
INCLUDE_DIRECTORIES (/usr/local/include)
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/HDB_comparison_library/lib/include/)

# HELIB
INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR})


# 공통 링크 라이브러리 (-l)
FIND_PACKAGE(helib REQUIRED)
LINK_LIBRARIES(helib)
LINK_LIBRARIES(stdc++fs)

# 공통 링크 라이브러리 디렉토리 (-L)
LINK_DIRECTORIES (/usr/lib )
LINK_DIRECTORIES (/usr/local/lib)
LINK_DIRECTORIES (${CMAKE_SOURCE_DIR}${CMAKE_SOURCE_DIR}/HDB_comparison_library/lib/bin/)





# # main 
# SET(MAIN_SOURCES ${CMAKE_SOURCE_DIR}/src/main_query_test.cpp)

# ADD_EXECUTABLE(searchable_db 
# 		${CMAKE_SOURCE_DIR}/HDB_comparison_library/comp_lib/comparator.cpp
# 		${CMAKE_SOURCE_DIR}/HDB_comparison_library/comp_lib/tools.cpp
# 		${MAIN_SOURCES} 
# 		)

# TARGET_LINK_LIBRARIES(searchable_db ${CMAKE_SOURCE_DIR}/lib_HDB/bin/libHDB_supergate_lib.a)
# SET_TARGET_PROPERTIES(searchable_db PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

# #TS_test
# SET(TS ${CMAKE_SOURCE_DIR}/src/TS_test.cpp)
# ADD_EXECUTABLE(TS 
# 		${CMAKE_SOURCE_DIR}/HDB_comparison_library/comp_lib/comparator.cpp
# 		${CMAKE_SOURCE_DIR}/HDB_comparison_library/comp_lib/tools.cpp
# 		${TS} 
# 		)

# TARGET_LINK_LIBRARIES(TS ${CMAKE_SOURCE_DIR}/lib_HDB/bin/libHDB_supergate_lib.a)
# SET_TARGET_PROPERTIES(TS PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)


#Nslots
SET(nslots ${CMAKE_SOURCE_DIR}/src/nslots_test.cpp)
ADD_EXECUTABLE(nslots 
		${CMAKE_SOURCE_DIR}/HDB_comparison_library/comp_lib/comparator.cpp
		${CMAKE_SOURCE_DIR}/HDB_comparison_library/comp_lib/tools.cpp
		${nslots} 
		)

TARGET_LINK_LIBRARIES(nslots ${CMAKE_SOURCE_DIR}/lib_HDB/bin/libHDB_supergate_lib.a)
SET_TARGET_PROPERTIES(nslots PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

#save DB
# SET(save ${CMAKE_SOURCE_DIR}/src/save_test.cpp)
SET(save ${CMAKE_SOURCE_DIR}/src/construct_hedb.cpp)
ADD_EXECUTABLE(save 
		${CMAKE_SOURCE_DIR}/HDB_comparison_library/comp_lib/comparator.cpp
		${CMAKE_SOURCE_DIR}/HDB_comparison_library/comp_lib/tools.cpp
		${save} 
		)

TARGET_LINK_LIBRARIES(save ${CMAKE_SOURCE_DIR}/lib_HDB/bin/libHDB_supergate_lib.a)
SET_TARGET_PROPERTIES(save PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

#load and Query
SET(query ${CMAKE_SOURCE_DIR}/src/load_and_query_hedb.cpp)
ADD_EXECUTABLE(query 
		${CMAKE_SOURCE_DIR}/HDB_comparison_library/comp_lib/comparator.cpp
		${CMAKE_SOURCE_DIR}/HDB_comparison_library/comp_lib/tools.cpp
		${query} 
		)

TARGET_LINK_LIBRARIES(query ${CMAKE_SOURCE_DIR}/lib_HDB/bin/libHDB_supergate_lib.a)
SET_TARGET_PROPERTIES(query PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

# foreach(_target
# eq_normal
# eq_ext
# eq_ind
# lt_normal
# lt_ext
# lt_ind
# leq_normal
# leq_ext
# leq_ind
# )
# 	SET(_target ${CMAKE_SOURCE_DIR}/src/for_presentation/${_target}.cpp)
# 	ADD_EXECUTABLE(_target 
# 			${CMAKE_SOURCE_DIR}/HDB_comparison_library/comp_lib/comparator.cpp
# 			${CMAKE_SOURCE_DIR}/HDB_comparison_library/comp_lib/tools.cpp
# 			${_target} 
# 			)
	
# 	TARGET_LINK_LIBRARIES(_target ${CMAKE_SOURCE_DIR}/lib_HDB/bin/libHDB_supergate_lib.a)
# 	SET_TARGET_PROPERTIES(_target PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
# endforeach()


#cmake -Dhelib_DIR=/home/smhan/Documents/helib_install/helib_pack/share/cmake/helib ..