# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /root/cis3800/big3_searchable_hedb

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /root/cis3800/big3_searchable_hedb/build

# Include any dependencies generated for this target.
include CMakeFiles/eq_normal.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/eq_normal.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/eq_normal.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/eq_normal.dir/flags.make

CMakeFiles/eq_normal.dir/HDB_comparison_library/comp_lib/comparator.cpp.o: CMakeFiles/eq_normal.dir/flags.make
CMakeFiles/eq_normal.dir/HDB_comparison_library/comp_lib/comparator.cpp.o: ../HDB_comparison_library/comp_lib/comparator.cpp
CMakeFiles/eq_normal.dir/HDB_comparison_library/comp_lib/comparator.cpp.o: CMakeFiles/eq_normal.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/cis3800/big3_searchable_hedb/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/eq_normal.dir/HDB_comparison_library/comp_lib/comparator.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/eq_normal.dir/HDB_comparison_library/comp_lib/comparator.cpp.o -MF CMakeFiles/eq_normal.dir/HDB_comparison_library/comp_lib/comparator.cpp.o.d -o CMakeFiles/eq_normal.dir/HDB_comparison_library/comp_lib/comparator.cpp.o -c /root/cis3800/big3_searchable_hedb/HDB_comparison_library/comp_lib/comparator.cpp

CMakeFiles/eq_normal.dir/HDB_comparison_library/comp_lib/comparator.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/eq_normal.dir/HDB_comparison_library/comp_lib/comparator.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/cis3800/big3_searchable_hedb/HDB_comparison_library/comp_lib/comparator.cpp > CMakeFiles/eq_normal.dir/HDB_comparison_library/comp_lib/comparator.cpp.i

CMakeFiles/eq_normal.dir/HDB_comparison_library/comp_lib/comparator.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/eq_normal.dir/HDB_comparison_library/comp_lib/comparator.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/cis3800/big3_searchable_hedb/HDB_comparison_library/comp_lib/comparator.cpp -o CMakeFiles/eq_normal.dir/HDB_comparison_library/comp_lib/comparator.cpp.s

CMakeFiles/eq_normal.dir/HDB_comparison_library/comp_lib/tools.cpp.o: CMakeFiles/eq_normal.dir/flags.make
CMakeFiles/eq_normal.dir/HDB_comparison_library/comp_lib/tools.cpp.o: ../HDB_comparison_library/comp_lib/tools.cpp
CMakeFiles/eq_normal.dir/HDB_comparison_library/comp_lib/tools.cpp.o: CMakeFiles/eq_normal.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/cis3800/big3_searchable_hedb/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/eq_normal.dir/HDB_comparison_library/comp_lib/tools.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/eq_normal.dir/HDB_comparison_library/comp_lib/tools.cpp.o -MF CMakeFiles/eq_normal.dir/HDB_comparison_library/comp_lib/tools.cpp.o.d -o CMakeFiles/eq_normal.dir/HDB_comparison_library/comp_lib/tools.cpp.o -c /root/cis3800/big3_searchable_hedb/HDB_comparison_library/comp_lib/tools.cpp

CMakeFiles/eq_normal.dir/HDB_comparison_library/comp_lib/tools.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/eq_normal.dir/HDB_comparison_library/comp_lib/tools.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/cis3800/big3_searchable_hedb/HDB_comparison_library/comp_lib/tools.cpp > CMakeFiles/eq_normal.dir/HDB_comparison_library/comp_lib/tools.cpp.i

CMakeFiles/eq_normal.dir/HDB_comparison_library/comp_lib/tools.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/eq_normal.dir/HDB_comparison_library/comp_lib/tools.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/cis3800/big3_searchable_hedb/HDB_comparison_library/comp_lib/tools.cpp -o CMakeFiles/eq_normal.dir/HDB_comparison_library/comp_lib/tools.cpp.s

CMakeFiles/eq_normal.dir/src/eq_normal.cpp.o: CMakeFiles/eq_normal.dir/flags.make
CMakeFiles/eq_normal.dir/src/eq_normal.cpp.o: ../src/eq_normal.cpp
CMakeFiles/eq_normal.dir/src/eq_normal.cpp.o: CMakeFiles/eq_normal.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/cis3800/big3_searchable_hedb/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/eq_normal.dir/src/eq_normal.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/eq_normal.dir/src/eq_normal.cpp.o -MF CMakeFiles/eq_normal.dir/src/eq_normal.cpp.o.d -o CMakeFiles/eq_normal.dir/src/eq_normal.cpp.o -c /root/cis3800/big3_searchable_hedb/src/eq_normal.cpp

CMakeFiles/eq_normal.dir/src/eq_normal.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/eq_normal.dir/src/eq_normal.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/cis3800/big3_searchable_hedb/src/eq_normal.cpp > CMakeFiles/eq_normal.dir/src/eq_normal.cpp.i

CMakeFiles/eq_normal.dir/src/eq_normal.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/eq_normal.dir/src/eq_normal.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/cis3800/big3_searchable_hedb/src/eq_normal.cpp -o CMakeFiles/eq_normal.dir/src/eq_normal.cpp.s

# Object files for target eq_normal
eq_normal_OBJECTS = \
"CMakeFiles/eq_normal.dir/HDB_comparison_library/comp_lib/comparator.cpp.o" \
"CMakeFiles/eq_normal.dir/HDB_comparison_library/comp_lib/tools.cpp.o" \
"CMakeFiles/eq_normal.dir/src/eq_normal.cpp.o"

# External object files for target eq_normal
eq_normal_EXTERNAL_OBJECTS =

../bin/eq_normal: CMakeFiles/eq_normal.dir/HDB_comparison_library/comp_lib/comparator.cpp.o
../bin/eq_normal: CMakeFiles/eq_normal.dir/HDB_comparison_library/comp_lib/tools.cpp.o
../bin/eq_normal: CMakeFiles/eq_normal.dir/src/eq_normal.cpp.o
../bin/eq_normal: CMakeFiles/eq_normal.dir/build.make
../bin/eq_normal: /root/cis3800/helib_install/helib_pack/lib/libhelib.a
../bin/eq_normal: ../lib_HDB/bin/libHDB_supergate_lib.a
../bin/eq_normal: /root/cis3800/helib_install/helib_pack/lib/libntl.so
../bin/eq_normal: /root/cis3800/helib_install/helib_pack/lib/libgmp.so
../bin/eq_normal: CMakeFiles/eq_normal.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/root/cis3800/big3_searchable_hedb/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking CXX executable ../bin/eq_normal"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/eq_normal.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/eq_normal.dir/build: ../bin/eq_normal
.PHONY : CMakeFiles/eq_normal.dir/build

CMakeFiles/eq_normal.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/eq_normal.dir/cmake_clean.cmake
.PHONY : CMakeFiles/eq_normal.dir/clean

CMakeFiles/eq_normal.dir/depend:
	cd /root/cis3800/big3_searchable_hedb/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/cis3800/big3_searchable_hedb /root/cis3800/big3_searchable_hedb /root/cis3800/big3_searchable_hedb/build /root/cis3800/big3_searchable_hedb/build /root/cis3800/big3_searchable_hedb/build/CMakeFiles/eq_normal.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/eq_normal.dir/depend

