# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.25

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
CMAKE_SOURCE_DIR = /home/smhan/Documents/big3_searchable_hedb

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/smhan/Documents/big3_searchable_hedb/build

# Include any dependencies generated for this target.
include CMakeFiles/util.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/util.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/util.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/util.dir/flags.make

CMakeFiles/util.dir/HDB_comparison_library/comp_lib/comparator.cpp.o: CMakeFiles/util.dir/flags.make
CMakeFiles/util.dir/HDB_comparison_library/comp_lib/comparator.cpp.o: /home/smhan/Documents/big3_searchable_hedb/HDB_comparison_library/comp_lib/comparator.cpp
CMakeFiles/util.dir/HDB_comparison_library/comp_lib/comparator.cpp.o: CMakeFiles/util.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/smhan/Documents/big3_searchable_hedb/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/util.dir/HDB_comparison_library/comp_lib/comparator.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/util.dir/HDB_comparison_library/comp_lib/comparator.cpp.o -MF CMakeFiles/util.dir/HDB_comparison_library/comp_lib/comparator.cpp.o.d -o CMakeFiles/util.dir/HDB_comparison_library/comp_lib/comparator.cpp.o -c /home/smhan/Documents/big3_searchable_hedb/HDB_comparison_library/comp_lib/comparator.cpp

CMakeFiles/util.dir/HDB_comparison_library/comp_lib/comparator.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/util.dir/HDB_comparison_library/comp_lib/comparator.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/smhan/Documents/big3_searchable_hedb/HDB_comparison_library/comp_lib/comparator.cpp > CMakeFiles/util.dir/HDB_comparison_library/comp_lib/comparator.cpp.i

CMakeFiles/util.dir/HDB_comparison_library/comp_lib/comparator.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/util.dir/HDB_comparison_library/comp_lib/comparator.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/smhan/Documents/big3_searchable_hedb/HDB_comparison_library/comp_lib/comparator.cpp -o CMakeFiles/util.dir/HDB_comparison_library/comp_lib/comparator.cpp.s

CMakeFiles/util.dir/HDB_comparison_library/comp_lib/tools.cpp.o: CMakeFiles/util.dir/flags.make
CMakeFiles/util.dir/HDB_comparison_library/comp_lib/tools.cpp.o: /home/smhan/Documents/big3_searchable_hedb/HDB_comparison_library/comp_lib/tools.cpp
CMakeFiles/util.dir/HDB_comparison_library/comp_lib/tools.cpp.o: CMakeFiles/util.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/smhan/Documents/big3_searchable_hedb/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/util.dir/HDB_comparison_library/comp_lib/tools.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/util.dir/HDB_comparison_library/comp_lib/tools.cpp.o -MF CMakeFiles/util.dir/HDB_comparison_library/comp_lib/tools.cpp.o.d -o CMakeFiles/util.dir/HDB_comparison_library/comp_lib/tools.cpp.o -c /home/smhan/Documents/big3_searchable_hedb/HDB_comparison_library/comp_lib/tools.cpp

CMakeFiles/util.dir/HDB_comparison_library/comp_lib/tools.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/util.dir/HDB_comparison_library/comp_lib/tools.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/smhan/Documents/big3_searchable_hedb/HDB_comparison_library/comp_lib/tools.cpp > CMakeFiles/util.dir/HDB_comparison_library/comp_lib/tools.cpp.i

CMakeFiles/util.dir/HDB_comparison_library/comp_lib/tools.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/util.dir/HDB_comparison_library/comp_lib/tools.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/smhan/Documents/big3_searchable_hedb/HDB_comparison_library/comp_lib/tools.cpp -o CMakeFiles/util.dir/HDB_comparison_library/comp_lib/tools.cpp.s

CMakeFiles/util.dir/src/util.cpp.o: CMakeFiles/util.dir/flags.make
CMakeFiles/util.dir/src/util.cpp.o: /home/smhan/Documents/big3_searchable_hedb/src/util.cpp
CMakeFiles/util.dir/src/util.cpp.o: CMakeFiles/util.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/smhan/Documents/big3_searchable_hedb/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/util.dir/src/util.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/util.dir/src/util.cpp.o -MF CMakeFiles/util.dir/src/util.cpp.o.d -o CMakeFiles/util.dir/src/util.cpp.o -c /home/smhan/Documents/big3_searchable_hedb/src/util.cpp

CMakeFiles/util.dir/src/util.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/util.dir/src/util.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/smhan/Documents/big3_searchable_hedb/src/util.cpp > CMakeFiles/util.dir/src/util.cpp.i

CMakeFiles/util.dir/src/util.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/util.dir/src/util.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/smhan/Documents/big3_searchable_hedb/src/util.cpp -o CMakeFiles/util.dir/src/util.cpp.s

# Object files for target util
util_OBJECTS = \
"CMakeFiles/util.dir/HDB_comparison_library/comp_lib/comparator.cpp.o" \
"CMakeFiles/util.dir/HDB_comparison_library/comp_lib/tools.cpp.o" \
"CMakeFiles/util.dir/src/util.cpp.o"

# External object files for target util
util_EXTERNAL_OBJECTS =

/home/smhan/Documents/big3_searchable_hedb/bin/util: CMakeFiles/util.dir/HDB_comparison_library/comp_lib/comparator.cpp.o
/home/smhan/Documents/big3_searchable_hedb/bin/util: CMakeFiles/util.dir/HDB_comparison_library/comp_lib/tools.cpp.o
/home/smhan/Documents/big3_searchable_hedb/bin/util: CMakeFiles/util.dir/src/util.cpp.o
/home/smhan/Documents/big3_searchable_hedb/bin/util: CMakeFiles/util.dir/build.make
/home/smhan/Documents/big3_searchable_hedb/bin/util: /home/smhan/Documents/helib_install/helib_pack/lib/libhelib.a
/home/smhan/Documents/big3_searchable_hedb/bin/util: /home/smhan/Documents/big3_searchable_hedb/HDB_lib/bin/libHDB_supergate_lib.a
/home/smhan/Documents/big3_searchable_hedb/bin/util: /home/smhan/Documents/helib_install/helib_pack/lib/libntl.so
/home/smhan/Documents/big3_searchable_hedb/bin/util: /home/smhan/Documents/helib_install/helib_pack/lib/libgmp.so
/home/smhan/Documents/big3_searchable_hedb/bin/util: CMakeFiles/util.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/smhan/Documents/big3_searchable_hedb/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking CXX executable /home/smhan/Documents/big3_searchable_hedb/bin/util"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/util.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/util.dir/build: /home/smhan/Documents/big3_searchable_hedb/bin/util
.PHONY : CMakeFiles/util.dir/build

CMakeFiles/util.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/util.dir/cmake_clean.cmake
.PHONY : CMakeFiles/util.dir/clean

CMakeFiles/util.dir/depend:
	cd /home/smhan/Documents/big3_searchable_hedb/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/smhan/Documents/big3_searchable_hedb /home/smhan/Documents/big3_searchable_hedb /home/smhan/Documents/big3_searchable_hedb/build /home/smhan/Documents/big3_searchable_hedb/build /home/smhan/Documents/big3_searchable_hedb/build/CMakeFiles/util.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/util.dir/depend

