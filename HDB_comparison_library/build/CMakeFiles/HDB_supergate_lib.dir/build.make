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

# Produce verbose output by default.
VERBOSE = 1

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
CMAKE_SOURCE_DIR = /root/cis3800/big3_searchable_hedb/HDB_comparison_library

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /root/cis3800/big3_searchable_hedb/HDB_comparison_library/build

# Include any dependencies generated for this target.
include CMakeFiles/HDB_supergate_lib.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/HDB_supergate_lib.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/HDB_supergate_lib.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/HDB_supergate_lib.dir/flags.make

CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate.cpp.o: CMakeFiles/HDB_supergate_lib.dir/flags.make
CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate.cpp.o: ../src/HDB_supergate.cpp
CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate.cpp.o: CMakeFiles/HDB_supergate_lib.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/cis3800/big3_searchable_hedb/HDB_comparison_library/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate.cpp.o -MF CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate.cpp.o.d -o CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate.cpp.o -c /root/cis3800/big3_searchable_hedb/HDB_comparison_library/src/HDB_supergate.cpp

CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/cis3800/big3_searchable_hedb/HDB_comparison_library/src/HDB_supergate.cpp > CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate.cpp.i

CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/cis3800/big3_searchable_hedb/HDB_comparison_library/src/HDB_supergate.cpp -o CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate.cpp.s

CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate_server.cpp.o: CMakeFiles/HDB_supergate_lib.dir/flags.make
CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate_server.cpp.o: ../src/HDB_supergate_server.cpp
CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate_server.cpp.o: CMakeFiles/HDB_supergate_lib.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/cis3800/big3_searchable_hedb/HDB_comparison_library/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate_server.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate_server.cpp.o -MF CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate_server.cpp.o.d -o CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate_server.cpp.o -c /root/cis3800/big3_searchable_hedb/HDB_comparison_library/src/HDB_supergate_server.cpp

CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate_server.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate_server.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/cis3800/big3_searchable_hedb/HDB_comparison_library/src/HDB_supergate_server.cpp > CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate_server.cpp.i

CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate_server.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate_server.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/cis3800/big3_searchable_hedb/HDB_comparison_library/src/HDB_supergate_server.cpp -o CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate_server.cpp.s

CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate_user.cpp.o: CMakeFiles/HDB_supergate_lib.dir/flags.make
CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate_user.cpp.o: ../src/HDB_supergate_user.cpp
CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate_user.cpp.o: CMakeFiles/HDB_supergate_lib.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/cis3800/big3_searchable_hedb/HDB_comparison_library/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate_user.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate_user.cpp.o -MF CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate_user.cpp.o.d -o CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate_user.cpp.o -c /root/cis3800/big3_searchable_hedb/HDB_comparison_library/src/HDB_supergate_user.cpp

CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate_user.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate_user.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/cis3800/big3_searchable_hedb/HDB_comparison_library/src/HDB_supergate_user.cpp > CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate_user.cpp.i

CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate_user.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate_user.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/cis3800/big3_searchable_hedb/HDB_comparison_library/src/HDB_supergate_user.cpp -o CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate_user.cpp.s

# Object files for target HDB_supergate_lib
HDB_supergate_lib_OBJECTS = \
"CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate.cpp.o" \
"CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate_server.cpp.o" \
"CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate_user.cpp.o"

# External object files for target HDB_supergate_lib
HDB_supergate_lib_EXTERNAL_OBJECTS =

libHDB_supergate_lib.a: CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate.cpp.o
libHDB_supergate_lib.a: CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate_server.cpp.o
libHDB_supergate_lib.a: CMakeFiles/HDB_supergate_lib.dir/src/HDB_supergate_user.cpp.o
libHDB_supergate_lib.a: CMakeFiles/HDB_supergate_lib.dir/build.make
libHDB_supergate_lib.a: CMakeFiles/HDB_supergate_lib.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/root/cis3800/big3_searchable_hedb/HDB_comparison_library/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking CXX static library libHDB_supergate_lib.a"
	$(CMAKE_COMMAND) -P CMakeFiles/HDB_supergate_lib.dir/cmake_clean_target.cmake
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/HDB_supergate_lib.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/HDB_supergate_lib.dir/build: libHDB_supergate_lib.a
.PHONY : CMakeFiles/HDB_supergate_lib.dir/build

CMakeFiles/HDB_supergate_lib.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/HDB_supergate_lib.dir/cmake_clean.cmake
.PHONY : CMakeFiles/HDB_supergate_lib.dir/clean

CMakeFiles/HDB_supergate_lib.dir/depend:
	cd /root/cis3800/big3_searchable_hedb/HDB_comparison_library/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/cis3800/big3_searchable_hedb/HDB_comparison_library /root/cis3800/big3_searchable_hedb/HDB_comparison_library /root/cis3800/big3_searchable_hedb/HDB_comparison_library/build /root/cis3800/big3_searchable_hedb/HDB_comparison_library/build /root/cis3800/big3_searchable_hedb/HDB_comparison_library/build/CMakeFiles/HDB_supergate_lib.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/HDB_supergate_lib.dir/depend

