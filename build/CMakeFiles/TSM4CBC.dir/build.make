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
CMAKE_SOURCE_DIR = /home/ryanclq/src/SM4_expand

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/ryanclq/src/SM4_expand/build

# Include any dependencies generated for this target.
include CMakeFiles/TSM4CBC.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/TSM4CBC.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/TSM4CBC.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/TSM4CBC.dir/flags.make

CMakeFiles/TSM4CBC.dir/test/test_sm4_cbc.c.o: CMakeFiles/TSM4CBC.dir/flags.make
CMakeFiles/TSM4CBC.dir/test/test_sm4_cbc.c.o: ../test/test_sm4_cbc.c
CMakeFiles/TSM4CBC.dir/test/test_sm4_cbc.c.o: CMakeFiles/TSM4CBC.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ryanclq/src/SM4_expand/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/TSM4CBC.dir/test/test_sm4_cbc.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/TSM4CBC.dir/test/test_sm4_cbc.c.o -MF CMakeFiles/TSM4CBC.dir/test/test_sm4_cbc.c.o.d -o CMakeFiles/TSM4CBC.dir/test/test_sm4_cbc.c.o -c /home/ryanclq/src/SM4_expand/test/test_sm4_cbc.c

CMakeFiles/TSM4CBC.dir/test/test_sm4_cbc.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/TSM4CBC.dir/test/test_sm4_cbc.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/ryanclq/src/SM4_expand/test/test_sm4_cbc.c > CMakeFiles/TSM4CBC.dir/test/test_sm4_cbc.c.i

CMakeFiles/TSM4CBC.dir/test/test_sm4_cbc.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/TSM4CBC.dir/test/test_sm4_cbc.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/ryanclq/src/SM4_expand/test/test_sm4_cbc.c -o CMakeFiles/TSM4CBC.dir/test/test_sm4_cbc.c.s

# Object files for target TSM4CBC
TSM4CBC_OBJECTS = \
"CMakeFiles/TSM4CBC.dir/test/test_sm4_cbc.c.o"

# External object files for target TSM4CBC
TSM4CBC_EXTERNAL_OBJECTS =

TSM4CBC: CMakeFiles/TSM4CBC.dir/test/test_sm4_cbc.c.o
TSM4CBC: CMakeFiles/TSM4CBC.dir/build.make
TSM4CBC: libLIB.a
TSM4CBC: CMakeFiles/TSM4CBC.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/ryanclq/src/SM4_expand/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable TSM4CBC"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/TSM4CBC.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/TSM4CBC.dir/build: TSM4CBC
.PHONY : CMakeFiles/TSM4CBC.dir/build

CMakeFiles/TSM4CBC.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/TSM4CBC.dir/cmake_clean.cmake
.PHONY : CMakeFiles/TSM4CBC.dir/clean

CMakeFiles/TSM4CBC.dir/depend:
	cd /home/ryanclq/src/SM4_expand/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ryanclq/src/SM4_expand /home/ryanclq/src/SM4_expand /home/ryanclq/src/SM4_expand/build /home/ryanclq/src/SM4_expand/build /home/ryanclq/src/SM4_expand/build/CMakeFiles/TSM4CBC.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/TSM4CBC.dir/depend

