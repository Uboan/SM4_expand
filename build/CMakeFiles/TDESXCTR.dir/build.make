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
CMAKE_COMMAND = /home/kaye/opt/cmake/cmake-3.25.0-linux-x86_64/bin/cmake

# The command to remove a file.
RM = /home/kaye/opt/cmake/cmake-3.25.0-linux-x86_64/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/kaye/SM4_expand

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/kaye/SM4_expand/build

# Include any dependencies generated for this target.
include CMakeFiles/TDESXCTR.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/TDESXCTR.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/TDESXCTR.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/TDESXCTR.dir/flags.make

CMakeFiles/TDESXCTR.dir/test/TEST_DESX_CTR.c.o: CMakeFiles/TDESXCTR.dir/flags.make
CMakeFiles/TDESXCTR.dir/test/TEST_DESX_CTR.c.o: /home/kaye/SM4_expand/test/TEST_DESX_CTR.c
CMakeFiles/TDESXCTR.dir/test/TEST_DESX_CTR.c.o: CMakeFiles/TDESXCTR.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/kaye/SM4_expand/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/TDESXCTR.dir/test/TEST_DESX_CTR.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/TDESXCTR.dir/test/TEST_DESX_CTR.c.o -MF CMakeFiles/TDESXCTR.dir/test/TEST_DESX_CTR.c.o.d -o CMakeFiles/TDESXCTR.dir/test/TEST_DESX_CTR.c.o -c /home/kaye/SM4_expand/test/TEST_DESX_CTR.c

CMakeFiles/TDESXCTR.dir/test/TEST_DESX_CTR.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/TDESXCTR.dir/test/TEST_DESX_CTR.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/kaye/SM4_expand/test/TEST_DESX_CTR.c > CMakeFiles/TDESXCTR.dir/test/TEST_DESX_CTR.c.i

CMakeFiles/TDESXCTR.dir/test/TEST_DESX_CTR.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/TDESXCTR.dir/test/TEST_DESX_CTR.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/kaye/SM4_expand/test/TEST_DESX_CTR.c -o CMakeFiles/TDESXCTR.dir/test/TEST_DESX_CTR.c.s

# Object files for target TDESXCTR
TDESXCTR_OBJECTS = \
"CMakeFiles/TDESXCTR.dir/test/TEST_DESX_CTR.c.o"

# External object files for target TDESXCTR
TDESXCTR_EXTERNAL_OBJECTS =

TDESXCTR: CMakeFiles/TDESXCTR.dir/test/TEST_DESX_CTR.c.o
TDESXCTR: CMakeFiles/TDESXCTR.dir/build.make
TDESXCTR: libLIB.a
TDESXCTR: CMakeFiles/TDESXCTR.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/kaye/SM4_expand/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable TDESXCTR"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/TDESXCTR.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/TDESXCTR.dir/build: TDESXCTR
.PHONY : CMakeFiles/TDESXCTR.dir/build

CMakeFiles/TDESXCTR.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/TDESXCTR.dir/cmake_clean.cmake
.PHONY : CMakeFiles/TDESXCTR.dir/clean

CMakeFiles/TDESXCTR.dir/depend:
	cd /home/kaye/SM4_expand/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/kaye/SM4_expand /home/kaye/SM4_expand /home/kaye/SM4_expand/build /home/kaye/SM4_expand/build /home/kaye/SM4_expand/build/CMakeFiles/TDESXCTR.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/TDESXCTR.dir/depend

