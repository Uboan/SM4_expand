# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
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
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/uboan_linux/code/sm4_256

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/uboan_linux/code/sm4_256/build

# Include any dependencies generated for this target.
include CMakeFiles/TLCBC.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/TLCBC.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/TLCBC.dir/flags.make

CMakeFiles/TLCBC.dir/test/test_LM_cbc.c.o: CMakeFiles/TLCBC.dir/flags.make
CMakeFiles/TLCBC.dir/test/test_LM_cbc.c.o: ../test/test_LM_cbc.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/uboan_linux/code/sm4_256/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/TLCBC.dir/test/test_LM_cbc.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/TLCBC.dir/test/test_LM_cbc.c.o   -c /home/uboan_linux/code/sm4_256/test/test_LM_cbc.c

CMakeFiles/TLCBC.dir/test/test_LM_cbc.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/TLCBC.dir/test/test_LM_cbc.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/uboan_linux/code/sm4_256/test/test_LM_cbc.c > CMakeFiles/TLCBC.dir/test/test_LM_cbc.c.i

CMakeFiles/TLCBC.dir/test/test_LM_cbc.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/TLCBC.dir/test/test_LM_cbc.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/uboan_linux/code/sm4_256/test/test_LM_cbc.c -o CMakeFiles/TLCBC.dir/test/test_LM_cbc.c.s

# Object files for target TLCBC
TLCBC_OBJECTS = \
"CMakeFiles/TLCBC.dir/test/test_LM_cbc.c.o"

# External object files for target TLCBC
TLCBC_EXTERNAL_OBJECTS =

TLCBC: CMakeFiles/TLCBC.dir/test/test_LM_cbc.c.o
TLCBC: CMakeFiles/TLCBC.dir/build.make
TLCBC: libLIB.a
TLCBC: CMakeFiles/TLCBC.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/uboan_linux/code/sm4_256/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable TLCBC"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/TLCBC.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/TLCBC.dir/build: TLCBC

.PHONY : CMakeFiles/TLCBC.dir/build

CMakeFiles/TLCBC.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/TLCBC.dir/cmake_clean.cmake
.PHONY : CMakeFiles/TLCBC.dir/clean

CMakeFiles/TLCBC.dir/depend:
	cd /home/uboan_linux/code/sm4_256/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/uboan_linux/code/sm4_256 /home/uboan_linux/code/sm4_256 /home/uboan_linux/code/sm4_256/build /home/uboan_linux/code/sm4_256/build /home/uboan_linux/code/sm4_256/build/CMakeFiles/TLCBC.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/TLCBC.dir/depend

