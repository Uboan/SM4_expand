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
include CMakeFiles/TEM.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/TEM.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/TEM.dir/flags.make

CMakeFiles/TEM.dir/test/test_even_mansour.c.o: CMakeFiles/TEM.dir/flags.make
CMakeFiles/TEM.dir/test/test_even_mansour.c.o: ../test/test_even_mansour.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/uboan_linux/code/sm4_256/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/TEM.dir/test/test_even_mansour.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/TEM.dir/test/test_even_mansour.c.o   -c /home/uboan_linux/code/sm4_256/test/test_even_mansour.c

CMakeFiles/TEM.dir/test/test_even_mansour.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/TEM.dir/test/test_even_mansour.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/uboan_linux/code/sm4_256/test/test_even_mansour.c > CMakeFiles/TEM.dir/test/test_even_mansour.c.i

CMakeFiles/TEM.dir/test/test_even_mansour.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/TEM.dir/test/test_even_mansour.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/uboan_linux/code/sm4_256/test/test_even_mansour.c -o CMakeFiles/TEM.dir/test/test_even_mansour.c.s

# Object files for target TEM
TEM_OBJECTS = \
"CMakeFiles/TEM.dir/test/test_even_mansour.c.o"

# External object files for target TEM
TEM_EXTERNAL_OBJECTS =

TEM: CMakeFiles/TEM.dir/test/test_even_mansour.c.o
TEM: CMakeFiles/TEM.dir/build.make
TEM: libLIB.a
TEM: CMakeFiles/TEM.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/uboan_linux/code/sm4_256/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable TEM"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/TEM.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/TEM.dir/build: TEM

.PHONY : CMakeFiles/TEM.dir/build

CMakeFiles/TEM.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/TEM.dir/cmake_clean.cmake
.PHONY : CMakeFiles/TEM.dir/clean

CMakeFiles/TEM.dir/depend:
	cd /home/uboan_linux/code/sm4_256/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/uboan_linux/code/sm4_256 /home/uboan_linux/code/sm4_256 /home/uboan_linux/code/sm4_256/build /home/uboan_linux/code/sm4_256/build /home/uboan_linux/code/sm4_256/build/CMakeFiles/TEM.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/TEM.dir/depend

