# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.20

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
CMAKE_SOURCE_DIR = /home/coolder/git/c-hack-tools/000_syn_flood

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/coolder/git/c-hack-tools/000_syn_flood/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/000_syn_flood.dir/depend.make
# Include the progress variables for this target.
include CMakeFiles/000_syn_flood.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/000_syn_flood.dir/flags.make

CMakeFiles/000_syn_flood.dir/main.c.o: CMakeFiles/000_syn_flood.dir/flags.make
CMakeFiles/000_syn_flood.dir/main.c.o: ../main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/coolder/git/c-hack-tools/000_syn_flood/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/000_syn_flood.dir/main.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/000_syn_flood.dir/main.c.o -c /home/coolder/git/c-hack-tools/000_syn_flood/main.c

CMakeFiles/000_syn_flood.dir/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/000_syn_flood.dir/main.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/coolder/git/c-hack-tools/000_syn_flood/main.c > CMakeFiles/000_syn_flood.dir/main.c.i

CMakeFiles/000_syn_flood.dir/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/000_syn_flood.dir/main.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/coolder/git/c-hack-tools/000_syn_flood/main.c -o CMakeFiles/000_syn_flood.dir/main.c.s

CMakeFiles/000_syn_flood.dir/test.c.o: CMakeFiles/000_syn_flood.dir/flags.make
CMakeFiles/000_syn_flood.dir/test.c.o: test.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/coolder/git/c-hack-tools/000_syn_flood/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/000_syn_flood.dir/test.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/000_syn_flood.dir/test.c.o -c /home/coolder/git/c-hack-tools/000_syn_flood/cmake-build-debug/test.c

CMakeFiles/000_syn_flood.dir/test.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/000_syn_flood.dir/test.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/coolder/git/c-hack-tools/000_syn_flood/cmake-build-debug/test.c > CMakeFiles/000_syn_flood.dir/test.c.i

CMakeFiles/000_syn_flood.dir/test.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/000_syn_flood.dir/test.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/coolder/git/c-hack-tools/000_syn_flood/cmake-build-debug/test.c -o CMakeFiles/000_syn_flood.dir/test.c.s

# Object files for target 000_syn_flood
000_syn_flood_OBJECTS = \
"CMakeFiles/000_syn_flood.dir/main.c.o" \
"CMakeFiles/000_syn_flood.dir/test.c.o"

# External object files for target 000_syn_flood
000_syn_flood_EXTERNAL_OBJECTS =

000_syn_flood: CMakeFiles/000_syn_flood.dir/main.c.o
000_syn_flood: CMakeFiles/000_syn_flood.dir/test.c.o
000_syn_flood: CMakeFiles/000_syn_flood.dir/build.make
000_syn_flood: CMakeFiles/000_syn_flood.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/coolder/git/c-hack-tools/000_syn_flood/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C executable 000_syn_flood"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/000_syn_flood.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/000_syn_flood.dir/build: 000_syn_flood
.PHONY : CMakeFiles/000_syn_flood.dir/build

CMakeFiles/000_syn_flood.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/000_syn_flood.dir/cmake_clean.cmake
.PHONY : CMakeFiles/000_syn_flood.dir/clean

CMakeFiles/000_syn_flood.dir/depend:
	cd /home/coolder/git/c-hack-tools/000_syn_flood/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/coolder/git/c-hack-tools/000_syn_flood /home/coolder/git/c-hack-tools/000_syn_flood /home/coolder/git/c-hack-tools/000_syn_flood/cmake-build-debug /home/coolder/git/c-hack-tools/000_syn_flood/cmake-build-debug /home/coolder/git/c-hack-tools/000_syn_flood/cmake-build-debug/CMakeFiles/000_syn_flood.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/000_syn_flood.dir/depend

