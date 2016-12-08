# - Try to find Irssi
# Once done, this will define
#
#  Irssi_FOUND - system has LibIrssi
#  Irssi_INCLUDE_DIRS - the LibIrssi include directories
#  Irssi_LIBRARIES - link these to use LibIrssi
#
# See documentation on how to write CMake scripts at
# http://www.cmake.org/Wiki/CMake:How_To_Find_Libraries

include(LibFindMacros)

libfind_package(Irssi Glib)
find_path(Irssi_INCLUDE_DIR NAMES src/core/chatnets.h PATH_SUFFIXES irssi)

if (Irssi_INCLUDE_DIR)
  string(REGEX REPLACE "include/irssi$" "lib/irssi/modules" Irssi_MODULE_DIR "${Irssi_INCLUDE_DIR}")
  string(REGEX REPLACE "include/irssi$" "share/irssi" Irssi_SHARE_DIR "${Irssi_INCLUDE_DIR}")
endif()

# Irssi has b0rked headers that require subdirectories to be included in path
set(Irssi_src_INCLUDE_DIR ${Irssi_INCLUDE_DIR}/src)
set(Irssi_core_INCLUDE_DIR ${Irssi_INCLUDE_DIR}/src/core)
set(Irssi_PROCESS_INCLUDES Irssi_src_INCLUDE_DIR Irssi_core_INCLUDE_DIR)

# The headers would cause a lot of warnings...
add_definitions(-Wno-missing-field-initializers -Wno-unused-parameter)

libfind_process(Irssi)

