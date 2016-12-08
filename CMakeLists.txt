cmake_minimum_required(VERSION 2.8)
project(irssi-otr C)
set(PROJECT_VERSION "1.0.0")
set(BUILD_SHARED_LIBS ON)

# Avoid source tree pollution
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
	message(FATAL_ERROR "In-source builds are not permitted. Make a separate folder for building:\nmkdir build; cd build; cmake ..\nBefore that, remove the files already created:\nrm -rf CMakeCache.txt CMakeFiles")
endif(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")

# Add a sensible build type default and warning because empty means no optimization and no debug info.
if(NOT CMAKE_BUILD_TYPE)
	message("WARNING: CMAKE_BUILD_TYPE is not defined!\n         Defaulting to CMAKE_BUILD_TYPE=Debug. Use ccmake to set a proper value.")
	SET(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel." FORCE)
endif(NOT CMAKE_BUILD_TYPE)

# Disable assertions for release builds
if(CMAKE_BUILD_TYPE STREQUAL "Release")
	add_definitions("-DNDEBUG")
endif()

# Enable extra compiler flags...
set(CMAKE_C_FLAGS "-std=gnu99 -Wall -Wextra ${CMAKE_CXX_FLAGS}")

set(IRSSI_MODULE_DIR "lib/irssi/modules" CACHE STRING "Irssi module install path. Must be a relative path (from CMAKE_INSTALL_PREFIX), with no trailing slash.")
mark_as_advanced(IRSSI_MODULE_DIR)

set(IRSSI_HELP_DIR "share/irssi/help" CACHE STRING "Help page install path. Must be a relative path (from CMAKE_INSTALL_PREFIX), with no trailing slash.")
mark_as_advanced(IRSSI_HELP_DIR)

find_package(Threads REQUIRED)
find_package(OTR 4.0.0 REQUIRED)
find_package(Irssi REQUIRED)
include_directories(${Threads_INCLUDE_DIRS} ${OTR_INCLUDE_DIRS} ${Irssi_INCLUDE_DIRS})

add_definitions(-DMODULE_NAME=\"otr\")
add_definitions(-DVERSION=\"${PROJECT_VERSION}\")
add_definitions(-pthread)

file(GLOB srcfiles src/*.h src/*.c)
add_library(otr MODULE ${srcfiles})
target_link_libraries(otr ${Threads_LIBRARIES} ${OTR_LIBRARIES} ${Irssi_LIBRARIES})

install(TARGETS otr DESTINATION ${Irssi_MODULE_DIR})
install(FILES help/otr DESTINATION ${Irssi_SHARE_DIR}/help)

