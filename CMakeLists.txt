#
# Off-the-Record Messaging (OTR) module for the irssi IRC client
# Copyright (C) 2008  Uli Meis <a.sporto+bee@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
#

PROJECT(irssi-otr)

CMAKE_MINIMUM_REQUIRED(VERSION 2.4)
IF(COMMAND cmake_policy)
  cmake_policy(SET CMP0003 NEW)
ENDIF(COMMAND cmake_policy)

SET(CMAKE_MODULE_PATH 
  ${PROJECT_SOURCE_DIR}/cmake-extensions/
  ${PROJECT_BINARY_DIR})

INCLUDE(cmake-extensions/cscope.cmake)
INCLUDE(cmake-extensions/Git.cmake)
INCLUDE(CheckFunctionExists)
INCLUDE(CheckIncludeFile)
INCLUDE(CheckIncludeFiles)
INCLUDE(tarballdefs.cmake OPTIONAL)

# get version from git

IF(NOT IRSSIOTR_VERSION)
  IF(NOT EXISTS "${PROJECT_SOURCE_DIR}/.git")
    MESSAGE(FATAL_ERROR "Cannot determine the irssi-otr version since this is "
    "not a git checkout. Please set IRSSIOTR_VERSION, e.g.
    cmake -DIRSSIOTR_VERSION=mydistro-0.1
    or
    cmake -DIRSSIOTR_VERSION=mydistro-git-<git-commit>")
  ENDIF(NOT EXISTS "${PROJECT_SOURCE_DIR}/.git")
  FIND_GIT_TAGORCOMMIT(${PROJECT_SOURCE_DIR} IRSSIOTR_VERSION)
  IF(NOT IRSSIOTR_VERSION)
    MESSAGE(FATAL_ERROR 
      "Couldn't determine version. Please run cmake -DIRSSIOTR_VERSION=...")
  ENDIF(NOT IRSSIOTR_VERSION)
ENDIF(NOT IRSSIOTR_VERSION)

MESSAGE(STATUS "Building irssi-otr version ${IRSSIOTR_VERSION}")

# PkgConfig. Only available since 2.4.7, fetch if unavailable so people with
# older cmake can run this

FIND_PACKAGE(PkgConfig QUIET)

IF(NOT PKG_CONFIG_FOUND)
  MESSAGE(STATUS "Couldn't find the pkg-config cmake module. Seems you're
  running cmake < 2.4.7. Will try to fetch the module from 2.4.7...")
  FIND_PACKAGE(Wget REQUIRED)
  EXECUTE_PROCESS(COMMAND "bash" "-c"
    "${WGET_EXECUTABLE} '-O' '-' \\
    'http://www.cmake.org/files/v2.4/cmake-2.4.7.tar.gz' | \\
    tar xz cmake-2.4.7/Modules/FindPkgConfig.cmake && \\
    mv cmake-2.4.7/Modules/FindPkgConfig.cmake . && \\
    rmdir -p cmake-2.4.7/Modules"
    RESULT_VARIABLE PKGCONF_RET)
  IF(NOT PKGCONF_RET EQUAL 0)
    MESSAGE(FATAL_ERROR "Couldnt download cmake module for pkg-config")
  ENDIF(NOT PKGCONF_RET EQUAL 0)
  FIND_PACKAGE(PkgConfig REQUIRED)
ENDIF(NOT PKG_CONFIG_FOUND)

# GLIB

pkg_check_modules(GLIB REQUIRED glib-2.0)

# Python

FIND_PACKAGE(PythonInterp)
IF(NOT PYTHON_EXECUTABLE)
  MESSAGE(FATAL_ERROR "Couldn't find a python interpreter")
ENDIF(NOT PYTHON_EXECUTABLE)

# LIBOTR

FIND_PACKAGE(LibOTR REQUIRED)
IF (LIBOTR_VERSION LESS "3.1.0")
  MESSAGE(FATAL_ERROR "Need libotr version >= 3.1.0 (fragmentation)")
ENDIF (LIBOTR_VERSION LESS "3.1.0")

# LIBGCRYPT. A dependency of libotr and therefore one of ours.

FIND_PACKAGE(LibGcrypt REQUIRED)

# irssi public headers

FIND_PATH(IRSSI_INCLUDE_DIR NAMES irssi/src/core/module.h)
MARK_AS_ADVANCED(IRSSI_INCLUDE_DIR)

IF(NOT IRSSI_INCLUDE_DIR)
  MESSAGE(FATAL_ERROR "Couldn't find irssi headers, "
    "usually installed in /usr/include/irssi")
ENDIF(NOT IRSSI_INCLUDE_DIR)

# includes

SET(IRSSIOTR_INCLUDE_DIRS
  ${PROJECT_SOURCE_DIR} 
  ${PROJECT_BINARY_DIR} 
  ${GLIB_INCLUDE_DIRS} 
  ${LIBOTR_INCLUDE_DIRS} 
  ${IRSSI_INCLUDE_DIR}/irssi
  ${IRSSI_INCLUDE_DIR}/irssi/src
  ${IRSSI_INCLUDE_DIR}/irssi/src/core
  ${PROJECT_BINARY_DIR}/irssi-headers
  ${PROJECT_SOURCE_DIR}/irssi-headers)

include_directories(${IRSSIOTR_INCLUDE_DIRS})
SET(CMAKE_REQUIRED_INCLUDES ${IRSSIOTR_INCLUDE_DIRS})
SET(CMAKE_REQUIRED_DEFINITIONS -DHAVE_CONFIG_H ${LIBGCRYPT_CFLAGS})

# gregex.h 
# available since 2.13 AFAIK
# optional for html stripping and nick ignoring

CHECK_INCLUDE_FILE(glib/gregex.h HAVE_GREGEX_H)

# irssi headers

CHECK_INCLUDE_FILES("glib.h;common.h;fe-text/statusbar-item.h" HAVE_IRSSISBAR_H)

# Bad hack

IF (NOT HAVE_IRSSISBAR_H)
  MESSAGE(STATUS "Need to fetch irssi header statusbar-item.h (you don't have it yet)")
  IF (NOT WGET_EXECUTABLE)
    FIND_PACKAGE(Wget REQUIRED)
  ENDIF (NOT WGET_EXECUTABLE)
  EXECUTE_PROCESS(COMMAND "mkdir" -p irssi-headers/fe-text)
  EXECUTE_PROCESS(COMMAND "bash" "-c"
    "${WGET_EXECUTABLE} '--post-data=revision=4936&root=irssi' \\
    'http://svn.irssi.org/cgi-bin/viewvc.cgi/irssi/trunk/src/fe-text/statusbar-item.h' || exit 1"
    ${PROJECT_SOURCE_DIR} WORKING_DIRECTORY irssi-headers/fe-text
    RESULT_VARIABLE IISBAR_RET)
  IF(NOT IISBAR_RET EQUAL 0)
    MESSAGE(FATAL_ERROR "Couldn't check out irssi headers from SVN")
  ENDIF(NOT IISBAR_RET EQUAL 0)
  SET(HAVE_IRSSISBAR_H 1 CACHE INTERNAL "Having irssi headers" FORCE)
ENDIF (NOT HAVE_IRSSISBAR_H)

# check for strsignal

CHECK_FUNCTION_EXISTS(strsignal HAVE_STRSIGNAL)

# generate io-config.h

CONFIGURE_FILE(io-config.h.in io-config.h)

# defs

IF(NOT CMAKE_BUILD_TYPE)
  SET(CMAKE_BUILD_TYPE debug)
ENDIF(NOT CMAKE_BUILD_TYPE)
SET(CMAKE_C_FLAGS_DEBUG -g)

MESSAGE(STATUS "This is a ${CMAKE_BUILD_TYPE} build")

ADD_DEFINITIONS(-DHAVE_CONFIG_H -Wall ${LIBGCRYPT_CFLAGS})

# docdir

IF(NOT DOCDIR)
  SET(DOCDIR share/doc/${CMAKE_PROJECT_NAME})
ENDIF(NOT DOCDIR)

# generate otr-formats.{c,h}

ADD_CUSTOM_COMMAND(OUTPUT ${PROJECT_BINARY_DIR}/otr-formats.c 
  DEPENDS makeformats.py formats.txt README
  COMMAND 
  ${PYTHON_EXECUTABLE}
  ${PROJECT_SOURCE_DIR}/makeformats.py 
  ${PROJECT_SOURCE_DIR}/formats.txt
  ${PROJECT_SOURCE_DIR}/README
  )

# lib

ADD_LIBRARY(otr SHARED otr.c otrutil.c otr_ops.c otr_key.c ui.c ${PROJECT_BINARY_DIR}/otr-formats.c)

TARGET_LINK_LIBRARIES(otr ${GLIB_LIBRARIES} ${LIBOTR_LIBRARIES})

# Now that took some time to figure out...

IF(APPLE)
  SET(APPLE_LDFLAGS "-single_module -undefined dynamic_lookup")
  SET_TARGET_PROPERTIES(otr PROPERTIES SUFFIX ".so")
ENDIF(APPLE)

FOREACH(X ${LIBGCRYPT_LDFLAGS} ${GLIB_LDFLAGS} ${APPLE_LDFLAGS})
  SET(MAIN_LDFLAGS "${MAIN_LDFLAGS} ${X}")
ENDFOREACH(X ${LIBGCRYPT_LDFLAGS} ${GLIB_LDFLAGS} ${APPLE_LDFLAGS})

SET_TARGET_PROPERTIES(otr PROPERTIES 
  LINK_FLAGS "${MAIN_LDFLAGS}")

# cscope

FILE(GLOB CSANDHS *.c *.h)
ADD_CSCOPE_TARGET("${CSANDHS}" "${IRSSIOTR_INCLUDE_DIRS}")

# Install / CPack

IF(CMAKE_INSTALL_TYPE MATCHES "package-.*")
  INCLUDE(Packaging.cmake)
ELSEIF(CMAKE_INSTALL_TYPE MATCHES "home")
  INSTALL(TARGETS otr DESTINATION "$ENV{HOME}/.irssi/modules")
ELSE(CMAKE_INSTALL_TYPE MATCHES "package-.*")
  INSTALL(TARGETS otr DESTINATION lib${LIB_SUFFIX}/irssi/modules)
  INSTALL(FILES README LICENSE DESTINATION ${DOCDIR})
ENDIF(CMAKE_INSTALL_TYPE MATCHES "package-.*")
