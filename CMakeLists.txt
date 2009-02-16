#
# Off-the-Record Messaging (OTR) modules for IRC
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

PROJECT(irc-otr)

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

IF(NOT IRCOTR_VERSION)
  IF(NOT EXISTS "${PROJECT_SOURCE_DIR}/.git")
    MESSAGE(FATAL_ERROR "Cannot determine the irc-otr version since this is "
    "not a git checkout. Please set IRCOTR_VERSION, e.g.
    cmake -DIRCOTR_VERSION=mydistro-0.1
    or
    cmake -DIRCOTR_VERSION=mydistro-git-<git-commit>")
  ENDIF(NOT EXISTS "${PROJECT_SOURCE_DIR}/.git")
  FIND_GIT_TAGORCOMMIT(${PROJECT_SOURCE_DIR} IRCOTR_VERSION)
  IF(NOT IRCOTR_VERSION)
    MESSAGE(FATAL_ERROR 
      "Couldn't determine version. Please run cmake -DIRCOTR_VERSION=...")
  ENDIF(NOT IRCOTR_VERSION)
ENDIF(NOT IRCOTR_VERSION)

MESSAGE(STATUS "Building irc-otr version ${IRCOTR_VERSION}")

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

# includes

SET(IRCOTR_INCLUDE_DIRS
  ${PROJECT_SOURCE_DIR} 
  ${PROJECT_BINARY_DIR} 
  ${GLIB_INCLUDE_DIRS} 
  ${LIBOTR_INCLUDE_DIRS})

SET(CMAKE_REQUIRED_INCLUDES ${IRCOTR_INCLUDE_DIRS})
SET(CMAKE_REQUIRED_DEFINITIONS -DHAVE_CONFIG_H ${LIBGCRYPT_CFLAGS})


include_directories(${IRCOTR_INCLUDE_DIRS})

# gregex.h 
# available since 2.13 AFAIK
# optional for html stripping and nick ignoring

CHECK_INCLUDE_FILE(glib/gregex.h HAVE_GREGEX_H)

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

# generate otr-formats.{c,h}

ADD_CUSTOM_COMMAND(OUTPUT 
  otr-formats.c 
  xchat-formats.c 
  DEPENDS makeformats.py formats.txt README
  COMMAND 
  ${PYTHON_EXECUTABLE}
  ${PROJECT_SOURCE_DIR}/makeformats.py 
  ${PROJECT_SOURCE_DIR}/formats.txt
  ${PROJECT_SOURCE_DIR}/README
  )


add_custom_target(otrformats DEPENDS otr-formats.c)

# Now that took some time to figure out...

IF(APPLE)
  SET(APPLE_LDFLAGS "-single_module -undefined dynamic_lookup")
ENDIF(APPLE)

FOREACH(X ${LIBGCRYPT_LDFLAGS} ${GLIB_LDFLAGS} ${APPLE_LDFLAGS})
  SET(MAIN_LDFLAGS "${MAIN_LDFLAGS} ${X}")
ENDFOREACH(X ${LIBGCRYPT_LDFLAGS} ${GLIB_LDFLAGS} ${APPLE_LDFLAGS})

FIND_PATH(IRSSI_INCLUDE_DIR NAMES irssi/src/core/module.h)
MARK_AS_ADVANCED(IRSSI_INCLUDE_DIR)

FIND_PATH(WEECHAT_INCLUDE_DIR NAMES weechat/weechat-plugin.h
  PATHS ${CMAKE_SOURCE_DIR} ${CMAKE_BINARY_DIR})
MARK_AS_ADVANCED(WEECHAT_INCLUDE_DIR)

FIND_PATH(XCHAT_INCLUDE_DIR NAMES xchat/xchat-plugin.h)
MARK_AS_ADVANCED(XCHAT_INCLUDE_DIR)

IF(CMAKE_SOURCE_DIR MATCHES "irssi-[^/]*$")
  SET(W_IRSSI ON)
ELSEIF(CMAKE_SOURCE_DIR MATCHES "xchat-[^/]*$")
  SET(W_XCHAT ON)
ELSEIF(CMAKE_SOURCE_DIR MATCHES "weechat-[^/]*$")
  SET(W_WEECHAT ON)
ELSE(CMAKE_SOURCE_DIR MATCHES "irssi-[^/]*$")
  IF(IRSSI_INCLUDE_DIR)
    SET(W_IRSSI ON)
  ENDIF(IRSSI_INCLUDE_DIR)
  IF(XCHAT_INCLUDE_DIR)
    SET(W_XCHAT ON)
  ENDIF(XCHAT_INCLUDE_DIR)
  IF(WEECHAT_INCLUDE_DIR)
    SET(W_WEECHAT ON)
  ENDIF(WEECHAT_INCLUDE_DIR)
ENDIF(CMAKE_SOURCE_DIR MATCHES "irssi-[^/]*$")

OPTION(WANT_IRSSI "build irssi plugin" ${W_IRSSI})
OPTION(WANT_XCHAT "build xchat plugin" ${W_XCHAT})
OPTION(WANT_WEECHAT "build weechat plugin" ${W_WEECHAT})

IF(WANT_IRSSI)
  add_subdirectory(irssi)
ENDIF(WANT_IRSSI)
IF(WANT_XCHAT)
  add_subdirectory(xchat)
ENDIF(WANT_XCHAT)
IF(WANT_WEECHAT)
  add_subdirectory(weechat)
ENDIF(WANT_WEECHAT)

# cscope

FILE(GLOB CSANDHS *.c *.h)
ADD_CSCOPE_TARGET("${CSANDHS}" "${IRCOTR_INCLUDE_DIRS}")

# Source tarball
ADD_CUSTOM_TARGET(src-tarball 
  ${PROJECT_SOURCE_DIR}/mksrcpackage.sh ${PROJECT_SOURCE_DIR} 
  ${IRCOTR_VERSION})
