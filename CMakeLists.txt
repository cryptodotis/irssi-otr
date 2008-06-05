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

PROJECT(IRSSIOTR)

SET(CMAKE_MODULE_PATH 
  ${PROJECT_SOURCE_DIR}/cmake-extensions/
  ${PROJECT_BINARY_DIR})

INCLUDE(cmake-extensions/cscope.cmake)
INCLUDE(CheckFunctionExists)

# wget

FIND_PACKAGE(Wget REQUIRED)

# PkgConfig. Only available since 2.4.7, fetch if unavailable so people with
# older cmake can run this

FIND_PACKAGE(PkgConfig QUIET)

IF(NOT PKG_CONFIG_FOUND)
  MESSAGE(STATUS "Couldn't find the pkg-config cmake module. Seems you're
  running cmake < 2.4.7. Will try to fetch the module from 2.4.7...")
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

# irssi public headers

FIND_PATH(IRSSI_INCLUDE_DIR NAMES irssi/src/core/module.h)
MARK_AS_ADVANCED(IRSSI_INCLUDE_DIR)

IF(NOT IRSSI_INCLUDE_DIR)
  MESSAGE(FATAL_ERROR "Couldn't find irssi headers, "
    "usually installed in /usr/include/irssi")
ENDIF(NOT IRSSI_INCLUDE_DIR)

# Bad hack for irssi private headers

IF (NOT EXISTS "mainwindows.h")
  MESSAGE(STATUS "Need to fetch and patch irssi private headers "
    "mainwindows.h,statusbar.h,term.h from SVN (see irssi FS#535)")
  EXECUTE_PROCESS(COMMAND "bash" "-c"
    "${WGET_EXECUTABLE} '--post-data=revision=4806&root=irssi' \\
    'http://svn.irssi.org/cgi-bin/viewvc.cgi/irssi/trunk/src/fe-text/mainwindows.h' \\
    'http://svn.irssi.org/cgi-bin/viewvc.cgi/irssi/trunk/src/fe-text/term.h' \\
    'http://svn.irssi.org/cgi-bin/viewvc.cgi/irssi/trunk/src/fe-text/statusbar.h' || exit 1
    patch -p0 mainwindows.h < \"$0/privheaders.patch\" || exit 1" 
    ${PROJECT_SOURCE_DIR} RESULT_VARIABLE IIPRIV_RET)
  IF(NOT IIPRIV_RET EQUAL 0)
    MESSAGE(FATAL_ERROR "Couldn't check out irssi private headers from SVN")
  ENDIF(NOT IIPRIV_RET EQUAL 0)
ENDIF (NOT EXISTS "mainwindows.h")

# includes

SET(IRSSIOTR_INCLUDE_DIRS
  ${PROJECT_SOURCE_DIR} ${PROJECT_BINARY_DIR} ${GLIB_INCLUDE_DIRS} 
  ${LIBOTR_INCLUDE_DIRS} 
  ${IRSSI_INCLUDE_DIR}/irssi
  ${IRSSI_INCLUDE_DIR}/irssi/src
  ${IRSSI_INCLUDE_DIR}/irssi/src/core)

include_directories(${IRSSIOTR_INCLUDE_DIRS})

# check for strsignal

CHECK_FUNCTION_EXISTS(strsignal HAVE_STRSIGNAL)
IF(HAVE_STRSIGNAL)
  SET_SOURCE_FILES_PROPERTIES(otr_key.c PROPERTIES COMPILE_FLAGS 
    "-DHAVE_STRSIGNAL")
ENDIF(HAVE_STRSIGNAL)

# defs

ADD_DEFINITIONS(-DHAVE_CONFIG_H -Wall -g)

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

# Install

INSTALL(SCRIPT cmake-extensions/InstallAsUser.cmake)
INSTALL(TARGETS otr DESTINATION modules/)

# cscope

FILE(GLOB CSANDHS *.c *.h)
ADD_CSCOPE_TARGET("${CSANDHS}" "${IRSSIOTR_INCLUDE_DIRS}")
