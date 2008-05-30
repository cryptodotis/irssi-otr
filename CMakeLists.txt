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

SET(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake-extensions/)
INCLUDE(cmake-extensions/cscope.cmake)

# GLIB

FIND_PACKAGE(PkgConfig REQUIRED)
pkg_check_modules(GLIB REQUIRED glib-2.0)

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

FIND_PACKAGE(Wget REQUIRED)

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

# defs

ADD_DEFINITIONS(-DHAVE_CONFIG_H -Wall -g)

# generate otr-formats.{c,h}

ADD_CUSTOM_COMMAND(OUTPUT ${PROJECT_BINARY_DIR}/otr-formats.c 
  DEPENDS makeformats.py formats.txt README
  COMMAND 
  ${PROJECT_SOURCE_DIR}/makeformats.py 
  ${PROJECT_SOURCE_DIR}/formats.txt
  ${PROJECT_SOURCE_DIR}/README
  )

# lib

ADD_LIBRARY(otr SHARED otr.c otrutil.c otr_ops.c otr_key.c ui.c ${PROJECT_BINARY_DIR}/otr-formats.c)

TARGET_LINK_LIBRARIES(otr ${GLIB_LIBRARIES} ${LIBOTR_LIBRARIES})

# Install

EXECUTE_PROCESS(COMMAND "whoami" OUTPUT_VARIABLE WHOAMI)
IF(WHOAMI STREQUAL "root\n")
  SET(IRSSIOTR_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/lib/irssi/modules/")
  MESSAGE(STATUS "Install will be into ${IRSSIOTR_INSTALL_DIR}")
ELSE(WHOAMI STREQUAL "root\n")
  SET(IRSSIOTR_INSTALL_DIR "$ENV{HOME}/.irssi/modules/")
  MESSAGE(STATUS "You're not root. Install will be into ${IRSSIOTR_INSTALL_DIR}")
ENDIF(WHOAMI STREQUAL "root\n")

INSTALL(TARGETS otr DESTINATION ${IRSSIOTR_INSTALL_DIR})

# cscope

FILE(GLOB CSANDHS *.c *.h)
ADD_CSCOPE_TARGET(${CSANDHS} ${IRSSIOTR_INCLUDE_DIRS})
