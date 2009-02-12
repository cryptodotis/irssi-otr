# irssi public headers

IF(NOT IRSSI_INCLUDE_DIR)
  MESSAGE(FATAL_ERROR "*** no irssi found. If you don't want this plugin set the
  appropriate option to OFF, use for instance 'ccmake .' ***")
ENDIF(NOT IRSSI_INCLUDE_DIR)

MESSAGE(STATUS "*** building for irssi ***")

SET(IRCOTR_INCLUDE_DIRS
  ${IRCOTR_INCLUDE_DIRS}
  ${IRSSI_INCLUDE_DIR}/irssi
  ${IRSSI_INCLUDE_DIR}/irssi/src
  ${IRSSI_INCLUDE_DIR}/irssi/src/core
  ${PROJECT_BINARY_DIR}/irssi-headers
  ${PROJECT_SOURCE_DIR}/irssi-headers
  irssi)

INCLUDE_DIRECTORIES(${IRCOTR_INCLUDE_DIRS})

SET(CMAKE_REQUIRED_INCLUDES ${IRCOTR_INCLUDE_DIRS})

# irssi statusbar header

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
    MESSAGE(FATAL_ERROR_ERROR "Couldn't check out irssi headers from SVN")
  ENDIF(NOT IISBAR_RET EQUAL 0)
  SET(HAVE_IRSSISBAR_H 1 CACHE INTERNAL "Having irssi headers" FORCE)
ENDIF (NOT HAVE_IRSSISBAR_H)

ADD_LIBRARY(irssiotr SHARED irssi/irssi_otr.c otr_util.c otr_ops.c otr_key.c io_util.c ${CMAKE_BINARY_DIR}/otr-formats.c)
TARGET_LINK_LIBRARIES(irssiotr ${GLIB_LIBRARIES} ${LIBOTR_LIBRARIES})
SET_TARGET_PROPERTIES(irssiotr PROPERTIES 
  COMPILE_FLAGS -DTARGET_IRSSI
  OUTPUT_NAME "otr"
  LINK_FLAGS "${MAIN_LDFLAGS}")
IF(APPLE)
  SET_TARGET_PROPERTIES(irssiotr PROPERTIES SUFFIX ".so")
ENDIF(APPLE)

# docdir

IF(NOT DOCDIR)
  SET(DOCDIR share/doc/irssi-otr)
ENDIF(NOT DOCDIR)

IF(CMAKE_INSTALL_TYPE MATCHES "home")
  INSTALL(TARGETS irssiotr DESTINATION "$ENV{HOME}/.irssi/modules")
ELSE(CMAKE_INSTALL_TYPE MATCHES "home")
  INSTALL(TARGETS irssiotr DESTINATION lib${LIB_SUFFIX}/irssi/modules)
  INSTALL(FILES README LICENSE DESTINATION ${DOCDIR})
ENDIF(CMAKE_INSTALL_TYPE MATCHES "home")
