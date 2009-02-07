IF(NOT XCHAT_INCLUDE_DIR)
  MESSAGE(FATAL_ERROR "*** no xchat found. If you don't want this plugin set the
  appropriate option to OFF, use for instance 'ccmake .' ***")
ENDIF(NOT XCHAT_INCLUDE_DIR)

MESSAGE(STATUS "*** building for xchat ***")

SET(IRCOTR_INCLUDE_DIRS
  ${IRCOTR_INCLUDE_DIRS}
  ${XCHAT_INCLUDE_DIR}/xchat
  xchat)

INCLUDE_DIRECTORIES(${IRCOTR_INCLUDE_DIRS})

ADD_LIBRARY(xchatotr SHARED xchat/xchat_otr.c otr_util.c otr_ops.c otr_key.c ${PROJECT_BINARY_DIR}/xchat-formats.c)
TARGET_LINK_LIBRARIES(xchatotr ${GLIB_LIBRARIES} ${LIBOTR_LIBRARIES})
SET_TARGET_PROPERTIES(xchatotr PROPERTIES 
  COMPILE_FLAGS -DTARGET_XCHAT
  OUTPUT_NAME "xchatotr"
  LINK_FLAGS "${MAIN_LDFLAGS}")

IF(APPLE)
  SET_TARGET_PROPERTIES(xchatotr PROPERTIES SUFFIX ".so")
ENDIF(APPLE)

# docdir

IF(NOT DOCDIR)
  SET(DOCDIR share/doc/xchat-otr)
ENDIF(NOT DOCDIR)

INSTALL(TARGETS xchatotr DESTINATION lib${LIB_SUFFIX}/xchat/plugins)
INSTALL(FILES README LICENSE DESTINATION ${DOCDIR})
