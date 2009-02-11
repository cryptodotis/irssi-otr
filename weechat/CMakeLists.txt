IF(NOT WEECHAT_INCLUDE_DIR)
  MESSAGE(FATAL_ERROR "*** no weechat found. If you don't want this plugin set the
  appropriate option to OFF, use for instance 'ccmake .' ***")
ENDIF(NOT WEECHAT_INCLUDE_DIR)

MESSAGE(STATUS "*** building for weechat ***")
SET(IRCOTR_INCLUDE_DIRS
  ${IRCOTR_INCLUDE_DIRS}
  ${WEECHAT_INCLUDE_DIR}/weechat
  weechat)

INCLUDE_DIRECTORIES(${IRCOTR_INCLUDE_DIRS})

ADD_LIBRARY(weechatotr SHARED weechat/weechat_otr.c otr_util.c otr_ops.c otr_key.c ${PROJECT_BINARY_DIR}/xchat-formats.c)
TARGET_LINK_LIBRARIES(weechatotr ${GLIB_LIBRARIES} ${LIBOTR_LIBRARIES})
SET_TARGET_PROPERTIES(weechatotr PROPERTIES 
  COMPILE_FLAGS -DTARGET_WEECHAT
  OUTPUT_NAME "weechatotr"
  LINK_FLAGS "${MAIN_LDFLAGS}")
IF(APPLE)
  SET_TARGET_PROPERTIES(weechatotr PROPERTIES SUFFIX ".so")
ENDIF(APPLE)

# docdir

IF(NOT DOCDIR)
  SET(DOCDIR share/doc/weechat-otr)
ENDIF(NOT DOCDIR)

SET_TARGET_PROPERTIES(weechatotr PROPERTIES PREFIX "" OUTPUT_NAME "irc-otr")

INSTALL(TARGETS weechatotr DESTINATION lib${LIB_SUFFIX}/weechat/plugins)
INSTALL(FILES README LICENSE DESTINATION ${DOCDIR})
