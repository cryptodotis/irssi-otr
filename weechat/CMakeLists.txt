IF(NOT WEECHAT_INCLUDE_DIR)
  MESSAGE(FATAL_ERROR "*** no weechat found. If you don't want this plugin set the
  appropriate option to OFF, use for instance 'ccmake .' ***")
ENDIF(NOT WEECHAT_INCLUDE_DIR)

MESSAGE(STATUS "*** building for weechat ***")

SET(WEECHATOTR_INCLUDE_DIRS
  ${WEECHAT_INCLUDE_DIR}/weechat
  ${PROJECT_SOURCE_DIR}/weechat)

INCLUDE_DIRECTORIES(${WEECHATOTR_INCLUDE_DIRS})

ADD_LIBRARY(weechatotr SHARED weechat_otr.c ../otr_util.c ../otr_ops.c ../otr_key.c ../io_util.c ../io_set.c ${PROJECT_BINARY_DIR}/xchat-formats.c)
TARGET_LINK_LIBRARIES(weechatotr ${GLIB_LIBRARIES} ${LIBOTR_LIBRARIES})
SET_TARGET_PROPERTIES(weechatotr PROPERTIES 
  COMPILE_FLAGS -DTARGET_WEECHAT
  OUTPUT_NAME "weechatotr"
  LINK_FLAGS "${MAIN_LDFLAGS}")

add_dependencies(weechatotr otrformats)
set_source_files_properties(${CMAKE_BINARY_DIR}/xchat-formats.c PROPERTIES GENERATED TRUE)

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
