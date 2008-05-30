#
# Uli Meis <a.sporto+bee@gmail.com>
#
# Handy macro for generating the cscope database
#

MACRO(ADD_CSCOPE_TARGET CSCOPE_SOURCES CSCOPE_INCLUDES)
  ADD_CUSTOM_COMMAND(
    OUTPUT cscope.out
    DEPENDS ${CSCOPE_SOURCES}
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    COMMAND 
      echo '${CSCOPE_SOURCES}' | tr ' ' '\\n' >cscope.files
    COMMAND
      cscope -b `echo ${CSCOPE_INCLUDES} | xargs -n1 bash -c 'echo -I$$0'`)
  ADD_CUSTOM_TARGET(cscope DEPENDS cscope.out)
ENDMACRO(ADD_CSCOPE_TARGET)
