# - Try to find OTR
# Once done, this will define
#
#  OTR_FOUND - system has LibOTR
#  OTR_INCLUDE_DIRS - the LibOTR include directories
#  OTR_LIBRARIES - link these to use LibOTR
#
# See documentation on how to write CMake scripts at
# http://www.cmake.org/Wiki/CMake:How_To_Find_Libraries

include(LibFindMacros)

libfind_pkg_detect(OTR libotr FIND_PATH libotr/version.h FIND_LIBRARY otr)
libfind_version_header(OTR libotr/version.h OTRL_VERSION)
libfind_process(OTR)

