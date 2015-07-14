# - Try to find libevent include dirs and libraries
#
# Usage of this module as follows:
#
#     find_package(Event)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  EVENT_ROOT                Set this variable to the root installation of
#                            libevent if the module has problems finding the
#                            proper installation path.
#
# Variables defined by this module:
#
#  EVENT_FOUND                System has libevent, include and library dirs found
#  EVENT_INCLUDE_DIR          The libevent include directories.
#  EVENT_LIBRARY              The libevent library (possibly includes a thread
#                            library e.g. required by pf_ring's libevent)

find_path(EVENT_ROOT
    NAMES include/event.h
)

find_path(EVENT_INCLUDE_DIR
    NAMES event.h
    HINTS ${EVENT_ROOT}/include
)

find_library(EVENT_LIBRARY
    NAMES event
    HINTS ${EVENT_ROOT}/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(EVENT DEFAULT_MSG
    EVENT_LIBRARY
    EVENT_INCLUDE_DIR
)

include(CheckCSourceCompiles)
set(CMAKE_REQUIRED_LIBRARIES ${EVENT_LIBRARY})
set(CMAKE_REQUIRED_INCLUDES ${EVENT_INCLUDE_DIR})
#check_c_source_compiles("#include <event.h> int main() { return 0; }" EVENT_LINKS_SOLO)
set(CMAKE_REQUIRED_LIBRARIES)

mark_as_advanced(
    EVENT_ROOT
    EVENT_INCLUDE_DIR
    EVENT_LIBRARY
)