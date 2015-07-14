# - Try to find libre2 include dirs and libraries
#
# Usage of this module as follows:
#
#     find_package(RE2)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  RE2_ROOT                  Set this variable to the root installation of
#                            libre2 if the module has problems finding the
#                            proper installation path.
#
# Variables defined by this module:
#
#  RE2_FOUND                 System has libre2, include and library dirs found
#  RE2_INCLUDE_DIR           The libre2 include directories.
#  RE2_LIBRARY               The libre2 library (possibly includes a thread
#                            library e.g. required by pf_ring's libre2)

find_path(RE2_ROOT
    NAMES include/re2/re2.h
)

find_path(RE2_INCLUDE_DIR
    NAMES re2/re2.h
    HINTS ${RE2_ROOT}/include
)

find_library(RE2_LIBRARY
    NAMES re2
    HINTS ${RE2_ROOT}/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(RE2 DEFAULT_MSG
    RE2_LIBRARY
    RE2_INCLUDE_DIR
)

# include(CheckCSourceCompiles)
# set(CMAKE_REQUIRED_LIBRARIES ${RE2_LIBRARY})
# check_c_source_compiles("#include <re2.h> int main() { return 0; }" RE2_LINKS_SOLO)
# set(CMAKE_REQUIRED_LIBRARIES)

mark_as_advanced(
    RE2_ROOT
    RE2_INCLUDE_DIR
    RE2_LIBRARY
)