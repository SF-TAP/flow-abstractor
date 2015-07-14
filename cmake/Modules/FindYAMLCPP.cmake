# - Try to find libyaml-cpp include dirs and libraries
#
# Usage of this module as follows:
#
#     find_package(YAMLCPP)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  YAMLCPP_ROOT          Set this variable to the root installation of
#                        libyaml-cpp if the module has problems finding the
#                        proper installation path.
#
# Variables defined by this module:
#
#  YAMLCPP_FOUND         System has libyaml-cpp, include and library dirs found
#  YAMLCPP_INCLUDE_DIR   The libyaml-cpp include directories.
#  YAMLCPP_LIBRARY       The libyaml-cpp library (possibly includes a thread
#                        library e.g. required by pf_ring's libyaml-cpp)

find_path(YAMLCPP_ROOT
    NAMES include/yaml-cpp/yaml.h
)

find_path(YAMLCPP_INCLUDE_DIR
    NAMES yaml-cpp/yaml.h
    HINTS ${YAMLCPP_ROOT}/include
)

find_library(YAMLCPP_LIBRARY
    NAMES yaml-cpp
    HINTS ${YAMLCPP_ROOT}/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(YAMLCPP DEFAULT_MSG
    YAMLCPP_LIBRARY
    YAMLCPP_INCLUDE_DIR
)

mark_as_advanced(
    YAMLCPP_ROOT
    YAMLCPP_INCLUDE_DIR
    YAMLCPP_LIBRARY
)