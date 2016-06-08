if(POLICY CMP0026)
   cmake_policy(SET CMP0022 OLD)
endif()
cmake_minimum_required (VERSION 2.6)
project (flow-abstractor)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

set (FABS_VERSION_MAJOR 0)
set (FABS_VERSION_MINOR 2)

add_subdirectory(src)
