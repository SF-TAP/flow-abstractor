if(POLICY CMP0026)
  cmake_policy(SET CMP0022 OLD)
endif()

option(USE_JEMALLOC "Use jemalloc" 0)

IF(POLICY CMP0042)
  cmake_policy(SET CMP0042 NEW)
ENDIF(POLICY CMP0042)

IF(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  set(CMAKE_CXX_FLAGS "-Wall -fPIC -std=c++11 -framework CoreFoundation")
  set(CMAKE_CXX_FLAGS_DEBUG "-g -O0")
  set(CMAKE_CXX_FLAGS_RELEASE "-O3")
ELSE(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  set(CMAKE_CXX_FLAGS "-Wall -fPIC -std=c++11")
  set(CMAKE_CXX_FLAGS_DEBUG "-g -O0")
  set(CMAKE_CXX_FLAGS_RELEASE "-O3")
ENDIF(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")

option(COMPILE_STATIC_LIB "Compile Static Library" 0)

FILE(GLOB CPPSources *.cpp)
FILE(GLOB CPPHeaders *.hpp)
FILE(GLOB CPPMain fabs_main.cpp)

list(REMOVE_ITEM CPPSources ${CPPMain})

find_package(Boost COMPONENTS thread system iostreams filesystem REQUIRED)
find_package(PCAP REQUIRED)
find_package(Event REQUIRED)
find_package(RE2 REQUIRED)
find_package(YAMLCPP REQUIRED)

include_directories(BEFORE ${RE2_INCLUDE_DIR} ${Boost_INCLUDE_DIR} ${EVENT_INCLUDE_DIR} ${PCAP_INCLUDE_DIR} ${YAMLCPP_INCLUDE_DIR})

add_library(fabs SHARED ${CPPSources})
add_executable(sftap_fabs ${CPPMain})

set(LIBS pthread ${Boost_THREAD_LIBRARY} ${Boost_SYSTEM_LIBRARY} ${Boost_IOSTREAMS_LIBRARY} ${Boost_FILESYSTEM_LIBRARY} ${PCAP_LIBRARY} ${EVENT_LIBRARY} ${RE2_LIBRARY} ${YAMLCPP_LIBRARY})

IF(USE_JEMALLOC)
  add_definitions(-DUSE_JEMALLOC)
  SET(LIBS ${LIBS} jemalloc)
ENDIF(USE_JEMALLOC)

IF(USE_NETMAP)
  add_definitions(-DUSE_NETMAP)
  FILE(GLOB NETMAPHeaders netmap/*.hpp)
  INSTALL(FILES ${NETMAPHeaders} DESTINATION include/fabs/netmap)
ENDIF(USE_NETMAP)

target_link_libraries(sftap_fabs ${LIBS} fabs)
target_link_libraries(fabs ${LIBS})

INSTALL(TARGETS fabs sftap_fabs RUNTIME DESTINATION bin
                                LIBRARY DESTINATION lib
                                ARCHIVE DESTINATION lib)

IF(COMPILE_STATIC_LIB)
  add_library(fabs_static STATIC ${CPPSources})
  INSTALL(TARGETS fabs_static ARCHIVE DESTINATION lib)
ENDIF(COMPILE_STATIC_LIB)

INSTALL(FILES ${CPPHeaders} DESTINATION include/fabs)
