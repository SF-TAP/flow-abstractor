cmake_policy(SET CMP0022 OLD)

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

option(USE_DIVERT "Use Divert" 0)
option(COMPILE_STATIC_LIB "Compile Static Library" 0)

FILE(GLOB CPPSources *.cpp)
FILE(GLOB CPPHeaders *.hpp)
FILE(GLOB CPPMain fabs_main.cpp)

list(REMOVE_ITEM CPPSources ${CPPMain})

find_package(Boost COMPONENTS thread system regex iostreams filesystem REQUIRED)

IF(USE_DIVERT)
  add_definitions(-DUSE_DIVERT)
ENDIF(USE_DIVERT)

add_library(fabs SHARED ${CPPSources})
add_executable(stap_fabs ${CPPMain})

set(LIBS event event_pthreads ${Boost_THREAD_LIBRARY} ${Boost_SYSTEM_LIBRARY} ${Boost_REGEX_LIBRARY} ${Boost_IOSTREAMS_LIBRARY} ${Boost_FILESYSTEM_LIBRARY} pcap crypto pthread ssl)

target_link_libraries(stap_fabs ${LIBS} fabs)
target_link_libraries(fabs ${LIBS})

INSTALL(TARGETS fabs stap_fabs RUNTIME DESTINATION bin
                               LIBRARY DESTINATION lib
                               ARCHIVE DESTINATION lib)

IF(COMPILE_STATIC_LIB)
  add_library(fabs_static STATIC ${CPPSources})
  INSTALL(TARGETS fabs_static ARCHIVE DESTINATION lib)
ENDIF(COMPILE_STATIC_LIB)

INSTALL(FILES ${CPPHeaders} DESTINATION include/fabs)
