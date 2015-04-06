# SF-TAP Flow Abstractor

SF-TAP flow abstractor abstracts L7-flows for L7-level network traffic analysis.

### Dependencies

Required:

* [Boost C++ Library](http://www.boost.org/ "Boost")
* [libpcap](http://www.tcpdump.org/ "tcpdump/libpcap")
* [libevent 2.0 or later](http://libevent.org/ "libevent")
* [RE2](https://github.com/google/re2 "RE2")

Optional:

* [jemalloc](http://www.canonware.com/jemalloc/ "jemalloc")


### How to Compile

    $ cmake -DCMAKE_BUILD_TYPE=Release CMakeLists.txt
    $ make

If you want to compile as debug mode, set an option of CMAKE_BUILD_YPE=Debug when running cmake. Debug mode passes an option of -g and a definition of DEBUG=1 to the compiler.

    $ cmake -DCMAKE_BUILD_TYPE=Debug CMakeLists.txt
    $ make

If you want to build static library, set an option of COMPILE_STATIC_LIB=1.

    $ cmake -DCOMPILE_STATIC_LIB=1 CMakeLists.txt
    $ make

If you want to use jemalloc, set an option of USE_JEMALLOC=1.

    $ cmake -DUSE_JEMALLOC=1 CMakeLists.txt
    $ make

You can use a verbose mode when compiling.

    $ make VERBOSE=1

### How to run SF-TAP flow abstractor

You can specify a network interface by -i option, and a config file by -c option.

Example:

    $ ./src/sftap_fabs -i eth0 -c ./examples/fabs.conf

### To Do:
* protect from SYN flooding
* deal with fast TCP open
* calculate checksum
