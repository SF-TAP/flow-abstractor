# SF-TAP Flow Absractor

SF-TAP flow abstractor is an abstraction layer for L7 flows.

### Dependencies

Required:

* [Boost C++ Library](http://www.boost.org/ "Boost")
* [libpcap](http://www.tcpdump.org/ "tcpdump/libpcap")
* [libevent 2.0 or later](http://libevent.org/ "libevent")

### How to Compile

    $ cmake -DCMAKE_BUILD_TYPE=Release CMakeLists.txt
    $ make

If you want to compile as debug mode, set a option of CMAKE_BUILD_YPE=Debug when running cmake. Debug mode passes a option of -g and a definition of DEBUG=1 to the compiler.

    $ cmake -DCMAKE_BUILD_TYPE=Debug CMakeLists.txt
    $ make

If you want to build static library, set a option of COMPILE_STATIC_LIB=1.

    $ cmake -DCOMPILE_STATIC_LIB=1 CMakeLists.txt
    $ make

You can use a verbose mode when compiling.

    $ make VERBOSE=1

### How to run SF-TAP flow abstractor

You can specify a network interface by -i option, and a config file by -c option.

Example:

    $ ./src/sf-tap_fabs -i eth0 -c ./examples/fabs.conf

If you want to use divert socket (FreeBSD/MacOS X only) instead of pcap, use -d option.
You can specify a port number of divert socket by -4 option.

Example:

    $ ./src/sf-tap_fabs -d -4 100 -c ./examples/fabs.conf

### To Do:
* protect from SYN flooding
* deal with fast TCP open
* calculate checksum
