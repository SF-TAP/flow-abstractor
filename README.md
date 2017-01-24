# SF-TAP Flow Abstractor

The SF-TAP flow abstractor provides flow abstraction interfaces for application level network traffic analysis.

[![Build Status](https://travis-ci.org/SF-TAP/flow-abstractor.svg?branch=master)](https://travis-ci.org/SF-TAP/flow-abstractor)

### Dependencies

Required:

* [Boost C++ Library](http://www.boost.org/ "Boost")
* [libpcap](http://www.tcpdump.org/ "tcpdump/libpcap")
* [libevent 2.0 or later](http://libevent.org/ "libevent")
* [RE2](https://github.com/google/re2 "RE2")
* [yaml-cpp](https://github.com/jbeder/yaml-cpp "yaml-cpp")

Optional:

* [jemalloc](http://www.canonware.com/jemalloc/ "jemalloc")

### Operating Systems

SF-TAP flow abstractor is available on the following OSes.

* [Linux](http://sf-tap.github.io/installation/2015/11/21/install-flow-abstractor.html)
* [*BSD](http://sf-tap.github.io/installation/2015/11/21/install-cell-incubator.html)
* MacOS X

### How to Compile

#### Environment Variables

Before compiling, set environment variables for cmake as follows.

    $ export CMAKE_LIBRARY_PATH=/lib:/usr/lib:/usr/local/lib
    $ export CMAKE_INCLUDE_PATH=/usr/include:/usr/local/include

#### Compile

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

If you want to use netmap, set an option of USE_NETMAP=1.

    $ cmake -DUSE_NETMAP=1 CMakeLists.txt
    $ make

You can use a verbose mode when compiling.

    $ make VERBOSE=1

#### Tell Root Directories for Libraries

If you installed above libraries in unordinal places (not /usr or /usr/local), please tell paths to the directoris as follows.

    $ cmake -DBOOST_ROOT=/homebrew -DEVENT_ROOT=/homebrew -DRE2_ROOT=/homebrew -DYAMLCPP_ROOT=/homebrew .

### How to run SF-TAP flow abstractor

You can specify a network interface by -i option, and a config file by -c option.

Example:

    $ ./src/sftap_fabs -i eth0 -c ./examples/fabs.yaml

If you encounter an error as follows,

    terminate called after throwing an instance of 'std::runtime_error'
    what():  locale::facet::_S_create_c_locale name not valid

please install the suitable language package like as follows.

    $ apt-get install language-pack-ja

### Use netmap

If you want to use netmap, pass -n option as follows.

    $ ./src/sftap_fabs -i eth0 -c ./examples/fabs.yaml -n

### Documents

Other documents are available on the following link.

[SF-TAP's Home Page](http://sf-tap.github.io/ "SF-TAP")

### TODO

* open multiple interfaces
* calculate checksum
* daemon mode
* handling web socket
* handling QUIC
