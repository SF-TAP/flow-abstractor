#ifndef FABS_COMMON_HPP
#define FABS_COMMON_HPP

#ifdef USE_JEMALLOC
    #include <stdlib.h>
    #include <jemalloc/jemalloc.h>
#endif // USE_JEMALLOC

#include <stdio.h>

#define PERROR() do {                                           \
    char s[256];                                                \
    snprintf(s, sizeof(s), "%s:%d", __FILE__, __LINE__);        \
    perror(s);                                                  \
} while (false)

#ifdef USE_COZ
    #include "coz.h"
#else
    #define COZ_PROGRESS
    #define COZ_PROGRESS_NAMED(X)
    #define COZ_BEGIN(X)
    #define COZ_END(X)
#endif // USE_COZ

#endif // FABS_COMMON_HPP
