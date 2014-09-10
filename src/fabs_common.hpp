#ifndef FABS_COMMON_HPP
#define FABS_COMMON_HPP

#ifdef USE_JEMALLOC
    #include <stdlib.h>
    #include <jemalloc/jemalloc.h>
#endif

#include <stdio.h>

#define PERROR() do {                                           \
    char s[256];                                                \
    snprintf(s, sizeof(s), "%s:%d", __FILE__, __LINE__);        \
    perror(s);                                                  \
} while (false)

#endif // FABS_COMMON_HPP
