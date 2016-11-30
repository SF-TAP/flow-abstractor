#ifndef FABS_COMMON_HPP
#define FABS_COMMON_HPP

#ifdef USE_JEMALLOC
    #include <stdlib.h>
    #include <jemalloc/jemalloc.h>
#endif // USE_JEMALLOC

#ifndef __linux__
#include <sys/param.h>
#endif // __linux__

#if !defined(__APPLE__) and defined(BSD)
#include <pthread_np.h>
#endif // !defined(__APPLE__) and defined(BSD)

#ifdef USE_PERF
    #define SET_THREAD_NAME(HDL, STR)
#else
    #ifdef __APPLE__
        #define SET_THREAD_NAME(HDL, STR) pthread_setname_np((STR))
    #elif defined(__linux__)
        #define SET_THREAD_NAME(HDL, STR) pthread_setname_np((HDL), (STR))
    #elif defined(BSD)
        #define SET_THREAD_NAME(HDL, STR) pthread_set_name_np((HDL), (STR));
    #else
        #define SET_THREAD_NAME(HDL, STR)
    #endif // __APPLE__
#endif // USE_PERF

#include <stdio.h>

#define PERROR() do {                                           \
    char s[256];                                                \
    snprintf(s, sizeof(s), "%s:%d", __FILE__, __LINE__);        \
    perror(s);                                                  \
} while (false)

#endif // FABS_COMMON_HPP
