#ifndef FABS_ASM_HPP
#define FABS_ASM_HPP

#include <stdint.h>

#define TZCNTQ(DST, SRC)        \
    do {                        \
        asm (                   \
            "tzcntq %1, %0;"    \
            : "=r" (DST)        \
            : "r" (SRC)         \
            );                  \
    } while (0)

#define POPCNTQ(DST, SRC)       \
    do {                        \
        asm (                   \
            "popcntq %1, %0;"   \
            : "=r" (DST)        \
            : "r" (SRC)         \
            );                  \
    } while (0)

inline uint64_t
tzcntq(uint64_t num)
{
#ifdef __x86_64__
    uint64_t ret;
    TZCNTQ(ret, num);
    return ret;
#else
    return __builtin_ctzll(num);
#endif // __x86_64__
}

inline uint64_t
popcntq(uint64_t num)
{
#ifdef __x86_64__
    uint64_t ret;
    POPCNTQ(ret, num);
    return ret;
#else
    return __builtin_popcountll(num);
#endif // __x86_64__
}

#endif // FABS_ASM_HPP