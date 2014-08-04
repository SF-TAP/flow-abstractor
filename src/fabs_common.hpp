#ifndef FABS_COMMON_HPP
#define FABS_COMMON_HPP

#include <stdio.h>

#include "fabs_bytes.hpp"

#define PERROR() do {                                           \
    char s[256];                                                \
    snprintf(s, sizeof(s), "%s:%d", __FILE__, __LINE__);        \
    perror(s);                                                  \
} while (false)

#endif // FABS_COMMON_HPP
