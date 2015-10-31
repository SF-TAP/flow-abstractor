#pragma once

#include <stdio.h>
#include <string.h>
#include <vector>
#include <pthread.h>

#include <arpa/inet.h>

#include <string>

bool debug = true;

#ifdef DEBUG
#define MESG(format, ...) do {                             \
    if (debug) {                                           \
        fprintf(stderr, "%s:%s(%d): " format "\n",         \
        __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__);  \
    }                                                      \
} while (false)
#else
#define MESG(format, ...) do {} while (false)
#endif //DEBUG


#ifdef DEBUG
#define PERROR(func) do {                    \
    if (debug) {                             \
    char s[BUFSIZ];                          \
    memset(s, 0, BUFSIZ);                    \
    snprintf(s, BUFSIZ, "%s:%s(%d): %s",     \
    __FILE__, __FUNCTION__, __LINE__, func); \
    perror(s);                               \
    }                                        \
} while (false)
#else
#define PERROR(func) do {} while (false)
#endif //DEBUG


void pktdump(uint8_t* buf, int len)
{
    #define P(x) ((c >= ' ' && c < 0x7f) ? c : '.')
    int i;
    char t[128];
    char hex[] = "0123456789abcdef";
    fprintf(stderr, "--- %d bytes at %p\n", len, buf);
    /*
    if (len > 160) {
        len = 160;
    }
    */
    for (i = 0; i < len; i++) {
        uint8_t c = (uint8_t)buf[i];
        int o = i % 16;
        if (o == 0) {
            if (i > 0) {
                fprintf(stderr, "%s\n", t);
            }
            memset(t, ' ', 79);
            t[80] = '\0';
            t[0] = hex[(i>>12) & 0xf];
            t[1] = hex[(i>>8) & 0xf];
            t[2] = hex[(i>>4) & 0xf];
            t[3] = hex[(i>>0) & 0xf];
            t[4] = ':';
        }
        t[6 + 3*o + (o >> 3)] = hex[c >> 4];
        t[7 + 3*o + (o >> 3)] = hex[c & 0xf];
        t[56 + o + (o >> 3)] = P(c);
    }
    if (i % 16 != 0) {
        fprintf(stderr, "%s\n", t);
    }

    return;
}

void memdump(void* buffer, int length)
{

    uint32_t* addr32 = (uint32_t*)buffer;
    int i;
    int j;
    int k;
    int lines = length/16 + (length%16?1:0);
    if (lines > 1 || length == 16) {
        for (i=0; i<lines; i++) {
            printf("%p : %08x %08x %08x %08x\n",
                    addr32,
                    htonl(*(addr32)),
                    htonl(*(addr32+1)),
                    htonl(*(addr32+2)),
                    htonl(*(addr32+3))
                  );
            addr32 += 4;
        }
    } else {
    }

    j = length%16;
    if (j == 0) {
        return;
    }

    k = 0;
    uint8_t*  addr8 = (uint8_t*)addr32;
    printf("%p : ", addr8);
    for (i=0; i<16; i++) {
        if (k%4 == 0 && i != 0) printf(" ");
        if (j > i) {
            printf("%02x", *addr8);
            addr8++;
        } else {
            printf("XX");
        }
        k++;
    }
    printf("\n");

    return;
}

inline void trim_space(std::string& buf)
{
    size_t pos;
    while ((pos = buf.find_first_of(" 　\t")) != std::string::npos) {
        buf.erase(pos, 1);
    }
}

std::vector<std::string>
split(const std::string& src, const char *c)
{
    std::vector<std::string> retval;
    std::string::size_type i = 0;
    std::string::size_type j = src.find(c);
    std::string tmp = src.substr(i, j-i);

    if (tmp.size() == 0) return retval;
    retval.push_back(tmp);

    while (j != std::string::npos) {
        i = j++;
        j = src.find(c, j);
        if (j == std::string::npos) {
            retval.push_back(src.substr(i+1, src.size()));
            break;
        }
        tmp = src.substr(i, j-i);
        retval.push_back(tmp.substr(1, tmp.size()));
    }
    return retval;
}
