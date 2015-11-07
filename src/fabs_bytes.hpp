#ifndef FABS_BYTES_HPP
#define FABS_BYTES_HPP

#include "fabs_common.hpp"
#include "fabs_exclusive_ptr.hpp"

#include <string.h>

#include <deque>
#include <string>
#include <vector>
#include <iostream>

class fabs_bytes {
public:
    fabs_bytes() : m_ptr(nullptr), m_pos(0), m_len(0) { }
    fabs_bytes(const char *str) { *this = str; }

    virtual ~fabs_bytes() { delete[] m_ptr; }

    fabs_bytes & operator = (const char *str) {
        int len = strlen(str);
        try {
            m_ptr = new char[len];
        } catch (std::bad_alloc e) {
            std::cerr << __FILE__ << ":" << __LINE__ << ":" << ":"
                      <<__func__ << ": " << e.what() << std::endl;
            m_len = 0;
            m_pos = 0;
            return *this;
        }

        memcpy(m_ptr, str, len);
        m_len = len;
        m_pos = 0;

        return *this;
    }

    /*
    fabs_bytes & operator = (const fabs_bytes &rhs) {
        m_ptr = rhs.m_ptr;
        m_len = rhs.m_len;
        m_pos = rhs.m_pos;

        return *this;
    }
    */

    bool operator == (const fabs_bytes &rhs) const {
        if (m_len != rhs.m_len)
            return false;

        return memcmp(m_ptr + m_pos, rhs.m_ptr + rhs.m_pos,
                      m_len) == 0;
    }

    bool operator < (const fabs_bytes &rhs) const {
        if (m_len == rhs.m_len)
            return memcmp(m_ptr + m_pos, rhs.m_ptr + rhs.m_pos,
                          m_len) < 0;

        int len = m_len < rhs.m_len ? m_len : rhs.m_len;
        int result;

        result = memcmp(m_ptr + m_pos, rhs.m_ptr + rhs.m_pos, len);
        if (result < 0) {
            return true;
        } else if (result > 0) {
            return false;
        } else {
            return m_len < rhs.m_len;
        }
        
        return false;
    }

    bool operator > (const fabs_bytes &rhs) const {
        return rhs < *this;
    }

    void fill_zero() {
        memset(m_ptr + m_pos, 0, m_len);
    }

    bool is_zero() {
        try {
            char z[m_len - m_pos];
            memset(z, 0, m_len - m_pos);
            return memcmp(z, m_ptr, m_len - m_pos) == 0 ? true : false;
        } catch (std::bad_alloc e) {
            std::cerr << __FILE__ << ":" << __LINE__ << ":" << ":"
                      <<__func__ << ": " << e.what() << std::endl;
            return false;
        }
    }

    void alloc(size_t len) {
        try {
            m_ptr = new char[len];
        } catch (std::bad_alloc e) {
            std::cerr << __FILE__ << ":" << __LINE__ << ":" << ":"
                      <<__func__ << ": " << e.what() << ", len = " << len
                      << std::endl;
            m_len = 0;
            m_pos = 0;
            return;
        }

        if (m_ptr == nullptr) {
            PERROR();
            exit(-1);
        }

        m_len = len;
    }

    void set_buf(const char *buf, int len) {
        try {
            delete[] m_ptr;
            m_ptr = new char[len];
        } catch (std::bad_alloc e) {
            std::cerr << __func__ << e.what() << std::endl;
            m_len = 0;
            m_pos = 0;
            return;
        }

        memcpy(m_ptr, buf, len);

        m_len = len;
        m_pos = 0;
    }

    void clear() {
        delete[] m_ptr;
        m_ptr = nullptr;
        m_pos = 0;
        m_len = 0;
    }

    char* get_head() {
        return m_ptr + m_pos;
    }

    int get_len() {
        return m_len;
    }

    bool skip_tail(int len) {
        m_len -= len;

        if (m_len < 0)
            return false;

        return true;
    }

    bool skip(int len) {
        m_pos += len;
        m_len -= len;

        if (m_len < 0)
            return false;

        return true;
    }

private:
    char *m_ptr;
    int   m_pos;
    int   m_len;

    fabs_bytes(const fabs_bytes &rhs) { }
    fabs_bytes & operator = (const fabs_bytes &rhs) { return *this; }

    friend int read_bytes_ec(const std::deque<fabs_bytes*> &bytes, char *buf,
                             int len, char c);
    friend int read_bytes(std::deque<fabs_exclusive_ptr<fabs_bytes>> &bytes,
                          char *buf, int len);
    friend int skip_bytes(std::deque<fabs_bytes*> &bytes, int len);
    friend void get_digest(fabs_bytes &md_value, const char *alg,
                           const char *buf, unsigned int len);

};

typedef fabs_exclusive_ptr<fabs_bytes> ptr_fabs_bytes;

int read_bytes_ec(const std::deque<fabs_bytes*> &bytes, char *buf, int len,
                  char c);
int read_bytes(std::deque<ptr_fabs_bytes> &bytes, char *buf, int len);
int skip_bytes(std::deque<fabs_bytes*> &bytes, int len);
int find_char(const char *buf, int len, char c);
void get_digest(fabs_bytes &md_value, const char *alg, const char *buf,
                unsigned int len);
std::string bin2str(const char *buf, int len);
void print_binary(const char *buf, int len);
void to_lower_str(std::string &str);
void decompress_gzip(const char *buf, int len, std::string &out_buf);
void decompress_zlib(const char *buf, int len, std::string &out_buf);
std::string trim(const std::string &str,
                 const char *trimCharacterList = " \t\v\r\n");

#endif // FABS_BYTES_HPP
