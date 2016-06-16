#include "fabs_bytes.hpp"

#include <ctype.h>

#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/iostreams/filter/zlib.hpp>

#include <sstream>
#include <iostream>

using namespace std;
namespace io = boost::iostreams; //<-- good practice


int
read_bytes_ec(const deque<ptr_fabs_bytes> &bytes, char *buf, int len, char c)
{
    deque<ptr_fabs_bytes>::const_iterator it;
    int read_len = 0;

    for (it = bytes.begin(); it != bytes.end(); ++it) {
        const char *p = (*it)->m_ptr + (*it)->m_pos;

        if (! (*it)->m_ptr)
            continue;

        for (int i = 0; i < (*it)->m_len; i++) {
            if (read_len >= len)
                return read_len;

            buf[read_len] = p[i];

            read_len++;

            if (p[i] == c)
                return read_len;
        }
    }

    return read_len;
}

int
skip_bytes(deque<ptr_fabs_bytes> &bytes, int len)
{
    deque<ptr_fabs_bytes>::iterator it;
    int skip_len = 0;

    while (! bytes.empty()) {
        auto &front = bytes.front();

        if (len >= front->m_len) {
            len -= front->m_len;
            skip_len += front->m_len;
            bytes.pop_front();
            
            if (len == 0)
                break;
        } else {
            front->m_len -= len;
            front->m_pos += len;
            skip_len += len; 
            break;
        }
    }

    return skip_len;
}

int
read_bytes(deque<ptr_fabs_bytes> &bytes, char *buf, int len)
{
    deque<ptr_fabs_bytes>::iterator it;
    int read_len = 0;

    for (it = bytes.begin(); it != bytes.end(); ++it) {
        int remain = len - read_len;

        if (! (*it)->m_ptr)
            continue;

        if (remain < (*it)->m_len) {
            memcpy(buf, (*it)->m_ptr + (*it)->m_pos, remain);
            read_len += remain;

            break;
        }

        memcpy(buf, (*it)->m_ptr + (*it)->m_pos, (*it)->m_len);

        buf += (*it)->m_len;
        read_len += (*it)->m_len;
    }

    return read_len;
}

int
find_char(const char *buf, int len, char c)
{
    int n = 0;
    const char *end = buf + len;

    for (; buf < end; buf++) {
        if (*buf == c)
            return n;

        n++;
    }

    return -1;
}

void
print_binary(const char *buf, int len)
{
    const char *hex[] = {"0", "1", "2", "3", 
                         "4", "5", "6", "7",
                         "8", "9", "a", "b",
                         "c", "d", "e", "f"};

    for (int i = 0; i < len; i++) {
        cout << hex[(buf[i] >> 4) & 0x0f] << hex[buf[i] & 0x0f];
    }
}

int
lower_case(int c)
{
    return tolower(c);
}

void
to_lower_str(string &str)
{
    transform(str.begin(), str.end(), str.begin(), lower_case);
}

string
bin2str(const char *buf, int len)
{
    ostringstream os;

    const char *hex[] = {"0", "1", "2", "3", 
                         "4", "5", "6", "7",
                         "8", "9", "a", "b",
                         "c", "d", "e", "f"};

    for (int i = 0; i < len; i++) {
        os << hex[(buf[i] >> 4) & 0x0f] << hex[buf[i] & 0x0f];
    }

    return os.str();
}

void
decompress_gzip(const char *buf, int len, std::string &out_buf)
{
    io::filtering_ostream os;

    os.push(io::gzip_decompressor());
    os.push(io::back_inserter(out_buf));

    io::write(os, buf, len);
}

void
decompress_zlib(const char *buf, int len, std::string &out_buf)
{
    io::filtering_ostream os;

    os.push(io::zlib_decompressor());
    os.push(io::back_inserter(out_buf));

    io::write(os, buf, len);
}

string
trim(const string &str, const char *trimCharacterList)
{
    string result;

    string::size_type left = str.find_first_not_of(trimCharacterList);

    if (left != string::npos) {
        string::size_type right = str.find_last_not_of(trimCharacterList);
        result = str.substr(left, right - left + 1);
    }

    return result;
}
