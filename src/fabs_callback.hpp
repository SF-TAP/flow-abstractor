#ifndef FABS_CALLBACK_HPP
#define FABS_CALLBACK_HPP

#include "fabs_common.hpp"
#include "fabs_tcp.hpp"
#include "fabs_udp.hpp"

class fabs_callback {
public:
    fabs_callback(std::string conf);
    virtual ~fabs_callback() { }

    void operator() (fabs_bytes buf);
    void print_stat() { m_tcp.print_stat(); }

private:
    ptr_fabs_appif m_appif;
    fabs_tcp m_tcp;
    fabs_udp m_udp;

};

#endif
