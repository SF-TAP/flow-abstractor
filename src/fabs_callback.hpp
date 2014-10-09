#ifndef FABS_CALLBACK_HPP
#define FABS_CALLBACK_HPP

#include "fabs_common.hpp"
#include "fabs_tcp.hpp"
#include "fabs_udp.hpp"

#define TCPNUM 4

class fabs_callback {
public:
    fabs_callback();
    virtual ~fabs_callback() { }

    void operator() (int idx, fabs_bytes buf);
    void print_stat() {
        for (int i = 0; i < TCPNUM; i++) {
            m_tcp[i].print_stat();
        }
    }

    void set_appif(ptr_fabs_appif appif) {
        m_appif = appif;
        m_udp.set_appif(appif);

        for (int i = 0; i < TCPNUM; i++) {
            m_tcp[i].set_appif(appif);
            m_tcp[i].set_timeout(appif->get_tcp_timeout());
        }
    }

private:
    ptr_fabs_appif m_appif;
    fabs_tcp m_tcp[TCPNUM];
    fabs_udp m_udp;

};

#endif
