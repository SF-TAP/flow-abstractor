#ifndef FABS_CALLBACK_HPP
#define FABS_CALLBACK_HPP

#include "fabs_common.hpp"
#include "fabs_tcp.hpp"
#include "fabs_udp.hpp"

#include <iostream>

#define TCPNUM 4

class fabs_callback {
public:
    fabs_callback();
    virtual ~fabs_callback() { }

    void operator() (int idx, fabs_bytes buf);
    void print_stat() {
        int n = 0;
        int t = 0;
        for (int i = 0; i < TCPNUM; i++) {
            n += m_tcp[i].get_active_num();
            t += m_tcp[i].get_total_num();
        }

        std::cout << "total TCP sessions: " << t
                  << "\nactive TCP sessions: " << n << std::endl;
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
