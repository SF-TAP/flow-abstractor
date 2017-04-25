#ifndef FABS_CALLBACK_HPP
#define FABS_CALLBACK_HPP

#include "fabs_common.hpp"
#include "fabs_tcp.hpp"
#include "fabs_udp.hpp"
#include "fabs_icmp.hpp"

#include <iostream>

class fabs_callback {
public:
    fabs_callback();
    virtual ~fabs_callback() { }

    void operator() (int idx, ptr_fabs_bytes buf);
    void print_stat() {
        uint64_t n = 0;
        uint64_t t = 0;
        for (int i = 0; i < m_appif->get_num_tcp_threads(); i++) {
            n += m_tcp[i]->get_active_num();
            t += m_tcp[i]->get_total_num();
        }

        std::cout << "total TCP sessions: " << t
                  << "\nactive TCP sessions: " << n << std::endl;
    }

    void set_appif(ptr_fabs_appif appif) {
        m_appif = appif;
        m_udp.set_appif(appif);
        m_icmp.set_appif(appif);

        m_tcp = new fabs_tcp*[m_appif->get_num_tcp_threads()];

        for (int i = 0; i < m_appif->get_num_tcp_threads(); i++) {
            m_tcp[i] = new fabs_tcp(i);
            m_tcp[i]->set_appif(appif);
            m_tcp[i]->set_timeout(appif->get_tcp_timeout());
        }
    }

    void stop() {
        for (int i = 0; i < m_appif->get_num_tcp_threads(); i++) {
            m_tcp[i]->stop();
        }

        m_appif->stop();
    }

private:
    ptr_fabs_appif m_appif;
    fabs_tcp **m_tcp;
    fabs_udp m_udp;
    fabs_icmp m_icmp;

};

#endif
