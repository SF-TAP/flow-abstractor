#ifndef FABS_CALLBACK_HPP
#define FABS_CALLBACK_HPP

#include "fabs_common.hpp"
#include "fabs_tcp.hpp"
#include "fabs_udp.hpp"

#include <iostream>

class fabs_callback {
public:
    fabs_callback();
    virtual ~fabs_callback() {
        std::cout << "deleting TCP threads... " << std::flush;
        delete[] m_tcp;
        std::cout << "done" << std::endl;
    }

    void operator() (int idx, ptr_fabs_bytes buf);
    void print_stat() {
        int n = 0;
        int t = 0;
        for (int i = 0; i < m_appif->get_num_tcp_threads(); i++) {
            n += m_tcp[i].get_active_num();
            t += m_tcp[i].get_total_num();
        }

        std::cout << "total TCP sessions: " << t
                  << "\nactive TCP sessions: " << n << std::endl;
    }

    void set_appif(ptr_fabs_appif appif) {
        m_appif = appif;
        m_udp.set_appif(appif);

        m_tcp = new fabs_tcp[m_appif->get_num_tcp_threads()];

        for (int i = 0; i < m_appif->get_num_tcp_threads(); i++) {
            m_tcp[i].set_appif(appif);
            m_tcp[i].set_timeout(appif->get_tcp_timeout());
        }
    }

private:
    ptr_fabs_appif m_appif;
    fabs_tcp *m_tcp;
    fabs_udp m_udp;

};

#endif
