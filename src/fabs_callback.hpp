#ifndef FABS_CALLBACK_HPP
#define FABS_CALLBACK_HPP

#include "fabs_common.hpp"
#include "fabs_tcp.hpp"
#include "fabs_udp.hpp"

#include <iostream>

#define NUM_TCP 4


class fabs_callback {
public:
    fabs_callback();
    virtual ~fabs_callback() { }

    void operator() (int idx, fabs_bytes buf);
    void print_stat() {
        int num = 0;
        int total = 0;

        for (int i = 0; i < NUM_TCP; i++) {
            num += m_tcp[i].get_active_num();
            total += m_tcp[i].get_total();
        }

        std::cout << "total TCP sessions: " << total
                  << "\nactive TCP sessions: " << num << std::endl;
    }

    void set_appif(ptr_fabs_appif appif) {
        m_appif = appif;
        m_udp.set_appif(appif);

        for (int i = 0; i < NUM_TCP; i++) {
            m_tcp[i].set_appif(appif);
        }
    }

    void set_idx(int idx) { m_idx = idx; }

private:
    ptr_fabs_appif m_appif;
    fabs_tcp m_tcp[NUM_TCP];
    fabs_udp m_udp;
    int      m_idx;
};

#endif
