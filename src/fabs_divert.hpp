#ifndef FABS_DIVERT_HPP
#define FABS_DIVERT_HPP

#ifdef USE_DIVERT

#include "fabs_id.hpp"
#include "fabs_callback.hpp"
#include "fabs_tcp.hpp"

#include <stdint.h>
#include <event.h>

#include <iostream>
#include <string>

#include <boost/shared_ptr.hpp>
#include <boost/regex.hpp>


class fabs_divert {
public:
    fabs_divert(std::string conf) : m_callback(conf) {}
    virtual ~fabs_divert() {}

    void set_ev_base(event_base *ev_base) { m_ev_base = ev_base; }
    void set_event_listener(ptr_fabs_event_listener listener) {
        m_callback.set_event_listener(listener);
    }

    void run(uint16_t ipv4_port, uint16_t ipv6_port);

private:
    int  open_divert(uint16_t port);

    fabs_callback m_callback;

    event_base *m_ev_base;
    event      *m_ev_ipv4;
    event      *m_ev_ipv6;
    int         m_fd_ipv4;
    int         m_fd_ipv6;

    friend void callback_ipv4(evutil_socket_t fd, short what, void *arg);
    friend void callback_ipv6(evutil_socket_t fd, short what, void *arg);
};

void run_divert(int port, std::string conf);

#endif // USE_DIVERT

#endif // FABS_DIVERT_HPP
