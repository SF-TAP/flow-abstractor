#ifdef USE_DIVERT

#include "fabs_divert.hpp"

#include <iostream>

#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#ifndef IPPROTO_DIVERT
    #define IPPROTO_DIVERT          254
#endif // IPPROTO_DIVERT

using namespace std;

void callback_ipv4(evutil_socket_t fd, short what, void *arg)
{
    fabs_divert *dvt = (fabs_divert*)arg;
    sockaddr_in  sin;
    socklen_t    sin_len;
    ssize_t      size;
    char         buf[1024 * 100];

    sin_len = sizeof(sin);
    size = recvfrom(fd, buf, sizeof(buf), 0, (sockaddr*)&sin, &sin_len);

    if (size < 0) {
        perror("recvfrom");
        exit(-1);
    }

#ifdef DEBUG
    ip   *hdr;
    char  src[32], dst[32];

    hdr = (ip*)buf;

    inet_ntop(PF_INET, &hdr->ip_src, src, sizeof(src));
    inet_ntop(PF_INET, &hdr->ip_dst, dst, sizeof(dst));

    //cout << "recv IPv4: src = " << src << ", dst = " << dst << endl;
#endif // DEBUG

    dvt->m_callback(buf, size, IPPROTO_IP);

    sendto(fd, buf, size, 0, (sockaddr*)&sin, sin_len);
}

void callback_ipv6(evutil_socket_t fd, short what, void *arg)
{
    fabs_divert  *dvt = (fabs_divert*)arg;
    sockaddr_in6  sin;
    ip6_hdr      *hdr;
    socklen_t     sin_len;
    ssize_t       size;
    char          buf[1024 * 100];
    char          src[64], dst[64];

    sin_len = sizeof(sin);
    size = recvfrom(fd, buf, sizeof(buf), 0, (sockaddr*)&sin, &sin_len);

    if (size < 0) {
        perror("recvfrom");
        exit(-1);
    }

    hdr = (ip6_hdr*)buf;

    inet_ntop(PF_INET, &hdr->ip6_src, src, sizeof(src));
    inet_ntop(PF_INET, &hdr->ip6_dst, dst, sizeof(dst));

    cout << "recv IPv6: src = " << src << ", dst = " << dst << endl;

    dvt->m_callback(buf, size, IPPROTO_IPV6);

    sendto(fd, buf, size, 0, (sockaddr*)&sin, sin_len);
}

int
fabs_divert::open_divert(uint16_t port)
{
    sockaddr_in bind_port;
    int fd;

    fd = socket(PF_INET, SOCK_RAW, IPPROTO_DIVERT);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    memset(&bind_port, 0, sizeof(bind_port));

    bind_port.sin_family = PF_INET;
    bind_port.sin_port   = htons(port);

    if (bind(fd, (sockaddr*)&bind_port, sizeof(bind_port)) < 0) {
        close(fd);
        perror("bind");
        return -1;
    }

    return fd;
}

void
fabs_divert::run(uint16_t ipv4_port, uint16_t ipv6_port)
{
    if (ipv4_port > 0) {
        m_fd_ipv4 = open_divert(ipv4_port);
        if (m_fd_ipv4 < 0) {
            cerr << "couldn't open divert socket's port " << ipv4_port << endl;
            exit(-1);
        }

        m_ev_ipv4 = event_new(m_ev_base, m_fd_ipv4, EV_READ | EV_PERSIST,
                              callback_ipv4, this);
        if (!m_ev_ipv4) {
            cerr << "couldn't new event" << endl;
            exit(-1);
        }

        event_add(m_ev_ipv4, NULL);
    }


    // divert socket is not supporting IPv6
    if (ipv6_port > 0) {
        m_fd_ipv6 = open_divert(ipv6_port);
        if (m_fd_ipv6 < 0) {
            cerr << "couldn't open divert socket's port" << ipv6_port << endl;
            exit(-1);
        }

        m_ev_ipv6 = event_new(m_ev_base, m_fd_ipv6, EV_READ | EV_PERSIST,
                              callback_ipv6, this);
        if (!m_ev_ipv6) {
            cerr << "couldn't new event" << endl;
            exit(-1);
        }

        event_add(m_ev_ipv6, NULL);
    }
}

void
run_divert(int port, std::string conf)
{
    event_base *ev_base = event_base_new();
    fabs_divert dvt(conf);

    if (!ev_base) {
        std::cerr << "couldn't new event_base" << std::endl;
        exit(-1);
    }

    dvt.set_ev_base(ev_base);
    dvt.run(port, 0);

    event_base_dispatch(ev_base);
}


#endif // USE_DIVERT
