#ifndef FABS_NETMAP_CPP
#define FABS_NETMAP_CPP

#ifdef USE_NETMAP

#define POLL

#include "fabs_dlcap.hpp"
#include "fabs_ether.hpp"
#include "netmap/netmap.hpp"

class fabs_netmap : public fabs_dlcap {
public:
    fabs_netmap(std::string conf);
    virtual ~fabs_netmap();

    void set_dev(std::string dev) { m_dev = dev; }
    void run();
    void stop() { m_is_break = true; }

    virtual void print_stat() const;

private:
    void rx_in(struct netmap_ring* rxring);

    fabs_ether m_ether;
    netmap    *m_netmap;
    time_t     m_t;

    std::string m_dev;
    uint64_t    m_recv_cnt;
    volatile bool m_is_break;
};

inline void
fabs_netmap::rx_in(struct netmap_ring* rxring)
{
    size_t len = m_netmap->get_ethlen(rxring);
    struct ether_header* rx_eth = m_netmap->get_eth(rxring);

    timeval tm;
    gettimeofday(&tm, nullptr);

    m_ether.ether_input((const uint8_t*)rx_eth, len, tm);

    m_recv_cnt++;
}

#endif // USE_NETMAP

#endif // FABS_NETMAP_CPP
