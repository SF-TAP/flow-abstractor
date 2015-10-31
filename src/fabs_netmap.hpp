#ifndef FABS_NETMAP_CPP
#define FABS_NETMAP_CPP

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

    virtual void print_stat() const;

private:
    void slot_swap(struct netmap_ring* rxring, struct netmap_ring* txring);

    fabs_ether m_ether;
    netmap    *m_netmap;

    std::string m_dev;
    int m_recv_cnt;
};

inline void
fabs_netmap::slot_swap(struct netmap_ring* rxring, struct netmap_ring* txring)
{
    struct netmap_slot* rx_slot =
        ((netmap_slot*)&rxring->slot[rxring->cur]);
    struct netmap_slot* tx_slot =
        ((netmap_slot*)&txring->slot[txring->cur]);

    struct ether_header* rx_eth =
        (struct ether_header*)NETMAP_BUF(rxring, rx_slot->buf_idx);

    m_ether.ether_input((const uint8_t*)rx_eth, rx_slot->len);

#ifdef DEEPCOPY

    struct ether_header* tx_eth =
        (struct ether_header*)NETMAP_BUF(txring, tx_slot->buf_idx);
    memcpy(tx_eth, rx_eth, rx_slot->len);

#else

    uint32_t buf_idx;
    buf_idx = tx_slot->buf_idx;
    tx_slot->buf_idx = rx_slot->buf_idx;
    rx_slot->buf_idx = buf_idx;
    tx_slot->flags |= NS_BUF_CHANGED;
    rx_slot->flags |= NS_BUF_CHANGED;

#endif

    tx_slot->len = rx_slot->len;

    // if (debug) {
        //uint8_t* tx_eth = (uint8_t*)NETMAP_BUF(txring, tx_slot->buf_idx);
        //pktdump(tx_eth, tx_slot->len);
        // if (m_recv_cnt % 100 == 0) {
        //    printf("true : m_recv_cnt %d\n", m_recv_cnt);
        // }
    // }

    m_recv_cnt++;

    return;
}

#endif // FABS_NETMAP_CPP
