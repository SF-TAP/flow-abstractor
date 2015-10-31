#include "fabs_netmap.hpp"

#include <iostream>

fabs_netmap::fabs_netmap(std::string conf) : m_ether(conf, this),
                                             m_netmap(NULL),
                                             m_recv_cnt(0)
{

}

fabs_netmap::~fabs_netmap()
{
    if (m_netmap != NULL)
        delete m_netmap;
}

void
fabs_netmap::run()
{
    m_netmap = new netmap();
    if (m_netmap->open_if(m_dev) == false) {
        std::cerr << "could not open device " << m_dev << " (netmap)"
                  << std::endl;
        exit(-1);
    }

    // max queue number
    int mq = m_netmap->get_rx_qnum();
    struct pollfd pfd[mq];
    memset(pfd, 0, sizeof(pfd));

    for (int i = 0; i < mq; i++) {
        pfd[i].fd = m_netmap->get_fd(i);
        pfd[i].events = POLLIN;
    }
    // printf("max_queue:%d\n", mq);
    pfd[mq].fd = m_netmap->get_fd_sw();
    pfd[mq].events = POLLIN;

    // for (int i = 0; i < mq + 1; i++) {
    //     printf("%d:%d\n", i, pfd[i].fd);
    // }

    int retval;
    int loop_count = 0;
    int rx_avail = 0;
    int tx_avail = 0;
    struct netmap_ring* rx = NULL;
    struct netmap_ring* tx = NULL;

    std::cout << "start capturing " << m_dev << " (netmap)" << std::endl;

    for (;;) {

        retval = poll(pfd, mq+1, -1);

        if (retval <= 0) {
            PERROR();
            return;
        }

        // nic -> host
        for (int i = 0; i < mq; i++) {

            if (pfd[i].revents & POLLERR) {

                MESG("rx_hard poll error");

            } else if (pfd[i].revents & POLLIN) {

                rx = m_netmap->get_rx_ring(i);
                tx = m_netmap->get_tx_ring_sw();

                rx_avail = m_netmap->get_avail(rx);
                tx_avail = m_netmap->get_avail(tx);
                int burst = (rx_avail <= tx_avail) ?  rx_avail : tx_avail;

                while (burst--) {
                    //printf("nic->host:rx_avail:%d\n", rx_avail);
                    //printf("nic->host:tx_avail:%d\n", tx_avail);
                    if (tx_avail > 0) {
                        slot_swap(rx, tx);
                        m_netmap->next(tx);
                        m_netmap->next(rx);
                    } else {
                        break;
                    }
                }
            }
        }


        // host -> nic
        if (pfd[mq].revents & POLLERR) {

            MESG("rx_soft poll error");

        } else if (pfd[mq].revents & POLLIN) {

            int dest_ring = loop_count % mq;
            rx = m_netmap->get_rx_ring_sw();
            tx = m_netmap->get_tx_ring(dest_ring);

            rx_avail = m_netmap->get_avail(rx);
            tx_avail = m_netmap->get_avail(tx);
            int burst = (rx_avail <= tx_avail) ?  rx_avail : tx_avail;

            while (burst--) {
                //printf("host->nic:rx_avail:%d\n", rx_avail);
                //printf("host->nic:tx_avail:%d\n", tx_avail);
                if (tx_avail > 0) {
                    slot_swap(rx, tx);
                    m_netmap->next(tx);
                    m_netmap->next(rx);
                } else {
                    break;
                }
            }
        }

        /*
        for (int i = 0; i < mq + 1; i++) {
            pfd[i].revents = 0;
        }
        */

        loop_count++;
    }
}

void
fabs_netmap::print_stat() const
{
    std::cout << "received packets: " << m_recv_cnt << std::endl;
}
