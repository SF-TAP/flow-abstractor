#ifdef USE_NETMAP

#include "fabs_netmap.hpp"

#include <iostream>

fabs_netmap::fabs_netmap(std::string conf) : m_ether(conf, this),
                                             m_netmap(NULL),
                                             m_t(time(NULL)),
                                             m_recv_cnt(0),
                                             m_is_break(false)
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

    int retval;
    int rx_avail = 0;
    struct netmap_ring* rx = NULL;

    std::cout << "start capturing " << m_dev << " (netmap)" << std::endl;

    for (;;) {

        retval = poll(pfd, mq+1, 500);

        if (m_is_break)
            return;

        if (retval == 0)
            continue;

        if (retval < 0) {
            PERROR();
            return;
        }

        for (int i = 0; i < mq; i++) {

            if (pfd[i].revents & POLLERR) {

                MESG("rx_hard poll error");

            } else if (pfd[i].revents & POLLIN) {

                rx = m_netmap->get_rx_ring(i);

                rx_avail = m_netmap->get_avail(rx);

                while (rx_avail--) {
                    rx_in(rx);
                    m_netmap->next(rx);

                    if (m_is_break)
                        return;
                }
            }
        }
    }
}

void
fabs_netmap::print_stat() const
{
    std::cout << "received packets: " << m_recv_cnt << std::endl;
}

#endif // USE_NETMAP
