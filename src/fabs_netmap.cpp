#ifdef USE_NETMAP

#include "fabs_netmap.hpp"

#include <iostream>

fabs_netmap::fabs_netmap(std::string conf) : m_ether(conf, this),
                                             m_netmap(NULL),
                                             m_t(time(NULL)),
                                             m_num_thread(0),
                                             m_recv_cnt(0),
                                             m_is_break(false)
{

}

fabs_netmap::~fabs_netmap()
{
    std::cout << "cleaning up netmap... " << std::flush;
    m_ether.stop();

    for (int i = 0; i < m_num_thread; i++) {
        m_thread[i]->join();
        delete m_thread[i];
    }

    delete m_thread;

    if (m_netmap != NULL)
        delete m_netmap;

    std::cout << "done" << std::endl;
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

    std::cout << "start capturing " << m_dev << " (netmap)" << std::endl;

    if (mq >= 2) {
        m_num_thread = mq - 1;
        m_thread = new std::thread*[m_num_thread];
        for (int i = 0; i < m_num_thread; i++) {
            int fd = m_netmap->get_fd(i + 1);
            m_netmap->set_timestamp(m_netmap->get_rx_ring(i + 1));
            m_thread[i] = new std::thread(std::bind(&fabs_netmap::run_netmap, this, i + 1, fd));

            std::ostringstream os;
            os << "netmap[" << i << "]";
            SET_THREAD_NAME(m_thread[i]->native_handle(), os.str().c_str());
        }
    }

    std::ostringstream os;
    os << "netmap[0]";
    SET_THREAD_NAME(pthread_self(), os.str().c_str());
    run_netmap(0, m_netmap->get_fd(0));
}

void
fabs_netmap::run_netmap(int idx, int fd)
{
    struct pollfd pfd;
    int retval;
    int rx_avail = 0;
    struct netmap_ring* rx = NULL;

    memset(&pfd, 0, sizeof(pfd));

    pfd.fd = fd;
    pfd.events = POLLIN;

    for (;;) {
        retval = poll(&pfd, 1, 500);

        if (m_is_break)
            return;

        if (retval == 0)
            continue;

        if (retval < 0) {
            PERROR();
            return;
        }

        if (pfd.revents & POLLERR) {
            MESG("rx_hard poll error");
        } else if (pfd.revents & POLLIN) {
            rx = m_netmap->get_rx_ring(idx);

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

void
fabs_netmap::print_stat() const
{
    std::cout << "received packets (" << m_dev << "): " << m_recv_cnt << std::endl;
}

#endif // USE_NETMAP
