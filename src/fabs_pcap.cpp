#include "fabs_pcap.hpp"

#include <iostream>
#include <string>

void
pcap_callback(uint8_t *user, const struct pcap_pkthdr *h, const uint8_t *bytes)
{
    fabs_pcap *pcap = (fabs_pcap*)user;

    pcap->callback(h, bytes);
}

#ifdef USE_PERF
fabs_pcap::fabs_pcap(fabs_conf &conf, time_t t) : fabs_dlcap(t),
                                                  m_ether(conf, this),
                                                  m_handle(NULL),
                                                  m_is_break(false),
                                                  m_recv_cnt(0),
                                                  m_recv_cnt_prev(0)
{
    gettimeofday(&m_tv, nullptr);
}
#endif // USE_PERF

fabs_pcap::fabs_pcap(fabs_conf &conf) : m_ether(conf, this),
                                        m_handle(NULL),
                                        m_is_break(false),
                                        m_recv_cnt_prev(0)
{
    gettimeofday(&m_tv, nullptr);
}

fabs_pcap::~fabs_pcap()
{

}

void
fabs_pcap::callback(const struct pcap_pkthdr *h, const uint8_t *bytes)
{
    if (m_is_break) {
        pcap_breakloop(m_handle);
        return;
    }

    m_recv_cnt++;

#ifdef USE_PERF
    if (is_time_to_end()) {
        pcap_breakloop(m_handle);
        return;
    }

#endif // USE_PERF

    m_ether.ether_input(bytes, h->caplen, h->ts, false);
}

void
fabs_pcap::set_dev(std::string dev)
{
    m_dev = dev;
}

void
fabs_pcap::set_bufsize(int size)
{
    m_bufsize = size;
}

void
fabs_pcap::print_stat() const
{
    if (m_handle == NULL)
        return;

    pcap_stat stat;
    pcap_stats(m_handle, &stat);

    timeval tv;
    gettimeofday(&tv, nullptr);

    uint64_t pktnum = m_recv_cnt - m_recv_cnt_prev;
    double diff = (tv.tv_sec + tv.tv_usec * 1e-6) - (m_tv.tv_sec + m_tv.tv_usec * 1e-6);

    m_recv_cnt_prev = m_recv_cnt;
    m_tv = tv;

    std::cout << "received packets (" << m_dev << "): " << m_recv_cnt << ", " << pktnum / diff << " [pps]"
              << "\ndropped packets by pcap (" << m_dev << "): " << stat.ps_drop
              << "\ndropped packets by IF (" << m_dev << "): " << stat.ps_ifdrop
              << std::endl;

}

void
fabs_pcap::run()
{
    char errbuf[PCAP_ERRBUF_SIZE];

    if (m_dev == "") {
        char *dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            std::cerr << "could not find default device: " << errbuf
                      << std::endl;
            return;
        }

        m_dev = dev;
    }

    std::cout << "start capturing " << m_dev << std::endl;

    m_handle = pcap_create(m_dev.c_str(), errbuf);

    if (m_handle == NULL) {
        std::cerr << "could not open device " << m_dev << ": " << errbuf
                  << std::endl;
        return;
    }

    pcap_set_snaplen(m_handle, 65535);
    pcap_set_promisc(m_handle, 1);
    pcap_set_buffer_size(m_handle, m_bufsize * 1000);
    pcap_set_timeout(m_handle, 1000);

    if (pcap_activate(m_handle) != 0) {
        pcap_perror(m_handle, (char*)"Activate");
        exit(-1);
    }


    m_dl_type = pcap_datalink(m_handle);

    for (;;) {
        switch (pcap_dispatch(m_handle, -1, pcap_callback, (u_char*)this)) {
        case 0:
            if (m_is_break)
                return;
            break;
        case -1:
        {
            char *err = pcap_geterr(m_handle);
            std::cerr << "an error was encouterd while pcap_dispatch(): "
                      << err
                      << std::endl;
            break;
        }
        case -2:
            return;
        }
    }
}

