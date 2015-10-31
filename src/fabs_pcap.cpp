#include "fabs_pcap.hpp"

#include <iostream>
#include <string>

boost::shared_ptr<fabs_pcap> pcap_inst;
bool pcap_is_running = false;

void
stop_pcap()
{
    pcap_inst->stop();
}

void
pcap_callback(uint8_t *user, const struct pcap_pkthdr *h, const uint8_t *bytes)
{
    fabs_pcap *pcap = (fabs_pcap*)user;

    pcap->callback(h, bytes);
}

fabs_pcap::fabs_pcap(std::string conf) : m_ether(conf, this),
                                         m_handle(NULL),
                                         m_is_break(false)
{

}

fabs_pcap::~fabs_pcap()
{
    if (m_handle != NULL)
        pcap_close(m_handle);
}

void
fabs_pcap::callback(const struct pcap_pkthdr *h, const uint8_t *bytes)
{
    if (m_is_break) {
        pcap_breakloop(m_handle);
        return;
    }

    m_ether.ether_input(bytes, h->caplen);
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

    std::cout << "received packets: " << stat.ps_recv
              << "\ndropped packets: " << stat.ps_drop
              << "\ndropped packets by IF: " << stat.ps_ifdrop
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

void
run_pcap(std::string dev, std::string conf, int bufsize)
{
    for (;;) {
        if (pcap_is_running) {
            stop_pcap();
            sleep(1);
        } else {
            break;
        }
    }

    pcap_is_running = true;

    pcap_inst = boost::shared_ptr<fabs_pcap>(new fabs_pcap(conf));

    pcap_inst->set_dev(dev);
    pcap_inst->set_bufsize(bufsize);
    pcap_inst->run();

    pcap_is_running = false;
}
