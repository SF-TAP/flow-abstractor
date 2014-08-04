#include "fabs_pcap.hpp"
#include "fabs_divert.hpp"

#include <unistd.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <iostream>

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN 0x8100 /* IEEE 802.1Q VLAN tagging */
#endif

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd /* IPv6 */
#endif

using namespace std;

boost::shared_ptr<fabs_pcap> pcap_inst;
bool pcap_is_running = false;

time_t t0 = time(NULL);

struct vlanhdr {
    uint16_t m_tci;
    uint16_t m_type;
};

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

void
fabs_pcap::callback(const struct pcap_pkthdr *h, const uint8_t *bytes)
{
    uint8_t proto;
    const uint8_t *ip_hdr = get_ip_hdr(bytes, h->caplen, proto);
    uint32_t len = h->caplen - (ip_hdr - bytes);
    uint32_t plen;

    if (m_is_break) {
        pcap_breakloop(m_handle);
        return;
    }

    if (ip_hdr == NULL)
        return;

    time_t t1 = time(NULL);

    if (t1 - t0 > 60) {
        pcap_stat stat;
        t0 = t1;
        pcap_stats(m_handle, &stat);

        cout << "received: " << stat.ps_recv
             << "\ndropped: " << stat.ps_drop
             << "\ndropped by IF: " << stat.ps_ifdrop << "\n"
             << endl;
    }

    switch (proto) {
    case IPPROTO_IP:{
        ip       *iph = (ip*)ip_hdr;
        uint16_t  off = ntohs(iph->ip_off);

        // not support IP fragment
        if (off & IP_MF || (off & 0x1fff) > 0)
            return;

        plen = ntohs(iph->ip_len);

        if (plen > len)
            return;

        m_callback((char*)ip_hdr, plen, proto);

        break;
    }
    case IPPROTO_IPV6:
    {
        ip6_hdr *ip6h = (ip6_hdr*)ip_hdr;
        uint8_t  nxt  = ip6h->ip6_nxt;
        char    *p    = (char*)ip6h + sizeof(ip6_hdr);
        
        for (;;) {
            switch(nxt) {
            case IPPROTO_HOPOPTS:
            case IPPROTO_ROUTING:
            case IPPROTO_ESP:
            case IPPROTO_AH:
            case IPPROTO_DSTOPTS:
            {
                ip6_ext *ext = (ip6_ext*)p;

                nxt = ext->ip6e_nxt;

                if (ext->ip6e_len == 0)
                    p += 8;
                else
                    p += ext->ip6e_len * 8;

                break;
            }
            case IPPROTO_NONE:
            case IPPROTO_FRAGMENT:
            case IPPROTO_ICMPV6:
                return;
            default:
                goto end_loop;
            }
        }
    end_loop:
        plen = ntohs(ip6h->ip6_plen) + sizeof(ip6_hdr);
        if (plen > len)
            return;

        m_callback((char*)ip_hdr, plen, proto);

        break;
    }
    default:
        break;
    }
}

void
fabs_pcap::set_dev(std::string dev)
{
    m_dev = dev;
}

void
fabs_pcap::run()
{
    char errbuf[PCAP_ERRBUF_SIZE];

    if (m_dev == "") {
        char *dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            cerr << "Couldn't find default device: " << errbuf << endl;
            return;
        }

        m_dev = dev;
    }

    cout << "start capturing " << m_dev << endl;

    m_handle = pcap_open_live(m_dev.c_str(), 65535, 1, 1000, errbuf);

    if (m_handle == NULL) {
        cerr << "Couldn't open device " << m_dev << ": " << errbuf << endl;
        return;
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
            cerr << "An error was encouterd while pcap_dispatch(): "
                 << err << endl;
            break;
        }
        case -2:
            return;
        }
    }
}

const uint8_t *
fabs_pcap::get_ip_hdr(const uint8_t *bytes, uint32_t len, uint8_t &proto)
{
    const uint8_t *ip_hdr = NULL;
    switch (m_dl_type) {
    case DLT_EN10MB:
    {
        if (len < sizeof(ether_header))
            break;

        const ether_header *ehdr = (const ether_header*)bytes;
        uint16_t ether_type = ntohs(ehdr->ether_type);
        int      skip       = sizeof(ether_header);

    retry:

        switch (ether_type) {
        case ETHERTYPE_VLAN:
        {
            const vlanhdr *vhdr = (const vlanhdr*)(bytes + skip);
            ether_type = ntohs(vhdr->m_type);

            skip += sizeof(vlanhdr);

            goto retry;

            break;
        }
        case ETHERTYPE_IP:
            proto = IPPROTO_IP;
            ip_hdr = bytes + skip;
            break;
        case ETHERTYPE_IPV6:
            proto = IPPROTO_IPV6;
            ip_hdr = bytes + skip;
            break;
        default:
            break;
        }

        break;
    }
    case DLT_IEEE802_11:
        // TODO
    default:
        break;
    }

    return ip_hdr;
}

void
run_pcap(std::string dev, std::string conf)
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
    pcap_inst->run();

    pcap_is_running = false;
}
