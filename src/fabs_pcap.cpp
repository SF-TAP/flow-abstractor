#include "fabs_pcap.hpp"

#include <unistd.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <iostream>
#include <string>

#include <boost/bind.hpp>

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN 0x8100 /* IEEE 802.1Q VLAN tagging */
#endif

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd /* IPv6 */
#endif

#define QNUM 8192

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

fabs_pcap::fabs_pcap(std::string conf)
    : m_handle(NULL),
      m_is_break(false),
      m_bufsize(10000),
      m_fragment(*this),
      m_appif(new fabs_appif),
      m_thread_consume_frag(boost::bind(&fabs_pcap::consume_fragment, this)),
      m_thread_timer(boost::bind(&fabs_pcap::timer, this))
{
    m_appif->read_conf(conf);
    m_callback.set_appif(m_appif);
    m_appif->run();

    for (int i = 0; i < TCPNUM; i++) {
        m_thread_consume[i] = new boost::thread(boost::bind(&fabs_pcap::consume, this, i));

        m_spinlock[i].lock();

        m_qitem[i].m_queue = boost::shared_array<fabs_bytes>(new fabs_bytes[QNUM]);
        m_qitem[i].m_num   = 0;

        m_spinlock[i].unlock();
    }
}

void
fabs_pcap::produce(int idx, fabs_bytes &buf)
{
    m_spinlock[idx].lock();

    m_qitem[idx].m_queue[m_qitem[idx].m_num] = buf;
    m_qitem[idx].m_num++;

    if (m_qitem[idx].m_num == QNUM) {
        boost::mutex::scoped_lock lock(m_mutex[idx]);
        m_queue[idx].push_back(m_qitem[idx]);
        m_condition[idx].notify_one();

        m_qitem[idx].m_queue = boost::shared_array<fabs_bytes>(new fabs_bytes[QNUM]);
        m_qitem[idx].m_num   = 0;
    }

    m_spinlock[idx].unlock();
}

inline void
fabs_pcap::produce(int idx, const char *buf, int len)
{
    m_spinlock[idx].lock();

    m_qitem[idx].m_queue[m_qitem[idx].m_num].set_buf(buf, len);
    m_qitem[idx].m_num++;

    if (m_qitem[idx].m_num == QNUM) {
        boost::mutex::scoped_lock lock(m_mutex[idx]);
        m_queue[idx].push_back(m_qitem[idx]);
        m_condition[idx].notify_one();

        m_qitem[idx].m_queue = boost::shared_array<fabs_bytes>(new fabs_bytes[QNUM]);
        m_qitem[idx].m_num   = 0;
    }

    m_spinlock[idx].unlock();
}

void
fabs_pcap::timer()
{
    for (;;) {
        for (int i = 0; i < TCPNUM; i++) {
            m_spinlock[i].lock();

            if (m_qitem[i].m_num > 0) {
                boost::mutex::scoped_lock lock(m_mutex[i]);
                m_queue[i].push_back(m_qitem[i]);
                m_condition[i].notify_one();

                m_qitem[i].m_queue = boost::shared_array<fabs_bytes>(new fabs_bytes[QNUM]);
                m_qitem[i].m_num   = 0;
            }

            m_spinlock[i].unlock();
        }


        time_t t1 = time(NULL);

        if (t1 - t0 > 10) {
            pcap_stat stat;
            t0 = t1;
            pcap_stats(m_handle, &stat);

            cout << "received packets: " << stat.ps_recv
                 << "\ndropped packets: " << stat.ps_drop
                 << "\ndropped packets by IF: " << stat.ps_ifdrop
                 << endl;

            m_callback.print_stat();

            cout << endl;
        }

        boost::this_thread::sleep(boost::posix_time::milliseconds(100));
    }
}

void
fabs_pcap::consume(int idx)
{
    for (;;) {
        int size;
        vector<qitem> items;

        {
            boost::mutex::scoped_lock lock(m_mutex[idx]);
            while (m_queue[idx].empty()) {
                m_condition[idx].wait(lock);
            }

            size = m_queue[idx].size();

            items.resize(size);

            int i = 0;
            for (auto it = m_queue[idx].begin(); it != m_queue[idx].end(); ++it) {
                items[i] = *it;
                i++;
            }

            m_queue[idx].clear();
        }

        for (auto it = items.begin(); it != items.end(); ++it) {
            for (int i = 0; i < it->m_num; i++) {
                fabs_bytes &buf = it->m_queue[i];
                uint8_t proto;
                const uint8_t *ip_hdr = get_ip_hdr((uint8_t*)buf.get_head(),
                                                   buf.get_len(), proto);

                buf.skip((char*)ip_hdr - buf.get_head());

                uint32_t len = buf.get_len();
                uint32_t plen;
                static int count_frag = 0;


                if (ip_hdr == NULL) {
                    continue;
                }

                switch (proto) {
                case IPPROTO_IP:{
                    ip       *iph = (ip*)ip_hdr;
                    uint16_t  off = ntohs(iph->ip_off);

                    plen = ntohs(iph->ip_len);

                    if (plen > len) {
                        goto err;
                    }

                    if (off & IP_MF || (off & 0x1fff) > 0) {
                        // produce fragment packet
                        boost::mutex::scoped_lock lock(m_mutex_frag);
                        m_queue_frag.push_back(buf);
                        count_frag++;

                        if (count_frag > 1000) {
                            m_condition_frag.notify_one();
                            count_frag = 0;
                        }
                    } else {
                        m_callback(idx, buf);
                    }

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
                            goto err;
                        default:
                            goto end_loop;
                        }
                    }
                end_loop:
                    plen = ntohs(ip6h->ip6_plen) + sizeof(ip6_hdr);
                    if (plen > len) {
                        goto err;
                    }

                    m_callback(idx, buf);

                    break;
                }
                default:
                    break;
                }

            err:
                do {} while (false);
            }
        }

        items.clear();
    }
}

void
fabs_pcap::consume_fragment()
{
    for (;;) {
        int size;
        vector<fabs_bytes> bytes;

        {
            boost::mutex::scoped_lock lock(m_mutex_frag);
            while (m_queue_frag.empty()) {
                boost::system_time timeout = boost::get_system_time() + boost::posix_time::milliseconds(100);
                m_condition_frag.timed_wait(lock, timeout);
            }

            size = m_queue_frag.size();

            bytes.resize(size);

            int i = 0;
            for (auto it = m_queue_frag.begin(); it != m_queue_frag.end();
                 ++it) {
                bytes[i] = *it;
                i++;
            }

            m_queue_frag.clear();
        }

        for (auto it = bytes.begin(); it != bytes.end(); ++it) {
            m_fragment.input_ip(*it);
        }

        bytes.clear();
    }
}

void
fabs_pcap::callback(const struct pcap_pkthdr *h, const uint8_t *bytes)
{
    if (m_is_break) {
        pcap_breakloop(m_handle);
        return;
    }

    uint8_t proto;
    const uint8_t *ip_hdr = get_ip_hdr(bytes, h->caplen, proto);
    uint32_t hash;

    if (ip_hdr == NULL)
        return;

    if (proto == IPPROTO_IP) {
        const ip *iph = (const ip*)ip_hdr;
        hash = ntohl(iph->ip_src.s_addr ^ iph->ip_dst.s_addr);
    } else if (proto == IPPROTO_IPV6) {
        const ip6_hdr *iph = (const ip6_hdr*)ip_hdr;
        const uint32_t *p1, *p2;

        p1 = (uint32_t*)&iph->ip6_src;
        p2 = (uint32_t*)&iph->ip6_dst;

        hash = p1[0] ^ p1[1] ^ p1[2] ^ p1[3] ^ p2[0] ^ p2[1] ^ p2[2] ^ p2[3];
        hash = ntohl(hash);
    } else {
        return;
    }

    produce(hash % TCPNUM, (char*)bytes, h->caplen);
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

    m_handle = pcap_create(m_dev.c_str(), errbuf);

    if (m_handle == NULL) {
        cerr << "Couldn't open device " << m_dev << ": " << errbuf << endl;
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
            cerr << "An error was encouterd while pcap_dispatch(): "
                 << err << endl;
            break;
        }
        case -2:
            return;
        }
    }
}

inline const uint8_t *
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
