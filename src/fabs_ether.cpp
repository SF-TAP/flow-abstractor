#include "fabs_ether.hpp"

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

#define NOTIFY_NUM 1024

time_t t0 = time(NULL);

struct vlanhdr {
    uint16_t m_tci;
    uint16_t m_type;
};

fabs_ether::fabs_ether(std::string conf, const fabs_dlcap *dlcap)
    : m_is_break(false),
      m_num_dropped(0),
      m_dlcap(dlcap),
      m_appif(new fabs_appif(*this)),
      m_fragment(*this, m_appif),
      m_is_consuming_frag(false),
      m_num_pcap(0),
      m_thread_consume_frag(boost::bind(&fabs_ether::consume_fragment, this)),
      m_thread_timer(boost::bind(&fabs_ether::timer, this))
{
    m_appif->read_conf(conf);
    m_callback.set_appif(m_appif);
    m_appif->run();

    int numtcp = m_appif->get_num_tcp_threads();

    m_queue = new fabs_cb<ptr_fabs_bytes>[numtcp];
    m_is_consuming = new bool[numtcp];

    for (int i = 0; i < numtcp; i++) {
        m_is_consuming[i] = false;
    }

    m_mutex = new boost::mutex[numtcp];
    m_condition = new boost::condition[numtcp];
    m_thread_consume = new boost::thread*[numtcp];

    for (int i = 0; i < numtcp; i++) {
        m_thread_consume[i] = new boost::thread(boost::bind(&fabs_ether::consume, this, i));
    }


    boost::mutex::scoped_lock lock(m_mutex_init);
    m_condition_init.notify_all();
}

fabs_ether::~fabs_ether()
{
    std::cout << "deleting Ethernet threads... " << std::flush;

    m_is_break = true;

    {
        boost::mutex::scoped_lock lock(m_mutex_frag);
        m_condition_frag.notify_one();
    }

    m_thread_consume_frag.join();

    for (int i = 0; i < m_appif->get_num_tcp_threads(); i++) {
        {
            boost::mutex::scoped_lock lock(m_mutex[i]);
            m_condition[i].notify_one();
        }

        m_thread_consume[i]->join();
        delete m_thread_consume[i];
    }

    m_thread_timer.join();

    delete[] m_thread_consume;
    delete[] m_condition;
    delete[] m_mutex;
    delete[] m_queue;

    std::cout << "done" << std::endl;
}

void
fabs_ether::produce(int idx, ptr_fabs_bytes buf)
{
    if (! m_queue[idx].push(buf)) {
        m_num_dropped++;
        return;
    }

    if (m_queue[idx].get_len() >= NOTIFY_NUM) {
        if (! m_is_consuming[idx]) {
            boost::try_mutex::scoped_try_lock lock(m_mutex[idx]);
            if (lock)
                m_condition[idx].notify_one();
        }
    }
}

inline void
fabs_ether::produce(int idx, const char *buf, int len)
{
    ptr_fabs_bytes bytes(new fabs_bytes);

    bytes->set_buf(buf, len);

    produce(idx, std::move(bytes));
}

void
fabs_ether::timer()
{
    {
        boost::mutex::scoped_lock lock_init(m_mutex_init);
        m_condition_init.wait(lock_init);
    }

    for (;;) {
        time_t t1 = time(NULL);

        if (t1 - t0 > 10) {
            t0 = t1;

            std::cout << "received packets (pcap): " << m_num_pcap << std::endl;

            if (m_dlcap)
                m_dlcap->print_stat();

            std::cout << "dropped packets internally: " << m_num_dropped << std::endl;

            if (m_num_dropped > 0) {
                std::cout << "    (Warning. increase the number of threads for TPC and regex,\n"
                          << "     or use the SF-TAP cell incubator)"
                          << std::endl;
            }

            m_callback.print_stat();

            std::cout << std::endl;
        }

        boost::this_thread::sleep(boost::posix_time::milliseconds(100));
        if (m_is_break)
            return;
    }
}

void
fabs_ether::consume(int idx)
{
    for (;;) {
        {
            boost::mutex::scoped_lock lock(m_mutex[idx]);
            while (m_queue[idx].get_len() == 0) {
                m_is_consuming[idx] = false;

                boost::system_time timeout = boost::get_system_time() + boost::posix_time::milliseconds(50);
                m_condition[idx].timed_wait(lock, timeout);

                if (m_is_break)
                    return;
            }

            m_is_consuming[idx] = true;
        }

        ptr_fabs_bytes buf;
        for (int i = 0; i < NOTIFY_NUM; i++) {
            while (m_queue[idx].pop(&buf)) {
                if (m_is_break)
                    return;

                uint8_t proto;
                const uint8_t *ip_hdr = get_ip_hdr((uint8_t*)buf->get_head(),
                                                   buf->get_len(), proto);

                buf->skip((char*)ip_hdr - buf->get_head());

                uint32_t len = buf->get_len();
                uint32_t plen;

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
                        m_queue_frag.push(buf);

                        if (! m_is_consuming_frag &&
                            m_queue_frag.get_len() > NOTIFY_NUM) {
                            boost::mutex::scoped_lock lock(m_mutex_frag);
                            m_condition_frag.notify_one();
                        }
                    } else {
                        m_callback(idx, std::move(buf));
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

                    m_callback(idx, std::move(buf));

                    break;
                }
                default:
                    break;
                }

            err:
                do {} while (false);
            }
        }
    }
}

void
fabs_ether::consume_fragment()
{
    {
        boost::mutex::scoped_lock lock_init(m_mutex_init);
        m_condition_init.wait(lock_init);
    }

    for (;;) {
        {
            boost::mutex::scoped_lock lock(m_mutex_frag);
            while (m_queue_frag.get_len() == 0) {
                m_is_consuming_frag = false;
                boost::system_time timeout = boost::get_system_time() + boost::posix_time::milliseconds(100);
                m_condition_frag.timed_wait(lock, timeout);

                if (m_is_break) {
                    return;
                }
            }
        }

        ptr_fabs_bytes buf;
        for (int i = 0; i < NOTIFY_NUM; i++) {
            while (m_queue_frag.pop(&buf)) {
                if (m_is_break)
                    return;
                m_fragment.input_ip(std::move(buf));
            }
        }
    }
}

void
fabs_ether::ether_input(const uint8_t *bytes, int len, bool is_pcap)
{
    if (is_pcap) m_num_pcap++;
    
    uint8_t proto;
    const uint8_t *ip_hdr = get_ip_hdr(bytes, len, proto);
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

    produce(hash % m_appif->get_num_tcp_threads(), (char*)bytes, len);
}

inline const uint8_t *
fabs_ether::get_ip_hdr(const uint8_t *bytes, uint32_t len, uint8_t &proto)
{
    const uint8_t *ip_hdr = NULL;

    if (len < sizeof(ether_header))
        return ip_hdr;

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

    return ip_hdr;
}
