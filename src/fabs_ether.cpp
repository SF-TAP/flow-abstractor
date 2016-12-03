#include "fabs_ether.hpp"

#include <unistd.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <iostream>
#include <string>
#include <functional>

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

fabs_ether::fabs_ether(fabs_conf &conf, const fabs_dlcap *dlcap)
    : m_is_break(false),
      m_num_dropped(0),
      m_dlcap(dlcap),
      m_appif(new fabs_appif(*this)),
      m_fragment(*this, m_appif),
      m_is_consuming_frag(false),
      m_num_pcap(0),
      m_thread_consume_frag(std::bind(&fabs_ether::consume_fragment, this)),
      m_thread_timer(std::bind(&fabs_ether::timer, this))
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

    m_mutex = new std::mutex[numtcp];
    m_condition = new std::condition_variable[numtcp];
    m_thread_consume = new std::thread*[numtcp];

    for (int i = 0; i < numtcp; i++) {
        m_thread_consume[i] = new std::thread(std::bind(&fabs_ether::consume, this, i));
    }


    std::unique_lock<std::mutex> lock(m_mutex_init);
    m_condition_init.notify_all();
}

fabs_ether::~fabs_ether()
{

}

void
fabs_ether::produce(int idx, ptr_fabs_bytes buf)
{
    if (! m_queue[idx].push(buf)) {
        __sync_fetch_and_add(&m_num_dropped, 1);
        return;
    }

    if (m_queue[idx].get_len() >= NOTIFY_NUM) {
        if (! m_is_consuming[idx]) {
            if (m_mutex[idx].try_lock()) {
                m_condition[idx].notify_one();
                m_mutex[idx].unlock();
            }
        }
    }
}

inline void
fabs_ether::produce(int idx, const char *buf, int len, const timeval &tm)
{
    ptr_fabs_bytes bytes(new fabs_bytes);

    bytes->set_buf(buf, len);
    bytes->m_tm = tm;

    produce(idx, std::move(bytes));
}

void
fabs_ether::timer()
{
    {
        std::unique_lock<std::mutex> lock_init(m_mutex_init);
        m_condition_init.wait(lock_init);
    }

    timeval tv;
    gettimeofday(&tv, nullptr);

    double tv0 = tv.tv_sec + tv.tv_usec * 1.0e-6;

    uint64_t num_dropped = m_num_dropped;
    for (;;) {
        time_t t1 = time(NULL);

        if (t1 - t0 > 10) {
            gettimeofday(&tv, nullptr);
            double tv1 = tv.tv_sec + tv.tv_usec * 1.0e-6;

            std::cout << "uptime: " << tv1 - tv0 << " [s]" << std::endl;

            t0 = t1;

            std::cout << "received packets (pcap): " << m_num_pcap << std::endl;

            if (m_dlcap)
                m_dlcap->print_stat();

            std::cout << "dropped packets internally: " << m_num_dropped << std::endl;

            if (m_num_dropped > num_dropped) {
                num_dropped = m_num_dropped;
                std::cout << "    (warning: increase the number of threads of TCP or regex,\n"
                          << "     or use the SF-TAP cell incubator)"
                          << std::endl;
            }

            m_callback.print_stat();

            std::cout << std::endl;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        if (m_is_break)
            return;
    }
}

void
fabs_ether::consume(int idx)
{
    std::ostringstream os;
    os << "SF-TAP TCP[" << idx << "]";
    SET_THREAD_NAME(pthread_self(), os.str().c_str());

    for (;;) {
        {
            std::unique_lock<std::mutex> lock(m_mutex[idx]);
            if (m_is_break)
                return;

            while (m_queue[idx].get_len() == 0) {
                m_is_consuming[idx] = false;

                m_condition[idx].wait_for(lock, std::chrono::milliseconds(50));

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
                            std::unique_lock<std::mutex> lock(m_mutex_frag);
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
                        case IPPROTO_AH:
                        case IPPROTO_DSTOPTS:
                        {
                            ip6_ext *ext = (ip6_ext*)p;

                            nxt = ext->ip6e_nxt;
                            p  += ext->ip6e_len * 8 + 8;

                            break;
                        }
                        case IPPROTO_ESP:
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
        std::unique_lock<std::mutex> lock_init(m_mutex_init);
        m_condition_init.wait(lock_init);
    }

    for (;;) {
        {
            std::unique_lock<std::mutex> lock(m_mutex_frag);
            while (m_queue_frag.get_len() == 0) {
                m_is_consuming_frag = false;
                m_condition_frag.wait_for(lock, std::chrono::milliseconds(100));

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
fabs_ether::ether_input(const uint8_t *bytes, int len, const timeval &tm, bool is_pcap)
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

    produce(hash & (m_appif->get_num_tcp_threads() - 1), (char*)bytes, len, tm);
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
