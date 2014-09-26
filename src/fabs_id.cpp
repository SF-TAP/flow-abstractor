#include "fabs_id.hpp"

#include <sys/socket.h>

#ifdef __linux__
    #define __FAVOR_BSD
#endif

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <boost/lexical_cast.hpp>

#include <iostream>

using namespace boost;
using namespace std;

fabs_direction
fabs_id::set_iph(char *iph, char **l4hdr)
{
    char protocol = iph[0] & 0xf0;

    switch (protocol) {
    case 0x40:
    {
        boost::shared_ptr<fabs_peer> addr1(new fabs_peer);
        boost::shared_ptr<fabs_peer> addr2(new fabs_peer);
        ip *iph4 = (ip*)iph;

        *l4hdr = NULL;

        memset(addr1.get(), 0, sizeof(fabs_peer));
        memset(addr2.get(), 0, sizeof(fabs_peer));

        addr1->l3_addr.b32 = iph4->ip_src.s_addr;
        addr2->l3_addr.b32 = iph4->ip_dst.s_addr;

        if (iph4->ip_p == IPPROTO_TCP) {
            tcphdr *tcph = (tcphdr*)(iph + iph4->ip_hl * 4);

            addr1->l4_port = tcph->th_sport;
            addr2->l4_port = tcph->th_dport;

            *l4hdr = (char*)tcph;
        } else if (iph4->ip_p == IPPROTO_UDP) {
            udphdr *udph = (udphdr*)(iph + iph4->ip_hl * 4);

            addr1->l4_port = udph->uh_sport;
            addr2->l4_port = udph->uh_dport;

            *l4hdr = (char*)udph;
        }

        m_l3_proto = IPPROTO_IP;
        m_l4_proto = iph4->ip_p;

        if (*addr1 < *addr2) {
            m_addr1 = addr1;
            m_addr2 = addr2;

            return FROM_ADDR1;
        } else {
            m_addr1 = addr2;
            m_addr2 = addr1;

            return FROM_ADDR2;
        }

        // not reach here
        break;
    }
    case 0x60:
    {
        boost::shared_ptr<fabs_peer> addr1(new fabs_peer);
        boost::shared_ptr<fabs_peer> addr2(new fabs_peer);
        ip6_hdr *iph6 = (ip6_hdr*)iph;
        uint8_t  nxt  = iph6->ip6_nxt;
        char    *p    = (char*)iph6 + sizeof(ip6_hdr);

        *l4hdr = NULL;

        memset(addr1.get(), 0, sizeof(fabs_peer));
        memset(addr2.get(), 0, sizeof(fabs_peer));

        memcpy(&addr1->l3_addr.b128, &iph6->ip6_src, sizeof(in6_addr));
        memcpy(&addr2->l3_addr.b128, &iph6->ip6_dst, sizeof(in6_addr));

        m_l3_proto = IPPROTO_IPV6;

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
                goto end_loop;
            case IPPROTO_TCP:
            {
                tcphdr *tcph = (tcphdr*)(p);

                addr1->l4_port = tcph->th_sport;
                addr2->l4_port = tcph->th_dport;

                m_l4_proto = nxt;

                *l4hdr = (char*)tcph;

                goto end_loop;
            }
            case IPPROTO_UDP:
            {
                udphdr *udph = (udphdr*)(p);

                addr1->l4_port = udph->uh_sport;
                addr2->l4_port = udph->uh_dport;

                m_l4_proto = nxt;

                *l4hdr = (char*)udph;

                goto end_loop;
            }
            default:
                goto end_loop;
            }
        }
    end_loop:
        if (*addr1 < *addr2) {
            m_addr1 = addr1;
            m_addr2 = addr2;

            return FROM_ADDR1;
        } else {
            m_addr1 = addr2;
            m_addr2 = addr1;

            return FROM_ADDR2;
        }

        // not reach here
        break;
    }
    default:
        break;
    }

    return FROM_NONE;
}

void
fabs_id::set_appif_header(fabs_appif_header &header)
{
    boost::shared_ptr<fabs_peer> addr1(new fabs_peer);
    boost::shared_ptr<fabs_peer> addr2(new fabs_peer);

    memcpy(&addr1->l3_addr, &header.l3_addr1, sizeof(addr1->l3_addr));
    memcpy(&addr2->l3_addr, &header.l3_addr2, sizeof(addr2->l3_addr));

    addr1->l4_port = header.l4_port1;
    addr2->l4_port = header.l4_port2;

    m_l4_proto = header.l4_proto;
    m_l3_proto = header.l3_proto;

    m_hop = header.hop;

    m_addr1 = addr1;
    m_addr2 = addr2;
}

void
fabs_id::print_id() const
{
    char addr1[INET6_ADDRSTRLEN], addr2[INET6_ADDRSTRLEN];

    if (m_l3_proto == IPPROTO_IP) {
        inet_ntop(PF_INET, &m_addr1->l3_addr.b32, addr1, sizeof(addr1));
        inet_ntop(PF_INET, &m_addr2->l3_addr.b32, addr2, sizeof(addr2));
    } else if (m_l3_proto == IPPROTO_IPV6) {
        inet_ntop(PF_INET6, &m_addr1->l3_addr.b128, addr1, sizeof(addr1));
        inet_ntop(PF_INET6, &m_addr2->l3_addr.b128, addr2, sizeof(addr2));
    }

    cout << "addr1 = " << addr1 << ":" << ntohs(m_addr1->l4_port)
         << ", addr2 = " << addr2 << ":" << ntohs(m_addr2->l4_port)
         << ", l3_proto = " << (int)m_l3_proto
         << ", l4_proto = " << (int)m_l4_proto
         << ", hop = " << (int)m_hop
         << endl;
}
