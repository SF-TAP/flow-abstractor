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
fabs_id::set_iph(char *iph, uint16_t vlanid, char **l4hdr, int *len)
{
    char protocol = iph[0] & 0xf0;

    *l4hdr = NULL;
    m_vlanid = vlanid;

    switch (protocol) {
    case 0x40:
    {
        std::shared_ptr<fabs_peer> addr1(new fabs_peer);
        std::shared_ptr<fabs_peer> addr2(new fabs_peer);
        ip *iph4 = (ip*)iph;

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
        } else if (iph4->ip_p == IPPROTO_ICMP) {
            *l4hdr = iph + iph4->ip_hl * 4;
        }

        m_l3_proto = IPPROTO_IP;
        m_l4_proto = iph4->ip_p;

        *len = ntohs(iph4->ip_len) -  iph4->ip_hl * 4;

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
        std::shared_ptr<fabs_peer> addr1(new fabs_peer);
        std::shared_ptr<fabs_peer> addr2(new fabs_peer);
        ip6_hdr *iph6 = (ip6_hdr*)iph;
        uint8_t  nxt  = iph6->ip6_nxt;
        char    *p    = (char*)iph6 + sizeof(ip6_hdr);

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
                m_l4_proto = nxt;
                *l4hdr = (char*)p;
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
        *len = ntohs(iph6->ip6_plen);

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
    std::shared_ptr<fabs_peer> addr1(new fabs_peer);
    std::shared_ptr<fabs_peer> addr2(new fabs_peer);

    memcpy(&addr1->l3_addr, &header.l3_addr1, sizeof(addr1->l3_addr));
    memcpy(&addr2->l3_addr, &header.l3_addr2, sizeof(addr2->l3_addr));

    addr1->l4_port = header.l4_port1;
    addr2->l4_port = header.l4_port2;

    m_l4_proto = header.l4_proto;
    m_l3_proto = header.l3_proto;

    m_hop = header.hop;

    m_addr1 = addr1;
    m_addr2 = addr2;

    m_vlanid = header.vlanid;
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

uint32_t
fabs_id::get_hash() const
{
    union {
        uint32_t h32;
        uint16_t h16[2];
    } hash;

    hash.h32 = ntohs(m_addr1->l4_port ^ m_addr2->l4_port);
    hash.h32 ^= ntohs(m_vlanid);

    if (m_l3_proto == IPPROTO_IP) {
        hash.h32 ^= ntohl(m_addr1->l3_addr.b32 ^ m_addr2->l3_addr.b32);
    } else if (get_l3_proto() == IPPROTO_IPV6) {
        uint32_t *p = (uint32_t*)m_addr1->l3_addr.b128;

        hash.h32 ^= ntohl(p[0]);
        hash.h32 ^= ntohl(p[1]);
        hash.h32 ^= ntohl(p[2]);
        hash.h32 ^= ntohl(p[3]);
        hash.h32 ^= ntohl(p[4]);


        p = (uint32_t*)m_addr2->l3_addr.b128;

        hash.h32 ^= ntohl(p[0]);
        hash.h32 ^= ntohl(p[1]);
        hash.h32 ^= ntohl(p[2]);
        hash.h32 ^= ntohl(p[3]);
        hash.h32 ^= ntohl(p[4]);
    }

    hash.h32 += m_hop;

    uint16_t hash2 = hash.h16[0] ^ hash.h16[1];

    return hash2;
}
