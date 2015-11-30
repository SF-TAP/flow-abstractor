#ifndef FABS_ID_HPP
#define FABS_ID_HPP

#include "fabs_common.hpp"
#include "fabs_bytes.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <stdint.h>
#include <string.h>

#include <boost/shared_ptr.hpp>

enum fabs_direction {
    FROM_ADDR1 = 0,
    FROM_ADDR2 = 1,
    FROM_NONE  = 3,
};

struct fabs_appif_header {
    union {
        uint32_t b32; // big endian
        uint8_t  b128[16];
    } l3_addr1;

    union {
        uint32_t b32; // big endian
        uint8_t  b128[16];
    } l3_addr2;

    uint16_t l4_port1; // big endian
    uint16_t l4_port2; // big endian

    uint8_t  event; // 0: created, 1: destroyed, 2: data
    uint8_t  from;  // FROM_ADDR1: from addr1, FROM_ADDR2: from addr2
    uint16_t len;
    uint8_t  hop;
    uint8_t  l3_proto; // IPPROTO_IP or IPPROTO_IPV6
    uint8_t  l4_proto; // IPPROTO_TCP or IPPROTO_UDP
    uint8_t  match; // 0: matched up's regex, 1: matched down's regex, 2: none
};

typedef boost::shared_ptr<fabs_appif_header> ptr_appif_header;

struct fabs_peer {
    union {
        uint32_t b32; // big endian
        uint8_t  b128[16];
    } l3_addr;

    uint16_t l4_port; // big endian
    uint16_t padding;

    fabs_peer() { memset(this, 0, sizeof(*this)); }
    fabs_peer(const fabs_peer &rhs) { *this = rhs; }

    bool operator< (const fabs_peer &rhs) const {
        return memcmp(this, &rhs, sizeof(fabs_peer)) < 0 ? true : false;
    };

    bool operator> (const fabs_peer &rhs) const {
        return rhs < *this;
    }

    bool operator== (const fabs_peer &rhs) const {
        return memcmp(this, &rhs, sizeof(fabs_peer)) == 0 ? true : false;
    }

    fabs_peer& operator= (const fabs_peer &rhs) {
        memcpy(this, &rhs, sizeof(fabs_peer));
        return *this;
    }
};

class fabs_id {
public:
    fabs_id() : m_hop(0) { }
    virtual ~fabs_id(){ };

    fabs_direction set_iph(char *iph, char **l4hdr, int *len);
    void set_appif_header(fabs_appif_header &header);
    void print_id() const;

    bool operator< (const fabs_id &rhs) const {
        if (m_hop == rhs.m_hop) {
            if (m_l3_proto == rhs.m_l3_proto) {
                if (m_l4_proto == rhs.m_l4_proto) {
                    int n = memcmp(m_addr1.get(), rhs.m_addr1.get(),
                                   sizeof(fabs_peer));

                    if (n == 0)
                        return *m_addr2 < *rhs.m_addr2;

                    return n < 0 ? true : false;
                }

                return m_l4_proto < rhs.m_l4_proto;
            }

            return m_l3_proto < rhs.m_l3_proto;
        }

        return m_hop < rhs.m_hop;
    }

    bool operator> (const fabs_id &rhs) const {
        return rhs < *this;
    }

    bool operator== (const fabs_id &rhs) const {
        return (m_hop      == rhs.m_hop &&
                m_l3_proto == rhs.m_l3_proto &&
                m_l4_proto == rhs.m_l4_proto &&
                *m_addr1   == *rhs.m_addr1 &&
                *m_addr2   == *rhs.m_addr2);
    }

    std::string to_str() const {
        std::string addr1, addr2;

        addr1 = bin2str((char*)m_addr1.get(), sizeof(fabs_peer));
        addr2 = bin2str((char*)m_addr2.get(), sizeof(fabs_peer));

        return addr1 + ":" + addr2;
    }

    uint8_t get_l3_proto() const { return m_l3_proto; }
    uint8_t get_l4_proto() const { return m_l4_proto; }

    boost::shared_ptr<fabs_peer> m_addr1, m_addr2;
    uint8_t m_hop;

    uint32_t get_hash() const;

private:
    uint8_t m_l3_proto;
    uint8_t m_l4_proto;
};

struct fabs_id_dir {
    fabs_id        m_id;
    fabs_direction m_dir;

    bool operator< (const fabs_id_dir &rhs) const {
        if (m_dir == rhs.m_dir)
            return m_id < rhs.m_id;

        return m_dir < rhs.m_dir;
    }

    bool operator> (const fabs_id_dir &rhs) const {
        return rhs < *this;
    }

    bool operator== (const fabs_id_dir &rhs) const {
        return m_dir == rhs.m_dir && m_id == rhs.m_id;
    }


    void get_addr_src(char *buf, int len) const {
        boost::shared_ptr<fabs_peer> addr;

        addr = (m_dir == FROM_ADDR1) ? m_id.m_addr1 : m_id.m_addr2;

        get_addr(addr, buf, len);
    }

    void get_addr_dst(char *buf, int len) const {
        boost::shared_ptr<fabs_peer> addr;

        addr = (m_dir == FROM_ADDR1) ? m_id.m_addr2 : m_id.m_addr1;

        get_addr(addr, buf, len);
    }

    void get_addr1(char *buf, int len) const {
        get_addr(m_id.m_addr1, buf, len);
    }

    void get_addr2(char *buf, int len) const {
        get_addr(m_id.m_addr2, buf, len);
    }

    uint32_t get_ipv4_addr_src() const {
        return m_dir == FROM_ADDR1 ?
            m_id.m_addr1->l3_addr.b32 :
            m_id.m_addr2->l3_addr.b32;
    }

    uint32_t get_ipv4_addr_dst() const {
        return m_dir == FROM_ADDR1 ?
            m_id.m_addr2->l3_addr.b32 :
            m_id.m_addr1->l3_addr.b32;
    }

    uint16_t get_port_src() const {
        return m_dir == FROM_ADDR1 ?
            m_id.m_addr1->l4_port :
            m_id.m_addr2->l4_port;
    }

    uint16_t get_port_dst() const {
        return m_dir == FROM_ADDR1 ?
            m_id.m_addr2->l4_port :
            m_id.m_addr1->l4_port;
    }

    uint16_t get_port1() const {
        return m_id.m_addr1->l4_port;
    }

    uint16_t get_port2() const {
        return m_id.m_addr2->l4_port;
    }

    uint8_t get_l3_proto() const { return m_id.get_l3_proto(); }
    uint8_t get_l4_proto() const { return m_id.get_l4_proto(); }

private:
    void get_addr(boost::shared_ptr<fabs_peer> addr, char *buf, int len) const {
        if (m_id.get_l3_proto() == IPPROTO_IP) {
            inet_ntop(AF_INET, &addr->l3_addr.b32, buf, len);
        } else if (m_id.get_l3_proto() == IPPROTO_IPV6) {
            inet_ntop(AF_INET6, addr->l3_addr.b128, buf, len);
        }
    }
};

#endif // FABS_ID_HPP
