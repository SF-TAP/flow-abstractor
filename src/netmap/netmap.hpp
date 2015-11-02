#ifndef __netmap_hpp__
#define __netmap_hpp__

#include "common.hpp"
#include "ether.hpp"

#include <iostream>
#include <map>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <ifaddrs.h>
#include <pthread.h>

#include <sys/mman.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifdef POLL
#include <poll.h>
#else
#include <sys/select.h>
#endif

#include <net/if.h>

#ifdef __linux__
#include <linux/sockios.h>
#include <linux/ethtool.h>
#else 
#include <net/if_dl.h>
#endif

#include <net/ethernet.h>

#define NETMAP_WITH_LIBS
#include <net/netmap.h>
#include <net/netmap_user.h>

#define NETMAP_SYNCWAIT_FAILD 0
#define NETMAP_SYNCWAIT_SUCCESS 1
#define NETMAP_SYNCWAIT_TIMEOUT 2

class netmap
{
public:
    // constructor
    netmap();
    // destructor
    virtual ~netmap();

    // control methods
    bool open_if(const std::string& ifname);
    bool open_if(const char* ifname);
    bool open_vale(const std::string& ifname, int qnum);
    bool open_vale(const char* ifname, int qnum);

    // utils methods
    void dump_nmr();
    void dump_ring(int ringid);
    bool negate_capabilities();
    bool set_promisc();
    bool unset_promisc();

    // netmap getter
    char* get_ifname();
    uint16_t get_tx_qnum();
    uint16_t get_rx_qnum();
    struct ether_addr* get_mac();

    inline void next(struct netmap_ring* ring);

    inline size_t get_ethlen(struct netmap_ring* ring);
    inline void set_ethlen(struct netmap_ring* ring, size_t size);
    inline struct ether_header* get_eth(struct netmap_ring* ring);

    inline uint32_t get_cursor(struct netmap_ring* ring);
    inline struct netmap_slot* get_slot(struct netmap_ring* ring);

    inline int get_fd(int ringid);
    inline char* get_mem(int ringid);
    inline struct netmap_ring* get_tx_ring(int ringid);
    inline struct netmap_ring* get_rx_ring(int ringid);

    inline int get_fd_sw();
    inline char* get_mem();
    inline struct netmap_ring* get_rx_ring_sw();
    inline struct netmap_ring* get_tx_ring_sw();
    inline uint32_t get_avail(struct netmap_ring* ring);

private:
    uint32_t nm_version;
    uint16_t nm_rx_qnum;
    uint16_t nm_tx_qnum;
    uint32_t nm_memsize;
    char nm_ifname[IFNAMSIZ];
    struct ether_addr nm_mac;
    uint32_t nm_oui;
    uint32_t nm_bui;

    struct nmreq nm_nmr;

    //hard_info
    int* nm_fds;
    char** nm_mem_addrs;
    struct netmap_ring** nm_tx_rings;
    struct netmap_ring** nm_rx_rings;
    //soft_info
    int nm_fd_soft;
    char* nm_mem_addr_soft;
    struct netmap_ring* nm_tx_ring_soft;
    struct netmap_ring* nm_rx_ring_soft;

    bool _create_nmring(int qnum, int swhw);
    bool _remove_hw_ring(int qnum);
    bool _remove_sw_ring();
};

netmap::netmap()
{
    nm_version = 0;
    nm_rx_qnum = 0;
    nm_tx_qnum = 0;
    nm_memsize = 0;
    memset(nm_ifname, 0, sizeof(nm_ifname));
    memset(&nm_mac, 0, sizeof(nm_mac));
    nm_oui = 0;
    nm_bui = 0;
    nm_fds = NULL;
    nm_mem_addrs = NULL;
    nm_tx_rings = NULL;
    nm_rx_rings = NULL;
    nm_mem_addr_soft = NULL;
    nm_fd_soft = 0;
    nm_tx_ring_soft = NULL;
    nm_rx_ring_soft = NULL;
}

netmap::~netmap()
{
    for (int i = 0; i < nm_tx_qnum; i++) {
        if (nm_mem_addrs[i] != NULL) {
            _remove_hw_ring(i);
        }
    }
    if (nm_fds != NULL) free(nm_fds);
    if (nm_mem_addrs != NULL) free(nm_mem_addrs);
    if (nm_rx_rings != NULL) free(nm_rx_rings);
    if (nm_tx_rings != NULL) free(nm_tx_rings);

    _remove_sw_ring();
    nm_fd_soft = 0;
    nm_mem_addr_soft = NULL;
    nm_tx_ring_soft = NULL;
    nm_rx_ring_soft = NULL;
}

bool
netmap::open_vale(const std::string& ifname, int qnum)
{
    return open_vale(ifname.c_str(), qnum);
}

bool
netmap::open_vale(const char* ifname, int qnum)
{
    if (strncmp(ifname, "vale", 4) != 0) {
        MESG("can't open vale interface");
        return false;
    }

    int fd;
    fd = open("/dev/netmap", O_RDWR);

    if (fd < 0) {
        perror("open");
        MESG("Unable to open /dev/netmap");
        return false;
    }

    memset(&nm_nmr, 0, sizeof(nm_nmr));
    nm_version = NETMAP_API;
    nm_nmr.nr_version = nm_version;
    strncpy(nm_ifname, ifname, strlen(ifname));
    strncpy(nm_nmr.nr_name, ifname, strlen(ifname));

    if (ioctl(fd, NIOCGINFO, &nm_nmr) < 0) {
        perror("ioctl");
        MESG("unabe to get interface info for %s", ifname);
        memset(&nm_nmr, 0, sizeof(nm_nmr));
        close(fd);
        return false;
    }

    nm_tx_qnum = qnum;
    nm_rx_qnum = qnum;
    nm_memsize = nm_nmr.nr_memsize;
    close(fd);

    nm_fds = (int*)malloc(sizeof(int*)*nm_rx_qnum);
    memset(nm_fds, 0, sizeof(int*)*nm_rx_qnum);

    nm_mem_addrs = (char**)malloc(sizeof(char*)*nm_rx_qnum);
    memset(nm_mem_addrs, 0, sizeof(char*)*nm_rx_qnum);

    nm_rx_rings = 
        (struct netmap_ring**)malloc(sizeof(struct netmap_ring*)*nm_rx_qnum);
    memset(nm_rx_rings, 0, sizeof(struct netmap_rings**)*nm_rx_qnum);

    nm_tx_rings = 
        (struct netmap_ring**)malloc(sizeof(struct netmap_ring*)*nm_tx_qnum);
    memset(nm_tx_rings, 0, sizeof(struct netmap_rings**)*nm_tx_qnum);

    for (int i = 0; i < nm_rx_qnum; i++) {
        if (_create_nmring(i, 0) == false) {
            for (int j = 0; j < i; j++) {
                if (nm_mem_addrs[j] != NULL) {
                    _remove_hw_ring(j);
                }
            }
            if (nm_fds != NULL) free(nm_fds);
            if (nm_mem_addrs != NULL) free(nm_mem_addrs);
            if (nm_rx_rings != NULL) free(nm_rx_rings);
            if (nm_tx_rings != NULL) free(nm_tx_rings);
            return false;
        } else {
            if (debug) printf("(%s:%02d) open_fd :%d\n", ifname, i, nm_fds[i]);
            if (debug) printf("(%s:%02d) open_mem:%p\n", ifname, i, nm_mem_addrs[i]);
            if (debug) printf("(%s:%02d) rx_ring :%p\n", ifname, i, nm_rx_rings[i]);
            if (debug) printf("(%s:%02d) tx_ring :%p\n", ifname, i, nm_tx_rings[i]);
        }
    }

    return true;
}

bool
netmap::open_if(const std::string& ifname)
{
    return open_if(ifname.c_str());
}

bool
netmap::open_if(const char* ifname)
{
    if (strncmp(ifname, "vale", 4) == 0) {
        MESG("netmap::open_if cant use vale interface");
        return false;
    }

    int fd;
    fd = open("/dev/netmap", O_RDWR);

    if (fd < 0) {
        perror("open");
        MESG("Unable to open /dev/netmap");
        return false;
    }

    memset(&nm_nmr, 0, sizeof(nm_nmr));
    nm_version = NETMAP_API;
    nm_nmr.nr_version = nm_version;
    strncpy(nm_ifname, ifname, strlen(ifname));
    strncpy(nm_nmr.nr_name, ifname, strlen(ifname));

    if (ioctl(fd, NIOCGINFO, &nm_nmr) < 0) {
        perror("ioctl");
        MESG("unabe to get interface info for %s", ifname);
        memset(&nm_nmr, 0, sizeof(nm_nmr));
        close(fd);
        return false;
    }

    if (nm_nmr.nr_tx_rings != nm_nmr.nr_rx_rings) {
        MESG("%s NIC cant supported with this netmap class..", ifname);
        memset(&nm_nmr, 0, sizeof(nm_nmr));
        close(fd);
        return false;
    }

    nm_tx_qnum = nm_nmr.nr_tx_rings;
    nm_rx_qnum = nm_nmr.nr_rx_rings;
    nm_memsize = nm_nmr.nr_memsize;
    close(fd);

    nm_fds = (int*)malloc(sizeof(int*)*nm_rx_qnum);
    memset(nm_fds, 0, sizeof(int*)*nm_rx_qnum);

    nm_mem_addrs = (char**)malloc(sizeof(char*)*nm_rx_qnum);
    memset(nm_mem_addrs, 0, sizeof(char*)*nm_rx_qnum);

    nm_rx_rings = 
        (struct netmap_ring**)malloc(sizeof(struct netmap_ring*)*nm_rx_qnum);
    memset(nm_rx_rings, 0, sizeof(struct netmap_rings**)*nm_rx_qnum);

    nm_tx_rings = 
        (struct netmap_ring**)malloc(sizeof(struct netmap_ring*)*nm_tx_qnum);
    memset(nm_tx_rings, 0, sizeof(struct netmap_rings**)*nm_tx_qnum);

    get_mac_addr(ifname, &nm_mac);

#ifndef __linux__
    nm_oui = nm_mac.octet[0]<<16 | nm_mac.octet[1]<<8 | nm_mac.octet[2];
    nm_bui = nm_mac.octet[3]<<16 | nm_mac.octet[4]<<8 | nm_mac.octet[5];
#else
    nm_oui = nm_mac.ether_addr_octet[0]<<16 |
             nm_mac.ether_addr_octet[1]<<8  |
             nm_mac.ether_addr_octet[2];
    nm_bui = nm_mac.ether_addr_octet[3]<<16 |
             nm_mac.ether_addr_octet[4]<<8  |
             nm_mac.ether_addr_octet[5];
#endif

    if (debug) printf("%s_mac_address->%06x:%06x\n", nm_ifname, nm_oui, nm_bui);

    for (int i = 0; i < nm_rx_qnum; i++) {
        if (_create_nmring(i, NETMAP_HW_RING) == false) {
            for (int j = 0; j < i; j++) {
                if (nm_mem_addrs[j] != NULL) {
                    _remove_hw_ring(j);
                }
            }
            if (nm_fds != NULL) free(nm_fds);
            if (nm_mem_addrs != NULL) free(nm_mem_addrs);
            if (nm_rx_rings != NULL) free(nm_rx_rings);
            if (nm_tx_rings != NULL) free(nm_tx_rings);
            return false;
        } else {
            if (debug) printf("(%s:%02d) open_fd :%d\n", ifname, i, nm_fds[i]);
            if (debug) printf("(%s:%02d) open_mem:%p\n", ifname, i, nm_mem_addrs[i]);
            if (debug) printf("(%s:%02d) rx_ring :%p\n", ifname, i, nm_rx_rings[i]);
            if (debug) printf("(%s:%02d) tx_ring :%p\n", ifname, i, nm_tx_rings[i]);
        }
    }

    if (_create_nmring(nm_rx_qnum, NETMAP_SW_RING) == false) {
        _remove_sw_ring();
    } else {
        if (debug) printf("(%s:sw) open_fd :%d\n", ifname, nm_fd_soft);
        if (debug) printf("(%s:sw) open_mem:%p\n", ifname, nm_mem_addr_soft);
        if (debug) printf("(%s:sw) rx_ring :%p\n", ifname, nm_rx_ring_soft);
        if (debug) printf("(%s:sw) tx_ring :%p\n", ifname, nm_tx_ring_soft);
    }

    //dump_nmr();
    negate_capabilities();

    return true;
}

inline uint32_t
netmap::get_cursor(struct netmap_ring* ring)
{
    return ring->cur;
}

inline struct netmap_slot*
netmap::get_slot(struct netmap_ring* ring)
{
    return &ring->slot[ring->cur];
}

inline void
netmap::next(struct netmap_ring* ring)
{
    ring->head = ring -> cur =
        unlikely(ring->cur + 1 == ring->num_slots) ? 0 : ring->cur + 1;
    //ring->head = ring->cur = nm_ring_next (ring, ring->cur);
    return;
}

inline struct ether_header*
netmap::get_eth(struct netmap_ring* ring)
{
    struct netmap_slot* slot = get_slot(ring);
    return (struct ether_header*)NETMAP_BUF(ring, slot->buf_idx);
}

inline size_t
netmap::get_ethlen(struct netmap_ring* ring)
{
    struct netmap_slot* slot = get_slot(ring);
    return slot->len;
}


inline void
netmap::set_ethlen(struct netmap_ring* ring, size_t size)
{
    struct netmap_slot* slot = get_slot(ring);
    slot->len = size;
}

inline struct ether_addr*
netmap::get_mac()
{
    return &nm_mac;
}

inline int
netmap::get_fd_sw()
{
    return nm_fd_soft;
}

inline char*
netmap::get_mem()
{
    return nm_mem_addr_soft;
}

inline struct netmap_ring*
netmap::get_rx_ring_sw()
{
    return nm_rx_ring_soft;
}

inline struct netmap_ring*
netmap::get_tx_ring_sw()
{
    return nm_tx_ring_soft;
}

inline int
netmap::get_fd(int ringid)
{
    if (ringid > 0 && ringid >= nm_rx_qnum) {
        return 0;
    }
    return nm_fds[ringid];
}

inline char*
netmap::get_mem(int ringid)
{
    if (ringid > 0 && ringid >= nm_rx_qnum) {
        return NULL;
    }
    return nm_mem_addrs[ringid];
}

inline struct netmap_ring*
netmap::get_tx_ring(int ringid)
{
    if (ringid > 0 && ringid >= nm_tx_qnum) {
        return NULL;
    }
    return nm_tx_rings[ringid];
}

inline struct netmap_ring*
netmap::get_rx_ring(int ringid)
{
    if (ringid > 0 && ringid >= nm_rx_qnum) {
        return NULL;
    }
    return nm_rx_rings[ringid];
}

inline uint32_t
netmap::get_avail(struct netmap_ring* ring)
{
    return nm_ring_space(ring);
}

void
netmap::dump_ring(int ringid)
{
    struct netmap_ring* tx = get_tx_ring(ringid);
    if (tx == NULL) {
        MESG("cant get tx ring!");
        return;
    }

    return;
    struct netmap_ring* rx = get_rx_ring(ringid);
    if (rx == NULL) {
        MESG("cant get rx ring!");
        return;
    }
    printf("-- tx ring ----------\n");
    printf("tx_offset       : %ld\n", tx->buf_ofs);
    printf("tx_num_slots    : %d\n", tx->num_slots);
    printf("tx_buf_size     : %d\n", tx->nr_buf_size);
    printf("tx_ringid       : %d\n", tx->ringid);
    printf("tx_dir(tx0/rx1) : %d\n", tx->dir);
    printf("tx_head         : %d\n", tx->head);
    printf("tx_cur          : %d\n", tx->cur);
    printf("tx_flags        : %x\n", tx->flags);
    printf("tx_ts\n");
    printf("tx_ts_tv_sec    : %ld\n", tx->ts.tv_sec);
    printf("tx_ts_tv_usec   : %ld\n", tx->ts.tv_usec);
    printf("tx_sem          : XXX\n");
    printf("tx_slot         : XXX\n");
    printf("-- rx ring ----------\n");
    printf("rx_offset       : %ld\n", rx->buf_ofs);
    printf("rx_num_slots    : %d\n", rx->num_slots);
    printf("rx_buf_size     : %d\n", rx->nr_buf_size);
    printf("rx_ringid       : %d\n", rx->ringid);
    printf("rx_dir(tx0/rx1) : %d\n", rx->dir);
    printf("rx_head         : %d\n", rx->head);
    printf("rx_cur          : %d\n", rx->cur);
    printf("rx_flags        : %x\n", rx->flags);
    printf("rx_ts\n");
    printf("rx_ts_tv_sec    : %ld\n", rx->ts.tv_sec);
    printf("rx_ts_tv_usec   : %ld\n", rx->ts.tv_usec);
    printf("rx_sem          : XXX\n");
    printf("rx_slot         : XXX\n");
    return;
}

void
netmap::dump_nmr()
{
    printf("-----\n");
    printf("nr_name     : %s\n", nm_nmr.nr_name);
    printf("nr_varsion  : %d\n", nm_nmr.nr_version);
    printf("nr_offset   : %d\n", nm_nmr.nr_offset);
    printf("nr_memsize  : %d\n", nm_nmr.nr_memsize);
    printf("nr_tx_slots : %d\n", nm_nmr.nr_tx_slots);
    printf("nr_rx_slots : %d\n", nm_nmr.nr_rx_slots);
    printf("nr_tx_rings : %d\n", nm_nmr.nr_tx_rings);
    printf("nr_rx_rings : %d\n", nm_nmr.nr_rx_rings);
    printf("nr_ringid   : %d\n", nm_nmr.nr_ringid);
    printf("nr_cmd      : %d\n", nm_nmr.nr_cmd);
    printf("nr_arg1     : %d\n", nm_nmr.nr_arg1);
    printf("nr_arg2     : %d\n", nm_nmr.nr_arg2);
    printf("nr_spare2[0]: %x\n", nm_nmr.spare2[0]);
    printf("nr_spare2[1]: %x\n", nm_nmr.spare2[1]);
    printf("nr_spare2[2]: %x\n", nm_nmr.spare2[2]);
    printf("-----\n");
    return;
}

char*
netmap::get_ifname()
{
    return nm_ifname;
}

uint16_t
netmap::get_tx_qnum()
{
    return nm_tx_qnum;
}

uint16_t
netmap::get_rx_qnum()
{
    return nm_rx_qnum;
}

bool
netmap::negate_capabilities()
{
#ifdef __linux__

    return true;

#else

    int fd;
    struct  ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    char* ifname = get_ifname();
    strncpy(ifr.ifr_name, ifname, strlen(ifname));

    if (ioctl(fd, SIOCGIFCAP, (caddr_t)&ifr) < 0) {
        perror("ioctl");
        MESG("failed to get interface status");
        close(fd);
        return false;
    }

    ifr.ifr_curcap = 0x0;
    ifr.ifr_reqcap = 0x0;

    if (ioctl(fd, SIOCSIFCAP, (caddr_t)&ifr) < 0) {
        perror("ioctl");
        MESG("failed to set interface to promisc");
        close(fd);
        return false;
    }

    close(fd);
    return true;

#endif
}

bool
netmap::set_promisc()
{
#ifndef __linux__

    int fd;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    char* ifname = get_ifname();
    strncpy(ifr.ifr_name, ifname, strlen(ifname));
    if (ioctl(fd, SIOCGIFFLAGS, (caddr_t)&ifr) < 0) {
        perror("ioctl");
        MESG("failed to get interface status");
        close(fd);
        return false;
    }

    //printf("%04x%04x\n", ifr.ifr_flagshigh, ifr.ifr_flags & 0xffff);

    int flags = (ifr.ifr_flagshigh << 16) | (ifr.ifr_flags & 0xffff);

    flags |= IFF_PPROMISC;
    //flags = IFF_PPROMISC | IFF_UP;
    ifr.ifr_flags = flags & 0xffff;
    ifr.ifr_flagshigh = flags >> 16;

    //printf("%04x%04x\n", ifr.ifr_flagshigh, ifr.ifr_flags & 0xffff);

    if (ioctl(fd, SIOCSIFFLAGS, (caddr_t)&ifr) < 0) {
        perror("ioctl");
        MESG("failed to set interface to promisc");
        close(fd);
        return false;
    }
    close(fd);

    return true;

#else

    int fd;
    struct ifreq ifr;
    char* ifname = get_ifname();
    memset(&ifr, 0, sizeof(ifr));

    fd = socket (AF_INET, SOCK_DGRAM, 0);
    strncpy (ifr.ifr_name, ifname, strlen(ifname));

    if (ioctl (fd, SIOCGIFFLAGS, &ifr) != 0) {
        perror("ioctl");
        MESG("failed to get interface status");
        close(fd);
        return false;
    }

    ifr.ifr_flags |= IFF_PROMISC;
    //ifr.ifr_flags = IFF_PROMISC | IFF_UP


    if (ioctl (fd, SIOCSIFFLAGS, &ifr) != 0) {
        perror("ioctl");
        MESG("failed to set interface status");
        close(fd);
        return false;
    }

    close(fd);
    return true;

#endif
}

bool
netmap::unset_promisc()
{
#ifndef __linux__

    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    char* ifname = get_ifname();
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, strlen(ifname));
    if (ioctl (fd, SIOCGIFFLAGS, &ifr) != 0) {
        perror("ioctl");
        MESG("failed to get interface status");
        close(fd);
        return false;
    }
    
    ifr.ifr_flags &= ~IFF_PROMISC;
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) != 0) {
        perror("ioctl");
        MESG("failed to set interface to promisc");
        close(fd);
        return false;
    }
    close(fd);
    
    return true;

#else

    int fd;
    struct ifreq ifr;
    char* ifname = get_ifname();
    memset(&ifr, 0, sizeof(ifr));

    fd = socket (AF_INET, SOCK_DGRAM, 0);
    strncpy (ifr.ifr_name, ifname, strlen(ifname));

    if (ioctl (fd, SIOCGIFFLAGS, &ifr) != 0) {
        perror("ioctl");
        MESG("failed to get interface status");
        close(fd);
        return false;
    }

    ifr.ifr_flags &= ~IFF_PROMISC;

    if (ioctl (fd, SIOCSIFFLAGS, &ifr) != 0) {
        perror("ioctl");
        MESG("failed to set interface status");
        close(fd);
        return false;
    }

    close(fd);
    return true;

#endif

    return true;
}

bool netmap::_create_nmring(int ringid, int swhw)
{
    // swhw : soft ring or hard ring
    //NETMAP_HW_RING   0x4000
    //NETMAP_SW_RING   0x2000
    //NETMAP_RING_MASK 0x0fff

    int fd;

    struct nmreq nmr;
    struct netmap_if* nmif;

    fd = open("/dev/netmap", O_RDWR);
    if (fd < 0) {
        perror("open");
        MESG("unable to open /dev/netmap");
        return false;
    }

    //printf("open fd: %d\n", fd);

    memset (&nmr, 0, sizeof(nmr));
    //printf("nm_ifname:%s\n", nm_ifname);
    strncpy (nmr.nr_name, nm_ifname, strlen(nm_ifname));
    nmr.nr_version = nm_version;

    nmr.nr_ringid = swhw | ringid;
    if (swhw == NETMAP_SW_RING) {
        nmr.nr_flags |= NR_REG_SW;
    } else if (swhw == NETMAP_HW_RING) {
        nmr.nr_flags |= NR_REG_ONE_NIC;
    } else if (swhw == 0) {
        nmr.nr_flags |= NR_REG_ALL_NIC;
        //nmr.nr_flags |= NR_REG_ONE_NIC;
    }else {
        nmr.nr_flags = 0;
    }

    // メモリマップを再利用する時
    if (ringid != 0) {
        nmr.nr_arg2 = nmr.nr_arg2 | NM_OPEN_NO_MMAP;
    } 

    if (ioctl(fd, NIOCREGIF, &nmr) < 0) {
        perror("ioctl");
        MESG("unable to register interface %s", nm_ifname);
        close(fd);
        return false;
    }

    char* mem;
    if (ringid != 0) {
        mem = nm_mem_addrs[0];
    } else {
        mem = (char*)mmap(NULL, nmr.nr_memsize,
                PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
        if (mem == MAP_FAILED) {
            perror("mmap");
            MESG("unable to mmap");
            close(fd);
            return false;
        }
    }

    nmif = NETMAP_IF(mem, nmr.nr_offset);

    if (swhw == NETMAP_HW_RING) {
        nm_tx_rings[ringid] = NETMAP_TXRING(nmif, ringid);
        nm_rx_rings[ringid] = NETMAP_RXRING(nmif, ringid);
        nm_mem_addrs[ringid] = mem;
        nm_fds[ringid] = fd;
        return true;
    } else if (swhw == NETMAP_SW_RING) {
        nm_rx_ring_soft = NETMAP_RXRING(nmif, nm_rx_qnum);
        nm_tx_ring_soft = NETMAP_TXRING(nmif, nm_tx_qnum);
        nm_mem_addr_soft = mem;
        nm_fd_soft = fd;
        return true;
    } else if(swhw == 0) {
        // vale
        nm_tx_rings[ringid] = NETMAP_TXRING(nmif, ringid);
        nm_rx_rings[ringid] = NETMAP_RXRING(nmif, ringid);
        nm_mem_addrs[ringid] = mem;
        nm_fds[ringid] = fd;
        return true;
    } else {
        return false;
    }

    return false;
}

bool
netmap::_remove_hw_ring(int ringid)
{
    if (munmap(nm_mem_addrs[ringid], nm_memsize) != 0) {
        perror("munmap");
        return false;
    }
    nm_mem_addrs[ringid] = NULL;

    close(nm_fds[ringid]);
    nm_fds[ringid] = 0;
    nm_rx_rings[ringid] = NULL;
    nm_tx_rings[ringid] = NULL;
    return true;
}

bool
netmap::_remove_sw_ring()
{
    if (nm_mem_addrs == NULL || nm_fd_soft == 0) return true;
    if (munmap(nm_mem_addr_soft, nm_memsize) != 0) {
        perror("munmap");
        return false;
    }
    nm_mem_addr_soft = NULL;
    close(nm_fd_soft);
    nm_fd_soft = 0;
    nm_rx_ring_soft = NULL;
    nm_tx_ring_soft = NULL;

    return true;
}

#endif
