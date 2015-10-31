#pragma once

#include <iostream>
#include <vector>
#include <set>

#include <stdint.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>

#include <net/if.h>
#ifndef __linux__
#include <net/if_dl.h>
#endif

#include <ifaddrs.h>
 
// Get Destination Address
#define ETH_GDA(eth) \
    (struct ether_addr*)((struct eth_header*)eth->ether_dhost)

// Get Source Address
#define ETH_GSA(eth) \
    (struct ether_addr*)((struct eth_header*)eth->ether_shost)

// Set Destination Address
#define ETH_SDA(eth, addr)                                        \
    *((struct ether_addr*)((struct eth_header*)eth->ether_dhost)) \
                                    = *((struct ether_addr*)addr)

// Set Source Address
#define ETH_SSA(eth, addr)                                        \
    *((struct ether_addr*)((struct eth_header*)eth->ether_shost)) \
                                    = *((struct ether_addr*)addr)

void
swap_mac(struct ether_addr* mac1, struct ether_addr* mac2)
{
    struct ether_addr tmp;
    tmp = *mac1;
    *mac1 = *mac2;
    *mac2 = tmp;
    return;
}

void
printmac(const char* prefix, struct ether_addr* mac, const char* suffix)
{
#ifndef __linux__
    //struct ether_addr { 
    //    u_char octet[ETHER_ADDR_LEN];
    //} __packed;

    printf("%s"  , prefix);
    printf("%02x:", mac->octet[0]);
    printf("%02x:" , mac->octet[1]);
    printf("%02x:" , mac->octet[2]);
    printf("%02x:" , mac->octet[3]);
    printf("%02x:" , mac->octet[4]);
    printf("%02x " , mac->octet[5]);
    printf("%s"  , suffix);
    return;
#else
    /*
    // linux
    struct ether_addr {
       u_int8_t ether_addr_octet[ETH_ALEN];
    } __attribute__ ((__packed__));
    */
    printf("%s"    , prefix);
    printf("%02x:" , mac->ether_addr_octet[0]);
    printf("%02x:" , mac->ether_addr_octet[1]);
    printf("%02x:" , mac->ether_addr_octet[2]);
    printf("%02x:" , mac->ether_addr_octet[3]);
    printf("%02x:" , mac->ether_addr_octet[4]);
    printf("%02x " , mac->ether_addr_octet[5]);
    printf("%s"  , suffix);
#endif
}

bool is_exist_if(std::vector<std::string>& v, std::string& s)
{
    std::vector<std::string>::iterator it;
    bool retval = false;
    for (it = v.begin(); it != v.end(); it++) {
        if (*it == s) {
            retval = true;
        }
    }
    return retval;
}

bool get_mac_addr(const char* ifname, struct ether_addr* retval)
{
#ifndef __linux
    {
        struct ifaddrs *ifs;
        struct ifaddrs *ifp;
        struct sockaddr_dl* dl;

        if (getifaddrs(&ifs) != 0) {
            PERROR("getifaddrs");
            MESG("unabe to get interface info for %s", ifname);
            return false;
        }

        for (ifp=ifs; ifp; ifp=ifp->ifa_next) {
            int ifp_family = ifp->ifa_addr->sa_family;

            if (ifp->ifa_addr == NULL) {
                continue;
            } else if (ifp_family != AF_LINK) {
                continue;
            }

            dl = (struct sockaddr_dl*)ifp->ifa_addr;

            if (strncmp(ifname, dl->sdl_data, dl->sdl_nlen) == 0) {
                memcpy(retval, LLADDR(dl), ETHER_ADDR_LEN);
                break;
            }
        }
        freeifaddrs(ifs);
        return true;
    }
#else
    {
        int fd = 0;
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));

        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            return false;
        }
        ifr.ifr_addr.sa_family = AF_INET;
        strncpy(ifr.ifr_name, ifname, strlen(ifname));
        if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
            close(fd);
            return false;
        }
        close(fd);
        memcpy(retval, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
        return true;
    }
#endif
}

std::vector<std::string>
get_ifname_list()
{
    //getmac
    std::vector<std::string> v;

#ifndef __linux__

    std::set<std::string> s;
    struct ifaddrs *ifs;
    struct ifaddrs *ifp;

    if (getifaddrs(&ifs) != 0) {
        PERROR("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifp=ifs; ifp; ifp=ifp->ifa_next) {
        int ifp_family = ifp->ifa_addr->sa_family;

        if (ifp->ifa_addr == NULL) {
            continue;
        } else if (ifp_family != AF_LINK) {
            continue;
        }
        s.insert(std::string(ifp->ifa_name));

    }
    freeifaddrs(ifs);
    std::set<std::string>::iterator it;
    for (it = s.begin(); it != s.end(); it++) {
        v.push_back(*it);
    }

#else

    std::set<std::string> s;
    struct ifaddrs *ifs;
    struct ifaddrs *ifp;

    if (getifaddrs(&ifs) != 0) {
        PERROR("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifp=ifs; ifp; ifp=ifp->ifa_next) {
        if (ifp->ifa_addr == NULL) {
            continue;
        }
        s.insert(std::string(ifp->ifa_name));
    }
    freeifaddrs(ifs);

    std::set<std::string>::iterator it;
    for (it = s.begin(); it != s.end(); it++) {
        std::cout << *it << std::endl;
        v.push_back(*it);
    }

#endif

    return v;
}
