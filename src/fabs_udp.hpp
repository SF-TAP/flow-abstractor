#ifndef FABS_UDP_HPP
#define FABS_UDP_HPP

#include "fabs_common.hpp"
#include "fabs_bytes.hpp"
#include "fabs_id.hpp"
#include "fabs_appif.hpp"

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

class fabs_udp {
public:
    fabs_udp() {};
    virtual ~fabs_udp() {};

    void input_udp(fabs_id &id, fabs_direction dir, ptr_fabs_bytes buf)
    {
        // TODO: checksum
        fabs_id_dir id_dir;

        id_dir.m_id  = id;
        id_dir.m_dir = dir;

        if (buf->skip(sizeof(udphdr))) {
            m_appif->in_event(STREAM_DATA, id_dir, std::move(buf));
        }
    }

    void set_appif(ptr_fabs_appif appif) { m_appif = appif; }

private:
    ptr_fabs_appif   m_appif;

};

#endif // FABS_UDP_HPP
