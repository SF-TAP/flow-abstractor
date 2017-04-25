#ifndef FABS_ICMP_HPP
#define FABS_ICMP_HPP

#include "fabs_common.hpp"
#include "fabs_bytes.hpp"
#include "fabs_id.hpp"
#include "fabs_appif.hpp"

class fabs_icmp {
public:
    fabs_icmp() {};
    virtual ~fabs_icmp() {};

    void input_icmp(fabs_id &id, fabs_direction dir, ptr_fabs_bytes buf)
    {
        // TODO: checksum
        fabs_id_dir id_dir;

        id_dir.m_id  = id;
        id_dir.m_dir = dir;

        m_appif->in_event(STREAM_DATA, id_dir, std::move(buf));
    }

    void set_appif(ptr_fabs_appif appif) { m_appif = appif; }

private:
    ptr_fabs_appif   m_appif;

};

#endif // FABS_ICMP_HPP