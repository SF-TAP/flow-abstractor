#ifndef FABS_UDP_HPP
#define FABS_UDP_HPP

#include "fabs_common.hpp"
#include "fabs_bytes.hpp"
#include "fabs_id.hpp"
#include "fabs_appif.hpp"

#include <boost/thread.hpp>
#include <boost/thread/condition.hpp>

#include <queue>


class fabs_udp {
public:
    fabs_udp();
    virtual ~fabs_udp();

    void input_udp(fabs_id &id, fabs_direction dir, fabs_bytes *buf);
    void set_appif(ptr_fabs_appif appif) { m_appif = appif; }

private:
    ptr_fabs_appif   m_appif;

};

#endif // FABS_UDP_HPP
