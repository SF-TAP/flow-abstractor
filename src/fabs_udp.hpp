#ifndef FABS_UDP_HPP
#define FABS_UDP_HPP

#include "fabs_bytes.hpp"
#include "fabs_id.hpp"
#include "fabs_appif.hpp"

#include <boost/thread.hpp>
#include <boost/thread/condition.hpp>

#include <queue>

struct fabs_udp_packet {
    fabs_id_dir m_id_dir;
    fabs_bytes  m_bytes;
};

class fabs_udp {
public:
    fabs_udp(ptr_fabs_appif appif);
    virtual ~fabs_udp();

    void input_udp(fabs_id &id, fabs_direction dir, char *buf, int len,
                   char *l4hdr);
    void run();

private:
    std::queue<fabs_udp_packet> m_queue;

    bool             m_is_del;
    ptr_fabs_appif   m_appif;

    boost::mutex     m_mutex;
    boost::condition m_condition;
    boost::thread    m_thread;

    void input_udp4(fabs_id &id, fabs_direction dir, char *buf, int len);

};

#endif // FABS_UDP_HPP
