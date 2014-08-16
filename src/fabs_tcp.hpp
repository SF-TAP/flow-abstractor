#ifndef FABS_TCP_HPP
#define FABS_TCP_HPP

#include "fabs_bytes.hpp"
#include "fabs_id.hpp"
#include "fabs_appif.hpp"

#include <stdint.h>
#include <time.h>

#include <list>
#include <map>

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/thread.hpp>
#include <boost/thread/condition.hpp>

#define MAX_PACKETS 32

struct fabs_tcp_packet {
    fabs_bytes m_bytes;
    uint32_t   m_seq;
    uint32_t   m_nxt_seq;
    uint8_t    m_flags;
    int        m_data_pos;
    int        m_data_len;
    int        m_read_pos;
};

struct fabs_tcp_uniflow {
    std::map<uint32_t, fabs_tcp_packet> m_packets;
    time_t   m_time;
    uint32_t m_min_seq;
    bool     m_is_gaveup;
    bool     m_is_syn;
    bool     m_is_fin;
    bool     m_is_rm;

    fabs_tcp_uniflow() : m_min_seq(0), m_is_gaveup(false), m_is_syn(false),
                         m_is_fin(false), m_is_rm(false) { }
};

struct fabs_tcp_flow {
    fabs_tcp_uniflow m_flow1, m_flow2;
};

typedef boost::shared_ptr<fabs_tcp_flow> ptr_fabs_tcp_flow;

typedef boost::multi_index::multi_index_container<
    fabs_id_dir,
    boost::multi_index::indexed_by<
        boost::multi_index::ordered_unique<boost::multi_index::identity<fabs_id_dir> >,
        boost::multi_index::sequenced<>
    >
> fabs_id_dir_cont;

class fabs_tcp {
public:
    fabs_tcp(ptr_fabs_appif appif);
    virtual ~fabs_tcp();

    void input_tcp(fabs_id &id, fabs_direction dir, fabs_bytes buf);
    void garbage_collector();
    void set_timeout(time_t t) { m_timeout = t; }

private:
    std::map<fabs_id, ptr_fabs_tcp_flow> m_flow;
    fabs_id_dir_cont                     m_events;
    ptr_fabs_appif                       m_appif;

    time_t m_timeout;

    bool get_packet(const fabs_id &id, fabs_direction dir,
                    fabs_tcp_packet &packet);
    bool recv_fin(const fabs_id &id, fabs_direction dir);
    void rm_flow(const fabs_id &id, fabs_direction dir);
    int  num_packets(const fabs_id &id, fabs_direction dir);
    void input_tcp_event(fabs_id_dir tcp_event);

    boost::mutex     m_mutex;
    boost::mutex     m_mutex_gc;
    boost::condition m_condition_gc;
    bool             m_is_del;

    boost::thread    m_thread_gc;
    boost::thread    m_thread_fire;
};

#endif // FABS_TCP_HPP
