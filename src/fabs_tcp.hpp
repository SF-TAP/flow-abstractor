#ifndef FABS_TCP_HPP
#define FABS_TCP_HPP

#include "fabs_common.hpp"
#include "fabs_bytes.hpp"
#include "fabs_id.hpp"
#include "fabs_appif.hpp"

#include <stdint.h>
#include <time.h>

#include <atomic>
#include <list>
#include <map>

#include <boost/thread.hpp>
#include <boost/thread/condition.hpp>

#define MAX_PACKETS 32
#define NUM_TCPTREE 128

struct fabs_tcp_packet {
    ptr_fabs_bytes m_bytes;
    uint32_t m_seq;
    uint32_t m_nxt_seq;
    uint8_t  m_flags;
    int      m_data_pos;
    int      m_data_len;
    int      m_read_pos;
};

struct fabs_tcp_uniflow {
    std::map<uint32_t, fabs_tcp_packet> m_packets;
    time_t   m_time;
    uint32_t m_min_seq;
    bool     m_is_gaveup;
    bool     m_is_syn;
    bool     m_is_fin;
    bool     m_is_rm;
    bool     m_is_compromised;

    fabs_tcp_uniflow() : m_time(0), m_min_seq(0), m_is_gaveup(false),
                         m_is_syn(false), m_is_fin(false), m_is_rm(false), m_is_compromised(false) { }
};

struct fabs_tcp_flow {
    fabs_tcp_uniflow m_flow1, m_flow2;
};

typedef std::unique_ptr<fabs_tcp_flow> ptr_fabs_tcp_flow;

class fabs_tcp {
public:
    fabs_tcp(int idx);
    virtual ~fabs_tcp();

    void input_tcp(fabs_id &id, fabs_direction dir, ptr_fabs_bytes buf);
    void garbage_collector();
    void set_timeout(time_t t) { m_timeout = t; }
    void print_stat();
    void set_appif(ptr_fabs_appif appif) { m_appif = appif; }
    int  get_active_num();
    uint64_t get_total_num() { return m_total_session; }
    void stop() { m_is_del = true; }

private:
    std::map<fabs_id, ptr_fabs_tcp_flow> m_flow[NUM_TCPTREE];
    ptr_fabs_appif                       m_appif;

    time_t m_timeout;

    bool get_packet(int idx, const fabs_id &id, fabs_direction dir,
                    fabs_tcp_packet &packet);
    bool recv_fin(int idx, const fabs_id &id, fabs_direction dir);
    void rm_flow(int idx, const fabs_id &id, fabs_direction dir);
    void input_tcp_event(int idx, fabs_id_dir tcp_event);
    void garbage_collector2(int idx, time_t now);

    uint64_t m_total_session;

    std::mutex    m_mutex_flow[NUM_TCPTREE];
    std::mutex    m_mutex_gc;
    std::condition_variable m_condition_gc;
    volatile bool m_is_del;
    int m_idx;

    std::thread   m_thread_gc;
};

#endif // FABS_TCP_HPP
