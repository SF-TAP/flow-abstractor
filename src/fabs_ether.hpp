#ifndef FABS_ETHER_HPP
#define FABS_ETHER_HPP

#include "fabs_common.hpp"
#include "fabs_appif.hpp"
#include "fabs_callback.hpp"
#include "fabs_dlcap.hpp"
#include "fabs_bytes.hpp"
#include "fabs_fragment.hpp"
#include "fabs_cb.hpp"

#include <pcap/pcap.h>

#include <stdint.h>

#include <string>
#include <list>
#include <atomic>
#include <thread>
#include <condition_variable>

#include <boost/shared_array.hpp>

class fabs_fragment;

class fabs_ether {
public:
    fabs_ether(fabs_conf &conf, const fabs_dlcap *dlcap);
    virtual ~fabs_ether();

    void ether_input(const uint8_t *bytes, int len, const timeval &tm, bool is_pcap);

    void consume(int idx);
    void consume_fragment();
    void timer();
    void stop() { m_is_break = true; m_callback.stop(); }

    void produce(int idx, ptr_fabs_bytes buf);
    inline void produce(int idx, const char *buf, int len, const timeval &tm);

private:
    std::mutex m_mutex_init;
    std::condition_variable m_condition_init;

    volatile bool m_is_break;
    volatile uint64_t m_num_dropped;

    inline const uint8_t *get_ip_hdr(const uint8_t *bytes, uint32_t len,
                                     uint8_t &proto, uint16_t &vlanid);

    const fabs_dlcap *m_dlcap;
    ptr_fabs_appif m_appif;

    fabs_callback m_callback;
    fabs_fragment m_fragment;

    fabs_cb<ptr_fabs_bytes> *m_queue;
    fabs_cb<ptr_fabs_bytes>  m_queue_frag;

    bool *m_is_consuming;
    bool  m_is_consuming_frag;

    uint64_t m_num_pcap;

    std::mutex *m_mutex;
    std::mutex  m_mutex_frag;
    std::condition_variable *m_condition;
    std::condition_variable  m_condition_frag;
    std::thread **m_thread_consume;
    std::thread m_thread_consume_frag;
    std::thread m_thread_timer;
};

#endif // FABS_ETHER_HPP
