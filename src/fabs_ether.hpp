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

#include <boost/shared_array.hpp>
#include <boost/thread.hpp>
#include <boost/thread/condition.hpp>

class fabs_fragment;

class fabs_ether {
public:
    fabs_ether(std::string conf, const fabs_dlcap *dlcap);
    virtual ~fabs_ether();

    void ether_input(const uint8_t *bytes, int len);

    void consume(int idx);
    void consume_fragment();
    void timer();

    void produce(int idx, fabs_bytes *buf);
    inline void produce(int idx, const char *buf, int len);

private:
    boost::mutex     m_mutex_init;
    boost::condition m_condition_init;

    bool    m_is_break;

    inline const uint8_t *get_ip_hdr(const uint8_t *bytes, uint32_t len,
                                     uint8_t &proto);

    const fabs_dlcap *m_dlcap;
    ptr_fabs_appif m_appif;

    fabs_callback m_callback;
    fabs_fragment m_fragment;

    fabs_cb<fabs_bytes*> *m_queue;
    fabs_cb<fabs_bytes*>  m_queue_frag;

    bool *m_is_consuming;
    bool  m_is_consuming_frag;

    boost::mutex  *m_mutex;
    boost::mutex  m_mutex_frag;
    boost::condition *m_condition;
    boost::condition m_condition_frag;
    boost::thread **m_thread_consume;
    boost::thread m_thread_consume_frag;
    boost::thread m_thread_timer;
};

#endif // FABS_ETHER_HPP
