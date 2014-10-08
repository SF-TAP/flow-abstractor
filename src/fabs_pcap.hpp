#ifndef FABS_PCAP_HPP
#define FABS_PCAP_HPP

#include "fabs_common.hpp"
#include "fabs_callback.hpp"
#include "fabs_bytes.hpp"
#include "fabs_fragment.hpp"

#include <pcap/pcap.h>

#include <stdint.h>

#include <string>
#include <list>
#include <atomic>

#include <boost/shared_array.hpp>
#include <boost/thread.hpp>
#include <boost/thread/condition.hpp>

class fabs_fragment;

class spinlock {
private:
    typedef enum {Locked, Unlocked} LockState;
    std::atomic<LockState> state_;

public:
    spinlock() : state_(Unlocked) {}

    void lock()
    {
        while (state_.exchange(Locked, std::memory_order_acquire) == Locked) {
            /* busy-wait */
        }
    }

    void unlock()
    {
        state_.store(Unlocked, std::memory_order_release);
    }
};

class fabs_pcap {
public:
    fabs_pcap(std::string conf);

    virtual ~fabs_pcap() {
        if (m_handle != NULL)
            pcap_close(m_handle);
    }

    void set_dev(std::string dev);
    void set_bufsize(int size);

    void callback(const struct pcap_pkthdr *h, const uint8_t *bytes);
    
    void consume();
    void consume_fragment();
    void timer();

    void run();
    void stop() { m_is_break = true; }

    void produce(fabs_bytes &buf);
    inline void produce(const char *buf, int len);

private:
    std::string m_dev;
    pcap_t *m_handle;
    int     m_dl_type;
    bool    m_is_break;
    int     m_bufsize;

    inline const uint8_t *get_ip_hdr(const uint8_t *bytes, uint32_t len,
                                     uint8_t &proto);

    fabs_callback m_callback;
    fabs_fragment m_fragment;

    struct qitem {
        boost::shared_array<fabs_bytes> m_queue;
        int m_num;
    };

    qitem m_qitem;
    qitem m_qitem2;

    std::list<qitem> m_queue;
    std::list<fabs_bytes> m_queue_frag;
    boost::mutex  m_mutex;
    boost::mutex  m_mutex_frag;
    boost::condition m_condition;
    boost::condition m_condition_frag;
    boost::thread m_thread_consume;
    boost::thread m_thread_consume_frag;
    boost::thread m_thread_timer;
    spinlock m_spinlock;
};

extern boost::shared_ptr<fabs_pcap> pcap_inst;
extern bool pcap_is_running;

void stop_pcap();

void run_pcap(std::string dev, std::string conf, int bufsize);

#endif // FABS_PCAP_HPP
