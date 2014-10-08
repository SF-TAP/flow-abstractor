#ifndef FABS_PCAP_HPP
#define FABS_PCAP_HPP

#include "fabs_common.hpp"
#include "fabs_appif.hpp"
#include "fabs_callback.hpp"
#include "fabs_bytes.hpp"
#include "fabs_fragment.hpp"

#include <pcap/pcap.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>

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

    virtual ~fabs_pcap();

    void set_dev(std::string dev);
    void set_bufsize(int size);

    void callback(const struct pcap_pkthdr *h, const uint8_t *bytes);
    
    void consume(int idx);
    void consume_fragment();
    void timer();

    void run();
    void stop() { m_is_break = true; }

    void produce(int idx, fabs_bytes &buf);
    inline void produce(int idx, const char *buf, int len);

    static uint32_t get_ip_hash(const ip *iph) {
        return ntohl(iph->ip_src.s_addr) ^ ntohl(iph->ip_dst.s_addr);
    }

    static uint32_t get_ip6_hash(const ip6_hdr *iph) {
        const uint32_t *p1, *p2;

        p1 = (const uint32_t*)&iph->ip6_src;
        p2 = (const uint32_t*)&iph->ip6_dst;

        return p1[0] ^ p1[1] ^ p1[2] ^ p1[3] ^ p2[0] ^ p2[1] ^ p2[2] ^ p2[3];
    }

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

    qitem m_qitem[NUM_TCP];

    ptr_fabs_appif m_appif;

    std::list<qitem> m_queue[NUM_TCP];
    std::list<fabs_bytes> m_queue_frag;
    boost::mutex  m_mutex[NUM_TCP];
    boost::mutex  m_mutex_frag;
    boost::mutex  m_mutex_timer;
    boost::condition m_condition[NUM_TCP];
    boost::condition m_condition_frag;
    boost::condition m_condition_timer;
    boost::thread* m_thread_consume[NUM_TCP];
    boost::thread m_thread_consume_frag;
    boost::thread m_thread_timer;
    spinlock m_spinlock[NUM_TCP];
};

extern boost::shared_ptr<fabs_pcap> pcap_inst;
extern bool pcap_is_running;

void stop_pcap();

void run_pcap(std::string dev, std::string conf, int bufsize);

#endif // FABS_PCAP_HPP
