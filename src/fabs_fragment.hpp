#ifndef FABS_FRAGMENT_HPP
#define FABS_FRAGMENT_HPP

#include "fabs_common.hpp"
#include "fabs_id.hpp"
#include "fabs_bytes.hpp"
#include "fabs_callback.hpp"

#include <time.h>

#include <netinet/ip.h>

#include <map>

#include <boost/thread.hpp>
#include <boost/thread/condition.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/member.hpp>

class fabs_fragment {
public:
    fabs_fragment(fabs_callback &callback);
    virtual ~fabs_fragment();

    bool input_ip(fabs_bytes buf);
    void gc_timer();

private:
    struct fragments {
        boost::shared_ptr<std::map<int, fabs_bytes> > m_bytes;
        mutable bool    m_is_last;
        mutable time_t  m_time;
        mutable int     m_size;
        time_t   m_init;
        uint32_t m_ip_src;
        uint32_t m_ip_dst;
        uint16_t m_id;

        fragments () { }

        fragments(const ip *iph4, fabs_bytes bytes)
            : m_bytes(new std::map<int, fabs_bytes>),
              m_is_last(false)
        {
            m_time = m_init = time(NULL);

            int offset = ntohs(iph4->ip_off) & IP_OFFMASK;
            int mflag  = ntohs(iph4->ip_off) & IP_MF;

            (*m_bytes)[offset] = bytes;

            if (! mflag) {
                m_is_last = true;
            }

            m_ip_src = ntohl(iph4->ip_src.s_addr);
            m_ip_dst = ntohl(iph4->ip_dst.s_addr);
            m_id     = ntohs(iph4->ip_id);
        }

        bool operator< (const fragments &rhs) const {
            if (m_ip_src == rhs.m_ip_src) {
                if (m_ip_dst == rhs.m_ip_dst) {
                    return m_id < rhs.m_id;
                } else {
                    return m_ip_dst < rhs.m_ip_dst;
                }
            } else {
                return m_ip_src < rhs.m_ip_src;
            }
        }

        bool operator== (const fragments &rhs) const {
            return (m_ip_src == rhs.m_ip_src &&
                    m_ip_dst == rhs.m_ip_dst &&
                    m_id == rhs.m_id);
        }
    };

    typedef boost::multi_index::multi_index_container<
        fragments,
        boost::multi_index::indexed_by<
            boost::multi_index::ordered_unique<
                boost::multi_index::identity<fragments> >,
            boost::multi_index::sequenced<>
            > > frag_cont;

    bool defragment(const fragments &frgms, fabs_bytes &buf);

    frag_cont m_fragments;

    boost::mutex     m_mutex;
    boost::mutex     m_mutex_gc;
    boost::condition m_condition_gc;
    bool             m_is_del;

    boost::thread    m_thread_gc;

    fabs_callback   &m_callback;
};

#endif // FABS_FRAGMENT_HPP
