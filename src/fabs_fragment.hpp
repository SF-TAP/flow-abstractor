#ifndef FABS_FRAGMENT_HPP
#define FABS_FRAGMENT_HPP

#include "fabs_common.hpp"
#include "fabs_id.hpp"
#include "fabs_bytes.hpp"

#include <time.h>

#include <netinet/ip.h>

#include <map>

#include <boost/thread.hpp>
#include <boost/thread/condition.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/member.hpp>

class fabs_pcap;

class fabs_fragment {
public:
    fabs_fragment(fabs_pcap &fpcap);
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

        fragments ();
        fragments(const ip *iph4, fabs_bytes bytes);

        bool operator< (const fragments &rhs) const;
        bool operator== (const fragments &rhs) const;
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

    fabs_pcap       &m_pcap;
};

#endif // FABS_FRAGMENT_HPP