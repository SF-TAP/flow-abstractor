#ifndef FABS_FRAGMENT_HPP
#define FABS_FRAGMENT_HPP

#include "fabs_common.hpp"
#include "fabs_id.hpp"
#include "fabs_appif.hpp"
#include "fabs_bytes.hpp"

#include <time.h>

#include <netinet/ip.h>

#include <map>
#include <thread>
#include <condition_variable>

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/member.hpp>

class fabs_ether;

class fabs_fragment {
public:
    struct qtype {
        ptr_fabs_bytes m_buf;
        uint16_t       m_vlanid;

        qtype() { }
        qtype(ptr_fabs_bytes buf, uint16_t vlanid) : m_buf(std::move(buf)), m_vlanid(vlanid) { }

        fabs_fragment::qtype& operator=(fabs_fragment::qtype &rhs) {
            m_buf    = std::move(rhs.m_buf);
            m_vlanid = rhs.m_vlanid;
            return *this;
        }
    };

    fabs_fragment(fabs_ether &fether, ptr_fabs_appif appif);
    virtual ~fabs_fragment();

    bool input_ip(qtype &buf);
    void gc_timer();

private:
    struct fragments {
        std::shared_ptr<std::map<int, ptr_fabs_bytes> > m_bytes;
        mutable bool    m_is_last;
        mutable time_t  m_time;
        mutable int     m_size;
        time_t   m_init;
        uint32_t m_ip_src;
        uint32_t m_ip_dst;
        uint16_t m_id;
        uint16_t m_vlanid;

        fragments ();
        fragments(const ip *iph4, ptr_fabs_bytes bytes, uint16_t vlanid);
        virtual ~fragments();

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

    bool defragment(const fragments &frgms, ptr_fabs_bytes &buf);

    frag_cont m_fragments;

    std::mutex  m_mutex;
    std::mutex  m_mutex_gc;
    std::condition_variable m_condition_gc;
    bool        m_is_del;

    std::thread m_thread_gc;

    fabs_ether    &m_ether;
    ptr_fabs_appif m_appif;
};

#endif // FABS_FRAGMENT_HPP
