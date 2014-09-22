#include "fabs_fragment.hpp"

#include <boost/bind.hpp>

#define FRAGMENT_GC_TIMER 30

fabs_fragment::fabs_fragment(fabs_callback &callback) :
    m_is_del(false),
    m_thread_gc(boost::bind(&fabs_fragment::gc_timer, this)),
    m_callback(callback)
{

}

fabs_fragment::~fabs_fragment()
{
    m_is_del = true;

    {
        boost::mutex::scoped_lock lock(m_mutex_gc);
        m_condition_gc.notify_one();
    }

    m_thread_gc.join();
}

void
fabs_fragment::gc_timer()
{
    for (;;) {
        boost::mutex::scoped_lock lock_gc(m_mutex_gc);
        m_condition_gc.timed_wait(lock_gc, boost::posix_time::milliseconds(FRAGMENT_GC_TIMER * 1000));

        if (m_is_del) {
            return;
        }

        boost::mutex::scoped_lock lock(m_mutex);

        auto &seq = m_fragments.get<1>();
        time_t t  = time(NULL);

        for (auto it = seq.begin(); it != seq.end(); ) {
            if (t - it->m_init > FRAGMENT_GC_TIMER) {
                it = seq.erase(it);
                continue;
            } else {
                break;
            }
        }
    }
}

// true:  fragmented
// false: not fragmented
bool
fabs_fragment::input_ip(fabs_bytes buf)
{
    ip *iph4 = (ip*)buf.get_head();

    if (iph4->ip_v != 4)
        return false;

    if (ntohs(iph4->ip_len) > buf.get_len())
        return false;

    int offset = ntohs(iph4->ip_off) & IP_OFFMASK;
    int mflag  = ntohs(iph4->ip_off) & IP_MF;

    if (mflag || offset) {
        fragments frag;

        frag.m_ip_src = ntohl(iph4->ip_src.s_addr);
        frag.m_ip_dst = ntohl(iph4->ip_dst.s_addr);
        frag.m_id     = ntohs(iph4->ip_id);

        boost::mutex::scoped_lock lock(m_mutex);
        auto it = m_fragments.find(frag);
        if (it == m_fragments.end()) {
            m_fragments.insert(fragments(iph4, buf));
        } else {
            auto it2 = it->m_bytes->find(offset);
            if (it2 == it->m_bytes->end()) {
                (*it->m_bytes)[offset] = buf;

                if (! mflag) {
                    it->m_is_last = true;
                    it->m_size = offset * 8 + ntohs(iph4->ip_len) - iph4->ip_hl * 4;
                    if (it->m_size < 0) {
                        // error
                        m_fragments.erase(it);
                    }
                } else if (offset == 0) {
                    it->m_hlen = iph4->ip_hl * 4;
                }
            }

            if (it->m_is_last) {
                fabs_bytes buf;
                if (defragment(*it, buf)) {
                    // packets are defragmented
                    m_fragments.erase(it);
                    lock.unlock();

                    m_callback(buf);
                }
            }
        }

        return true;
    }

    return false;
}

bool
fabs_fragment::defragment(const fragments &frg, fabs_bytes &buf)
{
    int next = 0;

    assert(frg.m_bytes->size() == 0);

    buf.alloc(frg.m_size);

    memcpy(buf.get_head(), frg.m_bytes->begin()->second.get_head(), frg.m_hlen);

    for (auto it = frg.m_bytes->begin(); it != frg.m_bytes->end(); ++it) {
        int offset = it->first;
        ip *iph4   = (ip*)it->second.get_head();
        int len    = ntohs(iph4->ip_len) - iph4->ip_hl * 4;
        int pos    = offset * 8;

        if (next < pos) {
            // couldn't defragment
            return false;
        } else if (next > pos ||
                   len + pos + frg.m_hlen > frg.m_size) {
            // error
            m_fragments.erase(frg);
            return false;
        }

        memcpy(buf.get_head() + pos + frg.m_hlen,
               it->second.get_head() + iph4->ip_hl * 4, len);

        next += len;
    }

    ip *iph = (ip*)buf.get_head();

    iph->ip_id  = 0;
    iph->ip_off = 0;

    return true;
}
