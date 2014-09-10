#include "fabs_fragment.hpp"


fabs_fragment::fabs_fragment()
{

}

fabs_fragment::~fabs_fragment()
{

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
        frag.m_id = ntohs(iph4->ip_id);

        auto it = m_fragments.find(frag);
        if (it == m_fragments.end()) {
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
                if (defragment(*it)) {
                    m_fragments.erase(it);
                }
            }
        } else {
            m_fragments.insert(fragments(iph4, buf));
        }

        return true;
    }

    return false;
}

bool
fabs_fragment::defragment(const fragments &frgms)
{
    int next = 0;
    fabs_bytes buf;

    buf.alloc(frgms.m_size);

    for (auto it = frgms.m_bytes->begin(); it != frgms.m_bytes->end(); ++it) {
        int offset = it->first;
        ip *iph4 = (ip*)it->second.get_head();

        int pos = offset * 8;
        if (next < pos) {
            // couldn't defragment
            return false;
        } else if (next > pos) {
            // error
            m_fragments.erase(frgms);
            return false;
        }
    }

    return true;
}
