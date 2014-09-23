#include "fabs_tcp.hpp"

#include <unistd.h>

#include <sys/socket.h>

#ifdef __linux__
    #define __FAVOR_BSD
#endif

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <arpa/inet.h>

#include <boost/bind.hpp>

using namespace std;

#define TCP_GC_TIMER 30

#define DEBUG

fabs_tcp::fabs_tcp(ptr_fabs_appif appif) :
    m_appif(appif),
    m_timeout(600),
    m_is_del(false),
    m_thread_gc(boost::bind(&fabs_tcp::garbage_collector, this))
{

}

fabs_tcp::~fabs_tcp()
{
    m_is_del = true;

    {
        boost::mutex::scoped_lock lock(m_mutex_gc);
        m_condition_gc.notify_one();
    }
    m_thread_gc.join();
}

void
fabs_tcp::garbage_collector()
{
    for (;;) {

        boost::mutex::scoped_lock lock_gc(m_mutex_gc);
        m_condition_gc.timed_wait(lock_gc, boost::posix_time::milliseconds(TCP_GC_TIMER * 1000));

        if (m_is_del) {
            return;
        }

        list<fabs_id_dir> garbages;

        {
            boost::mutex::scoped_lock lock(m_mutex);

            std::map<fabs_id, ptr_fabs_tcp_flow>::iterator it;

            for (it = m_flow.begin(); it != m_flow.end(); ++it) {
                // close half opened connections
                if (((it->second->m_flow1.m_is_syn &&
                      ! it->second->m_flow2.m_is_syn) ||
                     (it->second->m_flow1.m_is_fin &&
                       ! it->second->m_flow2.m_is_fin)) &&
                    time(NULL) - it->second->m_flow1.m_time > TCP_GC_TIMER) {

                    it->second->m_flow1.m_is_rm = true;

                    fabs_id_dir id_dir;

                    id_dir.m_id  = it->first;
                    id_dir.m_dir = FROM_ADDR1;

                    garbages.push_back(id_dir);
                } else if (((! it->second->m_flow1.m_is_syn &&
                             it->second->m_flow2.m_is_syn) ||
                            (! it->second->m_flow1.m_is_fin &&
                            it->second->m_flow2.m_is_fin)) &&
                           time(NULL) - it->second->m_flow2.m_time > TCP_GC_TIMER) {

                    it->second->m_flow2.m_is_rm = true;

                    fabs_id_dir id_dir;

                    id_dir.m_id  = it->first;
                    id_dir.m_dir = FROM_ADDR2;

                    garbages.push_back(id_dir);
                }

                // close long-lived but do-nothing connections
                time_t now = time(NULL);
                if (now - it->second->m_flow1.m_time > m_timeout &&
                    now - it->second->m_flow2.m_time > m_timeout) {

                    it->second->m_flow1.m_is_rm = true;

                    fabs_id_dir id_dir;

                    id_dir.m_id  = it->first;
                    id_dir.m_dir = FROM_ADDR1;

                    garbages.push_back(id_dir);
                }

                // close compromised connections
                if (it->second->m_flow1.m_packets.size() > 4096 ||
                    it->second->m_flow2.m_packets.size() > 4096) {

                    it->second->m_flow1.m_is_rm = true;

                    fabs_id_dir id_dir;

                    id_dir.m_id  = it->first;
                    id_dir.m_dir = FROM_ADDR1;

                    garbages.push_back(id_dir);
                }
            }
        }

        for (auto it2 = garbages.begin(); it2 != garbages.end(); it2++) {
            input_tcp_event(*it2);
        }
    }
}

void
fabs_tcp::input_tcp_event(fabs_id_dir tcp_event)
{
#ifdef DEBUG
    char addr1[32], addr2[32];
#endif // DEBUG

    {
        boost::mutex::scoped_lock lock(m_mutex);

#ifdef DEBUG
        inet_ntop(PF_INET, &tcp_event.m_id.m_addr1->l3_addr.b32,
                  addr1, sizeof(addr1));
        inet_ntop(PF_INET, &tcp_event.m_id.m_addr2->l3_addr.b32,
                  addr2, sizeof(addr2));
#endif // DEBUG


        // garbage collection
        std::map<fabs_id, ptr_fabs_tcp_flow>::iterator it_flow;

        it_flow = m_flow.find(tcp_event.m_id);

        if (it_flow == m_flow.end()) {
            return;
        }

        fabs_bytes bytes;
        bool       is_rm = false;

        if ((tcp_event.m_dir == FROM_ADDR1 &&
             it_flow->second->m_flow1.m_is_rm) ||
            (tcp_event.m_dir == FROM_ADDR2 &&
             it_flow->second->m_flow2.m_is_rm)) {
            m_appif->in_event(STREAM_TIMEOUT, tcp_event, bytes);
            is_rm = true;
        }

        if (is_rm) {
            lock.unlock();
            rm_flow(tcp_event.m_id, tcp_event.m_dir);

            fabs_id_dir id_dir = tcp_event;
            id_dir.m_dir = FROM_NONE;
            m_appif->in_event(STREAM_DESTROYED, id_dir, bytes);

            return;
        }
    }

    fabs_tcp_packet packet;

    while (get_packet(tcp_event.m_id, tcp_event.m_dir, packet)) {
        if (packet.m_flags & TH_SYN) {
#ifdef DEBUG
            cout << "connection opened: addr1 = "
                 << addr1 << ":"
                 << ntohs(tcp_event.m_id.m_addr1->l4_port)
                 << ", addr2 = "
                 << addr2 << ":"
                 << ntohs(tcp_event.m_id.m_addr2->l4_port)
                 << ", from = " << tcp_event.m_dir
                 << endl;
#endif // DEBUG

            fabs_bytes bytes;
            m_appif->in_event(STREAM_SYN, tcp_event, bytes);
        } else if (packet.m_flags & TH_FIN) {
            if (packet.m_data_len > 0) {
                if (packet.m_bytes.skip(packet.m_data_pos)) {
                    m_appif->in_event(STREAM_DATA, tcp_event,
                                      packet.m_bytes);
                }
            }

            fabs_bytes bytes;

            m_appif->in_event(STREAM_FIN, tcp_event, bytes);

#ifdef DEBUG
            cout << "connection closed: addr1 = "
                 << addr1 << ":"
                 << ntohs(tcp_event.m_id.m_addr1->l4_port)
                 << ", addr2 = "
                 << addr2 << ":"
                 << ntohs(tcp_event.m_id.m_addr2->l4_port)
                 << ", from = " << tcp_event.m_dir
                 << endl;
#endif // DEBUG

            if (recv_fin(tcp_event.m_id, tcp_event.m_dir)) {
                fabs_id_dir id_dir = tcp_event;
                id_dir.m_dir = FROM_NONE;
                m_appif->in_event(STREAM_DESTROYED, id_dir, bytes);
            }
        } else if (packet.m_flags & TH_RST) {
#ifdef DEBUG
            cout << "connection reset: addr1 = "
                 << addr1 << ":"
                 << ntohs(tcp_event.m_id.m_addr1->l4_port)
                 << ", addr2 = "
                 << addr2 << ":"
                 << ntohs(tcp_event.m_id.m_addr2->l4_port)
                 << endl;
#endif // DEBUG

            fabs_bytes bytes;

            m_appif->in_event(STREAM_RST, tcp_event, bytes);

            rm_flow(tcp_event.m_id, tcp_event.m_dir);

            fabs_id_dir id_dir = tcp_event;
            id_dir.m_dir = FROM_NONE;
            m_appif->in_event(STREAM_DESTROYED, id_dir, bytes);
        } else {
#ifdef DEBUG
            cout << "data in: addr1 = "
                 << addr1 << ":"
                 << ntohs(tcp_event.m_id.m_addr1->l4_port)
                 << ", addr2 = "
                 << addr2 << ":"
                 << ntohs(tcp_event.m_id.m_addr2->l4_port)
                 << ", from = " << tcp_event.m_dir
                 << endl;
#endif // DEBUG

            if (packet.m_bytes.skip(packet.m_data_pos)) {
                m_appif->in_event(STREAM_DATA, tcp_event,
                                  packet.m_bytes);
            }
        }
    }
}

int
fabs_tcp::num_packets(const fabs_id &id, fabs_direction dir)
{
    boost::mutex::scoped_lock lock(m_mutex);

    map<fabs_id, ptr_fabs_tcp_flow>::iterator it_flow;
    fabs_tcp_uniflow *p_uniflow;

    it_flow = m_flow.find(id);
    if (it_flow == m_flow.end())
        return 0;

    if (dir == FROM_ADDR1)
        p_uniflow = &it_flow->second->m_flow1;
    else
        p_uniflow = &it_flow->second->m_flow2;

    return p_uniflow->m_packets.size();
}

bool
fabs_tcp::recv_fin(const fabs_id &id, fabs_direction dir)
{
    boost::mutex::scoped_lock lock(m_mutex);

    map<fabs_id, ptr_fabs_tcp_flow>::iterator it_flow;
    fabs_tcp_uniflow *peer;

    it_flow = m_flow.find(id);
    if (it_flow == m_flow.end())
        return false;

    if (dir == FROM_ADDR1)
        peer = &it_flow->second->m_flow2;
    else
        peer = &it_flow->second->m_flow1;

    if (peer->m_is_fin) {
        m_flow.erase(it_flow);
        return true;
    }

    return false;
}

void
fabs_tcp::rm_flow(const fabs_id &id, fabs_direction dir)
{
    boost::mutex::scoped_lock lock(m_mutex);

    map<fabs_id, ptr_fabs_tcp_flow>::iterator it_flow;

    it_flow = m_flow.find(id);
    if (it_flow == m_flow.end())
        return;

    m_flow.erase(it_flow);
}

bool
fabs_tcp::get_packet(const fabs_id &id, fabs_direction dir,
                     fabs_tcp_packet &packet)
{
    boost::mutex::scoped_lock lock(m_mutex);

    map<fabs_id, ptr_fabs_tcp_flow>::iterator it_flow;
    fabs_tcp_uniflow *p_uniflow;

    it_flow = m_flow.find(id);
    if (it_flow == m_flow.end())
        return false;

    if (dir == FROM_ADDR1)
        p_uniflow = &it_flow->second->m_flow1;
    else
        p_uniflow = &it_flow->second->m_flow2;

    
    map<uint32_t, fabs_tcp_packet>::iterator it_pkt;

    it_pkt = p_uniflow->m_packets.find(p_uniflow->m_min_seq);
    if (it_pkt == p_uniflow->m_packets.end()) {
        return false;
    }

    packet = it_pkt->second;

    p_uniflow->m_packets.erase(it_pkt);

    if (packet.m_flags & TH_FIN) {
        p_uniflow->m_is_fin = true;
    }

    p_uniflow->m_min_seq = packet.m_nxt_seq;

    return true;
}

void
fabs_tcp::input_tcp(fabs_id &id, fabs_direction dir, fabs_bytes buf)
{
    map<fabs_id, ptr_fabs_tcp_flow>::iterator it_flow;
    ptr_fabs_tcp_flow p_tcp_flow;
    fabs_tcp_packet   packet;
    tcphdr *tcph = (tcphdr*)buf.get_head();


#ifdef DEBUG
    cout << "TCP flags: ";
    if (tcph->th_flags & TH_SYN)
        cout << "S";
    if (tcph->th_flags & TH_RST)
        cout << "R";
    if (tcph->th_flags & TH_ACK)
        cout << "A";
    if (tcph->th_flags & TH_FIN)
        cout << "F";
    cout << endl;
#endif


    // TODO: checksum
    {
        boost::mutex::scoped_lock lock(m_mutex);

        it_flow = m_flow.find(id);

        if ((tcph->th_flags & TH_SYN) && it_flow == m_flow.end()) {
            p_tcp_flow = ptr_fabs_tcp_flow(new fabs_tcp_flow);
            m_flow[id] = p_tcp_flow;
        } else if (it_flow == m_flow.end()) {
            return;
        } else {
            p_tcp_flow = it_flow->second;
        }

        packet.m_bytes    = buf;
        packet.m_seq      = ntohl(tcph->th_seq);
        packet.m_flags    = tcph->th_flags;
        packet.m_data_pos = tcph->th_off * 4;
        packet.m_data_len = buf.get_len() - packet.m_data_pos;
        packet.m_nxt_seq  = packet.m_seq + packet.m_data_len;
        packet.m_read_pos = 0;


        fabs_tcp_uniflow *p_uniflow;
        
        if (dir == FROM_ADDR1) {
            p_uniflow = &p_tcp_flow->m_flow1;
        } else if (dir == FROM_ADDR2) {
            p_uniflow = &p_tcp_flow->m_flow2;
        } else {
            return;
        }

        if (packet.m_flags & TH_SYN) {
            if (! p_uniflow->m_is_syn) {
                p_uniflow->m_min_seq = packet.m_seq;
                p_uniflow->m_is_syn  = true;
                packet.m_nxt_seq = packet.m_seq + 1;
            } else {
                return;
            }
        } else if (! packet.m_flags & TH_RST &&
                   (int32_t)packet.m_seq - (int32_t)p_uniflow->m_min_seq < 0) {
            return;
        }

        if (packet.m_flags & TH_SYN || packet.m_flags & TH_FIN ||
            packet.m_data_len > 0) {
            p_uniflow->m_packets[packet.m_seq] = packet;
        } else if (packet.m_flags & TH_RST) {
            if (p_uniflow->m_is_syn) {
                p_uniflow->m_packets[packet.m_seq] = packet;
            } else {
                p_uniflow->m_packets[p_uniflow->m_min_seq] = packet;
            }
        }

        p_uniflow->m_time = time(NULL);
    }

    // produce event
    fabs_id_dir tcp_event;

    tcp_event.m_id  = id;
    tcp_event.m_dir = dir;

    input_tcp_event(tcp_event);
}
