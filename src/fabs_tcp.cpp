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

#include <boost/random.hpp>

#include <functional>

using namespace std;

#define TCP_GC_TIMER 30

// #define DEBUG

fabs_tcp::fabs_tcp() :
    m_timeout(600),
    m_total_session(0),
    m_is_del(false),
    m_thread_gc(std::bind(&fabs_tcp::garbage_collector, this))
{

}

fabs_tcp::~fabs_tcp()
{

}

int
fabs_tcp::get_active_num()
{
    int n = 0;

    for (int i = 0; i < NUM_TCPTREE; i++) {
        n += m_flow[i].size();
    }

    return n;
}

void
fabs_tcp::print_stat()
{
    int n = 0;

    for (int i = 0; i < NUM_TCPTREE; i++) {
        n += m_flow[i].size();
    }

    cout << "total TCP sessions: " << m_total_session
         << "\nactive TCP sessions: " << n << endl;
}

void
fabs_tcp::garbage_collector2(int idx, time_t now)
{
    list<fabs_id_dir> garbages;
    {
        std::unique_lock<std::mutex> lock(m_mutex_flow[idx]);

        for (auto it = m_flow[idx].begin(); it != m_flow[idx].end(); ++it) {
            if (m_is_del)
                return;
            // close half opened connections
            if (((it->second->m_flow1.m_is_syn &&
                  ! it->second->m_flow2.m_is_syn) ||
                 (it->second->m_flow1.m_is_fin &&
                  ! it->second->m_flow2.m_is_fin)) &&
                now - it->second->m_flow1.m_time > TCP_GC_TIMER) {

                it->second->m_flow1.m_is_rm = true;

                fabs_id_dir id_dir;

                id_dir.m_id  = it->first;
                id_dir.m_dir = FROM_ADDR1;

                garbages.push_back(id_dir);
                continue;
            } if (((! it->second->m_flow1.m_is_syn &&
                         it->second->m_flow2.m_is_syn) ||
                        (! it->second->m_flow1.m_is_fin &&
                         it->second->m_flow2.m_is_fin)) &&
                       now - it->second->m_flow2.m_time > TCP_GC_TIMER) {

                it->second->m_flow2.m_is_rm = true;

                fabs_id_dir id_dir;

                id_dir.m_id  = it->first;
                id_dir.m_dir = FROM_ADDR2;

                garbages.push_back(id_dir);
                continue;
            }

            // close long-lived but do-nothing connections
            if (now - it->second->m_flow1.m_time > m_timeout &&
                now - it->second->m_flow2.m_time > m_timeout) {

                it->second->m_flow1.m_is_rm = true;

                fabs_id_dir id_dir;

                id_dir.m_id  = it->first;
                id_dir.m_dir = FROM_ADDR1;

                garbages.push_back(id_dir);
                continue;
            }

            // close compromised connections
            if (it->second->m_flow1.m_packets.size() > 4096 ||
                it->second->m_flow2.m_packets.size() > 4096) {

                it->second->m_flow1.m_is_rm = true;

                fabs_id_dir id_dir;

                id_dir.m_id  = it->first;
                id_dir.m_dir = FROM_ADDR1;

                garbages.push_back(id_dir);
                continue;
            }
        }
    }

    for (auto it2 = garbages.begin(); it2 != garbages.end(); it2++) {
        input_tcp_event(idx, *it2);
    }
}

void
fabs_tcp::garbage_collector()
{
    boost::minstd_rand    gen((size_t)this);
    boost::uniform_real<> dst( 0, 1 );
    boost::variate_generator<
        boost::minstd_rand&, boost::uniform_real<>
        > rand( gen, dst );

    for (;;) {
        std::unique_lock<std::mutex> lock_gc(m_mutex_gc);
        m_condition_gc.wait_for(lock_gc, std::chrono::milliseconds((int)(TCP_GC_TIMER * 1000 + TCP_GC_TIMER * rand() * 1000)));

        if (m_is_del) {
            return;
        }

        time_t now = time(NULL);
        for (int i = 0; i < NUM_TCPTREE; i++) {
            garbage_collector2(i, now);
        }
    }
}

void
fabs_tcp::input_tcp_event(int idx, fabs_id_dir tcp_event)
{
#ifdef DEBUG
    char addr1[32], addr2[32];
#endif // DEBUG

    if (m_is_del)
        return;

    {
        std::unique_lock<std::mutex> lock(m_mutex_flow[idx]);


#ifdef DEBUG
        inet_ntop(PF_INET, &tcp_event.m_id.m_addr1->l3_addr.b32,
                  addr1, sizeof(addr1));
        inet_ntop(PF_INET, &tcp_event.m_id.m_addr2->l3_addr.b32,
                  addr2, sizeof(addr2));
#endif // DEBUG


        // garbage collection
        std::map<fabs_id, ptr_fabs_tcp_flow>::iterator it_flow;

        it_flow = m_flow[idx].find(tcp_event.m_id);

        if (it_flow == m_flow[idx].end()) {
            return;
        }

        bool is_rm = false;

        timeval dtm;
        if ((tcp_event.m_dir == FROM_ADDR1 &&
             it_flow->second->m_flow1.m_is_rm) ||
            (tcp_event.m_dir == FROM_ADDR2 &&
             it_flow->second->m_flow2.m_is_rm)) {
            auto f1 = it_flow->second->m_flow1.m_packets.rbegin();
            auto f2 = it_flow->second->m_flow2.m_packets.rbegin();

            if (f1 == it_flow->second->m_flow1.m_packets.rend() && f2 == it_flow->second->m_flow2.m_packets.rend()) {
                gettimeofday(&dtm, nullptr);
            } else if (f1 == it_flow->second->m_flow1.m_packets.rend()) {
                dtm = f2->second.m_bytes->m_tm;
            } else if (f2 == it_flow->second->m_flow2.m_packets.rend()) {
                dtm = f1->second.m_bytes->m_tm;
            } else {
                if (f1->second.m_bytes->m_tm.tv_sec > f2->second.m_bytes->m_tm.tv_sec)
                    dtm = f1->second.m_bytes->m_tm;
                else
                    dtm = f2->second.m_bytes->m_tm;
            }

            ptr_fabs_bytes buf(new fabs_bytes);
            buf->m_tm = dtm;
            m_appif->in_event(STREAM_TIMEOUT, tcp_event, std::move(buf));
            is_rm = true;
        }

        if (is_rm) {
            lock.unlock();
            rm_flow(idx, tcp_event.m_id, tcp_event.m_dir);

            fabs_id_dir id_dir = tcp_event;
            id_dir.m_dir = FROM_NONE;
            ptr_fabs_bytes buf(new fabs_bytes);
            buf->m_tm = dtm;
            m_appif->in_event(STREAM_DESTROYED, id_dir, std::move(buf));

            return;
        }
    }

    fabs_tcp_packet packet;

    while (get_packet(idx, tcp_event.m_id, tcp_event.m_dir, packet)) {
        if (m_is_del) return;

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

            m_appif->in_event(STREAM_SYN, tcp_event, std::move(packet.m_bytes));
        } else if (packet.m_flags & TH_FIN) {
            timeval tm = packet.m_bytes->m_tm;

            if (packet.m_data_len > 0 &&
                packet.m_bytes->skip(packet.m_data_pos)) {
                m_appif->in_event(STREAM_DATA, tcp_event, std::move(packet.m_bytes));
            }

            ptr_fabs_bytes buf = ptr_fabs_bytes(new fabs_bytes);
            buf->m_tm = tm;
            m_appif->in_event(STREAM_FIN, tcp_event, std::move(buf));

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

            if (recv_fin(idx, tcp_event.m_id, tcp_event.m_dir)) {
                fabs_id_dir id_dir = tcp_event;
                id_dir.m_dir = FROM_NONE;
                buf = ptr_fabs_bytes(new fabs_bytes);
                buf->m_tm = tm;
                m_appif->in_event(STREAM_DESTROYED, id_dir, std::move(buf));
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

            timeval tm = packet.m_bytes->m_tm;

            m_appif->in_event(STREAM_RST, tcp_event, std::move(packet.m_bytes));

            rm_flow(idx, tcp_event.m_id, tcp_event.m_dir);

            fabs_id_dir id_dir = tcp_event;
            id_dir.m_dir = FROM_NONE;
            ptr_fabs_bytes buf = ptr_fabs_bytes(new fabs_bytes);
            buf->m_tm = tm;
            m_appif->in_event(STREAM_DESTROYED, id_dir, std::move(buf));
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

            if (packet.m_bytes->skip(packet.m_data_pos)) {
                m_appif->in_event(STREAM_DATA, tcp_event, std::move(packet.m_bytes));
            }
        }
    }
}

bool
fabs_tcp::recv_fin(int idx, const fabs_id &id, fabs_direction dir)
{
    std::unique_lock<std::mutex> lock(m_mutex_flow[idx]);

    fabs_tcp_uniflow *peer;
    auto it_flow = m_flow[idx].find(id);

    if (it_flow == m_flow[idx].end())
        return false;

    if (dir == FROM_ADDR1)
        peer = &it_flow->second->m_flow2;
    else
        peer = &it_flow->second->m_flow1;

    if (peer->m_is_fin) {
        m_flow[idx].erase(it_flow);
        return true;
    }

    return false;
}

void
fabs_tcp::rm_flow(int idx, const fabs_id &id, fabs_direction dir)
{
    std::unique_lock<std::mutex> lock(m_mutex_flow[idx]);

    auto it_flow = m_flow[idx].find(id);
    if (it_flow == m_flow[idx].end())
        return;

    m_flow[idx].erase(it_flow);
}

bool
fabs_tcp::get_packet(int idx, const fabs_id &id, fabs_direction dir,
                     fabs_tcp_packet &packet)
{
    std::unique_lock<std::mutex> lock(m_mutex_flow[idx]);

    fabs_tcp_uniflow *p_uniflow;
    auto it_flow = m_flow[idx].find(id);

    if (it_flow == m_flow[idx].end())
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

    packet.m_bytes    = std::move(it_pkt->second.m_bytes);
    packet.m_seq      = it_pkt->second.m_seq;
    packet.m_nxt_seq  = it_pkt->second.m_nxt_seq;
    packet.m_flags    = it_pkt->second.m_flags;
    packet.m_data_pos = it_pkt->second.m_data_pos;
    packet.m_data_len = it_pkt->second.m_data_len;
    packet.m_read_pos = it_pkt->second.m_read_pos;

    p_uniflow->m_packets.erase(it_pkt);

    if (packet.m_flags & TH_FIN) {
        p_uniflow->m_is_fin = true;
    }

    p_uniflow->m_min_seq = packet.m_nxt_seq;

    return true;
}

void
fabs_tcp::input_tcp(fabs_id &id, fabs_direction dir, ptr_fabs_bytes buf)
{
    map<fabs_id, ptr_fabs_tcp_flow>::iterator it_flow;
    fabs_tcp_flow *p_tcp_flow;
    fabs_tcp_packet   packet;
    tcphdr *tcph = (tcphdr*)buf->get_head();


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

    int idx = id.get_hash() % NUM_TCPTREE;

    // TODO: checksum
    {
        std::unique_lock<std::mutex> lock(m_mutex_flow[idx]);

        it_flow = m_flow[idx].find(id);

        if ((tcph->th_flags & TH_SYN) && it_flow == m_flow[idx].end()) {
            auto ptr = ptr_fabs_tcp_flow(new fabs_tcp_flow);
            p_tcp_flow = ptr.get();
            m_flow[idx][id] = std::move(ptr);
            __sync_fetch_and_add(&m_total_session, 1);
        } else if (it_flow == m_flow[idx].end()) {
            return;
        } else {
            p_tcp_flow = it_flow->second.get();
        }

        packet.m_seq      = ntohl(tcph->th_seq);
        packet.m_flags    = tcph->th_flags;
        packet.m_data_pos = tcph->th_off * 4;
        packet.m_data_len = buf->get_len() - packet.m_data_pos;
        packet.m_nxt_seq  = packet.m_seq + packet.m_data_len;
        packet.m_read_pos = 0;
        packet.m_bytes    = std::move(buf);

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
        } else if (! (packet.m_flags & TH_RST) &&
                   (int32_t)packet.m_seq - (int32_t)p_uniflow->m_min_seq < 0) {
            return;
        }

        if (packet.m_flags & TH_SYN || packet.m_flags & TH_FIN ||
            packet.m_data_len > 0) {
            p_uniflow->m_packets[packet.m_seq].m_bytes    = std::move(packet.m_bytes);
            p_uniflow->m_packets[packet.m_seq].m_seq      = packet.m_seq;
            p_uniflow->m_packets[packet.m_seq].m_nxt_seq  = packet.m_nxt_seq;
            p_uniflow->m_packets[packet.m_seq].m_flags    = packet.m_flags;
            p_uniflow->m_packets[packet.m_seq].m_data_pos = packet.m_data_pos;
            p_uniflow->m_packets[packet.m_seq].m_data_len = packet.m_data_len;
            p_uniflow->m_packets[packet.m_seq].m_read_pos = packet.m_read_pos;
        } else if (packet.m_flags & TH_RST) {
            if (p_uniflow->m_is_syn) {
                p_uniflow->m_packets[packet.m_seq].m_bytes    = std::move(packet.m_bytes);
                p_uniflow->m_packets[packet.m_seq].m_seq      = packet.m_seq;
                p_uniflow->m_packets[packet.m_seq].m_nxt_seq  = packet.m_nxt_seq;
                p_uniflow->m_packets[packet.m_seq].m_flags    = packet.m_flags;
                p_uniflow->m_packets[packet.m_seq].m_data_pos = packet.m_data_pos;
                p_uniflow->m_packets[packet.m_seq].m_data_len = packet.m_data_len;
                p_uniflow->m_packets[packet.m_seq].m_read_pos = packet.m_read_pos;
            } else {
                p_uniflow->m_packets[p_uniflow->m_min_seq].m_bytes    = std::move(packet.m_bytes);
                p_uniflow->m_packets[p_uniflow->m_min_seq].m_seq      = packet.m_seq;
                p_uniflow->m_packets[p_uniflow->m_min_seq].m_nxt_seq  = packet.m_nxt_seq;
                p_uniflow->m_packets[p_uniflow->m_min_seq].m_flags    = packet.m_flags;
                p_uniflow->m_packets[p_uniflow->m_min_seq].m_data_pos = packet.m_data_pos;
                p_uniflow->m_packets[p_uniflow->m_min_seq].m_data_len = packet.m_data_len;
                p_uniflow->m_packets[p_uniflow->m_min_seq].m_read_pos = packet.m_read_pos;
            }
        }

        p_uniflow->m_time = time(NULL);
    }

    // produce event
    fabs_id_dir tcp_event;

    tcp_event.m_id  = id;
    tcp_event.m_dir = dir;

    input_tcp_event(idx, tcp_event);
}
