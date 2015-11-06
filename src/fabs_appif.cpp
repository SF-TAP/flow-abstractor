#include "fabs_appif.hpp"
#include "fabs_conf.hpp"
#include "fabs_callback.hpp"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>

#include <list>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iterator>

#include <boost/bind.hpp>
#include <boost/lexical_cast.hpp>

// #include <event2/thread.h>

using namespace std;
namespace fs = boost::filesystem;

void ux_read(int fd, short events, void *arg);
bool read_loopback7(int fd, fabs_appif *appif);
// bool read_loopback3(int fd, fabs_appif *appif);

fabs_appif::fabs_appif() :
    m_fd7(-1),
    m_fd3(-1),
    m_lb7_format(IF_TEXT),
    m_num_tcp_threads(1),
    m_num_consumer(1),
    m_home(new fs::path(fs::current_path())),
    m_is_lru(true),
    m_is_cache(true)
{

}

fabs_appif::~fabs_appif()
{

}

void
fabs_appif::run()
{
    boost::mutex::scoped_lock lock_init(m_mutex_init);

    {
        spin_lock_write lock(m_rw_mutex);

        assert(! m_thread_listen);

        m_thread_listen = ptr_thread(new boost::thread(boost::bind(&fabs_appif::ux_listen, this)));

        m_consumer = boost::shared_array<ptr_consumer>(new ptr_consumer[m_num_consumer]);

        for (int i = 0; i < m_num_consumer; i++) {
            m_consumer[i] = ptr_consumer(new appif_consumer(i, *this));
        }
    }

    m_condition_init.wait(lock_init);
}

void
ux_accept(int fd, short events, void *arg)
{
    int sock = accept(fd, NULL, NULL);
    fabs_appif *appif = static_cast<fabs_appif*>(arg);

    spin_lock_write lock(appif->m_rw_mutex);

    auto it = appif->m_fd2ifrule.find(fd);
    if (it == appif->m_fd2ifrule.end()) {
        assert(false);
        return;
    }

    auto it2 = it->second->m_fd2name.find(fd);
    if (it2 == it->second->m_fd2name.end()) {
        assert(false);
        return;
    }

    event *ev = event_new(appif->m_ev_base, sock, EV_READ | EV_PERSIST,
                          ux_read, arg);
    event_add(ev, NULL);

    auto peer = fabs_appif::ptr_uxpeer(new fabs_appif::uxpeer);
    peer->m_fd   = sock;
    peer->m_ev   = ev;
    peer->m_name = it2->second;

    appif->m_fd2uxpeer[sock] = peer;
    appif->m_name2uxpeer[it2->second].insert(sock);

    cout << "accepted on " << it->second->m_name
         << " (fd = " << sock << ")" << endl;

    if (fd == appif->m_fd7) {
        appif->m_lb7_state[sock] = fabs_appif::ptr_loopback_state(new fabs_appif::loopback_state);
    }
}

void
ux_close(int fd, fabs_appif *appif)
{
    auto it1 = appif->m_fd2uxpeer.find(fd);
    if (it1 != appif->m_fd2uxpeer.end()) {
        auto it2 = appif->m_name2uxpeer.find(it1->second->m_name);
        if (it2 != appif->m_name2uxpeer.end()) {
            it2->second.erase(fd);

            if (it2->second.size() == 0) {
                appif->m_name2uxpeer.erase(it2);
            }
        }

        event_del(it1->second->m_ev);
        event_free(it1->second->m_ev);

        cout << "closed on " << it1->second->m_name
             << " (fd = " << fd << ")" << endl;

        appif->m_fd2uxpeer.erase(it1);
    }

    shutdown(fd, SHUT_RDWR);
    close(fd);

    auto it3 = appif->m_lb7_state.find(fd);
    if (it3 != appif->m_lb7_state.end()) {
        fabs_id_dir id_dir;
        fabs_bytes *bytes = nullptr;

        for (auto it4 = it3->second->streams.begin();
             it4 != it3->second->streams.end(); ++it4) {
            id_dir.m_id  = *it4;
            id_dir.m_dir = FROM_NONE;

            appif->in_event(STREAM_DESTROYED, id_dir, bytes);
        }

        appif->m_lb7_state.erase(it3);
    }
}

void
ux_read(int fd, short events, void *arg)
{
    fabs_appif *appif = static_cast<fabs_appif*>(arg);
    fabs_appif::ptr_uxpeer peer;

    auto it1 = appif->m_fd2uxpeer.find(fd);
    if (it1 != appif->m_fd2uxpeer.end()) {
        peer = it1->second;
    }

    if (peer) {
        if (peer->m_name == "loopback7") {
            if (read_loopback7(fd, appif)) {
                spin_lock_write lock(appif->m_rw_mutex);

                ux_close(fd, appif);
                return;
            }
        } else {
            char buf[4096];
            int  recv_size = read(fd, buf, sizeof(buf) - 1);

            if (recv_size <= 0) {
                spin_lock_write lock(appif->m_rw_mutex);

                ux_close(fd, appif);
                return;
            }
        }
    }
}

bool
read_loopback7(int fd, fabs_appif *appif)
{
    fabs_appif_header *header;
    fabs_id_dir        id_dir;

    auto it = appif->m_lb7_state.find(fd);
    assert(it != appif->m_lb7_state.end());

    header = &it->second->header;

    if (it->second->is_header) {
        if (appif->m_lb7_format == fabs_appif::IF_BINARY) {
            // read binary header
            ssize_t len = read(fd, header, sizeof(*header));

            if (len <= 0) {
                // must close fd
                return true;
            } else if (len != sizeof(*header)) {
                cerr << "CAUTION! LOOPBACK 7 RECEIVED INVALID HEADER!: socket = "
                     << fd << endl;
                return false;
            }

            header->hop++;
        } else {
            // read text header
            map<string, string> h;
            string s;

            for (;;) {
                char c;
                ssize_t len = read(fd, &c, 1);

                if (len <= 0) {
                    // must close fd
                    return true;
                }

                if (c == '\n')
                    break;

                s += c;
            }

            stringstream ss1(s);
            while (ss1) {
                string elm;
                std::getline(ss1, elm, ',');

                if (elm.empty())
                    continue;

                stringstream ss2(elm);
                string key, val;
                std::getline(ss2, key, '=');
                std::getline(ss2, val);

                h[key] = val;
            }

            uint8_t l3_proto, l4_proto;
            int af;

            if (h["l3"] == "ipv4") {
                l3_proto = IPPROTO_IP;
                af = AF_INET;
            } else if (h["l3"] == "ipv6") {
                l3_proto = IPPROTO_IPV6;
                af = AF_INET6;
            } else {
                return false;
            }

            if (h["l4"] == "tcp") {
                l4_proto = IPPROTO_TCP;
            } else if (h["l4"] == "udp") {
                l4_proto = IPPROTO_UDP;
            } else {
                return false;
            }

            if (inet_pton(af, h["ip1"].c_str(), &header->l3_addr1) <= 0) {
                cerr << "CAUTION! LOOPBACK 7 RECEIVED INVALID HEADER! (inet_pton ip1): header = "
                     << s << endl;
                return false;
            }

            if (inet_pton(af, h["ip2"].c_str(), &header->l3_addr2) <= 0) {
                cerr << "CAUTION! LOOPBACK 7 RECEIVED INVALID HEADER! (inet_pton ip2): header = "
                     << s << endl;
                return false;
            }

            header->l3_proto = l3_proto;
            header->l4_proto = l4_proto;

            try {
                header->l4_port1 = boost::lexical_cast<int>(h["port1"]);
                header->l4_port2 = boost::lexical_cast<int>(h["port2"]);
                header->hop      = boost::lexical_cast<int>(h["hop"]);

                auto it_len = h.find("len");
                if (it_len != h.end()) {
                    header->len = boost::lexical_cast<int>(it_len->second);
                }
            } catch (boost::bad_lexical_cast e) {
                cerr << "CAUTION! LOOPBACK 7 RECEIVED INVALID HEADER! (lexical_cast): header = "
                     << s << endl;
                return false;
            }

            header->hop++;
            header->l4_port1 = htons(header->l4_port1);
            header->l4_port2 = htons(header->l4_port2);

            if (h["event"] == "CREATED") {
                header->event = STREAM_CREATED;
            } else if (h["event"] == "DESTROYED") {
                header->event = STREAM_DESTROYED;
            } else if (h["event"] == "DATA") {
                header->event = STREAM_DATA;
            } else {
                return false;
            }

            if (h["from"] == "0") {
                header->from = FROM_ADDR1;
            } else if (h["from"] == "1") {
                header->from = FROM_ADDR2;
            } else {
                header->from = FROM_NONE;
            }

            fabs_peer peer1, peer2;

            peer1.padding = 0;
            peer2.padding = 0;

            memcpy(&peer1.l3_addr, &header->l3_addr1, sizeof(peer1.l3_addr));
            memcpy(&peer2.l3_addr, &header->l3_addr2, sizeof(peer2.l3_addr));

            peer1.l4_port = header->l4_port1;
            peer2.l4_port = header->l4_port2;

            if (peer1 > peer2) {
                // swap
                memcpy(&header->l3_addr1, &peer2.l3_addr, sizeof(peer2.l3_addr));
                memcpy(&header->l3_addr2, &peer1.l3_addr, sizeof(peer1.l3_addr));
                header->l4_port1 = peer2.l4_port;
                header->l4_port2 = peer1.l4_port;

                if (header->from == FROM_ADDR1)
                    header->from = FROM_ADDR2;
                else if (header->from == FROM_ADDR2)
                    header->from = FROM_ADDR1;
            }
        }

        header->match = fabs_appif::MATCH_NONE;

        id_dir.m_id.set_appif_header(*header);

        if (header->from == 1) {
            id_dir.m_dir = FROM_ADDR1;
        } else if (header->from == 2) {
            id_dir.m_dir = FROM_ADDR2;
        } else {
            id_dir.m_dir = FROM_NONE;
        }

        it->second->id_dir = id_dir;


        if (header->event == STREAM_DATA) {
            it->second->is_header = false;
            return false;
        } else if (header->event == STREAM_CREATED) {
            fabs_bytes *bytes = nullptr;

            // invoke CREATED event
            appif->in_event(STREAM_CREATED, id_dir, bytes);

            it->second->streams.insert(id_dir.m_id);

            return false;
        } else if (header->event == STREAM_DESTROYED) {
            fabs_bytes *bytes = nullptr;

            // invoke DESTROYED event
            appif->in_event(STREAM_DESTROYED, id_dir, bytes);

            it->second->streams.erase(id_dir.m_id);

            return false;
        } else {
            cerr << "CAUTION! LOOPBACK 7 RECEIVED INVALID EVENT!: event = "
                 << header->event << endl;
            // must close fd
            return true;
        }
    } else {
        fabs_bytes *bytes = new fabs_bytes;

        bytes->alloc(header->len);
        if (bytes->get_len() == 0)
            return false;

        ssize_t len = read(fd, bytes->get_head(), header->len);

        if (len == 0) {
            // must close fd
            return true;
        } if (len < 0) {
            perror("error");
            // must close fd
            return true;
        } else if (len != header->len) {
            cerr << "CAUTION! LOOPBACK 7 RECEIVED INVALID BODY LENGTH!: len = "
                 << header->len << endl;
            // must close fd
            return true;
        }

        // invoke DATA event
        appif->in_event(STREAM_DATA, it->second->id_dir, bytes);

        it->second->is_header = true;

        return false;
    }
}

void
fabs_appif::makedir(fs::path path)
{
    if (fs::exists(path)) {
        if (! fs::is_directory(path)) {
            cerr << path.string() << " is not directory" << endl;
            exit(-1);
        }
    } else {
        try {
            fs::create_directories(path);
        } catch (fs::filesystem_error e) {
            cerr << "cannot create directories: " << e.path1().string()
                 << endl;
            exit(-1);
        }
    }
}

void
fabs_appif::ux_listen_ifrule(ptr_ifrule ifrule)
{
    for (int i = 0; i < ifrule->m_balance; i++) {
        int sock = socket(AF_UNIX, SOCK_STREAM, 0);

        if (sock == -1) {
            perror("socket");
            exit(-1);
        }

        struct sockaddr_un sa = {0};
        sa.sun_family = AF_UNIX;

        fs::path path;

        if (ifrule->m_proto == IF_UDP) {
            path = *m_home / fs::path("udp") / *ifrule->m_ux;
        } else if (ifrule->m_proto == IF_TCP) {
            path = *m_home / fs::path("tcp") / *ifrule->m_ux;
        } else {
            path = *m_home / *ifrule->m_ux;
        }

        if (ifrule->m_balance > 1) {
            path += fs::path(boost::lexical_cast<string>(i));
        }

        strncpy(sa.sun_path, path.string().c_str(), sizeof(sa.sun_path));

        remove(sa.sun_path);

        if (::bind(sock, (struct sockaddr*) &sa,
                   sizeof(struct sockaddr_un)) == -1) {
            perror("bind");
            exit(-1);
        }

        if (listen(sock, 128) == -1) {
            perror("listen");
            exit(-1);
        }

        event *ev = event_new(m_ev_base, sock, EV_READ | EV_PERSIST,
                              ux_accept, this);
        event_add(ev, NULL);

        ifrule->m_balance_name.push_back(path.string());
        ifrule->m_fd2name[sock] = path.string();
        m_fd2ifrule[sock] = ifrule;

        cout << "listening on " << path.string()
             << " (" << ifrule->m_balance_name[i] << ")" << endl;

        if (ifrule->m_name == "loopback7") {
            m_fd7 = sock;
            break;
        }
    }
}


void
fabs_appif::ux_listen()
{
    m_ev_base = event_base_new();
    if (m_ev_base == NULL) {
        cerr << "could not new ev_base" << endl;
        exit(-1);
    }

/*
    evthread_use_pthreads();
    if (evthread_make_base_notifiable(m_ev_base) < 0) {
        cerr << "couldn't make base notifiable " << endl;
        exit(-1);
    }
*/
    umask(0007);

    {
        spin_lock_write lock(m_rw_mutex);

        makedir(*m_home);
        makedir(*m_home / fs::path("tcp"));
        makedir(*m_home / fs::path("udp"));

        for (auto it_tcp = m_ifrule_tcp.begin(); it_tcp != m_ifrule_tcp.end();
             ++it_tcp) {
            for (auto it1 = it_tcp->second->ifrule.begin();
                 it1 != it_tcp->second->ifrule.end(); ++it1) {
                ux_listen_ifrule(*it1);
            }

            for (auto it2 = it_tcp->second->ifrule_no_regex.begin();
                 it2 != it_tcp->second->ifrule_no_regex.end(); ++it2) {
                ux_listen_ifrule(*it2);
            }
        }

        for (auto it_udp = m_ifrule_udp.begin(); it_udp != m_ifrule_udp.end();
             ++it_udp) {
            for (auto it1 = it_udp->second->ifrule.begin();
                 it1 != it_udp->second->ifrule.end(); ++it1) {
                ux_listen_ifrule(*it1);
            }

            for (auto it2 = it_udp->second->ifrule_no_regex.begin();
                 it2 != it_udp->second->ifrule_no_regex.end(); ++it2) {
                ux_listen_ifrule(*it2);
            }
        }

        if (m_ifrule7)
            ux_listen_ifrule(m_ifrule7);

        if (m_ifrule3)
            ux_listen_ifrule(m_ifrule3);

        if (m_tcp_default)
            ux_listen_ifrule(m_tcp_default);

        if (m_udp_default)
            ux_listen_ifrule(m_udp_default);
    }

    {
        boost::mutex::scoped_lock lock(m_mutex_init);
        m_condition_init.notify_all();
    }

    event_base_dispatch(m_ev_base);
}

void
fabs_appif::read_conf(string conf)
{
    fabs_conf c;

    if (! c.read_conf(conf))
        exit(-1);

    for (auto it1 = c.m_conf.begin(); it1 != c.m_conf.end(); ++it1) {
        if (it1->first == "global") {
            auto it2 = it1->second.find("home");
            if (it2 != it1->second.end()) {
                m_home = ptr_path(new fs::path(it2->second));
            }

            it2 = it1->second.find("timeout");
            if (it2 != it1->second.end()) {
                try {
                    m_tcp_timeout = boost::lexical_cast<time_t>(it2->second);
                } catch (boost::bad_lexical_cast e) {
                    cerr << "cannot convert \"" << it2->second
                         << "\" to time_t" << endl;
                    continue;
                }
            }

            it2 = it1->second.find("lru");
            if (it2 != it1->second.end()) {
                if (it2->second == "yes") {
                    m_is_lru = true;
                } else if (it2->second == "no") {
                    m_is_lru = false;
                } else {
                    // error
                }
            }

            it2 = it1->second.find("cache");
            if (it2 != it1->second.end()) {
                if (it2->second == "yes") {
                    m_is_cache = true;
                } else if (it2->second == "no") {
                    m_is_cache = false;
                } else {
                    // error
                }
            }

            it2 = it1->second.find("regex_threads");
            if (it2 != it1->second.end()) {
                try {
                    m_num_consumer = boost::lexical_cast<int>(it2->second);
                } catch (boost::bad_lexical_cast e) {
                    cerr << "cannot convert \"" << it2->second
                         << "\" to int" << endl;
                    continue;
                }
            }

            if (m_num_consumer < 1) {
                m_num_consumer = 1;
            } else if (m_num_consumer > 1024) {
                m_num_consumer = 1024;
            }

            it2 = it1->second.find("tcp_threads");
            if (it2 != it1->second.end()) {
                try {
                    m_num_tcp_threads = boost::lexical_cast<int>(it2->second);
                } catch (boost::bad_lexical_cast e) {
                    cerr << "cannot convert \"" << it2->second
                         << "\" to int" << endl;
                    continue;
                }
            }

            if (m_num_tcp_threads < 1) {
                m_num_tcp_threads = 1;
            } else if (m_num_tcp_threads > 1024) {
                m_num_tcp_threads = 1024;
            }
        } else {
            ptr_ifrule rule = ptr_ifrule(new ifrule);

            rule->m_name = it1->first;
            auto it3 = it1->second.find("if");
            if (it3 == it1->second.end()) {
                rule->m_ux = ptr_path(new fs::path(it1->first));
            } else {
                rule->m_ux = ptr_path(new fs::path(it3->second));
            }

            it3 = it1->second.find("up");
            if (it3 != it1->second.end()) {
                rule->m_up = ptr_regex(new RE2(it3->second));
            }

            it3 = it1->second.find("down");
            if (it3 != it1->second.end()) {
                rule->m_down = ptr_regex(new RE2(it3->second));
            }

            it3 = it1->second.find("nice");
            if (it3 != it1->second.end()) {
                try {
                    rule->m_nice = boost::lexical_cast<int>(it3->second);
                } catch (boost::bad_lexical_cast e) {
                    cerr << "cannot convert \"" << it3->second
                         << "\" to int" << endl;
                    continue;
                }
            }


            it3 = it1->second.find("proto");
            if (it3 != it1->second.end()) {
                if (it3->second == "TCP") {
                    rule->m_proto = IF_TCP;
                } else if (it3->second == "UDP") {
                    rule->m_proto = IF_UDP;
                } else {
                    // error
                }
            } else {
                // error
            }

            it3 = it1->second.find("format");
            if (it3 != it1->second.end()) {
                if (it3->second == "binary") {
                    rule->m_format = IF_BINARY;
                } else if (it3->second == "text") {
                    rule->m_format = IF_TEXT;
                } else {
                    // error
                }
            }

            it3 = it1->second.find("body");
            if (it3 != it1->second.end()) {
                if (it3->second == "yes") {
                    rule->m_is_body = true;
                } else if (it3->second == "no") {
                    rule->m_is_body = false;
                } else {
                    // error
                }
            }

            it3 = it1->second.find("balance");
            if (it3 != it1->second.end()) {
                try {
                    rule->m_balance = boost::lexical_cast<int>(it3->second);
                    if (rule->m_balance < 1) {
                        rule->m_balance = 1;
                    }
                } catch (boost::bad_lexical_cast e) {
                    cerr << "cannot convert \"" << it3->second
                         << "\" to int" << endl;
                    continue;
                }
            }

            it3 = it1->second.find("port");
            if (it3 != it1->second.end()) {
                stringstream ss(it3->second);

                while (ss) {
                    string port, n1, n2;
                    std::getline(ss, port, ',');

                    if (port.empty())
                        break;

                    port = trim(port);

                    stringstream ss2(port);
                    std::getline(ss2, n1, '-');
                    std::getline(ss2, n2);

                    n1 = trim(n1);
                    n2 = trim(n2);

                    pair<uint16_t, uint16_t> range;

                    try {
                        range.first = boost::lexical_cast<uint16_t>(n1);
                    } catch (boost::bad_lexical_cast e) {
                        cerr << "cannot convert \"" << n1
                             << "\" to uint16_t" << endl;
                        continue;
                    }

                    if (n2.size() > 0) {
                        try {
                            range.second = boost::lexical_cast<uint16_t>(n2);
                        } catch (boost::bad_lexical_cast e) {
                            cerr << "cannot convert \"" << n2
                                 << "\" to uint16_t" << endl;
                            continue;
                        }
                    } else {
                        range.second = range.first;
                    }

                    rule->m_port->push_back(range);
                }
            }

            // insert interface rule
            if (rule->m_name == "loopback7") {
                m_ifrule7 = rule;
                m_lb7_format = rule->m_format;
            } else if (rule->m_name == "tcp_default") {
                m_tcp_default = rule;
            } else if (rule->m_name == "udp_default") {
                m_udp_default = rule;
            } else if (rule->m_proto == IF_UDP) {
                auto it_udp = m_ifrule_udp.find(rule->m_nice);
                if (it_udp == m_ifrule_udp.end()) {
                    m_ifrule_udp[rule->m_nice] = ptr_ifrule_storage(new ifrule_storage);
                    it_udp = m_ifrule_udp.find(rule->m_nice);
                }

                if (rule->m_up)
                    it_udp->second->ifrule.push_back(rule);
                else
                    it_udp->second->ifrule_no_regex.push_back(rule);
            } else if (rule->m_proto == IF_TCP) {
                auto it_tcp = m_ifrule_tcp.find(rule->m_nice);
                if (it_tcp == m_ifrule_tcp.end()) {
                    m_ifrule_tcp[rule->m_nice] = ptr_ifrule_storage(new ifrule_storage);
                    it_tcp = m_ifrule_tcp.find(rule->m_nice);
                }

                if (rule->m_up && rule->m_down) {
                    it_tcp->second->ifrule.push_back(rule);
                } else {
                    it_tcp->second->ifrule_no_regex.push_back(rule);
                }
            }
        }
    }
}

void
fabs_appif::in_event(fabs_stream_event st_event,
                     const fabs_id_dir &id_dir, fabs_bytes *bytes)
{
    appif_event *ev = new appif_event;

    ev->st_event = st_event;
    ev->id_dir   = id_dir;
    ev->bytes    = bytes;

    int id = id_dir.m_id.get_hash() % m_num_consumer;

    m_consumer[id]->produce(ev);
}

void
fabs_appif::appif_consumer::in_stream_event(fabs_stream_event st_event,
                                            const fabs_id_dir &id_dir,
                                            fabs_bytes *bytes)
{
    switch (st_event) {
    case STREAM_SYN:
    case STREAM_CREATED:
    {
        auto it = m_info.find(id_dir.m_id);

        if (it == m_info.end()) {
            ptr_info info = ptr_info(new stream_info(id_dir.m_id));

            m_info[id_dir.m_id] = info;

            it = m_info.find(id_dir.m_id);
        }

        delete bytes;

        break;
    }
    case STREAM_DATA:
    {
        if (bytes->get_len() <= 0) {
            delete bytes;
            return;
        }

        auto it = m_info.find(id_dir.m_id);

        if (it == m_info.end()) {
            delete bytes;
            return;
        }

        if (it->second->m_is_giveup) {
            delete bytes;
            return;
        }

        if (id_dir.m_dir == FROM_ADDR1) {
            it->second->m_buf1.push_back(bytes);
            it->second->m_dsize1 += bytes->get_len();
            it->second->m_is_buf1 = true;
        } else if (id_dir.m_dir == FROM_ADDR2) {
            it->second->m_buf2.push_back(bytes);
            it->second->m_dsize2 += bytes->get_len();
            it->second->m_is_buf2 = true;
        } else {
            delete bytes;
            return;
        }

        if (send_tcp_data(it->second, id_dir)) {
            if (id_dir.m_dir == FROM_ADDR1 &&
                it->second->m_buf2.size() > 0) {
                fabs_id_dir id_dir2;
                id_dir2.m_id  = id_dir.m_id;
                id_dir2.m_dir = FROM_ADDR2;
                send_tcp_data(it->second, id_dir2);
            } else if (id_dir.m_dir == FROM_ADDR2 &&
                       it->second->m_buf1.size() > 0) {
                fabs_id_dir id_dir2;
                id_dir2.m_id  = id_dir.m_id;
                id_dir2.m_dir = FROM_ADDR1;
                send_tcp_data(it->second, id_dir2);
            }
        }

        break;
    }
    case STREAM_DESTROYED:
    {
        auto it = m_info.find(id_dir.m_id);

        if (it == m_info.end()) {
            delete bytes;
            return;
        }

        it->second->m_is_buf1 = true;
        it->second->m_is_buf2 = true;

        if (! it->second->m_buf1.empty()) {
            fabs_id_dir id_dir2 = id_dir;
            id_dir2.m_dir = FROM_ADDR1;
            send_tcp_data(it->second, id_dir2);
        }

        if (! it->second->m_buf2.empty()) {
            fabs_id_dir id_dir2 = id_dir;
            id_dir2.m_dir = FROM_ADDR2;
            send_tcp_data(it->second, id_dir2);
        }


        if (it->second->m_ifrule) {
            // invoke DESTROYED event
            int idx = it->second->m_hash % it->second->m_ifrule->m_balance;
            string &name = it->second->m_ifrule->m_balance_name[idx];

            spin_lock_read lock(m_appif.m_rw_mutex);

            auto it2 = m_appif.m_name2uxpeer.find(name);
            if (it2 != m_appif.m_name2uxpeer.end()) {
                for (auto it3 = it2->second.begin(); it3 != it2->second.end();
                     ++it3) {
                    m_appif.write_event(*it3, id_dir, it->second->m_ifrule,
                                        STREAM_DESTROYED, MATCH_NONE,
                                        &it->second->m_header, NULL, 0);
                }
            }
        }

        m_info.erase(it);
        delete bytes;

        break;
    }
    case STREAM_FIN:
    case STREAM_TIMEOUT:
    case STREAM_RST:
        // nothing to do
        delete bytes;
        break;
    default:
        assert(st_event != STREAM_CREATED);
    }
}

bool
fabs_appif::appif_consumer::send_tcp_data(ptr_info p_info, fabs_id_dir id_dir)
{
    bool is_classified = false;

    if (! p_info->m_ifrule && p_info->m_is_buf1 && p_info->m_is_buf2) {
        // classify
        ptr_ifrule ifrule;
        char buf1[4096], buf2[4096];
        int  len1, len2;

        len1 = read_bytes(p_info->m_buf1, buf1, sizeof(buf1));
        len2 = read_bytes(p_info->m_buf2, buf2, sizeof(buf2));

        for (auto it_tcp = m_ifrule_tcp.begin();
             it_tcp != m_ifrule_tcp.end(); ++it_tcp) {
            auto cache_up   = it_tcp->second->cache_up;
            auto cache_down = it_tcp->second->cache_down;

            // check cache
            if (m_appif.m_is_cache) {
                uint8_t idx;

                if (len1 > 0) {
                    idx = (uint8_t)buf1[0];
                    if (cache_up[idx] &&
                        RE2::PartialMatch(string(buf1, len1), *cache_up[idx]->m_up) &&
                        RE2::PartialMatch(string(buf2, len2), *cache_up[idx]->m_down)) {
                        ifrule = cache_up[idx];
                        is_classified = true;
                        p_info->m_match_dir[0] = MATCH_UP;
                        p_info->m_match_dir[1] = MATCH_DOWN;
                        p_info->m_ifrule = ifrule;

                        break;
                    } else if (cache_down[idx] &&
                               RE2::PartialMatch(string(buf1, len1), *cache_down[idx]->m_down) &&
                               RE2::PartialMatch(string(buf2, len2), *cache_down[idx]->m_up)) {
                        ifrule = cache_down[idx];
                        is_classified = true;
                        p_info->m_match_dir[0] = MATCH_DOWN;
                        p_info->m_match_dir[1] = MATCH_UP;
                        p_info->m_ifrule = ifrule;

                        break;
                    }
                }

                if (len2 > 0) {
                    idx = (uint8_t)buf2[0];
                    if (cache_up[idx] &&
                        RE2::PartialMatch(string(buf1, len1), *cache_up[idx]->m_up) &&
                        RE2::PartialMatch(string(buf2, len2), *cache_up[idx]->m_down)) {
                        ifrule = cache_up[idx];
                        is_classified = true;
                        p_info->m_match_dir[0] = MATCH_DOWN;
                        p_info->m_match_dir[1] = MATCH_UP;
                        p_info->m_ifrule = ifrule;

                        break;
                    } else if (cache_down[idx] &&
                               RE2::PartialMatch(string(buf1, len1), *cache_down[idx]->m_down) &&
                               RE2::PartialMatch(string(buf2, len2), *cache_down[idx]->m_up)) {
                        ifrule = cache_down[idx];
                        is_classified = true;
                        p_info->m_match_dir[0] = MATCH_UP;
                        p_info->m_match_dir[1] = MATCH_DOWN;
                        p_info->m_ifrule = ifrule;

                        break;
                    }
                }
            }

            // check list
            for (auto it1 = it_tcp->second->ifrule.begin();
                 it1 != it_tcp->second->ifrule.end(); ++it1) {
                if (m_appif.is_in_port((*it1)->m_port, id_dir.get_port_src(),
                               id_dir.get_port_dst())) {
                    if (RE2::PartialMatch(string(buf1, len1), *(*it1)->m_up) &&
                        RE2::PartialMatch(string(buf2, len2), *(*it1)->m_down)) {
                        ifrule = *it1;
                        is_classified = true;
                        p_info->m_match_dir[0] = MATCH_UP;
                        p_info->m_match_dir[1] = MATCH_DOWN;
                        p_info->m_ifrule = ifrule;

                        if (m_appif.m_is_cache) {
                            if (len1 > 0)
                                cache_up[(uint8_t)buf1[0]] = ifrule;

                            if (len2 > 0)
                                cache_down[(uint8_t)buf2[0]] = ifrule;
                        }

                        if (m_appif.m_is_lru) {
                            it_tcp->second->ifrule.erase(it1);
                            it_tcp->second->ifrule.push_front(ifrule);
                        }

                        goto brk;
                    } else if (RE2::PartialMatch(string(buf1, len1), *(*it1)->m_down) &&
                               RE2::PartialMatch(string(buf2, len2), *(*it1)->m_up)) {
                        ifrule = *it1;
                        is_classified = true;
                        p_info->m_match_dir[0] = MATCH_DOWN;
                        p_info->m_match_dir[1] = MATCH_UP;
                        p_info->m_ifrule = ifrule;

                        if (m_appif.m_is_cache) {
                            if (len1 > 0)
                                cache_down[(uint8_t)buf1[0]] = ifrule;

                            if (len2 > 0)
                                cache_up[(uint8_t)buf2[0]] = ifrule;
                        }

                        if (m_appif.m_is_lru) {
                            it_tcp->second->ifrule.erase(it1);
                            it_tcp->second->ifrule.push_front(ifrule);
                        }

                        goto brk;
                    }
                }
            }

            // check no regex list
            for (auto it2 = it_tcp->second->ifrule_no_regex.begin();
                 it2 != it_tcp->second->ifrule_no_regex.end(); ++it2) {
                if (m_appif.is_in_port((*it2)->m_port, id_dir.get_port_src(),
                               id_dir.get_port_dst())) {
                    ifrule = *it2;
                    is_classified = true;
                    p_info->m_ifrule = ifrule;

                    if (m_appif.m_is_lru) {
                        it_tcp->second->ifrule_no_regex.erase(it2);
                        it_tcp->second->ifrule_no_regex.push_front(ifrule);
                    }

                    goto brk;
                }
            }
        }

        if (! p_info->m_ifrule && m_appif.m_tcp_default) {
            // default I/F
            is_classified = true;
            p_info->m_ifrule = m_appif.m_tcp_default;
        }
    }

    brk:

    if (! p_info->m_ifrule) {
        // give up?
        if (p_info->m_dsize1 > 65536 * 2 || p_info->m_dsize2 > 65536 * 2) {
            p_info->m_is_giveup = true;
            p_info->clear_buf();
            return is_classified;
        } else if (p_info->m_dsize1 > 65536 || p_info->m_dsize2 > 65536) {
            p_info->m_is_buf1 = true;
            p_info->m_is_buf2 = true;
            return is_classified;
        }

        return false;
    }

    int idx = p_info->m_hash % p_info->m_ifrule->m_balance;
    string &name = p_info->m_ifrule->m_balance_name[idx];

    std::vector<int> fdvec;

    spin_lock_read(m_appif.m_rw_mutex);

    auto it = m_appif.m_name2uxpeer.find(name);

    if (it != m_appif.m_name2uxpeer.end()) {
        for (auto fd: it->second) {
            fdvec.push_back(fd);
        }
    }

    if (is_classified) {
        // invoke CREATED event
        for (auto fd: fdvec) {
            m_appif.write_event(fd, id_dir, p_info->m_ifrule,
                                STREAM_CREATED, MATCH_NONE,
                                &p_info->m_header, NULL, 0);
        }
    }

    // invoke DATA event and send data to I/F
    deque<fabs_bytes*> *bufs;

    if (id_dir.m_dir == FROM_ADDR1) {
        bufs = &p_info->m_buf1;
    } else if (id_dir.m_dir == FROM_ADDR2) {
        bufs = &p_info->m_buf2;
    } else {
        assert(false);
    }

    match_dir mdir;
    mdir = p_info->m_match_dir[id_dir.m_dir];

    while (! bufs->empty()) {
        auto front = bufs->front();

        for (auto fd: fdvec) {
            m_appif.write_event(fd, id_dir, p_info->m_ifrule,
                                STREAM_DATA, mdir,
                                &p_info->m_header,
                                front->get_head(),
                                front->get_len());
        }

        delete front;
        bufs->pop_front();
    }

    return is_classified;
}

bool
fabs_appif::write_event(int fd, const fabs_id_dir &id_dir, ptr_ifrule ifrule,
                        fabs_stream_event event, match_dir match,
                        fabs_appif_header *header, char *body, int bodylen)
{
    if (ifrule->m_format == IF_TEXT) {
        string s;
        char buf[256];

        s  = "ip1=";
        id_dir.get_addr1(buf, sizeof(buf));
        s += buf;

        s += ",ip2=";
        id_dir.get_addr2(buf, sizeof(buf));
        s += buf;

        s += ",port1=";
        s += boost::lexical_cast<string>(htons(id_dir.get_port1()));

        s += ",port2=";
        s += boost::lexical_cast<string>(htons(id_dir.get_port2()));

        s += ",hop=";
        s += boost::lexical_cast<string>((int)id_dir.m_id.m_hop);

        if (id_dir.m_id.get_l3_proto() == IPPROTO_IP) {
            s += ",l3=ipv4";
        } else if (id_dir.m_id.get_l3_proto() == IPPROTO_IPV6) {
            s += ",l3=ipv6";
        }

        if (id_dir.m_id.get_l4_proto() == IPPROTO_TCP) {
            s += ",l4=tcp";
        } else if (id_dir.m_id.get_l4_proto() == IPPROTO_UDP) {
            s += ",l4=udp";
        }

        switch (event) {
        case STREAM_CREATED:
            s += ",event=CREATED\n";
            break;
        case STREAM_DESTROYED:
            s += ",event=DESTROYED\n";
            break;
        case STREAM_DATA:
            s += ",event=DATA,from=";

            if (id_dir.m_dir == FROM_ADDR1) {
                s += "1,";
            } else if (id_dir.m_dir == FROM_ADDR2) {
                s += "2,";
            } else {
                s += "none,";
            }

            s += "match=";
            if (match == MATCH_UP) {
                s += "up";
            } else if (match == MATCH_DOWN) {
                s += "down";
            } else {
                s += "none";
            }

            s += ",len=";
            s += boost::lexical_cast<string>(bodylen);
            s += "\n";
            break;
        default:
            assert(false);
        }

        if (bodylen > 0 && ifrule->m_is_body) {
            iovec iov[2];

            iov[0].iov_base = const_cast<char*>(s.c_str());
            iov[0].iov_len  = s.size();

            iov[1].iov_base = body;
            iov[1].iov_len  = bodylen;

            writev(fd, iov, 2);
        } else {
            if (write(fd, s.c_str(), s.size()) < 0)
                return false;
        }
    } else {
        header->event    = event;
        header->from     = id_dir.m_dir;
        header->hop      = id_dir.m_id.m_hop;
        header->l3_proto = id_dir.m_id.get_l3_proto();
        header->l4_proto = id_dir.m_id.get_l4_proto();
        header->len      = bodylen;
        header->match    = match;

        if (bodylen > 0 && ifrule->m_is_body) {
            iovec iov[2];

            iov[0].iov_base = header;
            iov[0].iov_len  = sizeof(*header);

            iov[1].iov_base = body;
            iov[1].iov_len  = bodylen;

            writev(fd, iov, 2);
        } else {
            if (write(fd, header, sizeof(*header)) < 0)
                return false;
        }
    }

    return true;
}

fabs_appif::stream_info::stream_info(const fabs_id &id) :
    m_dsize1(0), m_dsize2(0), m_is_created(false), m_is_giveup(false),
    m_is_buf1(false), m_is_buf2(false)
{
    m_match_dir[0] = MATCH_NONE;
    m_match_dir[1] = MATCH_NONE;

    gettimeofday(&m_create_time, NULL);

    memset(&m_header, 0, sizeof(m_header));

    memcpy(&m_header.l3_addr1, &id.m_addr1->l3_addr,
           sizeof(m_header.l3_addr1));
    memcpy(&m_header.l3_addr2, &id.m_addr2->l3_addr,
           sizeof(m_header.l3_addr2));

    m_header.l4_port1 = id.m_addr1->l4_port;
    m_header.l4_port2 = id.m_addr2->l4_port;

    m_hash = id.get_hash();
}

fabs_appif::stream_info::~stream_info()
{
    clear_buf();
}

void
fabs_appif::stream_info::clear_buf()
{
    for (auto bytes: m_buf1) {
        delete bytes;
    }
    m_buf1.clear();

    for (auto bytes: m_buf2) {
        delete bytes;
    }
    m_buf2.clear();
}

bool
fabs_appif::is_in_port(boost::shared_ptr<std::list<std::pair<uint16_t, uint16_t> > > range,
                       uint16_t port1, uint16_t port2)
{
    if (range->empty())
        return true;

    for (auto it = range->begin(); it != range->end(); ++it) {
        if ((it->first <= ntohs(port1) && ntohs(port1) <= it->second) ||
            (it->first <= ntohs(port2) && ntohs(port2) <= it->second)) {
            return true;
        }
    }

    return false;
}


void
fabs_appif::appif_consumer::in_datagram(const fabs_id_dir &id_dir,
                                        fabs_bytes *bytes)
{
    uint8_t    idx = bytes->get_head()[0];
    ptr_ifrule ifrule;
    match_dir  match = MATCH_NONE;

    for (auto it_udp = m_ifrule_udp.begin(); it_udp != m_ifrule_udp.end();
         ++it_udp) {
        // check cache
        auto cache_udp = it_udp->second->cache_up;
        if (m_appif.m_is_cache && cache_udp[idx] &&
            m_appif.is_in_port(cache_udp[idx]->m_port,
                               id_dir.get_port_src(), id_dir.get_port_dst())) {

            ifrule = cache_udp[idx];

            assert(ifrule && ifrule->m_up);

            if (RE2::PartialMatch(string(bytes->get_head(), bytes->get_len()),
                                  *ifrule->m_up)) {
                // hit cache
                match = MATCH_UP;

                goto brk;
            }
        }

        // check list
        if (! it_udp->second->ifrule.empty()) {
            for (auto it1 = it_udp->second->ifrule.begin();
                 it1 != it_udp->second->ifrule.end(); ++it1) {
                if (m_appif.is_in_port((*it1)->m_port, id_dir.get_port_src(),
                                       id_dir.get_port_dst()) &&
                    RE2::PartialMatch(string(bytes->get_head(),
                                             bytes->get_len()),
                                      *(*it1)->m_up)) {
                    // found in list
                    ifrule = *it1;
                    match  = MATCH_UP;

                    // update cache and list
                    if (m_appif.m_is_cache)
                        cache_udp[idx] = ifrule;

                    if (m_appif.m_is_lru) {
                        it_udp->second->ifrule.erase(it1);
                        it_udp->second->ifrule.push_front(ifrule);
                    }

                    goto brk;
                }
            }
        }

        // check list of no regex
        for (auto it2 = it_udp->second->ifrule_no_regex.begin();
             it2 != it_udp->second->ifrule_no_regex.end(); ++it2) {

            if (m_appif.is_in_port((*it2)->m_port, id_dir.get_port_src(),
                                   id_dir.get_port_dst())) {
                // found in list
                ifrule = *it2;

                if (m_appif.m_is_lru) {
                    it_udp->second->ifrule_no_regex.push_front(*it2);
                    it_udp->second->ifrule_no_regex.erase(it2);
                }

                goto brk;
            }
        }
    }

    if (m_appif.m_udp_default)
        ifrule = m_appif.m_udp_default;

brk:
    if (! ifrule)
        return;


    fabs_appif_header header;

    memset(&header, 0, sizeof(header));

    memcpy(&header.l3_addr1, &id_dir.m_id.m_addr1->l3_addr,
           sizeof(header.l3_addr1));
    memcpy(&header.l3_addr2, &id_dir.m_id.m_addr2->l3_addr,
           sizeof(header.l3_addr2));

    header.l4_port1 = id_dir.m_id.m_addr1->l4_port;
    header.l4_port2 = id_dir.m_id.m_addr2->l4_port;
    header.event    = DATAGRAM_DATA;
    header.from     = id_dir.m_dir;
    header.hop      = id_dir.m_id.m_hop;
    header.l3_proto = id_dir.m_id.get_l3_proto();
    header.len      = bytes->get_len();
    header.match    = match;

    int idx2 = id_dir.m_id.get_hash() % ifrule->m_balance;
    string &name = ifrule->m_balance_name[idx2];

    spin_lock_read lock(m_appif.m_rw_mutex);

    auto it3 = m_appif.m_name2uxpeer.find(name);

    if (it3 != m_appif.m_name2uxpeer.end()) {
        for (auto it4 = it3->second.begin();
             it4 != it3->second.end(); ++it4) {
            if (! m_appif.write_event(*it4, id_dir, ifrule, STREAM_DATA,
                                      match, &header, bytes->get_head(),
                                      bytes->get_len())) {
                continue;
            }
        }
    }
}

void
fabs_appif::appif_consumer::consume()
{
    for (;;) {
        {
            // consume event
            boost::mutex::scoped_lock lock(m_mutex);
            while (m_ev_queue.get_len() == 0) {
                m_is_consuming = false;
                boost::system_time timeout = boost::get_system_time() + boost::posix_time::milliseconds(50);
                m_condition.timed_wait(lock, timeout);

                if (m_is_break)
                    return;
            }
            m_is_consuming = true;
        }

        appif_event *ev;
        while (m_ev_queue.pop(&ev)) {
            if (ev->id_dir.m_id.get_l4_proto() == IPPROTO_TCP) {
                in_stream_event(ev->st_event, ev->id_dir, ev->bytes);
            } else if (ev->id_dir.m_id.get_l4_proto() == IPPROTO_UDP) {
                in_datagram(ev->id_dir, ev->bytes);
                delete ev->bytes;
            } else {
                delete ev->bytes;
            }
            delete ev;
        }
    }
}

void
fabs_appif::appif_consumer::produce(appif_event *ev)
{
    // produce event
    while (! m_ev_queue.push(ev)) {
    }

    if (! m_is_consuming && m_ev_queue.get_len() > 1000) {
        boost::try_mutex::scoped_try_lock lock(m_mutex);
        if (lock)
            m_condition.notify_one();
    }
}

fabs_appif::appif_consumer::appif_consumer(int id, fabs_appif &appif) :
    m_id(id),
    m_is_break(false),
    m_is_consuming(false),
    m_appif(appif),
    m_thread(boost::bind(&fabs_appif::appif_consumer::consume, this))
{
    for (auto it_tcp = appif.m_ifrule_tcp.begin();
         it_tcp != appif.m_ifrule_tcp.end(); ++it_tcp) {
        ptr_ifrule_storage2 p = ptr_ifrule_storage2(new ifrule_storage2);

        p->ifrule = it_tcp->second->ifrule;
        p->ifrule_no_regex = it_tcp->second->ifrule_no_regex;

        m_ifrule_tcp[it_tcp->first] = p;
    }

    for (auto it_udp = appif.m_ifrule_udp.begin();
         it_udp != appif.m_ifrule_udp.end(); ++it_udp) {
        ptr_ifrule_storage2 p = ptr_ifrule_storage2(new ifrule_storage2);

        p->ifrule = it_udp->second->ifrule;
        p->ifrule_no_regex = it_udp->second->ifrule_no_regex;

        m_ifrule_udp[it_udp->first] = p;
    }
}

fabs_appif::appif_consumer::~appif_consumer()
{
    m_is_break = true;

    {
        boost::mutex::scoped_lock lock(m_mutex);
        m_condition.notify_one();
    }

    m_thread.join();
}

void
fabs_appif::print_info()
{
    spin_lock_read lock(m_rw_mutex);

    for (int i = 0; i < m_num_consumer; i++) {
        cout << "thread = " << m_consumer[i]->m_id << endl;
        for (auto it = m_consumer[i]->m_info.begin();
             it != m_consumer[i]->m_info.end(); ++it) {
            it->first.print_id();
        }
    }
}
