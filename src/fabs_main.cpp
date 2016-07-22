#include "fabs_common.hpp"
#include "fabs.hpp"
#include "fabs_appif.hpp"
#include "fabs_pcap.hpp"
#include "fabs_conf.hpp"

#ifdef USE_NETMAP
    #include "fabs_netmap.hpp"
#endif // USE_NETMAP

#include <unistd.h>
#include <signal.h>

#include <arpa/inet.h>

#include <netinet/in.h>

#include <iostream>
#include <string>

#include <boost/lexical_cast.hpp>

using namespace std;

extern char *optarg;
extern int optind, opterr, optopt;
bool is_stats = false;
fabs_pcap *pc;

#ifdef USE_NETMAP
bool is_netmap = false;
fabs_netmap *nm;
#endif // USE_NETMAP

volatile bool is_break = false;

void
print_usage(char *cmd)
{
#ifdef USE_NETMAP
    cout << "netmap: " << cmd << " -i dev -c conf -n\n"
         << "pcap:   " << cmd << " -i dev -c conf [-b bufsize]\n" << endl;
#else
    cout << cmd << " -i dev -c conf [-b bufsize]\n" << endl;
#endif // USE_NETMAP
}

namespace fs = boost::filesystem;

void
remove_uxfile(fabs_conf &conf)
{
    fs::path home;
    {
        auto it = conf.m_conf.find("global");
        if (it != conf.m_conf.end()) {
            auto it2 = it->second.find("home");
            home = it2->second;
        }
    }

    for (auto &pair: conf.m_conf) {
        if (pair.first == "global")
            continue;

        auto interface = pair.second.find("if");
        if (interface == pair.second.end())
            continue;

        if (pair.first == "loopback7" || pair.first == "pcap") {
            fs::path uxfile = home / interface->second;
            std::cout << "unlink " << uxfile.string() << std::endl;
            remove(uxfile.string().c_str());
        } else {
            auto proto = pair.second.find("proto");
            if (proto == pair.second.end())
                continue;

            std::string protostr;
            if (proto->second == "TCP")
                protostr = "tcp";
            else if (proto->second == "UDP")
                protostr = "udp";
            else
                continue;

            auto balance = pair.second.find("balance");
            if (balance == pair.second.end()) {
                fs::path uxfile = home / protostr / interface->second;
                std::cout << "unlink " << uxfile.string() << std::endl;
                remove(uxfile.string().c_str());
            } else {
                int num = atoi(balance->second.c_str());
                for (int i = 0; i < num; i++) {
                    fs::path uxfile = home / protostr / (interface->second + boost::lexical_cast<std::string>(i));
                    std::cout << "unlink " << uxfile.string() << std::endl;
                    remove(uxfile.string().c_str());
                }
            }
        }
    }
}

int
main(int argc, char *argv[])
{
    int opt;
    int bufsize = 10000;
    string dev;
    string confpath;

#ifdef USE_NETMAP
    const char *optstr = "i:hc:sb:n";
#else
    const char *optstr = "i:hc:sb:";
#endif // USE_NETMAP

    while ((opt = getopt(argc, argv, optstr)) != -1) {
        switch (opt) {
        case 'i':
            dev = optarg;
            break;
        case 'c':
            confpath = optarg;
            break;
        case 's':
            is_stats = true;
            break;
        case 'b':
            bufsize = atoi(optarg);
            break;
#ifdef USE_NETMAP
        case 'n':
            is_netmap = true;
            break;
#endif // USE_NETMAP
        case 'h':
        default:
            print_usage(argv[0]);
            return 0;
        }
    }

    fabs_conf conf;
    if (! conf.read_conf(confpath)) {
        std::cerr << "error: could not read config file" << std::endl;
        exit(1);
    }

    sigset_t sigpipe_mask;
    sigemptyset(&sigpipe_mask);
    sigaddset(&sigpipe_mask, SIGPIPE);
    if (pthread_sigmask(SIG_BLOCK, &sigpipe_mask, NULL) == -1) {
        perror("pthread_sigmask");
        exit(1);
    }

    pid_t result_pid;

    result_pid = fork();
    if (result_pid < 0) {
        perror("fork");
        exit(1);
    } else if (result_pid > 0) {
        sigemptyset(&sigpipe_mask);
        sigaddset(&sigpipe_mask, SIGINT);
        if (pthread_sigmask(SIG_BLOCK, &sigpipe_mask, NULL) == -1) {
            perror("pthread_sigmask");
            exit(1);
        }

        int status;
        waitpid(result_pid, &status, 0);
        std::cout << "wait!" << std::endl;

        remove_uxfile(conf);
        return 0;
    }


    if (dev.empty()) {
        fabs_ether ether(conf, nullptr);
        for (;;) {
            sleep(1000000);
        }
    }

#ifdef USE_NETMAP
    if (is_netmap) {
        nm = new fabs_netmap(conf);

        set_sig_handler();

        nm->set_dev(dev);
        nm->run();

        delete nm;
        return 0;
    }
#endif // USE_NETMAP

    SET_THREAD_NAME(pthread_self(), "SF-TAP main");

    pc = new fabs_pcap(conf);

    pc->set_dev(dev);
    pc->set_bufsize(bufsize);
    pc->run();

    delete pc;
    return 0;
}
