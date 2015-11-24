#include "fabs_common.hpp"
#include "fabs.hpp"
#include "fabs_appif.hpp"
#include "fabs_pcap.hpp"

#ifdef USE_NETMAP
    #include "fabs_netmap.hpp"
#endif // USE_NETMAP

#include <unistd.h>
#include <signal.h>

#include <arpa/inet.h>

#include <netinet/in.h>

#include <iostream>
#include <string>

using namespace std;

extern char *optarg;
extern int optind, opterr, optopt;
bool is_stats = false;

#ifdef USE_NETMAP
bool is_netmap = false;
fabs_netmap *nm;
#endif // USE_NETMAP

void
sig_handler(int s)
{
#ifdef USE_NETMAP
    std::cout << "SIGINT!" << std::endl;
    if (is_netmap) {
        nm->stop();
    } else {
        stop_pcap();
    }
#else
    stop_pcap();
#endif // USE_NETMAP
}

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

int
main(int argc, char *argv[])
{
    int opt;
    int bufsize = 10000;
    string dev;
    string conf;

#ifdef USE_NETMAP
    const char *optstr = "i:hc:sb:n";
#else
    const char *optstr = "i:hc:sb:";
#endif // USE_NETMAP

    signal( SIGPIPE , SIG_IGN ); 

    while ((opt = getopt(argc, argv, optstr)) != -1) {
        switch (opt) {
        case 'i':
            dev = optarg;
            break;
        case 'c':
            conf = optarg;
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

    struct sigaction sigact;

    sigact.sa_handler = sig_handler;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = 0;

    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);

#ifdef USE_NETMAP
    if (is_netmap) {
        nm = new fabs_netmap(conf);
        nm->set_dev(dev);
        nm->run();
        delete nm;
    } else {
        run_pcap(dev, conf, bufsize);
    }
#else
    run_pcap(dev, conf, bufsize);
#endif

    return 0;
}
