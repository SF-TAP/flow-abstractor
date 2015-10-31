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

void
print_usage(char *cmd)
{
#ifdef USE_NETMAP
    cout << cmd << " -i [NIF] -c [CONFIG_FILE] -n\n"
         << cmd << " -i [NIF] -c [CONFIG_FILE] -b [PCAP_BUFSIZE]\n" << endl;
#else
    cout << cmd << " -i [NIF] -c [CONFIG_FILE] -b [PCAP_BUFSIZE]\n" << endl;
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
    bool is_netmap = false;
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

#ifdef USE_NETMAP
    if (is_netmap) {
        fabs_netmap nm(conf);
        nm.set_dev(dev);
        nm.run();
    } else {
        run_pcap(dev, conf, bufsize);
    }
#else
    run_pcap(dev, conf, bufsize);
#endif

    return 0;
}
