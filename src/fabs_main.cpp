#include "fabs.hpp"
#include "fabs_appif.hpp"

#include <unistd.h>
#include <signal.h>

#include <arpa/inet.h>

#include <netinet/in.h>

#include <openssl/x509.h>

#include <iostream>
#include <string>

using namespace std;

extern char *optarg;
extern int optind, opterr, optopt;
bool is_stats = false;

void
print_usage(char *cmd)
{
#ifdef USE_DIVERT
    cout << "if you want to use divert socket (FreeBSD/MacOS X only), use -d option\n\t"
         << cmd << " -d -4 [divert port for IPv4]\n\n"
         << "if you want to use pcap, use -p option\n\t"
         << "-c option tells configuration file"
         << "if -s option is specified, stats are printed out periodically"
         << cmd << " -p -i [NIF] -s"
         << endl;
#else
    cout << "-i option tells a network interface to capture\n\t"
         << "-c option tells configuration file\n"
         << "if -s option is specified, stats are printed out periodically"
         << cmd << " -i [NIF]" << endl;
#endif
}

int
main(int argc, char *argv[])
{
    int opt;
    string dev;
    string conf;

#ifdef USE_DIVERT
    int  dvt_port = 100;
    bool is_pcap  = true;
    const char *optstr = "d4:pi:hc:s";
#else
    const char *optstr = "i:hc:s";
#endif // USE_DIVERT

    signal( SIGPIPE , SIG_IGN ); 

    while ((opt = getopt(argc, argv, optstr)) != -1) {
        switch (opt) {
#ifdef USE_DIVER
        case 'd':
            is_pcap = false;
            break;
        case '4':
            dvt_port = atoi(optarg);
            break;
        case 'p':
            is_pcap = true;
            break;
#endif // USE_DIVERT
        case 'i':
            dev = optarg;
            break;
        case 'c':
            conf = optarg;
            break;
        case 's':
            is_stats = true;
            break;
        case 'h':
        default:
            print_usage(argv[0]);
            return 0;
        }
    }

#ifdef USE_DIVERT
    if (is_pcap) {
        run_pcap(dev, conf);
    } else {
        run_divert(dvt_port, conf);
    }
#else
    run_pcap(dev, conf);
#endif // USE_DIVERT

    return 0;
}
