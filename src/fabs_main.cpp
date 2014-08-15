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
    cout << cmd << " -i [NIF] -c [CONFIG_FILE]\n" << endl;
}

int
main(int argc, char *argv[])
{
    int opt;
    string dev;
    string conf;

    const char *optstr = "i:hc:s";

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
        case 'h':
        default:
            print_usage(argv[0]);
            return 0;
        }
    }

    run_pcap(dev, conf);

    return 0;
}
