#include <getopt.h>
#include <signal.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <netinet/ip6.h>

using namespace std;

// SOURCE: https://stackoverflow.com/questions/1052746/getopt-does-not-parse-optional-arguments-to-parameters
// AUTHOR: https://stackoverflow.com/users/12979602/larsewi
#define OPTIONAL_ARGUMENT_IS_PRESENT \
    ((optarg == NULL && optind < argc && argv[optind][0] != '-') \
     ? (bool) (optarg = argv[optind++]) \
     : (optarg != NULL))

#define MAX_PORT 65535

typedef struct {
    string interface_name, arp, icmp4, icmp6, igmp, mld, tcp, udp, ndp;
    int port;
    int num;
} options_t;

options_t options;
pcap_t* handle;
