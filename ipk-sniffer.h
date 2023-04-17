// IPK project 2 - network sniffer - header file
// Author: David Sklenář - xsklen14
// Date: 2023/03/27

#include <getopt.h>
#include <signal.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <ctime>
#include <pcap.h>
#include <iomanip>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
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

#define MAC_ADDR_STR(mac_addr, str) \
    sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x", \
            mac_addr[0], mac_addr[1], mac_addr[2], \
            mac_addr[3], mac_addr[4], mac_addr[5])

#define MAX_PORT 65535
#define BYTES_PER_LINE 16

typedef struct {
    string interface_name, arp, icmp4, icmp6, igmp, mld, tcp, udp, ndp;
    int port;
    int num;
} options_t;

options_t options;
pcap_t* handle;


/**
    * Function for handling Ctrl+C interrupt
    * @param signum - number of signal
*/
void signal_handler(int signum);

/**
    * Function for creating libpcap handle.
    * @param device - network interface name
    * @param filter - packet filter expression
    * @return pcap_t* - libpcap handle
    * @return NULL - error
    * @source - https://vichargrave.github.io/programming/develop-a-packet-sniffer-with-libpcap/#build-and-run-the-sniffer
*/
pcap_t* create_pcap_handle(char* device, char* filter);

/**
    * Function for handling packets captured by libpcap.
    * @param user - user-defined pointer passed to pcap_loop()
    * @param packethdr - pointer to the packet header struct
    * @param packetptr - pointer to the packet data buffer
*/
void packet_handler(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr);

/**
    * Create packet filter expression based on options.
    * @param options - struct containing filter options
    * @return string - packet filter expression
*/
string create_filter(options_t options);

