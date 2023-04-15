// IPK project 2 - network sniffer
// Author: David Sklenář - xsklen14
// Date: 2023/03/27

#include <getopt.h>
#include <signal.h>
#include <iostream>
#include <vector>
#include <string>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <netinet/ip6.h>

using namespace std;


// stolen from https://stackoverflow.com/questions/1052746/getopt-does-not-parse-optional-arguments-to-parameters
#define OPTIONAL_ARGUMENT_IS_PRESENT \
    ((optarg == NULL && optind < argc && argv[optind][0] != '-') \
     ? (bool) (optarg = argv[optind++]) \
     : (optarg != NULL))





int main(int argc, char* argv[]) {

    static struct option long_options[] = {
        {"interface", optional_argument, 0, 'i'},
        {"tcp", no_argument, 0, 't'},
        {"udp", no_argument, 0, 'u'},
        {"arp", no_argument, 0, 'a'},
        {"icmp4", no_argument, 0, '4'},
        {"icmp6", no_argument, 0, '6'},
        {"igmp", no_argument, 0, 'g'},
        {"mld", no_argument, 0, 'm'},
        {"port", required_argument, 0, 'p'},
        {"num", required_argument, 0, 'n'},
        {0, 0, 0, 0}
    };

    int option_index = 0;
    int opt;

    // Set default values
    string interface_name = "";
    int port = -1;
    bool arp = false, icmp4 = false, icmp6 = false, igmp = false, mld = false, tcp = false, udp = false;
    int num = 1;
    while ((opt = getopt_long(argc, argv, "i::p:tua46gmn:", long_options, &option_index)) != -1) {
        //cout << "option: " << static_cast<char>(opt) << endl;
        switch (opt) {
        case 'i':
            if (OPTIONAL_ARGUMENT_IS_PRESENT) {
                interface_name = optarg;
            }
            break;
        case 'p':
            port = atoi(optarg);
            break;
        case 't':
            tcp = true;
            break;
        case 'u':
            udp = true;
            break;
        case 'a':
            arp = true;
            break;
        case '4':
            icmp4 = true;
            break;
        case '6':
            icmp6 = true;
            break;
        case 'g':
            igmp = true;
            break;
        case 'm':
            mld = true;
            break;
        case 'n':
            num = atoi(optarg);
            break;
        case ':':
            if (optopt == 'i') {
                interface_name = "";
            } else {
                cerr << "Option requires an argument: " << static_cast<char>(optopt) << endl;
            }
            break;
        case '?':
            cerr << "Invalid option: " << static_cast<char>(optopt) << endl;
            break;
        default:
            cerr << "Unknown option: " << static_cast<char>(optopt) << endl;
            break;
        }

    }
    if (interface_name == "" || argc == 1) {
        char error_buffer[PCAP_ERRBUF_SIZE];
        pcap_if_t* all_interfaces;
        if (pcap_findalldevs(&all_interfaces, error_buffer) == -1) {
            cout << "Error: " << error_buffer << endl;
            return 1;
        }
        vector<string> interface_names;
        for (pcap_if_t* interface = all_interfaces; interface; interface = interface->next) {
            interface_names.push_back(interface->name);
        }
        pcap_freealldevs(all_interfaces);
        for (const auto& name : interface_names) {
            cout << name << endl;
        }
        return 0;
    }

    if (pcap_descriptor = open_pcap_socket(interface, filter)) {
        
    }
    // Capture packets and analyze them
    pcap_loop(handle, num, analyze_packet, reinterpret_cast<u_char*>(&port));

    // Close the packet capture handle
    pcap_close(handle);



    return 0;
}