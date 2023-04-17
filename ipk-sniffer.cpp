// IPK project 2 - network sniffer
// Author: David Sklenář - xsklen14
// Date: 2023/03/27

#include "ipk-sniffer.h"


void signal_handler(int signum) {
    // Terminate program
    pcap_close(handle);
    exit(signum);
}


/*
    * Function for creating libpcap handle.
    * @param device - network interface name
    * @param filter - packet filter expression
    * @return pcap_t* - libpcap handle
    * @return NULL - error
    * @source - https://vichargrave.github.io/programming/develop-a-packet-sniffer-with-libpcap/#build-and-run-the-sniffer
*/
pcap_t* create_pcap_handle(char* device, char* filter) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    struct bpf_program bpf;
    bpf_u_int32 netmask;
    bpf_u_int32 srcip;

    // Get network device source IP address and netmask.
    if (pcap_lookupnet(device, &srcip, &netmask, errbuf) == PCAP_ERROR) {
        cerr << "pcap_lookupnet(): " << errbuf << endl;
        return NULL;
    }

    // Open the device for live capture.
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        cerr << "pcap_open_live(): " << errbuf << endl;
        return NULL;
    }

    // Convert the packet filter epxression into a packet filter binary.
    if (pcap_compile(handle, &bpf, filter, 0, netmask) == PCAP_ERROR) {
        cerr << "pcap_compile(): " << pcap_geterr(handle) << endl;
        return NULL;
    }

    // Bind the packet filter to the libpcap handle.
    if (pcap_setfilter(handle, &bpf) == PCAP_ERROR) {
        cerr << "pcap_setfilter(): " << pcap_geterr(handle) << endl;
        return NULL;
    }

    return handle;
}

void packet_handler(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr) {

    // Convert the packet timestamp to a time_t structure
    time_t timestamp_sec = packethdr->ts.tv_sec;
    struct tm *tm_info = localtime(&timestamp_sec);

    // Print the timestamp
    char timestamp[80];
    strftime(timestamp, 80, "%Y-%m-%dT%H:%M:%S", tm_info);
    char milliseconds[5];
    snprintf(milliseconds, sizeof(milliseconds), ".%03ld", packethdr->ts.tv_usec);
    strncat(timestamp, milliseconds, 5);
    char timezone[8];
    strftime(timezone, sizeof(timezone), "%z", tm_info);
    strncat(timestamp, timezone, 8);

    
    cout << "timestamp: " << timestamp << endl;

    //Print source and destination MAC addresses
    struct ether_header *eth_header = (struct ether_header *) packetptr;
    char src_mac[18];
    char dst_mac[18];
    MAC_ADDR_STR(eth_header->ether_shost, src_mac);
    MAC_ADDR_STR(eth_header->ether_dhost, dst_mac);
    cout << "src MAC: " << src_mac << endl;
    cout << "dst MAC: " << dst_mac << endl;

    // Print the packet length
    cout << "frame length: " << packethdr->len << endl;

    uint16_t eth_type = ntohs(eth_header->ether_type);
    if (eth_type == ETHERTYPE_IP) {
        // IPv4
        struct ip *ip_header = (struct ip *) (packetptr + sizeof(struct ether_header));
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
        cout << "src IP: " << src_ip << endl;
        cout << "dst IP: " << dst_ip << endl;
        if (ip_header->ip_p == IPPROTO_TCP) {
            // TCP
            struct tcphdr *tcp_header = (struct tcphdr *) (packetptr + sizeof(struct ether_header) + sizeof(struct ip));
            uint16_t src_port = ntohs(tcp_header->th_sport);
            uint16_t dst_port = ntohs(tcp_header->th_dport);
            cout << "src port: " << src_port << endl;
            cout << "dst port: " << dst_port << endl;
        } else if (ip_header->ip_p == IPPROTO_UDP) {
            // UDP
            struct udphdr *udp_header = (struct udphdr *) (packetptr + sizeof(struct ether_header) + sizeof(struct ip));
            uint16_t src_port = ntohs(udp_header->uh_sport);
            uint16_t dst_port = ntohs(udp_header->uh_dport);
            cout << "src port: " << src_port << endl;
            cout << "dst port: " << dst_port << endl;
        } else if (ip_header->ip_p == IPPROTO_ICMP) {
            // ICMP
            cout << "ICMP" << endl;
        }
    } else if (eth_type == ETHERTYPE_IPV6) {
        // IPv6
        cout << "IPv6" << endl;
        struct ip6_hdr *ip6_header = (struct ip6_hdr *) (packetptr + sizeof(struct ether_header));
        char src_ip6[INET6_ADDRSTRLEN];
        char dst_ip6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip6, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip6, INET6_ADDRSTRLEN);
        cout << "src IP: " << src_ip6 << endl;
        cout << "dst IP: " << dst_ip6 << endl;
        if (ip6_header->ip6_nxt == IPPROTO_TCP) {
            // TCP
            struct tcphdr *tcp_header = (struct tcphdr *) (packetptr + sizeof(struct ether_header) + sizeof(struct ip));
            uint16_t src_port = ntohs(tcp_header->th_sport);
            uint16_t dst_port = ntohs(tcp_header->th_dport);
            cout << "src port: " << src_port << endl;
            cout << "dst port: " << dst_port << endl;
        } else if (ip6_header->ip6_nxt == IPPROTO_UDP) {
            // UDP
            struct tcphdr *tcp_header = (struct tcphdr *) (packetptr + sizeof(struct ether_header) + sizeof(struct ip));
            uint16_t src_port = ntohs(tcp_header->th_sport);
            uint16_t dst_port = ntohs(tcp_header->th_dport);
            cout << "src port: " << src_port << endl;
            cout << "dst port: " << dst_port << endl;
        } else if (ip6_header->ip6_nxt == IPPROTO_ICMPV6) {
            // ICMPv6
            cout << "ICMPv6" << endl;
        }
    } else if (eth_type == ETHERTYPE_ARP) {
        // ARP
        cout << "ARP" << endl;
    }
    else {
        cout << "Unknown" << endl;
    }


    
}

string create_filter(options_t options){
    string filter = "";
    bool first = true;
    if (options.arp != "") {
        if (first) {
            filter += "arp";
            first = false;
        } else {
            filter += " or arp";
        }
    }
    if (options.icmp4 != "") {
        if (first) {
            filter += "icmp";
            first = false;
        } else {
            filter += " or icmp";
        }
    }
    if (options.icmp6 != "") {
        if (first) {
            filter += "icmp6";
            first = false;
        } else {
            filter += " or icmp6";
        }
    }
    if (options.igmp != "") {
        if (first) {
            filter += "igmp";
            first = false;
        } else {
            filter += " or igmp";
        }
    }
    if (options.mld != "") {
        if (first) {
            filter += "(icmp6 and icmp6[0] == 143)";
            first = false;
        } else {
            filter += " or (icmp6 and icmp6[0] == 143)";
        }
    }
    if (options.tcp != "") {
        if (options.port != -1) {
            if (first) {
                filter += "(tcp port " + to_string(options.port) + ")";
                first = false;
            } else {
                filter += " or (tcp port " + to_string(options.port) + ")";
            }
        } else {
            if (first) {
                filter += "tcp";
                first = false;
            } else {
                filter += " or tcp";
            }
        }
    }
    if (options.udp != "") {
        if (options.port != -1) {
            if (first) {
                filter += "(udp port " + to_string(options.port) + ")";
                first = false;
            } else {
                filter += " or (udp port " + to_string(options.port) + ")";
            }
        } else {
            if (first) {
                filter += "udp";
                first = false;
            } else {
                filter += " or udp";
            }
        }
    }
    if (options.ndp != "") {
        if (first) {
            filter += "(icmp6 and (icmp6[0] == 135 or icmp6[0] == 136 or icmp6[0] == 137))";
            first = false;
        } else {
            filter += " or (icmp6 and (icmp6[0] == 135 or icmp6[0] == 136 or icmp6[0] == 137))";
        }
    }
    return filter;

}

int main(int argc, char* argv[]) {
    string filter = "";

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
        {"ndp", no_argument, 0, 'd'},
        {0, 0, 0, 0}
    };

    int option_index = 0;
    int opt;

    // Set default values
    options.interface_name = "";
    options.port = -1;
    options.arp = "";
    options.icmp4 = "";
    options.icmp6 = "";
    options.igmp = "";
    options.mld = "";
    options.tcp = "";
    options.udp = "";
    options.num = 1;
    while ((opt = getopt_long(argc, argv, "i::p:tua46gmdn:", long_options, &option_index)) != -1) {
        //cout << "option: " << static_cast<char>(opt) << endl;
        switch (opt) {
        case 'i':
            if (OPTIONAL_ARGUMENT_IS_PRESENT) {
                options.interface_name = optarg;
            }
            break;
        case 'p':
            if (options.port != -1) {
                cerr << "Error: Port is already set." << endl;
                return 1;
            }
            options.port = atoi(optarg);
            break;
        case 't':
            if (options.tcp != "") {
                cerr << "Error: TCP is already set." << endl;
                return 1;
            }
            options.tcp = "tcp";
            break;
        case 'u':
            if (options.udp != "") {
                cerr << "Error: UDP is already set." << endl;
                return 1;
            }
            options.udp = "udp";
            break;
        case 'a':
            if (options.arp != "") {
                cerr << "Error: ARP is already set." << endl;
                return 1;
            }
            options.arp = "arp";
            break;
        case '4':
            if (options.icmp4 != "") {
                cerr << "Error: ICMP4 is already set." << endl;
                return 1;
            }
            options.icmp4 = "icmp4";
            break;
        case '6':
            if (options.icmp6 != "") {
                cerr << "Error: ICMP6 is already set." << endl;
                return 1;
            }
            options.icmp6 = "icmp6";
            break;
        case 'g':
            if (options.igmp != "") {
                cerr << "Error: IGMP is already set." << endl;
                return 1;
            }
            options.igmp = "igmp";
            break;
        case 'm':
            if (options.mld != "") {
                cerr << "Error: MLD is already set." << endl;
                return 1;
            }
            options.mld = "mld";
            break;
        case 'd':
            if (options.ndp != "") {
                cerr << "Error: NDP is already set." << endl;
                return 1;
            }
            options.ndp = "ndp";
            break;
        case 'n':
            if (options.num != 1) {
                cerr << "Error: Number of packets is already set." << endl;
                return 1;
            }
            options.num = atoi(optarg);
            break;
        case ':':
            cerr << "Option requires an argument: " << static_cast<char>(optopt) << endl;
            break;
        case '?':
            cerr << "Invalid option: " << static_cast<char>(optopt) << endl;
            break;
        default:
            cerr << "Unknown option: " << static_cast<char>(optopt) << endl;
            break;
        }

    }
    if (options.interface_name == "") {
        char error_buffer[PCAP_ERRBUF_SIZE];
        pcap_if_t* all_interfaces;
        if (pcap_findalldevs(&all_interfaces, error_buffer) == -1) {
            cerr << "Error: " << error_buffer << endl;
            return 1;
        }
        vector<string> interface_names;
        for (pcap_if_t* interface = all_interfaces; interface; interface = interface->next) {
            interface_names.push_back(interface->name);
        }
        pcap_freealldevs(all_interfaces);
        for (const auto& name : interface_names) {
            cerr << name << endl;
        }
        return 0;
    }

    signal(SIGINT, signal_handler);

    if (options.port != -1 && (options.port < 0 || options.port > MAX_PORT)) {
        cerr << "Invalid port number: " << options.port << endl;
        return 1;
    }
    if (options.port != -1 && (options.tcp == "" && options.udp == "")) {
        cerr << "Port number is set but no protocol is set." << endl;
        return 1;
    }

    if (options.num < 0 && options.num != -1) {
        cerr << "Invalid number of packets: " << options.num << endl;
        return 1;
    }

    if (options.tcp == "" && options.udp == "" && options.arp == "" && 
        options.icmp4 == "" && options.icmp6 == "" && options.igmp == "" && 
        options.mld == "" && options.ndp == "") {
        filter = "tcp or udp or arp or icmp or icmp6 or igmp or (icmp6 and icmp6[0] == 143) or (icmp6 and (icmp6[0] == 135 or icmp6[0] == 136 or icmp6[0] == 137))";
    }
    else {
        filter = create_filter(options);
    }
    //cout << "Filter: " << filter << endl;
    




    handle = create_pcap_handle((char *)options.interface_name.c_str(), (char *)filter.c_str());
    if(handle == NULL) {
        return 1;
    }
    int link_type;
    if ((link_type = pcap_datalink(handle)) < 0) {
        cerr << "pcap_datalink():" << pcap_geterr(handle) << endl;
        return -1;
    }
    if (link_type != DLT_EN10MB) {
        cerr << "This program only supports Ethernet." << endl;
        return -1;
    }


    if (pcap_loop(handle, options.num, packet_handler, (u_char*)NULL) < 0) {
        cerr << "pcap_loop():" << pcap_geterr(handle) << endl;
	    return -1;
    }

    pcap_close(handle);
    return 0;
}
