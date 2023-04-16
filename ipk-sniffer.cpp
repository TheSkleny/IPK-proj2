// IPK project 2 - network sniffer
// Author: David Sklenář - xsklen14
// Date: 2023/03/27

#include "ipk-sniffer.h"


void signal_handler(int signum) {
    // Terminate program
    exit(signum);
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
            options.port = atoi(optarg);
            break;
        case 't':
            options.tcp = "tcp ";
            break;
        case 'u':
            options.udp = "udp ";
            break;
        case 'a':
            options.arp = "arp ";
            break;
        case '4':
            options.icmp4 = "icmp4 ";
            break;
        case '6':
            options.icmp6 = "icmp6 ";
            break;
        case 'g':
            options.igmp = "igmp ";
            break;
        case 'm':
            options.mld = "mld ";
            break;
        case 'd':
            options.ndp = "ndp ";
            break;
        case 'n':
            options.num = atoi(optarg);
            break;
        case ':':
            if (optopt == 'i') {
                options.interface_name = "";
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
    if (options.interface_name == "" || argc == 1) {
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


    filter = options.arp + options.icmp4 + options.icmp6 + options.igmp + options.mld + options.tcp + options.udp + options.ndp;
    
    

    


    return 0;
}
