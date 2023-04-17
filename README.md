# IPK project 2 2022/2023 - network sniffer

# Requirements
- g++
- make

# Build and usage
```
make
./ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--ndp] [--mld] {-n num}
```

where

- -i eth0 (just one interface to sniff) or --interface. If this parameter is not specified list of active interfaces is printed
- -t or --tcp (will display TCP segments and is optionally complemented by -p functionality).
- -u or --udp (will display UDP datagrams and is optionally complemented by-p functionality).
- -p 23 (extends previous two parameters to filter TCP/UDP based on port number) part of TCP/UDP headers).
- --icmp4 (will display only ICMPv4 packets).
- --icmp6 (will display only ICMPv6 echo request/response).
- --arp (will display only ARP frames).
- --ndp (will display only ICMPv6 NDP packets).
- --igmp (will display only IGMP packets).
- --mld (will display only MLD packets).
- -n 10 (specifies the number of packets to display, i.e., the "time" the program runs; if not specified, consider displaying only one packet, i.e., as if -n 1)

# Theoretical foundations
It is neccessary to understand a few concepts, mainly the packets that are being captured

- TCP (Transmission Control Protocol): a connection-oriented protocol used to establish reliable, ordered, and error-checked streams of data between applications running on hosts on a network. It is a transport layer protocol, and it ensures that data is delivered in the correct order and that no data is lost or corrupted.
- UDP (User Datagram Protocol): a connectionless protocol that operates at the transport layer and is used for sending datagrams over an IP network. Unlike TCP, UDP does not establish a connection before sending data, and it does not provide any error checking or correction mechanisms.
- ARP (Address Resolution Protocol): a protocol used to map an IP address to a physical (MAC) address on a local network. It is used by network devices to send data to other devices on the same network.
- ICMPv4 (Internet Control Message Protocol version 4): a protocol used by network devices to send error messages and operational information about network conditions. It is used for diagnostics and troubleshooting and operates at the network layer of the OSI model.
- ICMPv6 (Internet Control Message Protocol version 6): similar to ICMPv4, but used in IPv6 networks.
- IGMP (Internet Group Management Protocol): a protocol used by hosts and adjacent multicast routers to establish multicast group memberships. It is used to manage multicast group memberships and to control the flow of multicast traffic on a network.
- NDP (Neighbor Discovery Protocol): a protocol used by IPv6 nodes to discover other nodes on the same link, and to determine the link-layer addresses of neighboring nodes. It is used to resolve IPv6 addresses to MAC addresses on a local network.
- MLD (Multicast Listener Discovery): similar to IGMP, but used in IPv6 networks to discover and manage multicast group memberships. It is used to control the flow of multicast traffic in an IPv6 network.

# Program
This program is using mainly pcap.h library for communication with interface and capturing packets. Then a list of other network libraries for parsing packet itself:
- arpa/inet.h
- netinet/tcp.h
- netinet/udp.h
- netinet/ip_icmp.h
- netinet/ether.h
- netinet/ip6.h

## Functions

### Main
``` cpp
int main(int argc, char* argv[])
```
- takes care of program arguments and of program flow

### Signal handler
``` cpp
/**
    * Function for handling Ctrl+C interrupt
    * @param signum - number of signal
*/
void signal_handler(int signum);
```
- reacts when user exits program with Ctrl+C

### Pcap handler
``` cpp
/**
    * Function for creating libpcap handle.
    * @param device - network interface name
    * @param filter - packet filter expression
    * @return pcap_t* - libpcap handle
    * @return NULL - error
    * @source - https://vichargrave.github.io/programming/develop-a-packet-sniffer-with-libpcap/#build-and-run-the-sniffer
*/
pcap_t* create_pcap_handle(char* device, char* filter);
```
- this function opens interface for packet capturing and sets filter (which protocols should be captured)
- it is copied from https://vichargrave.github.io/programming/develop-a-packet-sniffer-with-libpcap/#build-and-run-the-sniffer

### Packet handler
``` cpp
/**
    * Function for handling packets captured by libpcap.
    * @param user - user-defined pointer passed to pcap_loop()
    * @param packethdr - pointer to the packet header struct
    * @param packetptr - pointer to the packet data buffer
*/
void packet_handler(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr);
```

- handles packet captured by pcap_loop() function and prints packet in correct format

### Create filter

``` cpp
/**
    * Create packet filter expression based on options.
    * @param options - struct containing filter options
    * @return string - packet filter expression
*/
string create_filter(options_t options);

```
- creates filter based on user input


# Testing
Testing was done randomly and probably absolutely unsufficiently, I only started Wireshark with my at the same time sniffer and checked captured packets manually.


# References

[1] Pcap library [online] Available at: https://www.tcpdump.org/pcap.html

[2] Page how to write sniffer [online] Available at: https://vichargrave.github.io/programming/develop-a-packet-sniffer-with-libpcap/#build-and-run-the-sniffer

[3] Macro for argument parsing [online] Available at: https://stackoverflow.com/questions/1052746/getopt-does-not-parse-optional-arguments-to-parameters

[4] ICMPv6 protocol [online] Available at: https://en.wikipedia.org/wiki/ICMPv6

[5] libpcap prezentace FI MUNI [online] Publisher: FI MUNI, Brno, 1. 12. 2015, Jiří Novosad. Available at: https://is.muni.cz/el/fi/podzim2015/PB173/um/59281323/60427338/pb173_linux_10.pdf

and countless pages of stackoverflow questions...