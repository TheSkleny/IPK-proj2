# IPK project 2 - network sniffer - Makefile
# Author: David Sklenář - xsklen14
# Date: 2023/03/27
all:
	g++ -Wall -Wextra -o ipk-sniffer ipk-sniffer.cpp -lpcap