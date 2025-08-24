#include <pcap.h>
#include <iostream>
#include <fstream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <iphlpapi.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wpcap.lib")
using namespace std;

// Windows doesn't have the same IP/TCP/UDP headers as Linux, so we define our own
typedef struct ip_header
{
    unsigned char ip_hl : 4;       // header length
    unsigned char ip_v : 4;        // version
    unsigned char ip_tos;          // type of service
    unsigned short ip_len;         // total length
    unsigned short ip_id;          // identification
    unsigned short ip_off;         // fragment offset field
    unsigned char ip_ttl;          // time to live
    unsigned char ip_p;            // protocol
    unsigned short ip_sum;         // checksum
    struct in_addr ip_src, ip_dst; // source and dest address
} ip_header;

typedef struct tcp_header
{
    u_short th_sport; // source port
    u_short th_dport; // destination port
    u_int th_seq;     // sequence number
    u_int th_ack;     // acknowledgement number
    u_char th_offx2;  // data offset, rsvd
    u_char th_flags;  // flags
    u_short th_win;   // window
    u_short th_sum;   // checksum
    u_short th_urp;   // urgent pointer
} tcp_header;

typedef struct udp_header
{
    u_short uh_sport; // source port
    u_short uh_dport; // destination port
    u_short uh_ulen;  // udp length
    u_short uh_sum;   // udp checksum
} udp_header;

struct Packet
{
    string srcIP, destIP, protocol;
    int srcPort, destPort, size;
    time_t timestamp;
};

ofstream logfile("packets.csv", ios::app);

// Packet handler function
void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    // Ethernet header is 14 bytes, then IP header starts
    ip_header *iph = (ip_header *)(packet + 14);

    Packet pkt;
    pkt.timestamp = pkthdr->ts.tv_sec;
    pkt.size = pkthdr->len;

    // Use inet_ntoa for compatibility (older Windows versions)
    pkt.srcIP = inet_ntoa(iph->ip_src);
    pkt.destIP = inet_ntoa(iph->ip_dst);

    // Detect protocol
    if (iph->ip_p == IPPROTO_TCP)
    {
        pkt.protocol = "TCP";
        tcp_header *tcpHeader = (tcp_header *)(packet + 14 + (iph->ip_hl * 4));
        pkt.srcPort = ntohs(tcpHeader->th_sport);
        pkt.destPort = ntohs(tcpHeader->th_dport);
    }
    else if (iph->ip_p == IPPROTO_UDP)
    {
        pkt.protocol = "UDP";
        udp_header *udpHeader = (udp_header *)(packet + 14 + (iph->ip_hl * 4));
        pkt.srcPort = ntohs(udpHeader->uh_sport);
        pkt.destPort = ntohs(udpHeader->uh_dport);
    }
    else if (iph->ip_p == IPPROTO_ICMP)
    {
        pkt.protocol = "ICMP";
        pkt.srcPort = pkt.destPort = 0;
    }
    else
    {
        pkt.protocol = "Other";
        pkt.srcPort = pkt.destPort = 0;
    }

    // Log to CSV
    logfile << pkt.timestamp << "," << pkt.srcIP << "," << pkt.destIP << ","
            << pkt.srcPort << "," << pkt.destPort << "," << pkt.protocol << ","
            << pkt.size << endl;

    // Print on console
    cout << "Captured: " << pkt.srcIP << " -> " << pkt.destIP
         << " [" << pkt.protocol << "] " << pkt.size << " bytes" << endl;
}

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *device;

    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        cerr << "WSAStartup failed" << endl;
        return -1;
    }

    // Find network devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        cerr << "Error finding devices: " << errbuf << endl;
        WSACleanup();
        return -1;
    }

    if (alldevs == NULL)
    {
        cerr << "No network devices found!" << endl;
        WSACleanup();
        return -1;
    }

    device = alldevs; // Use the first device
    cout << "Using device: " << device->description << endl;

    pcap_t *handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (!handle)
    {
        cerr << "Couldn't open device: " << errbuf << endl;
        pcap_freealldevs(alldevs);
        WSACleanup();
        return -1;
    }

    // Add header to CSV
    if (logfile.tellp() == 0)
    { // Only write header if file is empty
        logfile << "timestamp,srcIP,destIP,srcPort,destPort,protocol,size\n";
    }

    cout << "Capturing 100 packets..." << endl;
    pcap_loop(handle, 100, packetHandler, NULL);

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    logfile.close();
    WSACleanup();
    cout << "Capture complete. Data saved to packets.csv" << endl;

    return 0;
}