#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <string.h>
#include <time.h>
#include <bsd/string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>

void ethernet_func(u_int32_t length, const u_char *content);
void ip_func(u_int32_t length, const u_char *content);
void tcp_func(u_int32_t length, const u_char *content);
void udp_func(u_int32_t length, const u_char *content);

void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *content) {
    static int id = 1;
    struct tm *time;
    char timestr[16];
    time_t local_tv_sec;

    local_tv_sec = header->ts.tv_sec;
    time = localtime(&local_tv_sec);
    strftime(timestr, sizeof(timestr), "%H:%M:%S", time);

    printf("%d ", id++);
    printf("| time: %s.%.6ld ", timestr, header->ts.tv_usec);
    
    ethernet_func(header->caplen, content);
    printf("\n");
}

void ethernet_func(u_int32_t length, const u_char *content) {
    struct ether_header *ethernet = (struct ether_header *)content;
    char dst_mac_addr[20] = {};
    char src_mac_addr[20] = {};
    u_int16_t type;

    //十六進位轉成字串格式
    strlcpy(dst_mac_addr, ether_ntoa(ethernet->ether_dhost), sizeof(dst_mac_addr));
    strlcpy(src_mac_addr, ether_ntoa(ethernet->ether_shost), sizeof(src_mac_addr));

    type = ntohs(ethernet->ether_type);  //轉換為HBO

    printf("| Destination MAC Address: %17s ", dst_mac_addr);
    printf("| Source MAC Address: %17s ", src_mac_addr);
    printf("| Ethernet Type: 0x%04x |\n", type);

    if(type == ETHERTYPE_IP){
        ip_func(length, content);
    }
}


void ip_func(u_int32_t length, const u_char *content) {
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    u_char protocol = ip->ip_p;
    static char str[INET_ADDRSTRLEN];

    printf("IP  ");
    inet_ntop(AF_INET, &ip->ip_src, str, sizeof(str)); //轉換為十進位制ip地址
    printf("| Source IP Address: %15s ",  str);
    inet_ntop(AF_INET, &ip->ip_dst, str, sizeof(str));
    printf("| Destination IP Address: %15s |\n", str);

    if(protocol == IPPROTO_TCP){
        tcp_func(length, content);
    }
    else if(protocol == IPPROTO_UDP){
        udp_func(length, content);
    }
    
}

void tcp_func(u_int32_t length, const u_char *content) {
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    struct tcphdr *tcp = (struct tcphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));

    u_int16_t src_port = ntohs(tcp->th_sport); //轉換為HBO
    u_int16_t dst_port = ntohs(tcp->th_dport);
    
    printf("TCP ");
    printf("| Source Port: %5u | Destination Port: %5u|\n", src_port, dst_port);
}

void udp_func(u_int32_t length, const u_char *content) {
    struct ip *ip = (struct ip *)(content + ETHER_HDR_LEN);
    struct udphdr *udp = (struct udphdr *)(content + ETHER_HDR_LEN + (ip->ip_hl << 2));

    u_int16_t src_port = ntohs(udp->uh_sport); //轉換為HBO
    u_int16_t dst_port = ntohs(udp->uh_dport);

    printf("UDP ");
    printf("| Source Port: %5u | Destination Port: %5u|\n", src_port, dst_port);
}


int main(int argc, const char * argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *file = NULL;

    const char *filename = argv[1];

    file = pcap_open_offline(filename, errbuf); //開啟並讀取檔案
    pcap_loop(file, -1, pcap_callback, NULL);

    pcap_close(file);

    return 0;
}
