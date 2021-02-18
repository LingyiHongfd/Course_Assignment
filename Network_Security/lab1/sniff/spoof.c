#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>

int num = 0;

typedef struct eth_hdr
{
    unsigned char dst_mac[6];
    unsigned char src_mac[6];
    unsigned short eth_type;
} eth_hdr;
eth_hdr *ethernet;

typedef struct ip_hdr
{
    char ip_ver;
    char ip_tos;
    unsigned short ip_totalen;
    unsigned short ident;
    unsigned short ip_flags;
    unsigned char ip_ttl;
    unsigned char ip_protocol;
    unsigned short ip_cksum;
    struct in_addr ip_srcip;
    struct in_addr ip_dstip;

} ip_hdr;
ip_hdr *ip;

typedef struct icmp_hdr
{
    char icmp_type;
    char icmp_code;
    unsigned short icmp_chksum;
    unsigned short icmp_id;
    unsigned short icmp_seq;
    unsigned long long icmp_timestamp;

} icmp_hdr;
icmp_hdr *icmp;

// 获取校验和
unsigned short get_checksum(unsigned short *buffer, int size)
{
    unsigned long cksum = 0;
    while (size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(unsigned short);
    }
    if (size)
        cksum += *(unsigned char *)buffer;
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (unsigned short)(~cksum);
}

void reply(u_char *args, const struct pcap_pkthdr *header, const u_char *packet_content)
{
    // 分析报文
    u_int eth_len = sizeof(struct eth_hdr);
    u_int ip_len = sizeof(struct ip_hdr);
    u_int icmp_len = sizeof(struct icmp_hdr);
    u_int load_end = 0;
    size_t load_len = 0;
    ip = (ip_hdr *)(packet_content + eth_len);

    if (ip->ip_protocol == 1)
    {
        icmp = (icmp_hdr *)(packet_content + eth_len + ip_len);

        if (icmp->icmp_type != 8)
            return;
        num++;
        printf("\n[%d] Got a request\n", num);

        load_end = ntohs(ip->ip_totalen) + eth_len;
        load_len = load_end - (eth_len + ip_len + icmp_len);

        char load[load_len];

        strncpy(load, packet_content + eth_len + ip_len + icmp_len, load_len);

        // 构造假的icmp报文

        char buffer[2000];
        memset(buffer, 0, 2000);

        struct icmp_hdr *send_icmp = (struct icmp_hdr *)(buffer + sizeof(struct ip_hdr));
        send_icmp->icmp_type = 0;
        send_icmp->icmp_code = 0;

        send_icmp->icmp_id = icmp->icmp_id;
        send_icmp->icmp_seq = icmp->icmp_seq;
        send_icmp->icmp_timestamp = icmp->icmp_timestamp;

        send_icmp->icmp_chksum = 0;

        struct ip_hdr *send_ip = (struct ip_hdr *)buffer;
        send_ip->ip_ver = 69;
        send_ip->ip_ttl = 20;
        send_ip->ip_srcip.s_addr = ip->ip_dstip.s_addr;
        send_ip->ip_dstip.s_addr = ip->ip_srcip.s_addr;
        send_ip->ip_protocol = IPPROTO_ICMP;
        send_ip->ip_totalen = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + load_len);

        char *send_load = buffer + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr);
        strncpy(send_load, load, load_len);

        send_icmp->icmp_chksum = get_checksum((unsigned short *)send_icmp, sizeof(struct icmp_hdr) + load_len);
        // 发送报文
        struct sockaddr_in dest_info;
        int enable = 1;

        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

        dest_info.sin_family = AF_INET;
        dest_info.sin_addr = send_ip->ip_dstip;

        sendto(sock, send_ip, ntohs(send_ip->ip_totalen), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
        printf("\n[%d] Send a fake ICMP\n", num);
        close(sock);
    }
}

int main()
{

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "icmp";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name enp0s3
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);
    // Step 3: Capture packets
    pcap_loop(handle, -1, reply, NULL);

    pcap_close(handle); //Close the handle
    return 0;
}