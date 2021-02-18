#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

typedef struct eth_hdr
{
    u_char dst_mac[6];
    u_char src_mac[6];
    u_short eth_type;
} eth_hdr;
eth_hdr *ethernet;

typedef struct ip_hdr
{
    int version : 4;
    int header_len : 4;
    u_char tos : 8;
    int total_len : 16;
    int ident : 16;
    int flags : 16;
    u_char ttl : 8;
    u_char protocol : 8;
    int checksum : 16;
    u_char sourceIP[4];
    u_char destIP[4];
} ip_hdr;
ip_hdr *ip;

typedef struct tcp_hdr
{
    u_short sport;
    u_short dport;
    u_int seq;
    u_int ack;
    u_char head_len;
    u_char flags;
    u_short wind_size;
    u_short check_sum;
    u_short urg_ptr;
} tcp_hdr;
tcp_hdr *tcp;

typedef struct udp_hdr
{
    u_short sport;
    u_short dport;
    u_short tot_len;
    u_short check_sum;
} udp_hdr;
udp_hdr *udp;

typedef struct icmp_hdr
{
    char icmp_type;
    char icmp_code;
    unsigned short icmp_chksum;
    unsigned short icmp_id;
    unsigned short icmp_seq;
    unsigned long long icmp_timestamp; //ping request has timestamp

} icmp_hdr;
icmp_hdr *icmp;

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    printf("Got a packet\n");
    int *packet_nums = (int *)args;
    printf("packet number:=%d\n", ++(*packet_nums));
    //printf("Packet length: %d\n", header->len);
    //printf("Number of bytes: %d\n", header->caplen);
    u_int eth_len = sizeof(struct eth_hdr);
    u_int ip_len = sizeof(struct ip_hdr);
    u_int tcp_len = sizeof(struct tcp_hdr);
    u_int udp_len = sizeof(struct udp_hdr);
    //printf("analyse information:\n\n");
    //printf("ethernet header information:\n");
    ethernet = (eth_hdr *)packet;
    //printf("src_mac : %02x-%02x-%02x-%02x-%02x-%02x\n",ethernet->src_mac[0],ethernet->src_mac[1],ethernet->src_mac[2],ethernet->src_mac[3],ethernet->src_mac[4],ethernet->src_mac[5]);
    //printf("dst_mac : %02x-%02x-%02x-%02x-%02x-%02x\n",ethernet->dst_mac[0],ethernet->dst_mac[1],ethernet->dst_mac[2],ethernet->dst_mac[3],ethernet->dst_mac[4],ethernet->dst_mac[5]);
    //printf("ethernet type : %u\n",ethernet->eth_type);

    /*
    if(ntohs(ethernet->eth_type)==0x0800){
        printf("IPV4 is used\n");
        printf("IPV4 header information:\n");
        ip=(ip_hdr*)(packet+eth_len);
        printf("source ip : %d.%d.%d.%d\n",ip->sourceIP[0],ip->sourceIP[1],ip->sourceIP[2],ip->sourceIP[3]);
        printf("dest ip : %d.%d.%d.%d\n",ip->destIP[0],ip->destIP[1],ip->destIP[2],ip->destIP[3]);
        if(ip->protocol==6){
            //printf("tcp is used:\n");
            tcp=(tcp_hdr*)(packet+eth_len+ip_len);
            //printf("tcp source port : %u\n",tcp->sport);
            //printf("tcp dest port : %u\n",tcp->dport);
        }
        else if(ip->protocol==17){
            //printf("udp is used:\n");
            udp=(udp_hdr*)(packet+eth_len+ip_len);
            //printf("udp source port : %u\n",udp->sport);
            //printf("udp dest port : %u\n",udp->dport);
        }
        else {
            //printf("other transport protocol is used\n");
        }
    }
    else {
        //printf("ipv6 is used\n");
    }
    */

    ip=(ip_hdr*)(packet+eth_len);
    
	int totalen=ip->total_len;
	
        if(ip->protocol==6){
            	tcp=(tcp_hdr*)(packet+eth_len+ip_len);
		unsigned int tcp_head_len=(unsigned char)(tcp->head_len>>4)*32/8;
		char *load=(char*)(packet+eth_len+ip_len+tcp_head_len);

		unsigned int data_len=header->len-(eth_len+ip_len+tcp_head_len);
		for(unsigned int i=0;i<data_len;i++){
			printf("keyword:  %c",*load);
			load++;
			}
		printf("\n");
	
        }


    printf("------------------done-------------------\n");
    printf("\n\n");
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip proto icmp";
    //char filter_exp[] = "icmp host 10.0.2.4 and 10.0.2.5";
    //char filter_exp[] = "tcp dst portrange 10-100";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name enp0s3
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);
    int packet_num = 0;
    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, (unsigned char *)&packet_num);

    pcap_close(handle); //Close the handle
    return 0;
}