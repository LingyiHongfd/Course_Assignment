#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>

typedef struct ip_hdr{	
	char ip_ver; //version&header_len
	char ip_tos;	
	unsigned short ip_totalen;	
	unsigned short ident;	
	unsigned short ip_flags;//flags&displacement	
	unsigned char ip_ttl;	
	unsigned char ip_protocol;	
	unsigned short ip_cksum;	
	struct in_addr ip_srcip;
	struct in_addr ip_dstip;
	
}ip_hdr;
//ip_hdr *ip;

typedef struct icmp_hdr{
	char icmp_type;
	char icmp_code;
	unsigned short icmp_chksum;
	unsigned short icmp_flag;
	unsigned short icmp_seq;

}icmp_hdr;


unsigned short in_chksum(unsigned short* buffer,int size)
{
	unsigned long cksum=0;
	while(size>1)
	{
		cksum+=*buffer++;
		size-=sizeof(unsigned short);
	}
	if(size) 	//if any byte left
		cksum+=*(unsigned char*)buffer;
	cksum=(cksum>>16)+(cksum&0xffff);	//unreel 
	cksum+=(cksum>>16);
	return (unsigned short)(~cksum); //return ones-complement code

}





int main()
{
    char* dst_ip="10.0.2.5";
    char buffer[1500];
	memset(buffer,0,1500);
	
	struct icmp_hdr *icmp=(struct  icmp_hdr *)(buffer+sizeof(struct ip_hdr));

	icmp->icmp_type=8;
	
	icmp->icmp_chksum=0;
	icmp->icmp_chksum=in_chksum((unsigned short*)icmp,sizeof(struct icmp_hdr));

	struct ip_hdr *ip=(struct ip_hdr*) buffer;
	ip->ip_ver=69; //0000 0000 -> 0100 0101 -> 64+4+1 ->69
	ip->ip_ttl=20;
	ip->ip_srcip.s_addr=inet_addr("10.0.2.4");
	ip->ip_dstip.s_addr=inet_addr(dst_ip);
	ip->ip_protocol=IPPROTO_ICMP;

	ip->ip_totalen=htons(sizeof(struct ip_hdr)+sizeof(struct icmp_hdr));




    struct sockaddr_in dest_info;
	int enable=1;

	//printf("%s"," socket ");

	int sock=socket(AF_INET,SOCK_RAW,IPPROTO_RAW); //open socket

	//printf("%s"," setsocket ");

	setsockopt(sock,IPPROTO_IP,IP_HDRINCL,&enable,sizeof(enable)); //set socket
	
	dest_info.sin_family=AF_INET;
	dest_info.sin_addr=ip->ip_dstip; //construct dest_info

	//printf("%s"," sendto ");

	sendto(sock,ip,ntohs(ip->ip_totalen),0,(struct sockaddr *)&dest_info,sizeof(dest_info));


	close(sock);    
}