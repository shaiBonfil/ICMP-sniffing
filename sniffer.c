#include <stdio.h>
#include <netinet/ip.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip_icmp.h>

int main()
{

    char buffer[IP_MAXPACKET];
    struct sockaddr saddr;
    struct packet_mreq mr;
    struct iphdr *ip;
    struct icmphdr *icmp;

    struct sockaddr_in src;
    struct sockaddr_in dst;
    unsigned int ipproto;
    unsigned int type;
    unsigned int code;
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    mr.mr_type = PACKET_MR_PROMISC;
    setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));
    int flag = 1;
    while (flag)
    {
        memset(buffer, 0, sizeof(buffer));
        int data_size = recvfrom(sock, buffer, IP_MAXPACKET, 0, &saddr, (socklen_t *)sizeof(saddr));
        if (data_size)
        {
            ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
            ipproto = (unsigned int)(ip->protocol);
            if (ipproto == 1)
            { // icmp protocol is 1
                icmp = (struct icmphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
                type = icmp->type;
                code = icmp->code;
                memset(&src, 0, sizeof(src));
                src.sin_addr.s_addr = ip->saddr;
                memset(&dst, 0, sizeof(dst));
                dst.sin_addr.s_addr = ip->daddr;
                printf("Source IP: %s\n", inet_ntoa(src.sin_addr));
                printf("Destination IP: %s\n", inet_ntoa(dst.sin_addr));
                printf("type: %d\n", type);
                printf("code: %d\n", code);
            }
        }
        else{
            flag = 0;
        }
    }
    close(sock);

    return 0;
}