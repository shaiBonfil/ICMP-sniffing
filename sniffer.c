#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

int main()
{
    char buffer[IP_MAXPACKET];

    struct sockaddr saddr;
    struct packet_mreq mr; 

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    mr.mr_type = PACKET_MR_PROMISC;
    setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));
    while (1)
    {
        memset(buffer, 0, sizeof(buffer));
        int data_size = recvfrom(sock, buffer, IP_MAXPACKET, 0, &saddr, (socklen_t *)sizeof(saddr));
        if (data_size)
        {
            struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
            unsigned int ipproto = (unsigned int)(ip->protocol);
            if (ipproto == IPPROTO_ICMP)
            {
                struct icmphdr *icmp = (struct icmphdr *)((char *)ip + (4 * ip->ihl));

                struct sockaddr_in src;
                struct sockaddr_in dst;

                unsigned int type = (unsigned int)(icmp->type);
                unsigned int code = (unsigned int)(icmp->code);  

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
            break;
        }
    }
    close(sock);

    return 0;
}