/*
 * router.c
 * Custom Router tool
 *
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <signal.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <linux/icmp.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <bits/ioctls.h>
#include <search.h>
#include <unistd.h>
#include <protocols/routed.h>
#include <pthread.h>
#include <signal.h>

#include "arp_content.h"
#include "my402list.h"
#include "router.h"
#include "common.h"

/* Global variable */
static router_input_t   input;
static int              raw_sockfd;

inf                     source_interfaces[10];

int                     num_macs = 0;
extern struct sockaddr_ll raw_sock_addr;
int                     mac_index = 0;
My402List               pkt_queue;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  cv    = PTHREAD_COND_INITIALIZER;

int                     pkt_num = 0;

typedef struct packet_t {
    int len;
    uint8_t *data;
    int num;
}packet;


int
retrieve_ip_from_mac(uint8_t * mac_addr) 
{
    int i = 0;
    for( i = 0 ; i < num_macs ; i++ ) {
        if(!memcmp(mac_addr, source_interfaces[i].mac_addr,
                   sizeof(char)*MAX_MAC_LEN)) {
            return i;
        }
    }
    return -1;
}


/* 
 * Get all MACs
 */
void get_all_macs()
{
  struct ifreq  ifr;
  struct ifconf ifc;
  char          buf[1024];
  int           sock = 0;
  struct sockaddr *addr;
  
  sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
  if (sock == -1) {
    error("Error creating socket for retreiving all macs");
  }
  
  ifc.ifc_len = sizeof(buf);
  ifc.ifc_buf = buf;
  
  if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { 
      error("Error IOCTL retreiving all macs");
  }

  struct ifreq* it = ifc.ifc_req;
  const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

  for (; it != end; it++) {
    strcpy(ifr.ifr_name, it->ifr_name);
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
        if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
	        if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
	            memcpy(&(source_interfaces[num_macs].mac_addr),
                       ifr.ifr_hwaddr.sa_data, 6);
                strcpy(source_interfaces[num_macs].interface, ifr.ifr_name);
	        }
            addr = &(it->ifr_addr);
            if (ioctl(sock, SIOCGIFADDR, &ifr) == 0) {
                inet_ntop(AF_INET, &(((struct sockaddr_in *)addr)->sin_addr),
                          source_interfaces[num_macs].ip_addr,
                          sizeof(char)*MAX_IP_LEN);
            }
            num_macs++; 
        }
    }
    else { 
      error("Error IOCTL iterating all macs"); 
    }
  }
} 

/*
 * RIP Response Packet
 */

void send_rip_response_pkt(char *src_ip, char* dst_ip)
{
	struct sockaddr_in sa;
	int sock,packet_len;

	long source,dest,target,netmask,gateway;
	int version,metric;

    struct in_addr localinterface;
	int on = 1;
    
    version=2;
    netmask=0;
    gateway=0;

    inet_aton(src_ip, (struct in_addr*)&source);
    inet_aton("224.0.0.9", (struct in_addr*)&dest);

    if( (sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
    {
        perror("RIP socket");
        exit(1);
    }

    localinterface.s_addr = inet_addr(src_ip);

    if (setsockopt(sock,IPPROTO_IP, IP_MULTICAST_IF,
                   (char *)&localinterface,sizeof(localinterface)) < 0)
    {
        perror("setsockopt: IP_MULTICAST");
        exit(1);
    }

    if (setsockopt(sock,IPPROTO_IP,IP_HDRINCL,(char *)&on,sizeof(on)) < 0)
    {
        perror("setsockopt: IP_HDRINCL");
        exit(1);
    }

    sa.sin_addr.s_addr = dest;
    sa.sin_family = AF_INET;

    packet_len = sizeof(struct raw_pkt);
    pkt = calloc((size_t)1,(size_t)packet_len);

    pkt->ip.ip_v = IPVERSION;
    pkt->ip.ip_hl = sizeof(struct ip_header) >> 2;
    pkt->ip.ip_tos = 0;
    pkt->ip.ip_len = htons(packet_len);
    pkt->ip.ip_id = htons(getpid() & 0xFFFF);
    pkt->ip.ip_off = 0;
    pkt->ip.ip_ttl = 0xdf;
    pkt->ip.ip_p = IPPROTO_UDP ;//UDP
    pkt->ip.ip_sum = 0;
    pkt->ip.ip_src = source;
    pkt->ip.ip_dst = sa.sin_addr.s_addr;
    pkt->ip.ip_sum = rip_checksum((unsigned short*)pkt,sizeof(struct ip_header));

    pkt->udp.uh_sport = htons(520);
    pkt->udp.uh_dport = htons(520);
    pkt->udp.uh_ulen = htons(sizeof(struct udp_header)+sizeof(struct u_rip));
    pkt->udp.uh_sum = 0;

    pkt->rip.command = 2;
    pkt->rip.version = version;
    int i = 0;
    for(i=0;i<num_rt_entry;i++){
        inet_aton(routing_entry[i].dest_subnet, (struct in_addr*)&target);
        metric=routing_entry[i].metric;
        if(metric > 15 || metric <= 0) {
            close(sock);
            return;
        }
        
        pkt->rip.routes[i].family = htons(2);
        pkt->rip.routes[i].ip = target;
        pkt->rip.routes[i].metric = htonl(metric);
    }

#if DEBUG_PRINT
    fprintf(stdout, "***************RIP Response sent*************\n");
#endif
    
    if(sendto(sock,pkt,packet_len,0,(struct sockaddr*)&sa,sizeof(sa)) < 0)
    {
        perror("RIP request sendto: ");
        exit(1);
    }
    close(sock);
}

/*
 * RIP Request Packet
 */

void send_rip_req_pkt(char *src_ip, char* dst_ip)
{
	struct sockaddr_in sa;
	int sock,packet_len;

    struct in_addr localinterface;

	long source,dest,target,netmask,gateway;
	int version,metric;

	int on = 1;
    
    version=2;
    netmask=0;
    gateway=0;

    inet_aton(src_ip,    (struct in_addr*)&source);
    inet_aton("224.0.0.9",    (struct in_addr*)&dest);
    metric=atoi("16");

    if( (sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
    {
        perror("RIP socket");
        exit(1);
    }

    localinterface.s_addr = inet_addr(src_ip);

    if (setsockopt(sock,IPPROTO_IP, IP_MULTICAST_IF,
                   (char *)&localinterface,sizeof(localinterface)) < 0)
    {
        perror("setsockopt: IP_MULTICAST");
        exit(1);
    }
    
    if (setsockopt(sock,IPPROTO_IP,IP_HDRINCL,(char *)&on,sizeof(on)) < 0)
    {
        perror("setsockopt: IP_HDRINCL");
        exit(1);
    }

    sa.sin_addr.s_addr = dest;
    sa.sin_family = AF_INET;

    packet_len = sizeof(struct raw_pkt);
    pkt = calloc((size_t)1,(size_t)packet_len);

    pkt->ip.ip_v = IPVERSION;
    pkt->ip.ip_hl = sizeof(struct ip_header) >> 2;
    pkt->ip.ip_tos = 0;
    pkt->ip.ip_len = htons(packet_len);
    pkt->ip.ip_id = htons(getpid() & 0xFFFF);
    pkt->ip.ip_off = 0;
    pkt->ip.ip_ttl = 0xdf;
    pkt->ip.ip_p = IPPROTO_UDP ;//UDP
    pkt->ip.ip_sum = 0;
    pkt->ip.ip_src = source;
    pkt->ip.ip_dst = sa.sin_addr.s_addr;
    pkt->ip.ip_sum = rip_checksum((unsigned short*)pkt,sizeof(struct ip_header));

    pkt->udp.uh_sport = htons(520);
    pkt->udp.uh_dport = htons(520);
    pkt->udp.uh_ulen = htons(sizeof(struct udp_header)+sizeof(struct u_rip));
    pkt->udp.uh_sum = 0;

    pkt->rip.command = 1;
    pkt->rip.version = version;
    pkt->rip.routes[0].metric = htonl(metric);


#if DEBUG_PRINT
    fprintf(stdout, "***************RIP Request sent*************\n");
#endif
    
    if(sendto(sock,pkt,packet_len,0,(struct sockaddr*)&sa,sizeof(sa)) < 0)
    {
        perror("RIP request sendto: ");
        exit(1);
    }
    close(sock);
}

/*
 * Adding the routing entry to the table
 */
void add_route (char       *dest_sub,
                char       *next_hop_ip,
                uint8_t    *next_hop_mac,
                uint8_t    *source_mac,
                char       *devinterface,
                int         subnetmask,
                int         metric)
{
    if( num_rt_entry < MAX_RT_ENTRY ) {
        strcpy(routing_entry[num_rt_entry].dest_subnet, dest_sub);
        strcpy(routing_entry[num_rt_entry].next_hop_ip, next_hop_ip);
        memcpy(routing_entry[num_rt_entry].next_hop_mac, next_hop_mac, MAX_MAC_LEN);
        memcpy(routing_entry[num_rt_entry].source_mac, source_mac, MAX_MAC_LEN);
        strcpy(routing_entry[num_rt_entry].interface_name, devinterface);
        routing_entry[num_rt_entry].sub_mask = subnetmask;
        routing_entry[num_rt_entry].metric = metric;
        gettimeofday(&(routing_entry[num_rt_entry].timestamp), NULL);

        num_rt_entry++;
    }
}

/*
 * Replace the entry in the route table
 */
void replace_route (char       *dest_sub,
                    char       *next_hop_ip,
                    uint8_t    *next_hop_mac,
                    uint8_t    *source_mac,
                    char       *devinterface,
                    int         subnetmask,
                    int         metric,
                    int         table_index)
{
    strcpy(routing_entry[table_index].dest_subnet, dest_sub);
    strcpy(routing_entry[table_index].next_hop_ip, next_hop_ip);
    memcpy(routing_entry[table_index].next_hop_mac, next_hop_mac, MAX_MAC_LEN);
    memcpy(routing_entry[table_index].source_mac, source_mac, MAX_MAC_LEN);
    strcpy(routing_entry[table_index].interface_name, devinterface);
    routing_entry[table_index].sub_mask = subnetmask;
    routing_entry[table_index].metric = metric; 
    gettimeofday(&(routing_entry[table_index].timestamp), NULL);
}

void add_local_routes() 
{
    int i = 0 ;
    int j = 0;
    struct  in_addr temp;
    uint32_t        ip_bin = 0, mask_bin = 0;
    char *destsubnet;
    struct ifreq ifmac;
    for (i = 0 ; i < num_arp_entry ; i++ ) {
        ip_bin = convert_ip_to_int32(arp_entry[i].ipaddr);
        mask_bin = convert_mask_to_int32(24);
        temp.s_addr = ip_bin & mask_bin;
        destsubnet = inet_ntoa(*(struct in_addr*)&temp.s_addr);

        memset(&ifmac, 0, sizeof(ifmac));
        ifmac = get_source_mac(arp_entry[i].devinterface);
        add_route(destsubnet, "0.0.0.0", 
                          arp_entry[i].hwaddr,
                          ifmac.ifr_hwaddr.sa_data,
                          arp_entry[i].devinterface, 24, 1);
    }
}

void replace_local_routes() 
{
    struct  in_addr temp;
    uint32_t        ip_bin = 0, mask_bin = 0;
    char           *destsubnet;
    struct ifreq ifmac;
    int             i = 0 ;
    int             j = 0;

    for (i = 0 ; i < num_arp_entry ; i++ ) {
        ip_bin = convert_ip_to_int32(arp_entry[i].ipaddr);
        mask_bin = convert_mask_to_int32(24);
        temp.s_addr = ip_bin & mask_bin;
        destsubnet = inet_ntoa(*(struct in_addr*)&temp.s_addr);

        memset(&ifmac, 0, sizeof(ifmac));
        ifmac = get_source_mac(arp_entry[i].devinterface);
        replace_route(destsubnet, "0.0.0.0", 
                          arp_entry[i].hwaddr,
                          ifmac.ifr_hwaddr.sa_data,
                          arp_entry[i].devinterface, 24, 1, i);
    }
}

/*
 * Thread call, to send rip request packet periodically
 */

void rip_request(void *arg)
{ 
    int i = 0, j = 0, not_found = 0;
    char s_ip[10];
    char d_ip[10];
    while (1) {
        for( i = 0 ; i < num_macs ; i++ ) {
            memset(s_ip, 0, sizeof(s_ip));
            memcpy(s_ip, source_interfaces[i].ip_addr, MAX_IP_LEN);
            not_found = 0;
            for ( j = 0; j < num_arp_entry; j++ ) {
                if(memcmp(source_interfaces[i].interface,
                          arp_entry[j].devinterface, 10) == 0){
                    memset(d_ip, 0, sizeof(d_ip));
                    memcpy(d_ip, arp_entry[j].ipaddr, MAX_IP_LEN);
                    not_found = 1;
                    break;
                }
            }
            if(not_found == 1) {
                if(strstr(d_ip, "192") != 0)
                    continue;
                send_rip_req_pkt(s_ip, d_ip);
                send_rip_response_pkt(s_ip, d_ip);
            }
        }
        
        replace_local_routes();
        usleep(RIP_REQ_TIMER);
    }
    
    fprintf(stdout, "Exiting from RIP request!\n");
    exit(-1);
}

int create_icmp_packet(uint8_t      *smac,
                       struct iphdr *iph_i,
                       char         *incoming_packet,
                       char         *outgoing_packet,
                       int           type ,
                       int           code) {

	struct ether_header *eh_o;
	struct iphdr *iph_o;

	struct icmphdr *icmph_i , *icmph_o;

	memset(outgoing_packet, 0, 65507);
	icmph_i = (struct icmphdr*) (iph_i + 1);

	eh_o = (struct ether_header*) outgoing_packet;
	iph_o = (struct iphdr*) (eh_o + 1);
	icmph_o = (struct icmphdr*) (iph_o + 1);
	
	if( create_eth(smac, eh_o) == -1) {
        return 0;
    }
    
    mac_index = retrieve_ip_from_mac((uint8_t*)eh_o->ether_shost);
    
#if DEBUG_PRINT
    fprintf(stdout, "MAC index: %d, interface name: %s\n", mac_index, source_interfaces[mac_index].interface);
#endif
    
    if(mac_index == -1) {
        fprintf(stdout, "Could not find the mac index\n");
        return 0;
    }
    
    char *ip_src = source_interfaces[mac_index].ip_addr;
    
#if DEBUG_PRINT
    fprintf(stdout, "IP src: %s\n", ip_src);
#endif
    
	create_iph( iph_i, iph_o, ip_src);
	create_icmph( icmph_i, icmph_o,iph_i, type, code);

	int ret = icmp_len;
	icmp_len = 0;
	return ret;	
}


void forward_local_packet(struct iphdr        *ip_hdr,
                          struct ether_header *eth_hdr,
                          char                *pkt,
                          int                  pkt_len,
                          int                  arp_entry_index)
{
    struct ifreq   if_mac;
    char          *interface;

#if DEBUG_PRINT    
    fprintf(stdout, "In forward packet\n");
#endif
    interface = arp_entry[arp_entry_index].devinterface;

#if DEBUG_PRINT    
    fprintf(stdout, "Sending interface is: %s\n", interface);
#endif
    memset(&raw_sock_addr, 0, sizeof(raw_sock_addr));
    if_mac = get_source_mac(interface);

    raw_sock_addr.sll_halen = ETH_ALEN;

    raw_sock_addr.sll_addr[0] = (uint8_t)(if_mac.ifr_hwaddr.sa_data)[0];
    raw_sock_addr.sll_addr[1] = (uint8_t)(if_mac.ifr_hwaddr.sa_data)[1];
    raw_sock_addr.sll_addr[2] = (uint8_t)(if_mac.ifr_hwaddr.sa_data)[2];
    raw_sock_addr.sll_addr[3] = (uint8_t)(if_mac.ifr_hwaddr.sa_data)[3];
    raw_sock_addr.sll_addr[4] = (uint8_t)(if_mac.ifr_hwaddr.sa_data)[4];
    raw_sock_addr.sll_addr[5] = (uint8_t)(if_mac.ifr_hwaddr.sa_data)[5];

    if( (raw_sock_addr.sll_ifindex = if_nametoindex(interface)) == 0 ) {
       error("if_nametoindex() failed to obtain index number for regular packets");
    }
    change_ip_header(ip_hdr);
    change_local_mac_header(eth_hdr, arp_entry_index);

    eth_hdr->ether_shost[0] = (uint8_t)(if_mac.ifr_hwaddr.sa_data)[0];
    eth_hdr->ether_shost[1] = (uint8_t)(if_mac.ifr_hwaddr.sa_data)[1];
    eth_hdr->ether_shost[2] = (uint8_t)(if_mac.ifr_hwaddr.sa_data)[2];
    eth_hdr->ether_shost[3] = (uint8_t)(if_mac.ifr_hwaddr.sa_data)[3];
    eth_hdr->ether_shost[4] = (uint8_t)(if_mac.ifr_hwaddr.sa_data)[4];
    eth_hdr->ether_shost[5] = (uint8_t)(if_mac.ifr_hwaddr.sa_data)[5];

#if DEBUG_PRINT    
    fprintf(stdout, "Packet is: %s, length: %d\n", pkt, pkt_len);
    fprintf(stdout, "Raw socket mac address: %02x:%02x:%02x:%02x:%02x:%02x\n",
            raw_sock_addr.sll_addr[0], raw_sock_addr.sll_addr[1], 
            raw_sock_addr.sll_addr[2], raw_sock_addr.sll_addr[3],
            raw_sock_addr.sll_addr[4], raw_sock_addr.sll_addr[5]);
#endif

    if (sendto(raw_sockfd, pkt, pkt_len, 0,
               (struct sockaddr*)&raw_sock_addr,
               sizeof(struct sockaddr_ll)) < 0) {
        fprintf(stderr, "Packet sent failed - %s\n", strerror(errno));
        exit(-1);
    }
}

void forward_packet(struct iphdr        *ip_hdr,
                    struct ether_header *eth_hdr,
                    char                *pkt,
                    int                  pkt_len,
                    int                  routing_entry_index)
{
    struct ifreq   if_mac;
    char          *interface;

#if DEBUG_PRINT    
    fprintf(stdout, "In forward packet\n");
#endif
    
    interface = routing_entry[routing_entry_index].interface_name;

#if DEBUG_PRINT    
    fprintf(stdout, "Sending interface is: %s\n", interface);
#endif
    
    memset(&raw_sock_addr, 0, sizeof(raw_sock_addr));
    if_mac = get_source_mac(interface);

    raw_sock_addr.sll_halen = ETH_ALEN;

    raw_sock_addr.sll_addr[0] = (uint8_t)(if_mac.ifr_hwaddr.sa_data)[0];
    raw_sock_addr.sll_addr[1] = (uint8_t)(if_mac.ifr_hwaddr.sa_data)[1];
    raw_sock_addr.sll_addr[2] = (uint8_t)(if_mac.ifr_hwaddr.sa_data)[2];
    raw_sock_addr.sll_addr[3] = (uint8_t)(if_mac.ifr_hwaddr.sa_data)[3];
    raw_sock_addr.sll_addr[4] = (uint8_t)(if_mac.ifr_hwaddr.sa_data)[4];
    raw_sock_addr.sll_addr[5] = (uint8_t)(if_mac.ifr_hwaddr.sa_data)[5];

    if( (raw_sock_addr.sll_ifindex = if_nametoindex(interface)) == 0 ) {
       error("if_nametoindex() failed to obtain index number for regular packets");
    }
    change_ip_header(ip_hdr);
    change_mac_header(eth_hdr, routing_entry_index);

#if DEBUG_PRINT    
    fprintf(stdout, "Packet is: %s, length: %d\n", pkt, pkt_len);
    fprintf(stdout, "Raw socket mac address: %02x:%02x:%02x:%02x:%02x:%02x\n",
            raw_sock_addr.sll_addr[0], raw_sock_addr.sll_addr[1], 
            raw_sock_addr.sll_addr[2], raw_sock_addr.sll_addr[3],
            raw_sock_addr.sll_addr[4], raw_sock_addr.sll_addr[5]);
#endif

    if (sendto(raw_sockfd, pkt, pkt_len, 0,
               (struct sockaddr*)&raw_sock_addr,
               sizeof(struct sockaddr_ll)) < 0) {
        fprintf(stderr, "Packet sent failed - %s\n", strerror(errno));
        exit(-1);
    }
}


int search_route(char *dest_ip)
{
    struct  in_addr temp;
    uint32_t        ip_bin = 0, mask_bin = 0;
    int             i=0;

    ip_bin = convert_ip_to_int32(dest_ip);

    for (i = 0 ; i < num_rt_entry ; i++ ) {
        mask_bin = 0;
        mask_bin = convert_mask_to_int32(routing_entry[i].sub_mask);

        temp.s_addr = ip_bin & mask_bin;
        if ((ip_bin & mask_bin) == convert_ip_to_int32(routing_entry[i].dest_subnet)) {

#if DEBUG_PRINT
            fprintf(stdout, "Found entry number: %d\n", i);
#endif
            return i;

        }
    }

    return -1; 
}

int search_in_arp(char *dest_ip) 
{
    int i = 0;
    for (i = 0 ; i < num_arp_entry ; i++ ) {
        if( memcmp(dest_ip, arp_entry[i].ipaddr, MAX_IP_LEN) == 0 ) {
            return i;
        }
    }
    return -1;
}

void print_routing_table(void)
{
    int i = 0;
    struct timeval curtime;
    gettimeofday(&curtime, NULL);
    for( i = 0 ; i < num_rt_entry ; i++) {
        fprintf(stdout, "Entry %d is: %s %d %s %02x:%02x:%02x:%02x:%02x:%02x  %02x:%02x:%02x:%02x:%02x:%02x %s %d %u\n",
                 i, routing_entry[i].dest_subnet, routing_entry[i].sub_mask, 
                 routing_entry[i].next_hop_ip, routing_entry[i].next_hop_mac[0], 
                 routing_entry[i].next_hop_mac[1], routing_entry[i].next_hop_mac[2], 
                 routing_entry[i].next_hop_mac[3], routing_entry[i].next_hop_mac[4], 
                 routing_entry[i].next_hop_mac[5], routing_entry[i].source_mac[0], 
                 routing_entry[i].source_mac[1], routing_entry[i].source_mac[2], 
                 routing_entry[i].source_mac[3], routing_entry[i].source_mac[4], 
                 routing_entry[i].source_mac[5], routing_entry[i].interface_name, 
                 routing_entry[i].metric, time_difference(&routing_entry[i].timestamp, &curtime)); 
    }
}

void parse_rip_packet(const uint8_t *bytes, char* source_ip)
{
    struct udphdr *udp_hdr;
    struct rip              *rp;
    struct netinfo          *ni;
    struct sockaddr_in      *dst_addr;
    char                    *dst_subnet;
    int                     metric;
    struct ifreq            ifmac;
    int                     i = 0, j = 0;
    int                     rt_index = 0;
    char                    src_ip[MAX_IP_LEN];
    struct timeval          curr_time;

    rp = (struct rip *)(bytes + sizeof(struct ether_header) +
                        sizeof(struct iphdr) + sizeof(struct udphdr));
    
    strcpy(src_ip, source_ip);
    
    for( j = 0 ; j < MAX_RIP_ENTRY; j++ ) {
        ni = &rp->ripun.ru_nets[j];
        
        dst_addr = (struct sockaddr_in*)&ni->rip_dst;
        dst_subnet = inet_ntoa(dst_addr->sin_addr);
        metric = ntohl(ni->rip_metric);

        if(!strcmp(dst_subnet, "0.0.0.0")) {
            break;
        }

#if DEBUG_PRINT
        fprintf(stdout, "RIP Command: %u\n", rp->rip_cmd);
        fprintf(stdout, "RIP Version: %u\n", rp->rip_vers);
        fprintf(stdout, "Netinfo rip_dst: %s\n", dst_subnet);
        fprintf(stdout, "Netinfo rip_metric: %d\n", metric);
        fprintf(stdout, "Source IP: %s\n", src_ip);
#endif

        if((rt_index = search_route(dst_subnet)) == -1 ) {
#if DEBUG_PRINT
            fprintf(stdout, "Route does not exist, adding...\n");
#endif

        for (i = 0 ; i < num_arp_entry ; i++ ) {
                if (strcmp(src_ip, arp_entry[i].ipaddr) == 0) {
                    memset(&ifmac, 0, sizeof(ifmac));
                    ifmac = get_source_mac(arp_entry[i].devinterface);
                    add_route(dst_subnet, src_ip, 
                          arp_entry[i].hwaddr,
                          ifmac.ifr_hwaddr.sa_data,
                          arp_entry[i].devinterface, 24, metric + 1);
                }
            }
        }
        else {
           gettimeofday(&curr_time, NULL);
           if( (routing_entry[rt_index].metric >= (metric + 1)) || 
                   ( time_difference(&routing_entry[rt_index].timestamp, &curr_time) > RIP_ENTRY_TTL) ) {
                for (i = 0 ; i < num_arp_entry ; i++ ) {
                    if (strcmp(src_ip, arp_entry[i].ipaddr) == 0) {
                        memset(&ifmac, 0, sizeof(ifmac));
                        ifmac = get_source_mac(arp_entry[i].devinterface);
                        replace_route(dst_subnet, src_ip, 
                            arp_entry[i].hwaddr,
                            ifmac.ifr_hwaddr.sa_data,
                            arp_entry[i].devinterface, 24, metric + 1, rt_index);
                    }
                }
           }
        }
    }

}


void build_rt_table (void)
{
    struct ifreq   ifmac;
    char           temp[MAX_IP_LEN];
    int            i = 0;

    strcpy(temp, "10.10.1.2");
    for (i = 0 ; i < num_arp_entry ; i++ ) {
        if (strcmp(temp, arp_entry[i].ipaddr) == 0) {
            memset(&ifmac, 0, sizeof(ifmac));
            ifmac = get_source_mac(arp_entry[i].devinterface);
            add_route("10.1.1.0", "10.10.1.2", 
                      arp_entry[i].hwaddr,
                      ifmac.ifr_hwaddr.sa_data,
                      arp_entry[i].devinterface, 24, 1);
        }
    }

    strcpy(temp, "10.10.2.1");
    for (i = 0 ; i < num_arp_entry ; i++ ) {
        if (strcmp(temp, arp_entry[i].ipaddr) == 0)  {
            memset(&ifmac, 0, sizeof(ifmac));
            ifmac = get_source_mac(arp_entry[i].devinterface);
            add_route("10.1.1.0", "10.10.2.1",
                      arp_entry[i].hwaddr,
                      ifmac.ifr_hwaddr.sa_data,
                      arp_entry[i].devinterface, 24, 2);
        }
    }

    print_routing_table();
}

/* Process and update caught packet */
static void
router_process_filtered_pkt (uint8_t                   *user,
                             const struct pcap_pkthdr  *hdr,
                             const uint8_t             *bytes)
{

    packet              *pkt_buffer;
    struct ether_header *ether;
    struct iphdr        *ip;
    struct udphdr       *udp;
    char                *source_ip, *dest_ip, sip[MAX_IP_LEN];

    pkt_buffer = (packet*)malloc(sizeof(packet));
    pkt_buffer->len = hdr->len;
    pkt_buffer->num = pkt_num++;
    pkt_buffer->data = (uint8_t*)malloc(sizeof(uint8_t)*hdr->len);
    memcpy(pkt_buffer->data, bytes, hdr->len);

    ether   = (struct ether_header *)(bytes);
    ip      = (struct iphdr *)(ether + 1);
    udp     = (struct udphdr *)(ip + 1);
    if (ether->ether_type != htons(ETHERTYPE_IP)) {
            goto DO_NOT_APPEND;
    }

    source_ip = inet_ntoa(*(struct in_addr *) &ip->saddr);
    memcpy(sip, source_ip, MAX_IP_LEN);
    dest_ip = inet_ntoa(*(struct in_addr *) &ip->daddr);
    
    /* Masking the RIPv2 packets */
    if( ((ntohs(udp->dest) == RIP_PORT) && (ntohs(udp->source) == RIP_PORT)) ) {
#if DEBUG_PRINT
        fprintf(stdout, "Found RIPv2 packets from source: %s, dest: %s\n", sip, dest_ip); 
#endif
            parse_rip_packet(bytes, sip);
            print_routing_table();
        goto DO_NOT_APPEND;
    }



    if(pthread_mutex_lock(&mutex) != 0) {
        fprintf(stderr, "Mutex lock error: %s\n", strerror(errno));
        exit(-1);
    }

    (void)My402ListAppend(&pkt_queue, pkt_buffer);
    if(My402ListLength(&pkt_queue) == 1) {
        pthread_cond_broadcast(&cv);
    }

    if(pthread_mutex_unlock(&mutex) != 0) {
        fprintf(stderr, "Mutex unlock error: %s\n", strerror(errno));
        exit(-1);
    }

DO_NOT_APPEND:{}
}

void* dequeue_pkt_fwd(void *arg) 
{
    struct ether_header  *ether, *eth_o;
    struct iphdr         *ip, *ip_o;
    struct udphdr        *udp;
    const uint8_t        *pkt_start;
    uint8_t              *payload;
    int                  hdr_len;
    int                   idx = -1;
    uint16_t              pkt_len;
    char                 *source_ip, dt_ip[MAX_IP_LEN];
    struct timeval       prsnt_time;
    char                 icmp_packet[65507];
    struct sockaddr_ll  temp_sock_addr;
    const struct sniff_ether  *eth_hdr;
    uint8_t             *bytes = NULL;
    My402ListElem       *pckt = NULL;
    packet              *temp;

    
    while(1) {

        if(pthread_mutex_lock(&mutex) != 0) {
            fprintf(stderr, "Mutex lock error: %s\n", strerror(errno));
            exit(-1);
        }

        if(My402ListEmpty(&pkt_queue) == TRUE) {
            pthread_cond_wait(&cv, &mutex);
        }
    
        pckt = My402ListFirst(&pkt_queue);
        temp = (packet*)(pckt->obj);
        bytes = temp->data;
        hdr_len = temp->len;
        My402ListUnlink(&pkt_queue, pckt);
 
        if(pthread_mutex_unlock(&mutex) != 0) {
            fprintf(stderr, "Mutex unlock error: %s\n", strerror(errno));
            exit(-1);
        }
    
        pkt_start = bytes;
        ether   = (struct ether_header *)(bytes);
        ip      = (struct iphdr *)(ether + 1);
        udp     = (struct udphdr *)(ip + 1);
        if (ether->ether_type != htons(ETHERTYPE_IP)) {
                goto DO_NOT_FWD;
        }

        source_ip = inet_ntoa(*(struct in_addr *) &ip->saddr);


        if(ip->ttl == 1) {
            uint8_t smac[MAX_MAC_LEN+1];
            int i=0;
            for (i = 0; i < MAX_MAC_LEN; i++) {
                smac[i] = *(bytes + 6 + i);
            }
          
            pkt_len = create_icmp_packet(smac, ip, (char*)pkt_start, icmp_packet,
                                         ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);

            if( pkt_len == 0 ) {
                goto DO_NOT_FWD;
            }
          
            eth_o = (struct ether_header*)icmp_packet;
            ip_o  = (struct iphdr*) (icmp_packet + sizeof(struct ether_header));
          
            if( (temp_sock_addr.sll_ifindex = if_nametoindex(source_interfaces[mac_index].interface)) == 0 ) {
                error("if_nametoindex() failed to obtain index number for ICMP packet");
            }

            temp_sock_addr.sll_halen = ETH_ALEN;
            temp_sock_addr.sll_addr[0] = (uint8_t)source_interfaces[mac_index].mac_addr[0];
            temp_sock_addr.sll_addr[1] = (uint8_t)source_interfaces[mac_index].mac_addr[1];
            temp_sock_addr.sll_addr[2] = (uint8_t)source_interfaces[mac_index].mac_addr[2];
            temp_sock_addr.sll_addr[3] = (uint8_t)source_interfaces[mac_index].mac_addr[3];
            temp_sock_addr.sll_addr[4] = (uint8_t)source_interfaces[mac_index].mac_addr[4];
            temp_sock_addr.sll_addr[5] = (uint8_t)source_interfaces[mac_index].mac_addr[5];
            
            if (sendto(raw_sockfd, icmp_packet, pkt_len, 0,
                      (struct sockaddr*)&temp_sock_addr,
                      sizeof(struct sockaddr_ll)) < 0) {
                    fprintf(stderr, "Packet sent failed - %s\n", strerror(errno));
            }
            goto DO_NOT_FWD;
        }

        idx = search_route(inet_ntoa(*(struct in_addr *) &ip->daddr));
        if (idx != -1) {
            gettimeofday(&prsnt_time, NULL);
            if( ( time_difference(&routing_entry[idx].timestamp,
                                  &prsnt_time) > RIP_ENTRY_TTL) ) {
#if DEBUG_PRINT    
                fprintf(stdout, "Routing entry stale, dropping - %u\n",
                        time_difference(&routing_entry[idx].timestamp,
                                        &prsnt_time)); 
#endif
                goto DO_NOT_FWD;
            }
            
#if DEBUG_PRINT
              fprintf(stdout, "Source IP  - %s\n", 
                            inet_ntoa(*(struct in_addr *) &ip->saddr));
              fprintf(stdout, "Dest IP  - %s\n", 
                            inet_ntoa(*(struct in_addr *) &ip->daddr));
              fprintf(stdout, "TTL  - %d\n", ip->ttl);
#endif

            forward_packet(ip, ether, (char*) pkt_start, (hdr_len), idx);
        }
        else {
            memset(dt_ip, 0, sizeof(dt_ip));
            strcpy(dt_ip, inet_ntoa(*(struct in_addr *) &ip->daddr));
            idx = search_in_arp(dt_ip);
            if(idx != -1){
                
#if DEBUG_PRINT
                fprintf(stdout, "In local: %d\n",idx);
#endif
                forward_local_packet(ip, ether, (char*)pkt_start, (hdr_len), idx);
            }
        }
DO_NOT_FWD:{}
    }
    fprintf(stdout, "Exiting from dequeue thread!\n");
    exit(-1);
    return 0;
}


void* router_start_scanning_packets (void*arg)
{
    struct in_addr           addr;
    pcap_t                  *pcap_hdl;
    char                     errbuf[PCAP_ERRBUF_SIZE];
    char                     buf[INET_ADDRSTRLEN];
    int                      ret;

    /* Open pcap file */
    fprintf(stdout, "New pcap handle with interface: %s\n", (char*)arg);
    pcap_hdl = pcap_open_live((char*)arg, BUFSIZ, 1, -1, errbuf);
    if (pcap_hdl == NULL) {
        printf("%s\n", errbuf);
        return;
    }

    /* Only interested in incoming packets */
    ret = pcap_setdirection(pcap_hdl, PCAP_D_IN);
    assert(ret == 0);

    /* Sniff Packets! */
    pcap_loop(pcap_hdl, -1, router_process_filtered_pkt, NULL);
    fprintf(stdout, "Exiting from router scanning!\n");
    exit(-1);
    return 0;
}

static inline void
router_setup_raw_socket (void)
{
    int          one  = 1;
    const int   *val = &one;

    /* Create socket */
    raw_sockfd = socket(PF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sockfd < 0){
        error("Error creating raw socket");
    }

    return;
}


int
main (int   argc,
      char *argv[])
{
    pthread_t rip_req_tid, pkt_send_tid;
    int       i = 0;
    char      *inf_name;

    memset(&pkt_queue, 0, sizeof(My402List));
    (void)My402ListInit(&pkt_queue);

    get_all_macs();
    
    /* Parse ARP table */
    parse_arp_content();

    add_local_routes();
    
    /* Setup Raw socket */
    router_setup_raw_socket();

    int thr_count = 0;
    pthread_t pkt_sniff_tid[num_macs];
    for( i = 0 ; i < num_macs; i++ ) {
        if(  strstr(source_interfaces[i].interface, "control") == NULL ) {
            fprintf(stdout, "Spawning a new thread - %d!\n", thr_count);
            pthread_create(&pkt_sniff_tid[thr_count], NULL,
                           (void*)&router_start_scanning_packets,
                           (void*)source_interfaces[i].interface);
            thr_count++;
        }
    }
    
    usleep(1000);
    pthread_create(&rip_req_tid, NULL, (void*)&rip_request, (void*)1);
    pthread_create(&pkt_send_tid, NULL, (void*)&dequeue_pkt_fwd, (void*)1);

    /* Start sniffing and forwarding packets */
    while(thr_count != 0){
        pthread_join(pkt_sniff_tid[--thr_count], NULL);
    }
    
    pthread_join(rip_req_tid, NULL);
    pthread_join(pkt_send_tid, NULL);
    return 0;
}
