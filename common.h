/*
 * Common header for Custom IP Router
 */

#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdlib.h>
#include "arp_content.h"

#define DEBUG_PRINT     0

#define TRUE            1
#define FALSE           0

#define MAX_RT_ENTRY    10
#define MAX_BUF_LEN     1024
#define MAX_RIP_ENTRY   15
#define RIP_PORT        520
#define RIP_ENTRY_TTL   60000000
#define	IPVERSION	    4
#define RIP_REQ_TIMER   5000000

struct sockaddr_ll      raw_sock_addr;
int                     len_tx = 0;
int                     num_rt_entry = 0;

typedef struct rt_table_t {
    char            dest_subnet[MAX_IP_LEN];
    int             sub_mask;
    char            next_hop_ip[MAX_IP_LEN];
    uint8_t         next_hop_mac[MAX_MAC_LEN];
    uint8_t         source_mac[MAX_MAC_LEN]; 
    char            interface_name[10]; 
    int             metric;
    struct timeval  timestamp; 
} rt_table;

typedef struct inf_t {
    char mac_addr[MAX_MAC_LEN];
    char ip_addr[MAX_IP_LEN];
    char    interface[10];
}inf;

rt_table                routing_entry[MAX_RT_ENTRY];

void error(const char *msg)
{
    perror(msg);
    exit(1);
}

int get_ifname_from_next_mac(uint8_t *next_hop_mac){
	int index;
	for (index = 0; index < num_arp_entry; index++) {
		if (!(memcmp(next_hop_mac, arp_entry[index].hwaddr,
                     sizeof(uint8_t)*MAX_MAC_LEN))) {
			return index;
		}
	}
	return -1;
}

unsigned short csum(unsigned short *buffer, int num)
{
    unsigned long sum;

    for(sum=0; num>0; num--) { 
        sum += *buffer++;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

/*
 * Find MAC address of a given interface
 */
struct ifreq get_source_mac (char *if_name)
{
    struct ifreq ifmac;
    int          sendfd = 0;

    sendfd = socket(PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
    if (sendfd < 0) {
        error("Error opening socket for getting MAC address");
    }

    memset(&ifmac, 0, sizeof(ifmac));
    snprintf(ifmac.ifr_name, sizeof(ifmac.ifr_name), "%s", if_name);

    if (ioctl(sendfd, SIOCGIFHWADDR, &ifmac) < 0 ) {
        error("IOCTL failed to get MAC address");
    }

    close(sendfd);
    return ifmac;
}

int check_packet (struct ether_header *eh, char *intf) 
{
    struct ifreq if_mac;
    int flag = 0, i = 0;

    if_mac = get_source_mac(intf);
    for(i=0;i<6;i++) {
        if((uint8_t)(if_mac.ifr_hwaddr.sa_data)[i] != eh->ether_dhost[i]) {
            flag = 1;
            break;
        }
    }
    return flag;
}



struct ip_header
{
	unsigned char  ip_hl:4,		/* header length */
		  ip_v:4;		/* version */
	unsigned char  ip_tos;		/* type of service */
	unsigned short ip_len;		/* total length */
	unsigned short ip_id;		/* identification */
	unsigned short ip_off;		/* fragment offset field */
#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	unsigned char  ip_ttl;		/* time to live */
	unsigned char  ip_p;			/* protocol */
	unsigned short ip_sum;		/* checksum */
	unsigned long ip_src, ip_dst; /* source and dest address */
};

struct udp_header
{
	unsigned short uh_sport;		/* source port */
	unsigned short uh_dport;		/* destination port */
	unsigned short uh_ulen;		/* udp length */
	unsigned short uh_sum;		/* udp checksum */
};

#define RIP_PORT  520

struct rip_message
{
	unsigned short family;
	unsigned short tag;
	unsigned long ip;
	unsigned long netmask;
	unsigned long gateway;
	unsigned long metric;
};

struct u_rip
{
	unsigned char command;
	unsigned char version;
	unsigned short domain;
	struct rip_message routes[MAX_RT_ENTRY];
};

struct raw_pkt
{
	struct ip_header ip;
	struct udp_header udp;
	struct u_rip rip;
};

struct raw_pkt* pkt;

/*Need to verify if the working is same as csum*/
unsigned short rip_checksum(unsigned short* addr,char len)
{
	register long sum = 0;

	while(len > 1)
	{
		sum += *addr++;
		len -= 2;
	}
	if(len > 0) sum += *addr;
		while (sum>>16) sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}


int icmp_len = 0;

int
copy_mac(uint8_t *smac, struct ether_header * eth2){
    
    struct ifreq if_mac;
    int i = 0;
    char if_name[10];
    int index = get_ifname_from_next_mac(smac);
    if(index == -1) {
    	fprintf(stdout, "No such next hop entry in routing table\n");
        return -1;
    }
    strcpy(if_name, arp_entry[index].devinterface);
    fprintf(stdout, "Source interface for ICMP is %s\n", if_name);
    if_mac = get_source_mac(if_name);
    for (i =0 ; i<6 ; i++){
        eth2->ether_shost[i] = (uint8_t)(if_mac.ifr_hwaddr.sa_data[i]);
        eth2->ether_dhost[i] = *(smac + i);
    }

    fprintf(stdout, "sMAC - %02x:%02x:%02x:%02x:%02x:%02x\n",
                 (uint8_t)eth2->ether_shost[0],
                 (uint8_t)eth2->ether_shost[1],
                 (uint8_t)eth2->ether_shost[2],
                 (uint8_t)eth2->ether_shost[3],
                 (uint8_t)eth2->ether_shost[4],
                 (uint8_t)eth2->ether_shost[5]);
    fprintf(stdout, "dMAC - %02x:%02x:%02x:%02x:%02x:%02x\n",
                 (uint8_t)eth2->ether_dhost[0],
                 (uint8_t)eth2->ether_dhost[1],
                 (uint8_t)eth2->ether_dhost[2],
                 (uint8_t)eth2->ether_dhost[3],
                 (uint8_t)eth2->ether_dhost[4],
                 (uint8_t)eth2->ether_dhost[5]);
    return 0;
}


int create_eth(uint8_t *smac, struct ether_header *eh_o) {
	if( copy_mac(smac, eh_o) == -1 ) {
        return -1;
    }
	eh_o->ether_type = htons(ETHERTYPE_IP);
        icmp_len += sizeof(struct ether_header);
        return 0;
}

void
create_icmph( struct icmphdr *icmph_i,
              struct icmphdr *icmph_o,
              struct iphdr   *iph_i,
              int             type,
              int             code)
{
	char *ptr = (char*) icmph_o;
	
	icmph_o->type = type;
	icmph_o->code = code;                     // TTL count exceeded
	icmph_o->un.echo.id = icmph_i->un.echo.id; 	
	icmph_o->un.echo.sequence = 1;
			
	ptr += sizeof(struct icmphdr);	
	memcpy(ptr,iph_i,28); 	
	icmp_len += (sizeof(struct icmphdr)+28);

	icmph_o->checksum = 0;
	icmph_o->checksum = csum((unsigned short *)(icmph_o),
                             (sizeof(struct icmphdr)/2)+ 14); //can be wrong !!! 

}

void create_iph(struct iphdr *iph_i,
                struct iphdr *iph_o,
                char *ip_src)
{
	iph_o->daddr = iph_i->saddr;
    inet_aton(ip_src, (struct in_addr*)&(iph_o->saddr)) ;
	iph_o->ihl = 5;                     // need to change to 20
	iph_o->tot_len = htons(56);
    iph_o->version = 4;
    iph_o->tos = 16;			 // Low delay
    iph_o->id = htons(54321);
    iph_o->ttl = 64; 			
    iph_o->protocol = IPPROTO_ICMP; 			
    iph_o->check = 0;
    iph_o->check = csum((unsigned short *)(iph_o), sizeof(struct iphdr)/2);
    icmp_len += sizeof(struct iphdr);		
}


struct sniff_ether {
    const struct ether_addr dmac;
    const struct ether_addr smac;
    uint8_t ether_type;
};



unsigned int
time_difference(struct timeval *begin,
                struct timeval *end)
{
  unsigned int time_diff = (end->tv_sec - begin->tv_sec)*1000000
                         + (end->tv_usec - begin->tv_usec);
  return time_diff;
}

unsigned int
gettime_in_usec(struct timeval *t) 
{
    return ((t->tv_sec * 1000000) + t->tv_usec);
}

void
parse_arp_content(void)
{
    FILE    *arp_fd;
    char    *arp_line_buffer;
    ssize_t line_len = 0;
    int     ret = 0;
    char    ipaddr[MAX_ARP_BUF_SIZE];
    char    hwtype[MAX_ARP_BUF_SIZE];
    char    flag[MAX_ARP_BUF_SIZE];
    char    mask[MAX_ARP_BUF_SIZE];
    uint8_t    hwaddr[MAX_MAC_LEN];
    char    device[MAX_ARP_BUF_SIZE];

    arp_fd = fopen("/proc/net/arp", "r");
    if (arp_fd == NULL) {
        error("Could not open arp file");
    }

    ret = getline(&arp_line_buffer, &line_len, arp_fd);
    if(ret == -1) {
        error("error reading the first line of the arp file");
    }

    while( (ret = getline(&arp_line_buffer, &line_len, arp_fd)) != -1) { 
        memset(ipaddr,  0,  MAX_ARP_BUF_SIZE);
        memset(hwtype,  0,  MAX_ARP_BUF_SIZE);
        memset(mask,    0,  MAX_ARP_BUF_SIZE);
        memset(hwaddr,  0,  MAX_MAC_LEN);
        memset(device,  0,  MAX_ARP_BUF_SIZE);

        sscanf(arp_line_buffer, "%s %s %s %"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8" %s %s",
               ipaddr, hwtype, flag, &hwaddr[0], &hwaddr[1], &hwaddr[2], 
               &hwaddr[3], &hwaddr[4], &hwaddr[5], mask, device);

        strcpy(arp_entry[num_arp_entry].ipaddr, ipaddr);
        memcpy(arp_entry[num_arp_entry].hwaddr, hwaddr, MAX_MAC_LEN);
        strcpy(arp_entry[num_arp_entry].devinterface, device);

#ifdef DEBUG_PRINT
        fprintf(stdout, "ARP Entry %d is: %s %s %s %02x:%02x:%02x:%02x:%02x:%02x %s %s\n",  
              num_arp_entry, ipaddr, hwtype, flag,
              arp_entry[num_arp_entry].hwaddr[0], 
              arp_entry[num_arp_entry].hwaddr[1], 
              arp_entry[num_arp_entry].hwaddr[2], 
              arp_entry[num_arp_entry].hwaddr[3], 
              arp_entry[num_arp_entry].hwaddr[4], 
              arp_entry[num_arp_entry].hwaddr[5], mask, device); 
#endif
        num_arp_entry++; 
    }

}

uint32_t convert_ip_to_int32(char *ip)
{
    struct in_addr ipaddr;
    inet_aton(ip, &ipaddr);

    return(ipaddr.s_addr);
}

void convert_octet_to_ip(char *ip, uint8_t *ip_octet)
{
    struct sockaddr_in addr;
    inet_aton(ip, &addr.sin_addr);
    ip_octet = inet_ntoa(addr.sin_addr);
}

uint32_t convert_mask_to_int32(int mask)
{
    int i = 0;
    uint32_t mask_bin = 0xFFFFFFFF;
    int num_leftshift = 32 - mask;
    
    mask_bin = (mask_bin >> num_leftshift) & 0xFFFFFFFF;

#if DEBUG_PRINT
    //fprintf(stdout, "MASK converted to int32: %x\n", mask_bin);
#endif

    return(mask_bin);
}


void change_ip_header(struct iphdr *iph)
{
    iph->ttl--;
#if DEBUG_PRINT   
    fprintf(stdout, "Updated TTL - %d\n", iph->ttl);
#endif
    iph->check = 0;
    iph->check = csum((unsigned short *)(iph), sizeof(struct iphdr)/2);
}

void change_local_mac_header(struct ether_header *mac_hdr, int entry)
{
    mac_hdr->ether_dhost[0] = arp_entry[entry].hwaddr[0];
    mac_hdr->ether_dhost[1] = arp_entry[entry].hwaddr[1];
    mac_hdr->ether_dhost[2] = arp_entry[entry].hwaddr[2];
    mac_hdr->ether_dhost[3] = arp_entry[entry].hwaddr[3];
    mac_hdr->ether_dhost[4] = arp_entry[entry].hwaddr[4];
    mac_hdr->ether_dhost[5] = arp_entry[entry].hwaddr[5];

#if DEBUG_PRINT   
    fprintf(stdout, "Next hop mac address: %02x:%02x:%02x:%02x:%02x:%02x\n",
            mac_hdr->ether_dhost[0], mac_hdr->ether_dhost[1], 
            mac_hdr->ether_dhost[2], mac_hdr->ether_dhost[3],
            mac_hdr->ether_dhost[4], mac_hdr->ether_dhost[5]);

    fprintf(stdout, "Source mac address: %02x:%02x:%02x:%02x:%02x:%02x\n",
            mac_hdr->ether_shost[0], mac_hdr->ether_shost[1], 
            mac_hdr->ether_shost[2], mac_hdr->ether_shost[3],
            mac_hdr->ether_shost[4], mac_hdr->ether_shost[5]);
#endif


    mac_hdr->ether_type = htons(ETH_P_IP);
}

void change_mac_header(struct ether_header *mac_hdr, int entry)
{
    mac_hdr->ether_shost[0] = routing_entry[entry].source_mac[0];
    mac_hdr->ether_shost[1] = routing_entry[entry].source_mac[1];
    mac_hdr->ether_shost[2] = routing_entry[entry].source_mac[2];
    mac_hdr->ether_shost[3] = routing_entry[entry].source_mac[3];
    mac_hdr->ether_shost[4] = routing_entry[entry].source_mac[4];
    mac_hdr->ether_shost[5] = routing_entry[entry].source_mac[5];

    mac_hdr->ether_dhost[0] = routing_entry[entry].next_hop_mac[0];
    mac_hdr->ether_dhost[1] = routing_entry[entry].next_hop_mac[1];
    mac_hdr->ether_dhost[2] = routing_entry[entry].next_hop_mac[2];
    mac_hdr->ether_dhost[3] = routing_entry[entry].next_hop_mac[3];
    mac_hdr->ether_dhost[4] = routing_entry[entry].next_hop_mac[4];
    mac_hdr->ether_dhost[5] = routing_entry[entry].next_hop_mac[5];

#if DEBUG_PRINT   
    fprintf(stdout, "Next hop mac address: %02x:%02x:%02x:%02x:%02x:%02x\n",
            mac_hdr->ether_dhost[0], mac_hdr->ether_dhost[1], 
            mac_hdr->ether_dhost[2], mac_hdr->ether_dhost[3],
            mac_hdr->ether_dhost[4], mac_hdr->ether_dhost[5]);

    fprintf(stdout, "Source mac address: %02x:%02x:%02x:%02x:%02x:%02x\n",
            mac_hdr->ether_shost[0], mac_hdr->ether_shost[1], 
            mac_hdr->ether_shost[2], mac_hdr->ether_shost[3],
            mac_hdr->ether_shost[4], mac_hdr->ether_shost[5]);
#endif


    mac_hdr->ether_type = htons(ETH_P_IP);
}

#endif /*_COMMON_H_*/
