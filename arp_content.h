#ifndef __ARP_CONTENT_H__
#define __ARP_CONTENT_H__

#include <inttypes.h>

#define MAX_ARP_BUF_SIZE    50
#define MAX_ARP_ENTRY       100
#define MAX_IP_LEN          20
#define MAX_MAC_LEN         6


typedef struct arp_content_t {
    char    ipaddr[MAX_IP_LEN];
    uint8_t hwaddr[MAX_MAC_LEN];
    char    devinterface[10];
}arp_content;

arp_content     arp_entry[MAX_ARP_ENTRY];
int             num_arp_entry = 0;

void parse_arp_content(void);

#endif /*__ARP_CONTENT_H__*/
