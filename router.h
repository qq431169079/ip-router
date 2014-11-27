/*
 * router.h
 * Custom Router header
 *
 * @author : Himanshu Mehra - hmehra@usc.edu
 *           Yash Goyal     - ygoyal@usc.edu
 *           Saket Mahajani - smmahajana@usc.edu
 * @team   : SHY
 */

#ifndef __ROUTER_H__
#define __ROUTER_H__

#include <stdint.h>
#include <assert.h>
#include "common.h"

typedef struct {
    uint32_t        epoch;
    uint16_t        tcp_port;
    uint16_t        udp_port;
    float           probability;
    FILE           *loghdl;
    double          epoch_start;
    uint32_t        epoch_cnt;
    uint32_t        local_addr;
} router_input_t;


typedef struct {
    uint32_t        router_addr;
    uint32_t        victim_addr;
    uint16_t        victim_port;
} router_pcap_loop_t;


#endif  /* #ifndef __ROUTER_H__ */
