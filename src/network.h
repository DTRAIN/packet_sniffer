#ifndef NETWORK_H
#define NETWORK_H
#include <stdio.h>
#include <pcap.h>
#include "errors.h"
#define STD_TIMEOUT 1000
#define MAX_FILTER_LENGTH 512
#define MAX_DEV_LENGTH 16
#define PROMISC_YES 1
#define PROMISC_NO 0
#define PCAP_COMP_OPTIMIZE 1
#define PCAP_COMP_NOOPTIMIZE 0
void get_pcap_netmask(char* device, bpf_u_int32* net, bpf_u_int32* mask);
char* select_pcap_dev(void);
pcap_t* open_pcap_session(char* dev);
int set_pcap_filter(pcap_t* session, char* regexp, bpf_u_int32 net);
#endif