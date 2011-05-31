#ifndef PACKET_H
#define PACKET_H
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET 14
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)
#define TH_OFF(th)	        (((th)->th_offx2 & 0xf0) >> 4)
/* Ethernet header */
struct ethernet_hdr {
  u_char dest_addr[ETHER_ADDR_LEN];/* dest addr */
  u_char src_addr[ETHER_ADDR_LEN];/* src addr */
  u_short ether_type; /* Protocol family */
};
/* IP header */
struct ip_hdr {
  u_char ip_vhl;/* version << 4 | header length >> 2 */
  u_char ip_tos;/* TOS */
  u_short ip_len;/* packet len */
  u_short ip_id;/* id */
  u_short ip_off;/* fragment offset field */
#define IP_RF 0x8000/* reserved fragment flag */
#define IP_DF 0x4000/* dont fragment flag */
#define IP_MF 0x2000/* more fragments flag */
#define IP_OFFMASK 0x1fff/* mask for fragmenting bits */
  u_char ip_ttl;/* TTL  */
  u_char ip_p;/* protocol */
  u_short ip_sum;/* checksum */
  struct in_addr ip_src,ip_dst; /* src and dest addr */
};

/* TCP header */
struct tcp_hdr {
  u_short th_sport;/* src port */
  u_short th_dport;/* dest port */
  u_int th_seq;/* seq # */
  u_int th_ack;/* ack # */
  u_char th_offx2;/* data offset, rsvd */
  u_char th_flags;/*packet flags*/
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
  u_short th_win;/* window */
  u_short th_sum;/* checksum */
  u_short th_urp;/* urgent pointer */
};
#endif
