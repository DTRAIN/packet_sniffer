#ifndef PACKET_H
#define PACKET_H
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET 14
#define IP_HDRLEN(ip)		(((ip)->ver_hdrlen) & 0x0f)
#define IP_VERSION(ip)		(((ip)->ver_hdrlen) >> 4)
#define TCP_OFFSET(tcp)	        (((tcp)->off & 0xf0) >> 4)
/* Ethernet header */
struct ethernet_hdr {
  u_char dest_addr[ETHER_ADDR_LEN];/* dest addr */
  u_char src_addr[ETHER_ADDR_LEN];/* src addr */
  u_short ether_type; /* Protocol family */
};
/* IP header */
struct ip_hdr {
  u_char ver_hdrlen;/* version << 4 | header length >> 2 */
  u_char tos;/* TOS */
  u_short len;/* packet len */
  u_short id;/* id */
  u_short off;/* fragment offset field */
#define IP_RF 0x8000/* reserved fragment flag */
#define IP_DF 0x4000/* dont fragment flag */
#define IP_MF 0x2000/* more fragments flag */
#define IP_OFFMASK 0x1fff/* mask for fragmenting bits */
  u_char ttl;/* TTL  */
  u_char prot;/* protocol */
  u_short chksum;/* checksum */
  struct in_addr src_ip, dest_ip; /* src and dest addr */
};

/* TCP header */
struct tcp_hdr {
  u_short src_prt;/* src port */
  u_short dest_prt;/* dest port */
  u_int seq;/* seq # */
  u_int ack;/* ack # */
  u_char off;/* data offset, rsvd */
  u_char flags;/*packet flags*/
#define FIN 0x01
#define SYN 0x02
#define RST 0x04
#define PSH 0x08
#define ACK 0x10
#define URG 0x20
#define ECE 0x40
#define CWR 0x80
#define FLAGS (FIN|SYN|RST|ACK|URG|ECE|CWR)
  u_short win;/* window */
  u_short chksum;/* checksum */
  u_short urg;/* urgent pointer */
};
#endif
