#include <unistd.h>
#include <string.h>
#include "network.h"
#include "errors.h"
int main(int argc, char** argv) {
  int opt = 0;
  const char* optstring = "f:d:";
  char* device = 0;
  char* filter_exp = 0;
  pcap_t* session = 0;
  bpf_u_int32 net, mask;
  if(geteuid() != 0) {
    print_err("Error: This application must be run as root");
    return USAGE_ERR;
  }
  if(argc > 1) {
    /* if there are args, parse them */
    while((opt = getopt(argc, argv, optstring)) != -1) {
      switch(opt) {
        /* user specified filter */
      case 'f':
        filter_exp = (char*)malloc(MAX_FILTER_LENGTH);
        memmove(filter_exp, optarg, MAX_FILTER_LENGTH);
        break;
        /* user specified device */
      case 'd':
        device = (char*)malloc(MAX_DEV_LENGTH);
        memmove(device, optarg, MAX_DEV_LENGTH);
        break;
        /* someone entered a wrong argument */
      default:
        print_err("Usage: ./sniffer [-d device] [-f filter]");
        return USAGE_ERR;
      }
    }
  }
  /*if no user selected device, have the program select one*/
  if(device == NULL) {
    device = select_pcap_dev();
  }
  /* if no device is found, return */
  if(device == NULL) {
    print_err("Could not find device\n");
    return DEV_ERR;
  }
  /* get the netmask */
  get_pcap_netmask(device, &net, &mask);
  /* open a session */
  session = open_pcap_session(device);
  /* if it fails to open a session, return */
  if(session == NULL) {
    print_err("Failed to open session\n");
    return DEV_ERR;
  }
  /* set the filter for this session */
  set_pcap_filter(session, filter_exp, net);
  if(filter_exp != NULL) {
    free(filter_exp);
  }
  //loop infinitely
  pcap_loop(session, -1, handle_pcap_pkt, NULL);
  /* close session for correct cleanup */
  pcap_close(session);
  return 0;
}
