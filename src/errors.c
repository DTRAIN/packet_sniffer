#include "errors.h"
void fatal_err(int error_code, char* error_msg) {
  fprintf(stderr, "%s\n", error_msg);
  exit(error_code);
}
void print_err(char* error_msg) {
  fprintf(stderr, "%s\n", error_msg);
}
void print_pcap_err(char* msg, char* pcap_msg) {
  fprintf(stderr, "%s %s\n", msg, pcap_msg);
}
