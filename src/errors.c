#include "errors.h"
void fatal_err(int error_code, char* error_msg) {
  fprintf(stderr, "%s", error_msg);
  exit(error_code);
}
void print_err(char* error_msg) {
  fprintf(stderr, "%s", error_msg);
}
