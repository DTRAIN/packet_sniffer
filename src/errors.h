#ifndef ERRORS_H
#define ERRORS_H
#include "stdio.h"
#include "stdlib.h"
#define USAGE_ERR 1
#define DEV_ERR 2
void fatal_err(int error_code, char* error_msg);
void print_err(char* error_msg);
#endif
