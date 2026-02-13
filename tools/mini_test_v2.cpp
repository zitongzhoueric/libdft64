#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include <iostream>

extern "C" {
void __attribute__((noinline)) __libdft_set_taint(void *p, size_t size, unsigned int offset) {
  printf("set: %p, size: %lu, offset: %d\n", p, size, offset);
}

void __attribute__((noinline)) __libdft_get_taint(void *p, size_t size) {
  printf("get: %p, size: %lu\n", p, size);
}

void __attribute__((noinline)) __libdft_getval_taint(uint64_t v) {
  printf("getval: %lu\n", v);
}
}

void __attribute__((noinline)) foo(uint64_t v) { __libdft_get_taint(&v, sizeof(v)); }

int main(int argc, char **argv) {
  if (argc < 2)
    return 0;

  FILE *fp;
  char buf[255];
  size_t ret;

  fp = fopen(argv[1], "rb");

  if (!fp) {
    printf("st err\n");
    return 0;
  }
  size_t len = 20;
  ret = fread(buf, sizeof *buf, len, fp);

  fclose(fp);
  if (ret < len) {
    return 0;
  }

  uint64_t m = 0;
  std::cout << "=== Tainting entire uint64_t m ===" << std::endl;
  __libdft_set_taint(&m, sizeof(m), 2);  // Taint entire uint64_t as coming from byte offset 2
  __libdft_get_taint(&m, sizeof(m));
  __libdft_getval_taint(m);

  uint16_t x = 0;
  std::cout << "\n=== Checking x before memcpy ===" << std::endl;
  __libdft_get_taint(&x, sizeof(x));  // Query only 2 bytes
  
  memcpy(&x, buf + 5, 2); // Copy 2 bytes from buffer
  
  std::cout << "\n=== Checking x after memcpy ===" << std::endl;
  __libdft_get_taint(&x, sizeof(x));  // Query only 2 bytes
  std::cout << "Register taint of x:" << std::endl;
  __libdft_getval_taint(x);

  uint64_t y = x + 2;
  std::cout << "\n=== Checking y = x + 2 ===" << std::endl;
  __libdft_getval_taint(y);

  return 0;
}
