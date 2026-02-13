#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"
#include <iostream>

extern "C" {
void __attribute__((noinline)) __libdft_set_taint(void *p, unsigned int offset) {
  printf("set: %p, offset: %d\n", p, offset);
}

void __attribute__((noinline)) __libdft_get_taint(void *p, size_t size) {
  printf("get: %p, size: %lu\n", p, size);
}

void __attribute__((noinline)) __libdft_getval_taint(uint64_t v) {
  printf("getval: %lu\n", v);
}
}

int main(int argc, char **argv) {
  printf("=== Granularity Test: Proving Byte-Level Taint Precision ===\n\n");

  // Test 1: Adjacent uint8_t variables with 16-byte padding
  printf("Test 1: Adjacent uint8_t variables (adjacent)\n");
  uint8_t a = 0xAA;
  uint8_t b = 0xBB;
  uint8_t c = 0xCC;

  printf("Address of a: %p\n", (void*)&a);
  printf("Address of b: %p (offset: %ld bytes)\n", (void*)&b, (char*)&b - (char*)&a);
  printf("Address of c: %p (offset: %ld bytes)\n\n", (void*)&c, (char*)&c - (char*)&a);

  // Taint only 'b' with offset 100
  printf("Tainting 'b' only (1 byte, offset 100):\n");
  __libdft_set_taint(&b, 100);
  
  printf("\nChecking taint on each variable:\n");
  __libdft_get_taint(&a, sizeof(a));  // Should be clean
  __libdft_get_taint(&b, sizeof(b));  // Should be tainted
  __libdft_get_taint(&c, sizeof(c));  // Should be clean

  return 0;
}
