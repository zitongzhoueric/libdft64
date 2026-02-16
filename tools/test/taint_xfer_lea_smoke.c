#include <stdio.h>
#include <stdint.h>

/* Dummy implementation - Pin tool will intercept this */
void __attribute__((noinline)) __libdft_set_taint(void *p, size_t size,
                                                  unsigned int offset) {
  (void)p;
  (void)size;
  (void)offset;
}

/* Dummy implementation - Pin tool will intercept this */
void __attribute__((noinline)) __libdft_get_taint(void *p, size_t size) {
  (void)p;
  (void)size;
}

static __attribute__((noinline)) void do_lea_ops(uint32_t *b32, uint32_t *i32,
                                                 uint64_t *b64, uint64_t *i64) {
  uint32_t o32 = 0;
  uint64_t o64 = 0;

  asm volatile("leal (%1,%2), %0" : "=r"(o32) : "r"(*b32), "r"(*i32)); // TRACE: lea_l
  asm volatile("leaq (%1,%2), %0" : "=r"(o64) : "r"(*b64), "r"(*i64)); // TRACE: lea_q

  __libdft_get_taint(&o32, sizeof(o32));
  __libdft_get_taint(&o64, sizeof(o64));
}

int main(void) {
  uint32_t b32 = 0x1000;
  uint32_t i32 = 0x2000;
  uint64_t b64 = 0x10000;
  uint64_t i64 = 0x20000;

  __libdft_set_taint(&b32, sizeof(b32), 72);
  __libdft_set_taint(&i32, sizeof(i32), 73);
  __libdft_set_taint(&b64, sizeof(b64), 74);
  __libdft_set_taint(&i64, sizeof(i64), 75);

  do_lea_ops(&b32, &i32, &b64, &i64);

  printf("Results: b32=0x%08x b64=0x%016lx\n", b32, b64);
  return 0;
}
