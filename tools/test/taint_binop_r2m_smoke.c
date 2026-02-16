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

/* Dummy implementation - Pin tool will intercept this */
void __attribute__((noinline)) __libdft_getval_taint(uint64_t v) {
  (void)v;
}

static __attribute__((noinline)) void op_r2m_b(uint8_t *out, uint8_t v) {
  asm volatile("orb %1, (%0)" : : "r"(out), "q"(v) : "memory"); // TRACE: r2m_b
}

static __attribute__((noinline)) void op_r2m_w(uint16_t *out, uint16_t v) {
  asm volatile("orw %1, (%0)" : : "r"(out), "r"(v) : "memory"); // TRACE: r2m_w
}

static __attribute__((noinline)) void op_r2m_l(uint32_t *out, uint32_t v) {
  asm volatile("xorl %1, (%0)" : : "r"(out), "r"(v) : "memory"); // TRACE: r2m_l
}

static __attribute__((noinline)) void op_r2m_q(uint64_t *out, uint64_t v) {
  asm volatile("xorq %1, (%0)" : : "r"(out), "r"(v) : "memory"); // TRACE: r2m_q
}

int main(void) {
  uint8_t out8 = 0;
  uint16_t out16 = 0;
  uint32_t out32 = 0;
  uint64_t out64 = 0;

  uint8_t a8 = 0x11;
  uint16_t a16 = 0x0f0f;
  uint32_t a32 = 0x12345678;
  uint64_t a64 = 0x0102030405060708ULL;

  printf("Tainting r2m inputs...\n");
  __libdft_set_taint(&a8, sizeof(a8), 40);
  __libdft_set_taint(&a16, sizeof(a16), 41);
  __libdft_set_taint(&a32, sizeof(a32), 42);
  __libdft_set_taint(&a64, sizeof(a64), 43);

  printf("Running r2m ops...\n");
  op_r2m_b(&out8, a8);
  op_r2m_w(&out16, a16);
  op_r2m_l(&out32, a32);
  op_r2m_q(&out64, a64);

  __libdft_get_taint(&out8, sizeof(out8));
  __libdft_get_taint(&out16, sizeof(out16));
  __libdft_get_taint(&out32, sizeof(out32));
  __libdft_get_taint(&out64, sizeof(out64));
  __libdft_getval_taint(out32);

  printf("Results: out8=0x%02x out16=0x%04x out32=0x%08x out64=0x%016lx\n",
         out8, out16, out32, out64);
  return 0;
}
