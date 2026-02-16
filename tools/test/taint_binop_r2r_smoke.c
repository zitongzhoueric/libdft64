#include <stdio.h>
#include <stdint.h>
#include <immintrin.h>

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

static __attribute__((noinline)) uint8_t op_r2r_b(uint8_t a, uint8_t b) {
  uint8_t res;
  asm volatile("orb %2, %0" : "=q"(res) : "0"(a), "q"(b)); // TRACE: r2r_b
  return res;
}

static __attribute__((noinline)) uint16_t op_r2r_w(uint16_t a, uint16_t b) {
  uint16_t res;
  asm volatile("xorw %2, %0" : "=r"(res) : "0"(a), "r"(b)); // TRACE: r2r_w
  return res;
}

static __attribute__((noinline)) uint32_t op_r2r_l(uint32_t a, uint32_t b) {
  uint32_t res;
  asm volatile("xorl %2, %0" : "=r"(res) : "0"(a), "r"(b)); // TRACE: r2r_l
  return res;
}

static __attribute__((noinline)) uint64_t op_r2r_q(uint64_t a, uint64_t b) {
  uint64_t res;
  asm volatile("xorq %2, %0" : "=r"(res) : "0"(a), "r"(b)); // TRACE: r2r_q
  return res;
}

static __attribute__((noinline)) __m128i op_r2r_xmm(__m128i a, __m128i b) {
  __m128i res;
  asm volatile("pxor %2, %0" : "=x"(res) : "0"(a), "x"(b)); // TRACE: r2r_xmm
  return res;
}

int main(void) {
  uint8_t a8 = 0x11;
  uint8_t b8 = 0x22;
  uint16_t a16 = 0x00ff;
  uint16_t b16 = 0x0f0f;
  uint32_t a32 = 0x12345678;
  uint32_t b32 = 0x01020304;
  uint64_t a64 = 0x1122334455667788ULL;
  uint64_t b64 = 0x0102030405060708ULL;
  __m128i a128 = _mm_set1_epi8(0x11);
  __m128i b128 = _mm_set1_epi8(0x22);

  printf("Tainting r2r inputs...\n");
  __libdft_set_taint(&a8, sizeof(a8), 10);
  __libdft_set_taint(&b8, sizeof(b8), 11);
  __libdft_set_taint(&a16, sizeof(a16), 12);
  __libdft_set_taint(&b16, sizeof(b16), 13);
  __libdft_set_taint(&a32, sizeof(a32), 14);
  __libdft_set_taint(&b32, sizeof(b32), 15);
  __libdft_set_taint(&a64, sizeof(a64), 16);
  __libdft_set_taint(&b64, sizeof(b64), 17);
  __libdft_set_taint(&a128, sizeof(a128), 18);
  __libdft_set_taint(&b128, sizeof(b128), 19);

  printf("Running r2r ops...\n");
  uint8_t out8 = op_r2r_b(a8, b8);
  uint16_t out16 = op_r2r_w(a16, b16);
  uint32_t out32 = op_r2r_l(a32, b32);
  uint64_t out64 = op_r2r_q(a64, b64);
  __m128i out128 = op_r2r_xmm(a128, b128);

  __libdft_get_taint(&out8, sizeof(out8));
  __libdft_get_taint(&out16, sizeof(out16));
  __libdft_get_taint(&out32, sizeof(out32));
  __libdft_get_taint(&out64, sizeof(out64));
  __libdft_get_taint(&out128, sizeof(out128));
  __libdft_getval_taint(out32);

  printf("Results: out8=0x%02x out16=0x%04x out32=0x%08x out64=0x%016lx\n",
         out8, out16, out32, out64);
  return 0;
}
