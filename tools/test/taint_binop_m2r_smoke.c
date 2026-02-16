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

static __attribute__((noinline)) uint8_t op_m2r_b(uint8_t *p) {
  uint8_t res = 0x5a;
  asm volatile("xorb %1, %0" : "+q"(res) : "m"(*p)); // TRACE: m2r_b
  return res;
}

static __attribute__((noinline)) uint16_t op_m2r_w(uint16_t *p) {
  uint16_t res = 0x1234;
  asm volatile("xorw %1, %0" : "+r"(res) : "m"(*p)); // TRACE: m2r_w
  return res;
}

static __attribute__((noinline)) uint32_t op_m2r_l(uint32_t *p) {
  uint32_t res = 0x12345678;
  asm volatile("xorl %1, %0" : "+r"(res) : "m"(*p)); // TRACE: m2r_l
  return res;
}

static __attribute__((noinline)) uint64_t op_m2r_q(uint64_t *p) {
  uint64_t res = 0x1122334455667788ULL;
  asm volatile("xorq %1, %0" : "+r"(res) : "m"(*p)); // TRACE: m2r_q
  return res;
}

static __attribute__((noinline)) __m128i op_m2r_xmm(__m128i *p) {
  __m128i res = _mm_set1_epi8(0x11);
  asm volatile("pxor %1, %0" : "+x"(res) : "m"(*p)); // TRACE: m2r_xmm
  return res;
}

int main(void) {
  uint8_t m8 = 0x0f;
  uint16_t m16 = 0x0f0f;
  uint32_t m32 = 0xaaaaaaaa;
  uint64_t m64 = 0x0102030405060708ULL;
  __m128i m128 = _mm_set1_epi8(0xaa);

  printf("Tainting m2r inputs...\n");
  __libdft_set_taint(&m8, sizeof(m8), 30);
  __libdft_set_taint(&m16, sizeof(m16), 31);
  __libdft_set_taint(&m32, sizeof(m32), 32);
  __libdft_set_taint(&m64, sizeof(m64), 33);
  __libdft_set_taint(&m128, sizeof(m128), 34);

  printf("Running m2r ops...\n");
  uint8_t out8 = op_m2r_b(&m8);
  uint16_t out16 = op_m2r_w(&m16);
  uint32_t out32 = op_m2r_l(&m32);
  uint64_t out64 = op_m2r_q(&m64);
  __m128i out128 = op_m2r_xmm(&m128);

  __libdft_get_taint(&out8, sizeof(out8));
  __libdft_get_taint(&out16, sizeof(out16));
  __libdft_get_taint(&out32, sizeof(out32));
  __libdft_get_taint(&out64, sizeof(out64));
  __libdft_get_taint(&out128, sizeof(out128));
  __libdft_getval_taint(out16);

  printf("Results: out8=0x%02x out16=0x%04x out32=0x%08x out64=0x%016lx\n",
         out8, out16, out32, out64);
  return 0;
}
