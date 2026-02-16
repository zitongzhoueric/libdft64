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

static __attribute__((noinline)) void do_r2m_byte(uint16_t *ax,
                                                  uint8_t *dst) {
  asm volatile("movb %%al, (%0)" : : "r"(dst), "a"(*ax) : "memory"); // TRACE: r2m_bl
  asm volatile("movb %%ah, (%0)" : : "r"(dst), "a"(*ax) : "memory"); // TRACE: r2m_bu
}

static __attribute__((noinline)) void do_r2m_sizes(uint16_t *ax, uint32_t *eax,
                                                   uint64_t *rax,
                                                   __m128i *xmm0,
                                                   uint16_t *dst16,
                                                   uint32_t *dst32,
                                                   uint64_t *dst64,
                                                   __m128i *dst128) {
  asm volatile("movw %%ax, (%0)" : : "r"(dst16), "a"(*ax) : "memory"); // TRACE: r2m_w
  asm volatile("movl %%eax, (%0)" : : "r"(dst32), "a"(*eax) : "memory"); // TRACE: r2m_l
  asm volatile("movq %%rax, (%0)" : : "r"(dst64), "a"(*rax) : "memory"); // TRACE: r2m_q
  asm volatile("movdqu %1, (%0)" : : "r"(dst128), "x"(*xmm0) : "memory"); // TRACE: r2m_x
}

int main(void) {
  uint16_t ax = 0x1234;
  uint32_t eax = 0x55667788;
  uint64_t rax = 0x1122334455667788ULL;
  __m128i xmm0 = _mm_set1_epi8(0x44);

  uint8_t out8 = 0;
  uint16_t out16 = 0;
  uint32_t out32 = 0;
  uint64_t out64 = 0;
  __m128i out128 = _mm_setzero_si128();

  __libdft_set_taint(&ax, sizeof(ax), 20);
  __libdft_set_taint(&eax, sizeof(eax), 21);
  __libdft_set_taint(&rax, sizeof(rax), 22);
  __libdft_set_taint(&xmm0, sizeof(xmm0), 23);

  do_r2m_byte(&ax, &out8);
  do_r2m_sizes(&ax, &eax, &rax, &xmm0, &out16, &out32, &out64, &out128);

  __libdft_get_taint(&out8, sizeof(out8));
  __libdft_get_taint(&out16, sizeof(out16));
  __libdft_get_taint(&out32, sizeof(out32));
  __libdft_get_taint(&out64, sizeof(out64));
  __libdft_get_taint(&out128, sizeof(out128));

  printf("Results: out8=0x%02x out16=0x%04x out32=0x%08x out64=0x%016lx\n",
         out8, out16, out32, out64);
  return 0;
}
