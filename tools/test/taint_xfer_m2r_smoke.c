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

static __attribute__((noinline)) void do_m2r_byte(uint8_t *p,
                                                  uint16_t *ax) {
  asm volatile("movb (%1), %%al" : "+a"(*ax) : "r"(p)); // TRACE: m2r_bl
  asm volatile("movb (%1), %%ah" : "+a"(*ax) : "r"(p)); // TRACE: m2r_bu
}

static __attribute__((noinline)) void do_m2r_sizes(uint16_t *p16,
                                                   uint32_t *p32,
                                                   uint64_t *p64,
                                                   __m128i *p128,
                                                   uint16_t *ax,
                                                   uint32_t *eax,
                                                   uint64_t *rax,
                                                   __m128i *xmm0) {
  asm volatile("movw (%1), %%ax" : "+a"(*ax) : "r"(p16)); // TRACE: m2r_w
  asm volatile("movl (%1), %%eax" : "+a"(*eax) : "r"(p32)); // TRACE: m2r_l
  asm volatile("movq (%1), %%rax" : "+a"(*rax) : "r"(p64)); // TRACE: m2r_q
  asm volatile("movdqu (%1), %0" : "+x"(*xmm0) : "r"(p128)); // TRACE: m2r_x
}

int main(void) {
  uint8_t m8 = 0x11;
  uint16_t m16 = 0x2233;
  uint32_t m32 = 0x44556677;
  uint64_t m64 = 0x8899aabbccddeeffULL;
  __m128i m128 = _mm_set1_epi8(0x7f);

  uint16_t ax = 0;
  uint32_t eax = 0;
  uint64_t rax = 0;
  __m128i xmm0 = _mm_setzero_si128();

  __libdft_set_taint(&m8, sizeof(m8), 10);
  __libdft_set_taint(&m16, sizeof(m16), 11);
  __libdft_set_taint(&m32, sizeof(m32), 12);
  __libdft_set_taint(&m64, sizeof(m64), 13);
  __libdft_set_taint(&m128, sizeof(m128), 14);

  do_m2r_byte(&m8, &ax);
  do_m2r_sizes(&m16, &m32, &m64, &m128, &ax, &eax, &rax, &xmm0);

  __libdft_get_taint(&ax, sizeof(ax));
  __libdft_get_taint(&eax, sizeof(eax));
  __libdft_get_taint(&rax, sizeof(rax));
  __libdft_get_taint(&xmm0, sizeof(xmm0));

  printf("Results: ax=0x%04x eax=0x%08x rax=0x%016lx\n", ax, eax, rax);
  return 0;
}
