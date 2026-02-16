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

static __attribute__((noinline)) void do_r2r_byte(uint16_t *ax, uint16_t *bx) {
  asm volatile("movb %%al, %%ah" : "+a"(*ax) : : "cc"); // TRACE: r2r_ul
  asm volatile("movb %%ah, %%al" : "+a"(*ax) : : "cc"); // TRACE: r2r_lu
  asm volatile("movb %%al, %%bl" : "+a"(*ax), "+b"(*bx) : : "cc"); // TRACE: r2r_ll
  asm volatile("movb %%ah, %%bh" : "+a"(*ax), "+b"(*bx) : : "cc"); // TRACE: r2r_uu
}

static __attribute__((noinline)) void do_r2r_sizes(uint16_t *ax, uint16_t *bx,
                                                   uint32_t *eax, uint32_t *ebx,
                                                   uint64_t *rax, uint64_t *rbx,
                                                   __m128i *xmm0,
                                                   __m128i *xmm1) {
  asm volatile("movw %%ax, %%bx" : "+a"(*ax), "+b"(*bx) : : "cc"); // TRACE: r2r_w
  asm volatile("movl %%eax, %%ebx" : "+a"(*eax), "+b"(*ebx) : : "cc"); // TRACE: r2r_l
  asm volatile("movq %%rax, %%rbx" : "+a"(*rax), "+b"(*rbx) : : "cc"); // TRACE: r2r_q
  asm volatile("movdqu %1, %0" : "+x"(*xmm1) : "x"(*xmm0)); // TRACE: r2r_x
}

int main(void) {
  uint16_t ax = 0x1234;
  uint16_t bx = 0x5678;
  uint32_t eax = 0x12345678;
  uint32_t ebx = 0;
  uint64_t rax = 0x1122334455667788ULL;
  uint64_t rbx = 0;
  __m128i xmm0 = _mm_set1_epi8(0x11);
  __m128i xmm1 = _mm_setzero_si128();

  __libdft_set_taint(&ax, sizeof(ax), 1);
  __libdft_set_taint(&eax, sizeof(eax), 2);
  __libdft_set_taint(&rax, sizeof(rax), 3);
  __libdft_set_taint(&xmm0, sizeof(xmm0), 4);

  do_r2r_byte(&ax, &bx);
  do_r2r_sizes(&ax, &bx, &eax, &ebx, &rax, &rbx, &xmm0, &xmm1);

  __libdft_get_taint(&bx, sizeof(bx));
  __libdft_get_taint(&ebx, sizeof(ebx));
  __libdft_get_taint(&rbx, sizeof(rbx));
  __libdft_get_taint(&xmm1, sizeof(xmm1));

  printf("Results: bx=0x%04x ebx=0x%08x rbx=0x%016lx\n", bx, ebx, rbx);
  return 0;
}
