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

static __attribute__((noinline)) void do_movlph(uint8_t *mem, __m128 *xmm) {
  asm volatile("movlps (%1), %0" : "+x"(*xmm) : "r"(mem) : "memory"); // TRACE: movlp_m2r
  asm volatile("movhps (%1), %0" : "+x"(*xmm) : "r"(mem) : "memory"); // TRACE: movhp_m2r
  asm volatile("movlps %1, (%0)" : : "r"(mem), "x"(*xmm) : "memory"); // TRACE: movlp_r2m
  asm volatile("movhps %1, (%0)" : : "r"(mem), "x"(*xmm) : "memory"); // TRACE: movhp_r2m
}

int main(void) {
  uint8_t mem[16] = {0};
  __m128 xmm = _mm_set1_ps(1.0f);

  __libdft_set_taint(mem, sizeof(mem), 60);
  __libdft_set_taint(&xmm, sizeof(xmm), 61);

  do_movlph(mem, &xmm);

  __libdft_get_taint(mem, sizeof(mem));
  __libdft_get_taint(&xmm, sizeof(xmm));

  printf("Results: mem0=0x%02x\n", mem[0]);
  return 0;
}
