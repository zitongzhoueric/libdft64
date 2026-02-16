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

static __attribute__((noinline)) void do_movbe(uint16_t *m16, uint32_t *m32,
                                               uint64_t *m64, uint16_t *o16,
                                               uint32_t *o32, uint64_t *o64) {
  asm volatile("movbe (%1), %0" : "=r"(*o16) : "r"(m16)); // TRACE: movbe_m2r_w
  asm volatile("movbe (%1), %0" : "=r"(*o32) : "r"(m32)); // TRACE: movbe_m2r_l
  asm volatile("movbe (%1), %0" : "=r"(*o64) : "r"(m64)); // TRACE: movbe_m2r_q

  asm volatile("movbe %1, (%0)" : : "r"(m16), "r"(*o16) : "memory"); // TRACE: movbe_r2m_w
  asm volatile("movbe %1, (%0)" : : "r"(m32), "r"(*o32) : "memory"); // TRACE: movbe_r2m_l
  asm volatile("movbe %1, (%0)" : : "r"(m64), "r"(*o64) : "memory"); // TRACE: movbe_r2m_q
}

int main(void) {
  uint16_t m16 = 0x1122;
  uint32_t m32 = 0x33445566;
  uint64_t m64 = 0x778899aabbccddeeULL;
  uint16_t o16 = 0;
  uint32_t o32 = 0;
  uint64_t o64 = 0;

  __libdft_set_taint(&m16, sizeof(m16), 50);
  __libdft_set_taint(&m32, sizeof(m32), 51);
  __libdft_set_taint(&m64, sizeof(m64), 52);

  do_movbe(&m16, &m32, &m64, &o16, &o32, &o64);

  __libdft_get_taint(&o16, sizeof(o16));
  __libdft_get_taint(&o32, sizeof(o32));
  __libdft_get_taint(&o64, sizeof(o64));

  printf("Results: o16=0x%04x o32=0x%08x o64=0x%016lx\n", o16, o32, o64);
  return 0;
}
