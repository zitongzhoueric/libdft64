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

static __attribute__((noinline)) void do_stos_ops(uint8_t *buf,
                                                  uint64_t *val_ptr) {
  uint8_t *dst;
  uint64_t val = *val_ptr;

  asm volatile("cld" : : : "cc");

  dst = buf;
  asm volatile("stosb" : "+D"(dst), "+a"(val) : : "memory"); // TRACE: stosb

  dst = buf + 8;
  asm volatile("stosw" : "+D"(dst), "+a"(val) : : "memory"); // TRACE: stosw

  dst = buf + 16;
  asm volatile("stosl" : "+D"(dst), "+a"(val) : : "memory"); // TRACE: stosd

  dst = buf + 24;
  asm volatile("stosq" : "+D"(dst), "+a"(val) : : "memory"); // TRACE: stosq
}

static __attribute__((noinline)) void do_rep_stos(uint8_t *buf,
                                                  uint64_t *val_ptr) {
  uint8_t *dst;
  uint64_t val = *val_ptr;
  size_t count = 4;

  asm volatile("cld" : : : "cc");

  dst = buf + 32;
  asm volatile("rep stosb" : "+D"(dst), "+c"(count), "+a"(val) : : "memory"); // TRACE: rep_stosb

  count = 4;
  dst = buf + 48;
  asm volatile("rep stosw" : "+D"(dst), "+c"(count), "+a"(val) : : "memory"); // TRACE: rep_stosw

  count = 4;
  dst = buf + 64;
  asm volatile("rep stosl" : "+D"(dst), "+c"(count), "+a"(val) : : "memory"); // TRACE: rep_stosd

  count = 4;
  dst = buf + 80;
  asm volatile("rep stosq" : "+D"(dst), "+c"(count), "+a"(val) : : "memory"); // TRACE: rep_stosq
}

int main(void) {
  uint8_t buf[128] = {0};
  uint64_t val = 0x0102030405060708ULL;

  __libdft_set_taint(&val, sizeof(val), 40);

  do_stos_ops(buf, &val);
  do_rep_stos(buf, &val);

  __libdft_get_taint(buf, 8);

  printf("Results: buf0=0x%02x buf1=0x%02x\n", buf[0], buf[1]);
  return 0;
}
