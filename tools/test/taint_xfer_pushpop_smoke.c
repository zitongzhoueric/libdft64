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

static __attribute__((noinline)) void do_push_pop_reg(uint64_t *val,
                                                      uint64_t *out) {
  uint64_t rbx = 0;
  asm volatile("pushq %0" : : "r"(*val) : "memory"); // TRACE: push_reg
  asm volatile("popq %0" : "=r"(rbx) : : "memory"); // TRACE: pop_reg
  *out = rbx;
}

static __attribute__((noinline)) void do_push_mem(uint64_t *src,
                                                  uint64_t *out) {
  uint64_t rbx = 0;
  asm volatile("pushq (%0)" : : "r"(src) : "memory"); // TRACE: push_mem
  asm volatile("popq %0" : "=r"(rbx) : : "memory");
  *out = rbx;
}

static __attribute__((noinline)) void do_pop_mem(uint64_t *val,
                                                 uint64_t *dst) {
  asm volatile("pushq %0" : : "r"(*val) : "memory");
  asm volatile("popq (%0)" : : "r"(dst) : "memory"); // TRACE: pop_mem
}

int main(void) {
  uint64_t v = 0x1122334455667788ULL;
  uint64_t out = 0;
  uint64_t mem = 0;

  __libdft_set_taint(&v, sizeof(v), 30);

  do_push_pop_reg(&v, &out);
  do_push_mem(&v, &out);
  do_pop_mem(&v, &mem);

  __libdft_get_taint(&out, sizeof(out));
  __libdft_get_taint(&mem, sizeof(mem));

  printf("Results: out=0x%016lx mem=0x%016lx\n", out, mem);
  return 0;
}
