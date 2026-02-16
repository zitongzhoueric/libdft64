#include "ins_binary_op.h"
#include "ins_helper.h"
#include "taint_log.h"

/* threads context */
extern thread_ctx_t *threads_ctx;

static void PIN_FAST_ANALYSIS_CALL __attribute__((unused))
r2r_binary_opb_ul(THREADID tid, uint32_t dst, uint32_t src) {
  tag_t src_tag = RTAG[src][0];
  tag_t dst_tag = RTAG[dst][1];

  RTAG[dst][1] = tag_combine(dst_tag, src_tag);
}

static void PIN_FAST_ANALYSIS_CALL __attribute__((unused))
r2r_binary_opb_lu(THREADID tid, uint32_t dst, uint32_t src) {
  tag_t src_tag = RTAG[src][1];
  tag_t dst_tag = RTAG[dst][0];

  RTAG[dst][0] = tag_combine(dst_tag, src_tag);
}

static void PIN_FAST_ANALYSIS_CALL __attribute__((unused))
r2r_binary_opb_u(THREADID tid, uint32_t dst, uint32_t src) {
  tag_t src_tag = RTAG[src][1];
  tag_t dst_tag = RTAG[dst][1];

  RTAG[dst][1] = tag_combine(dst_tag, src_tag);
}

static void PIN_FAST_ANALYSIS_CALL __attribute__((unused))
r2r_binary_opb_l(THREADID tid, uint32_t dst, uint32_t src) {
  tag_t src_tag = RTAG[src][0];
  tag_t dst_tag = RTAG[dst][0];

  RTAG[dst][0] = tag_combine(dst_tag, src_tag);
}

static void PIN_FAST_ANALYSIS_CALL __attribute__((unused))
r2r_binary_opw(THREADID tid, uint32_t dst, uint32_t src) {
  tag_t *src_tags = RTAG[src];
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 2; i++)
    dst_tags[i] = tag_combine(dst_tags[i], src_tags[i]);
}

static void PIN_FAST_ANALYSIS_CALL __attribute__((unused))
r2r_binary_opl(THREADID tid, uint32_t dst, uint32_t src) {
  tag_t *src_tags = RTAG[src];
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 4; i++)
    dst_tags[i] = tag_combine(dst_tags[i], src_tags[i]);
}

static void PIN_FAST_ANALYSIS_CALL __attribute__((unused))
r2r_binary_opq(THREADID tid, uint32_t dst, uint32_t src) {
  tag_t *src_tags = RTAG[src];
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 8; i++)
    dst_tags[i] = tag_combine(dst_tags[i], src_tags[i]);
}

static void PIN_FAST_ANALYSIS_CALL __attribute__((unused))
r2r_binary_opx(THREADID tid, uint32_t dst, uint32_t src) {
  tag_t *src_tags = RTAG[src];
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 16; i++)
    dst_tags[i] = tag_combine(dst_tags[i], src_tags[i]);
}

static void PIN_FAST_ANALYSIS_CALL __attribute__((unused))
r2r_binary_opy(THREADID tid, uint32_t dst, uint32_t src) {

  tag_t *src_tags = RTAG[src];
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 32; i++)
    dst_tags[i] = tag_combine(dst_tags[i], src_tags[i]);
}

static void PIN_FAST_ANALYSIS_CALL __attribute__((unused))
m2r_binary_opb_u(THREADID tid, uint32_t dst, ADDRINT src) {
  tag_t src_tag = MTAG(src);
  tag_t dst_tag = RTAG[dst][1];

  RTAG[dst][1] = tag_combine(src_tag, dst_tag);
}

static void PIN_FAST_ANALYSIS_CALL __attribute__((unused))
m2r_binary_opb_l(THREADID tid, uint32_t dst, ADDRINT src) {
  tag_t src_tag = MTAG(src);
  tag_t dst_tag = RTAG[dst][0];

  RTAG[dst][0] = tag_combine(src_tag, dst_tag);
}

static void PIN_FAST_ANALYSIS_CALL __attribute__((unused))
m2r_binary_opw(THREADID tid, uint32_t dst, ADDRINT src) {
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 2; i++)
    dst_tags[i] = tag_combine(dst_tags[i], MTAG(src + i));
}

static void PIN_FAST_ANALYSIS_CALL __attribute__((unused))
m2r_binary_opl(THREADID tid, uint32_t dst, ADDRINT src) {
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 4; i++)
    dst_tags[i] = tag_combine(dst_tags[i], MTAG(src + i));
}

static void PIN_FAST_ANALYSIS_CALL __attribute__((unused))
m2r_binary_opq(THREADID tid, uint32_t dst, ADDRINT src) {
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 8; i++)
    dst_tags[i] = tag_combine(dst_tags[i], MTAG(src + i));
}

static void PIN_FAST_ANALYSIS_CALL __attribute__((unused))
m2r_binary_opx(THREADID tid, uint32_t dst, ADDRINT src) {
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 16; i++)
    dst_tags[i] = tag_combine(dst_tags[i], MTAG(src + i));
}

static void PIN_FAST_ANALYSIS_CALL __attribute__((unused))
m2r_binary_opy(THREADID tid, uint32_t dst, ADDRINT src) {
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 32; i++)
    dst_tags[i] = tag_combine(dst_tags[i], MTAG(src + i));
}

static void PIN_FAST_ANALYSIS_CALL __attribute__((unused))
r2m_binary_opb_u(THREADID tid, ADDRINT dst, uint32_t src) {
  tag_t src_tag = RTAG[src][1];
  tag_t dst_tag = MTAG(dst);

  tag_t res_tag = tag_combine(dst_tag, src_tag);
  tagmap_setb(dst, res_tag);
}

static void PIN_FAST_ANALYSIS_CALL __attribute__((unused))
r2m_binary_opb_l(THREADID tid, ADDRINT dst, uint32_t src) {
  tag_t src_tag = RTAG[src][0];
  tag_t dst_tag = MTAG(dst);

  tag_t res_tag = tag_combine(dst_tag, src_tag);
  tagmap_setb(dst, res_tag);
}

static void PIN_FAST_ANALYSIS_CALL __attribute__((unused))
r2m_binary_opw(THREADID tid, ADDRINT dst, uint32_t src) {
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 2; i++)
    tagmap_setb(dst + i, tag_combine(MTAG(dst + i), src_tags[i]));
}

static void PIN_FAST_ANALYSIS_CALL __attribute__((unused))
r2m_binary_opl(THREADID tid, ADDRINT dst, uint32_t src) {
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 4; i++)
    tagmap_setb(dst + i, tag_combine(MTAG(dst + i), src_tags[i]));
}

static void PIN_FAST_ANALYSIS_CALL __attribute__((unused))
r2m_binary_opq(THREADID tid, ADDRINT dst, uint32_t src) {
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 8; i++)
    tagmap_setb(dst + i, tag_combine(MTAG(dst + i), src_tags[i]));
}

static void PIN_FAST_ANALYSIS_CALL __attribute__((unused))
r2m_binary_opx(THREADID tid, ADDRINT dst, uint32_t src) {
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 16; i++)
    tagmap_setb(dst + i, tag_combine(MTAG(dst + i), src_tags[i]));
}

static void PIN_FAST_ANALYSIS_CALL __attribute__((unused))
r2m_binary_opy(THREADID tid, ADDRINT dst, uint32_t src) {
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 32; i++)
    tagmap_setb(dst + i, tag_combine(MTAG(dst + i), src_tags[i]));
}

// -------------------------------------- LOGGING VERSIONS

/* Logging version for 8-bit upper/lower mixed ops (dst upper, src lower) */
static void PIN_FAST_ANALYSIS_CALL r2r_binary_opb_ul_log(THREADID tid,
                                                         ADDRINT addr,
                                                         uint32_t dst,
                                                         uint32_t src) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_REG_IDX(src, addr);
  tag_t src_tag = RTAG[src][0];
  tag_t dst_tag = RTAG[dst][1];

  if (is_tainted(src_tag) || is_tainted(dst_tag)) {
    log_taint(addr);
  }

  RTAG[dst][1] = tag_combine(dst_tag, src_tag);
}

/* Logging version for 8-bit lower/upper mixed ops (dst lower, src upper) */
static void PIN_FAST_ANALYSIS_CALL r2r_binary_opb_lu_log(THREADID tid,
                                                         ADDRINT addr,
                                                         uint32_t dst,
                                                         uint32_t src) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_REG_IDX(src, addr);
  tag_t src_tag = RTAG[src][1];
  tag_t dst_tag = RTAG[dst][0];

  if (is_tainted(src_tag) || is_tainted(dst_tag)) {
    log_taint(addr);
  }

  RTAG[dst][0] = tag_combine(dst_tag, src_tag);
}

/* Logging version for 8-bit upper ops */
static void PIN_FAST_ANALYSIS_CALL r2r_binary_opb_u_log(THREADID tid,
                                                        ADDRINT addr,
                                                        uint32_t dst,
                                                        uint32_t src) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_REG_IDX(src, addr);
  tag_t src_tag = RTAG[src][1];
  tag_t dst_tag = RTAG[dst][1];

  if (is_tainted(src_tag) || is_tainted(dst_tag)) {
    log_taint(addr);
  }

  RTAG[dst][1] = tag_combine(dst_tag, src_tag);
}

/* Logging version for 8-bit lower ops */
static void PIN_FAST_ANALYSIS_CALL r2r_binary_opb_l_log(THREADID tid,
                                                        ADDRINT addr,
                                                        uint32_t dst,
                                                        uint32_t src) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_REG_IDX(src, addr);
  tag_t src_tag = RTAG[src][0];
  tag_t dst_tag = RTAG[dst][0];

  if (is_tainted(src_tag) || is_tainted(dst_tag)) {
    log_taint(addr);
  }

  RTAG[dst][0] = tag_combine(dst_tag, src_tag);
}

/* Logging version for 16-bit operations */
static void PIN_FAST_ANALYSIS_CALL r2r_binary_opw_log(THREADID tid, ADDRINT addr,
                                                      uint32_t dst, uint32_t src) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_REG_IDX(src, addr);
  bool tainted = is_any_reg_tainted(tid, src, 2) ||
                 is_any_reg_tainted(tid, dst, 2);

  if (tainted) {
    log_taint(addr);
  }

  tag_t *src_tags = RTAG[src];
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 2; i++)
    dst_tags[i] = tag_combine(dst_tags[i], src_tags[i]);
}

/* Logging version for 32-bit operations */
static void PIN_FAST_ANALYSIS_CALL r2r_binary_opl_log(THREADID tid, ADDRINT addr,
                                                      uint32_t dst, uint32_t src) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_REG_IDX(src, addr);
  bool tainted = is_any_reg_tainted(tid, src, 4) ||
                 is_any_reg_tainted(tid, dst, 4);

  if (tainted) {
    log_taint(addr);
  }

  tag_t *src_tags = RTAG[src];
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 4; i++)
    dst_tags[i] = tag_combine(dst_tags[i], src_tags[i]);
}

/* Logging version for 64-bit operations */
static void PIN_FAST_ANALYSIS_CALL r2r_binary_opq_log(THREADID tid, ADDRINT addr,
                                                      uint32_t dst, uint32_t src) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_REG_IDX(src, addr);
  bool tainted = is_any_reg_tainted(tid, src, 8) ||
                 is_any_reg_tainted(tid, dst, 8);

  if (tainted) {
    log_taint(addr);
  }

  tag_t *src_tags = RTAG[src];
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 8; i++)
    dst_tags[i] = tag_combine(dst_tags[i], src_tags[i]);
}

/* Logging version for 128-bit operations */
static void PIN_FAST_ANALYSIS_CALL r2r_binary_opx_log(THREADID tid, ADDRINT addr,
                                                      uint32_t dst, uint32_t src) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_REG_IDX(src, addr);
  bool tainted = is_any_reg_tainted(tid, src, 16) ||
                 is_any_reg_tainted(tid, dst, 16);

  if (tainted) {
    log_taint(addr);
  }

  tag_t *src_tags = RTAG[src];
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 16; i++)
    dst_tags[i] = tag_combine(dst_tags[i], src_tags[i]);
}

/* Logging version for 256-bit operations */
static void PIN_FAST_ANALYSIS_CALL r2r_binary_opy_log(THREADID tid, ADDRINT addr,
                                                      uint32_t dst, uint32_t src) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_REG_IDX(src, addr);
  bool tainted = is_any_reg_tainted(tid, src, 32) ||
                 is_any_reg_tainted(tid, dst, 32);

  if (tainted) {
    log_taint(addr);
  }

  tag_t *src_tags = RTAG[src];
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 32; i++)
    dst_tags[i] = tag_combine(dst_tags[i], src_tags[i]);
}

/* Logging version for memory-to-register 8-bit upper ops */
static void PIN_FAST_ANALYSIS_CALL m2r_binary_opb_u_log(THREADID tid, ADDRINT addr,
                                                        uint32_t dst, ADDRINT src) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_MEM_EA(src, addr);
  tag_t src_tag = MTAG(src);
  tag_t dst_tag = RTAG[dst][1];

  if (is_tainted(src_tag) || is_tainted(dst_tag)) {
    log_taint(addr);
  }

  RTAG[dst][1] = tag_combine(src_tag, dst_tag);
}

/* Logging version for memory-to-register 8-bit lower ops */
static void PIN_FAST_ANALYSIS_CALL m2r_binary_opb_l_log(THREADID tid, ADDRINT addr,
                                                        uint32_t dst, ADDRINT src) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_MEM_EA(src, addr);
  tag_t src_tag = MTAG(src);
  tag_t dst_tag = RTAG[dst][0];

  if (is_tainted(src_tag) || is_tainted(dst_tag)) {
    log_taint(addr);
  }

  RTAG[dst][0] = tag_combine(src_tag, dst_tag);
}

/* Logging version for memory-to-register 16-bit ops */
static void PIN_FAST_ANALYSIS_CALL m2r_binary_opw_log(THREADID tid, ADDRINT addr,
                                                      uint32_t dst, ADDRINT src) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_MEM_EA(src, addr);
  bool tainted = is_any_mem_tainted(src, 2) ||
                 is_any_reg_tainted(tid, dst, 2);

  if (tainted) {
    log_taint(addr);
  }

  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 2; i++)
    dst_tags[i] = tag_combine(dst_tags[i], MTAG(src + i));
}

/* Logging version for memory-to-register 32-bit ops */
static void PIN_FAST_ANALYSIS_CALL m2r_binary_opl_log(THREADID tid, ADDRINT addr,
                                                      uint32_t dst, ADDRINT src) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_MEM_EA(src, addr);
  bool tainted = is_any_mem_tainted(src, 4) ||
                 is_any_reg_tainted(tid, dst, 4);

  if (tainted) {
    log_taint(addr);
  }

  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 4; i++)
    dst_tags[i] = tag_combine(dst_tags[i], MTAG(src + i));
}

/* Logging version for memory-to-register 64-bit ops */
static void PIN_FAST_ANALYSIS_CALL m2r_binary_opq_log(THREADID tid, ADDRINT addr,
                                                      uint32_t dst, ADDRINT src) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_MEM_EA(src, addr);
  bool tainted = is_any_mem_tainted(src, 8) ||
                 is_any_reg_tainted(tid, dst, 8);

  if (tainted) {
    log_taint(addr);
  }

  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 8; i++)
    dst_tags[i] = tag_combine(dst_tags[i], MTAG(src + i));
}

/* Logging version for memory-to-register 128-bit ops */
static void PIN_FAST_ANALYSIS_CALL m2r_binary_opx_log(THREADID tid, ADDRINT addr,
                                                      uint32_t dst, ADDRINT src) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_MEM_EA(src, addr);
  bool tainted = is_any_mem_tainted(src, 16) ||
                 is_any_reg_tainted(tid, dst, 16);

  if (tainted) {
    log_taint(addr);
  }

  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 16; i++)
    dst_tags[i] = tag_combine(dst_tags[i], MTAG(src + i));
}

/* Logging version for memory-to-register 256-bit ops */
static void PIN_FAST_ANALYSIS_CALL m2r_binary_opy_log(THREADID tid, ADDRINT addr,
                                                      uint32_t dst, ADDRINT src) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_MEM_EA(src, addr);
  bool tainted = is_any_mem_tainted(src, 32) ||
                 is_any_reg_tainted(tid, dst, 32);

  if (tainted) {
    log_taint(addr);
  }

  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 32; i++)
    dst_tags[i] = tag_combine(dst_tags[i], MTAG(src + i));
}

/* Logging version for register-to-memory 8-bit upper ops */
static void PIN_FAST_ANALYSIS_CALL r2m_binary_opb_u_log(THREADID tid, ADDRINT addr,
                                                        ADDRINT dst, uint32_t src) {
  LIBDFT_GUARD_REG_IDX(src, addr);
  LIBDFT_GUARD_MEM_EA(dst, addr);
  tag_t src_tag = RTAG[src][1];
  tag_t dst_tag = MTAG(dst);

  if (is_tainted(src_tag) || is_tainted(dst_tag)) {
    log_taint(addr);
  }

  tagmap_setb(dst, tag_combine(dst_tag, src_tag));
}

/* Logging version for register-to-memory 8-bit lower ops */
static void PIN_FAST_ANALYSIS_CALL r2m_binary_opb_l_log(THREADID tid, ADDRINT addr,
                                                        ADDRINT dst, uint32_t src) {
  LIBDFT_GUARD_REG_IDX(src, addr);
  LIBDFT_GUARD_MEM_EA(dst, addr);
  tag_t src_tag = RTAG[src][0];
  tag_t dst_tag = MTAG(dst);

  if (is_tainted(src_tag) || is_tainted(dst_tag)) {
    log_taint(addr);
  }

  tagmap_setb(dst, tag_combine(dst_tag, src_tag));
}

/* Logging version for register-to-memory 16-bit ops */
static void PIN_FAST_ANALYSIS_CALL r2m_binary_opw_log(THREADID tid, ADDRINT addr,
                                                      ADDRINT dst, uint32_t src) {
  LIBDFT_GUARD_REG_IDX(src, addr);
  LIBDFT_GUARD_MEM_EA(dst, addr);
  bool tainted = is_any_reg_tainted(tid, src, 2) ||
                 is_any_mem_tainted(dst, 2);

  if (tainted) {
    log_taint(addr);
  }

  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 2; i++)
    tagmap_setb(dst + i, tag_combine(MTAG(dst + i), src_tags[i]));
}

/* Logging version for register-to-memory 32-bit ops */
static void PIN_FAST_ANALYSIS_CALL r2m_binary_opl_log(THREADID tid, ADDRINT addr,
                                                      ADDRINT dst, uint32_t src) {
  LIBDFT_GUARD_REG_IDX(src, addr);
  LIBDFT_GUARD_MEM_EA(dst, addr);
  bool tainted = is_any_reg_tainted(tid, src, 4) ||
                 is_any_mem_tainted(dst, 4);

  if (tainted) {
    log_taint(addr);
  }

  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 4; i++)
    tagmap_setb(dst + i, tag_combine(MTAG(dst + i), src_tags[i]));
}

/* Logging version for register-to-memory 64-bit ops */
static void PIN_FAST_ANALYSIS_CALL r2m_binary_opq_log(THREADID tid, ADDRINT addr,
                                                      ADDRINT dst, uint32_t src) {
  LIBDFT_GUARD_REG_IDX(src, addr);
  LIBDFT_GUARD_MEM_EA(dst, addr);
  bool tainted = is_any_reg_tainted(tid, src, 8) ||
                 is_any_mem_tainted(dst, 8);

  if (tainted) {
    log_taint(addr);
  }

  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 8; i++)
    tagmap_setb(dst + i, tag_combine(MTAG(dst + i), src_tags[i]));
}

/* Logging version for register-to-memory 128-bit ops */
static void PIN_FAST_ANALYSIS_CALL r2m_binary_opx_log(THREADID tid, ADDRINT addr,
                                                      ADDRINT dst, uint32_t src) {
  LIBDFT_GUARD_REG_IDX(src, addr);
  LIBDFT_GUARD_MEM_EA(dst, addr);
  bool tainted = is_any_reg_tainted(tid, src, 16) ||
                 is_any_mem_tainted(dst, 16);

  if (tainted) {
    log_taint(addr);
  }

  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 16; i++)
    tagmap_setb(dst + i, tag_combine(MTAG(dst + i), src_tags[i]));
}

/* Logging version for register-to-memory 256-bit ops */
static void PIN_FAST_ANALYSIS_CALL r2m_binary_opy_log(THREADID tid, ADDRINT addr,
                                                      ADDRINT dst, uint32_t src) {
  LIBDFT_GUARD_REG_IDX(src, addr);
  LIBDFT_GUARD_MEM_EA(dst, addr);
  bool tainted = is_any_reg_tainted(tid, src, 32) ||
                 is_any_mem_tainted(dst, 32);

  if (tainted) {
    log_taint(addr);
  }

  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 32; i++)
    tagmap_setb(dst + i, tag_combine(MTAG(dst + i), src_tags[i]));
}
// -------------------------- END LOGGING VERSIONS

void ins_binary_op(INS ins) {
  if (INS_OperandIsImmediate(ins, OP_1))
    return;
  REG reg_dst, reg_src;
  if (INS_MemoryOperandCount(ins) == 0) {
    reg_dst = INS_OperandReg(ins, OP_0);
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_dst)) {
      R2R_CALL_LOG(r2r_binary_opq_log, reg_dst, reg_src);
    } else if (REG_is_gr32(reg_dst)) {
      R2R_CALL_LOG(r2r_binary_opl_log, reg_dst, reg_src);
    } else if (REG_is_gr16(reg_dst)) {
      R2R_CALL_LOG(r2r_binary_opw_log, reg_dst, reg_src);
    } else if (REG_is_xmm(reg_dst)) {
      R2R_CALL_LOG(r2r_binary_opx_log, reg_dst, reg_src);
    } else if (REG_is_ymm(reg_dst)) {
      // AVX YMM ops are typically three-operand (ternary) instructions.
      // Binary-op tests don't cover YMM; ternary handlers should be used.
      R2R_CALL_LOG(r2r_binary_opy_log, reg_dst, reg_src);
    } else if (REG_is_mm(reg_dst)) {
      R2R_CALL_LOG(r2r_binary_opq_log, reg_dst, reg_src);
    } else {
      if (REG_is_Lower8(reg_dst) && REG_is_Lower8(reg_src)) {
        R2R_CALL_LOG(r2r_binary_opb_l_log, reg_dst, reg_src);
      } else if (REG_is_Upper8(reg_dst) && REG_is_Upper8(reg_src))
        R2R_CALL_LOG(r2r_binary_opb_u_log, reg_dst, reg_src);
      else if (REG_is_Lower8(reg_dst))
        R2R_CALL_LOG(r2r_binary_opb_lu_log, reg_dst, reg_src);
      else
        R2R_CALL_LOG(r2r_binary_opb_ul_log, reg_dst, reg_src);
    }
  } else if (INS_OperandIsMemory(ins, OP_1)) {
    reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_dst)) {
      M2R_CALL_LOG(m2r_binary_opq_log, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
      M2R_CALL_LOG(m2r_binary_opl_log, reg_dst);
    } else if (REG_is_gr16(reg_dst)) {
      M2R_CALL_LOG(m2r_binary_opw_log, reg_dst);
    } else if (REG_is_xmm(reg_dst)) {
      M2R_CALL_LOG(m2r_binary_opx_log, reg_dst);
    } else if (REG_is_ymm(reg_dst)) {
      M2R_CALL_LOG(m2r_binary_opy_log, reg_dst);
    } else if (REG_is_mm(reg_dst)) {
      M2R_CALL_LOG(m2r_binary_opq_log, reg_dst);
    } else if (REG_is_Upper8(reg_dst)) {
      M2R_CALL_LOG(m2r_binary_opb_u_log, reg_dst);
    } else {
      M2R_CALL_LOG(m2r_binary_opb_l_log, reg_dst);
    }
  } else {
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_src)) {
      R2M_CALL_LOG(r2m_binary_opq_log, reg_src);
    } else if (REG_is_gr32(reg_src)) {
      R2M_CALL_LOG(r2m_binary_opl_log, reg_src);
    } else if (REG_is_gr16(reg_src)) {
      R2M_CALL_LOG(r2m_binary_opw_log, reg_src);
    } else if (REG_is_xmm(reg_src)) {
      R2M_CALL_LOG(r2m_binary_opx_log, reg_src);
    } else if (REG_is_ymm(reg_src)) {
      R2M_CALL_LOG(r2m_binary_opy_log, reg_src);
    } else if (REG_is_mm(reg_src)) {
      R2M_CALL_LOG(r2m_binary_opq_log, reg_src);
    } else if (REG_is_Upper8(reg_src)) {
      R2M_CALL_LOG(r2m_binary_opb_u_log, reg_src);
    } else {
      R2M_CALL_LOG(r2m_binary_opb_l_log, reg_src);
    }
  }
}
