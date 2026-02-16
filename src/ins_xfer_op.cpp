#include "ins_xfer_op.h"
#include "ins_clear_op.h"
#include "ins_helper.h"
#include "taint_log.h"

/* threads context */
extern thread_ctx_t *threads_ctx;

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opb_ul(THREADID tid, uint32_t dst,
                                            uint32_t src) {
  tag_t src_tag = RTAG[src][0];

  RTAG[dst][1] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opb_lu(THREADID tid, uint32_t dst,
                                            uint32_t src) {
  tag_t src_tag = RTAG[src][1];

  RTAG[dst][0] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opb_u(THREADID tid, uint32_t dst,
                                           uint32_t src) {
  tag_t src_tag = RTAG[src][1];

  RTAG[dst][1] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opb_l(THREADID tid, uint32_t dst,
                                           uint32_t src) {
  tag_t src_tag = RTAG[src][0];

  RTAG[dst][0] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opw(THREADID tid, uint32_t dst,
                                         uint32_t src) {
  for (size_t i = 0; i < 2; i++) {
    RTAG[dst][i] = RTAG[src][i];
    /*
    if (!tag_is_empty(RTAG[src][i]))
      LOGD("[xfer_w] i%ld: src: %d (%d) -> dst: %d (%d)\n", i, src,
           RTAG[src][i], dst, RTAG[dst][i]);
           */
  }
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opl(THREADID tid, uint32_t dst,
                                         uint32_t src) {
  for (size_t i = 0; i < 4; i++) {
    RTAG[dst][i] = RTAG[src][i];
  }
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opq(THREADID tid, uint32_t dst,
                                         uint32_t src) {
  for (size_t i = 0; i < 8; i++) {
    RTAG[dst][i] = RTAG[src][i];
  }
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opx(THREADID tid, uint32_t dst,
                                         uint32_t src) {
  for (size_t i = 0; i < 16; i++)
    RTAG[dst][i] = RTAG[src][i];
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opy(THREADID tid, uint32_t dst,
                                         uint32_t src) {
  for (size_t i = 0; i < 32; i++)
    RTAG[dst][i] = RTAG[src][i];
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opb_u(THREADID tid, uint32_t dst,
                                           ADDRINT src) {
  tag_t src_tag = MTAG(src);

  RTAG[dst][1] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opb_l(THREADID tid, uint32_t dst,
                                           ADDRINT src) {
  tag_t src_tag = MTAG(src);

  RTAG[dst][0] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opw(THREADID tid, uint32_t dst,
                                         ADDRINT src) {
  for (size_t i = 0; i < 2; i++)
    RTAG[dst][i] = MTAG(src + i);
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opl(THREADID tid, uint32_t dst,
                                         ADDRINT src) {
  for (size_t i = 0; i < 4; i++)
    RTAG[dst][i] = MTAG(src + i);
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opq(THREADID tid, uint32_t dst,
                                         ADDRINT src) {
  for (size_t i = 0; i < 8; i++)
    RTAG[dst][i] = MTAG(src + i);
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opx(THREADID tid, uint32_t dst,
                                         ADDRINT src) {
  for (size_t i = 0; i < 16; i++)
    RTAG[dst][i] = MTAG(src + i);
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opy(THREADID tid, uint32_t dst,
                                         ADDRINT src) {
  for (size_t i = 0; i < 32; i++)
    RTAG[dst][i] = MTAG(src + i);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opb_u(THREADID tid, ADDRINT dst,
                                           uint32_t src) {
  tag_t src_tag = RTAG[src][1];

  tagmap_setb(dst, src_tag);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opb_l(THREADID tid, ADDRINT dst,
                                           uint32_t src) {
  tag_t src_tag = RTAG[src][0];

  tagmap_setb(dst, src_tag);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opw(THREADID tid, ADDRINT dst,
                                         uint32_t src) {
  tag_t *src_tags = RTAG[src];

  tagmap_setb(dst, src_tags[0]);
  tagmap_setb(dst + 1, src_tags[1]);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opl(THREADID tid, ADDRINT dst,
                                         uint32_t src) {
  tag_t *src_tags = RTAG[src];

  for (size_t i = 0; i < 4; i++)
    tagmap_setb(dst + i, src_tags[i]);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opq(THREADID tid, ADDRINT dst,
                                         uint32_t src) {
  tag_t *src_tags = RTAG[src];

  for (size_t i = 0; i < 8; i++)
    tagmap_setb(dst + i, src_tags[i]);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opx(THREADID tid, ADDRINT dst,
                                         uint32_t src) {
  tag_t *src_tags = RTAG[src];

  for (size_t i = 0; i < 16; i++)
    tagmap_setb(dst + i, src_tags[i]);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opy(THREADID tid, ADDRINT dst,
                                         uint32_t src) {
  tag_t *src_tags = RTAG[src];

  for (size_t i = 0; i < 32; i++)
    tagmap_setb(dst + i, src_tags[i]);
}

void PIN_FAST_ANALYSIS_CALL m2m_xfer_opb(ADDRINT dst, ADDRINT src) {
  tag_t src_tag = MTAG(src);

  tagmap_setb(dst, src_tag);
}

void PIN_FAST_ANALYSIS_CALL m2m_xfer_opw(ADDRINT dst, ADDRINT src) {
  for (size_t i = 0; i < 2; i++)
    tagmap_setb(dst + i, MTAG(src + i));
}

void PIN_FAST_ANALYSIS_CALL m2m_xfer_opl(ADDRINT dst, ADDRINT src) {
  for (size_t i = 0; i < 4; i++)
    tagmap_setb(dst + i, MTAG(src + i));
}

void PIN_FAST_ANALYSIS_CALL m2m_xfer_opq(ADDRINT dst, ADDRINT src) {
  for (size_t i = 0; i < 8; i++)
    tagmap_setb(dst + i, MTAG(src + i));
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opq_h(THREADID tid, uint32_t dst,
                                           ADDRINT src) {
  for (size_t i = 0; i < 8; i++)
    RTAG[dst][i + 8] = MTAG(src + i);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opq_h(THREADID tid, ADDRINT dst,
                                           uint32_t src) {
  tag_t *src_tags = RTAG[src];

  for (size_t i = 0; i < 8; i++)
    tagmap_setb(dst + i, src_tags[i + 8]);
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opbn(THREADID tid, ADDRINT dst,
                                                 ADDRINT count,
                                                 ADDRINT eflags) {
  tag_t src_tag = RTAG[DFT_REG_RAX][0];
  if (likely(EFLAGS_DF(eflags) == 0)) {
    /* EFLAGS.DF = 0 */
    for (size_t i = 0; i < count; i++) {
      tagmap_setb(dst + i, src_tag);
    }
  } else {
    /* EFLAGS.DF = 1 */
    for (size_t i = 0; i < count; i++) {
      size_t dst_addr = dst - count + 1 + i;
      tagmap_setb(dst_addr, src_tag);
    }
  }
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opwn(THREADID tid, ADDRINT dst,
                                                 ADDRINT count,
                                                 ADDRINT eflags) {
  tag_t src_tag[] = R16TAG(DFT_REG_RAX);
  if (likely(EFLAGS_DF(eflags) == 0)) {
    /* EFLAGS.DF = 0 */
    for (size_t i = 0; i < (count << 1); i++) {
      tagmap_setb(dst + i, src_tag[i % 2]);
    }
  } else {
    /* EFLAGS.DF = 1 */
    for (size_t i = 0; i < (count << 1); i++) {
      size_t dst_addr = dst - (count << 1) + 1 + i;
      tagmap_setb(dst_addr, src_tag[i % 2]);
    }
  }
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opln(THREADID tid, ADDRINT dst,
                                                 ADDRINT count,
                                                 ADDRINT eflags) {
  tag_t src_tag[] = R32TAG(DFT_REG_RAX);
  if (likely(EFLAGS_DF(eflags) == 0)) {
    /* EFLAGS.DF = 0 */
    for (size_t i = 0; i < (count << 2); i++) {
      tagmap_setb(dst + i, src_tag[i % 4]);
    }
  } else {
    /* EFLAGS.DF = 1 */
    for (size_t i = 0; i < (count << 2); i++) {
      size_t dst_addr = dst - (count << 2) + 1 + i;
      tagmap_setb(dst_addr, src_tag[i % 4]);
    }
  }
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opqn(THREADID tid, ADDRINT dst,
                                                 ADDRINT count,
                                                 ADDRINT eflags) {
  tag_t src_tag[] = R64TAG(DFT_REG_RAX);
  if (likely(EFLAGS_DF(eflags) == 0)) {
    /* EFLAGS.DF = 0 */
    for (size_t i = 0; i < (count << 3); i++) {
      tagmap_setb(dst + i, src_tag[i % 8]);
    }
  } else {
    /* EFLAGS.DF = 1 */
    for (size_t i = 0; i < (count << 3); i++) {
      size_t dst_addr = dst - (count << 3) + 1 + i;
      tagmap_setb(dst_addr, src_tag[i % 8]);
    }
  }
}

static ADDRINT PIN_FAST_ANALYSIS_CALL rep_predicate(BOOL first_iteration) {
  /* return the flag; typically this is true only once */
  return first_iteration;
}

static void PIN_FAST_ANALYSIS_CALL _lea_opw(THREADID tid, uint32_t dst,
                                            uint32_t base, uint32_t index) {
  for (size_t i = 0; i < 2; i++)
    RTAG[dst][i] = tag_combine(RTAG[base][i], RTAG[index][i]);
}

static void PIN_FAST_ANALYSIS_CALL _lea_opl(THREADID tid, uint32_t dst,
                                            uint32_t base, uint32_t index) {
  for (size_t i = 0; i < 4; i++)
    RTAG[dst][i] = tag_combine(RTAG[base][i], RTAG[index][i]);
}

static void PIN_FAST_ANALYSIS_CALL _lea_opq(THREADID tid, uint32_t dst,
                                            uint32_t base, uint32_t index) {
  for (size_t i = 0; i < 8; i++)
    RTAG[dst][i] = tag_combine(RTAG[base][i], RTAG[index][i]);
}

// -------------------------- START LOGGING VERSIONS

static void PIN_FAST_ANALYSIS_CALL r2r_xfer_opb_ul_log(THREADID tid,
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

  r2r_xfer_opb_ul(tid, dst, src);
}

static void PIN_FAST_ANALYSIS_CALL r2r_xfer_opb_lu_log(THREADID tid,
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

  r2r_xfer_opb_lu(tid, dst, src);
}

static void PIN_FAST_ANALYSIS_CALL r2r_xfer_opb_u_log(THREADID tid,
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

  r2r_xfer_opb_u(tid, dst, src);
}

static void PIN_FAST_ANALYSIS_CALL r2r_xfer_opb_l_log(THREADID tid,
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

  r2r_xfer_opb_l(tid, dst, src);
}

static void PIN_FAST_ANALYSIS_CALL r2r_xfer_opw_log(THREADID tid, ADDRINT addr,
                                                    uint32_t dst,
                                                    uint32_t src) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_REG_IDX(src, addr);
  bool tainted = is_any_reg_tainted(tid, src, 2) ||
                 is_any_reg_tainted(tid, dst, 2);

  if (tainted) {
    log_taint(addr);
  }

  r2r_xfer_opw(tid, dst, src);
}

static void PIN_FAST_ANALYSIS_CALL r2r_xfer_opl_log(THREADID tid, ADDRINT addr,
                                                    uint32_t dst,
                                                    uint32_t src) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_REG_IDX(src, addr);
  bool tainted = is_any_reg_tainted(tid, src, 4) ||
                 is_any_reg_tainted(tid, dst, 4);

  if (tainted) {
    log_taint(addr);
  }

  r2r_xfer_opl(tid, dst, src);
}

static void PIN_FAST_ANALYSIS_CALL r2r_xfer_opq_log(THREADID tid, ADDRINT addr,
                                                    uint32_t dst,
                                                    uint32_t src) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_REG_IDX(src, addr);
  bool tainted = is_any_reg_tainted(tid, src, 8) ||
                 is_any_reg_tainted(tid, dst, 8);

  if (tainted) {
    log_taint(addr);
  }

  r2r_xfer_opq(tid, dst, src);
}

static void PIN_FAST_ANALYSIS_CALL r2r_xfer_opx_log(THREADID tid, ADDRINT addr,
                                                    uint32_t dst,
                                                    uint32_t src) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_REG_IDX(src, addr);
  bool tainted = is_any_reg_tainted(tid, src, 16) ||
                 is_any_reg_tainted(tid, dst, 16);

  if (tainted) {
    log_taint(addr);
  }

  r2r_xfer_opx(tid, dst, src);
}

static void PIN_FAST_ANALYSIS_CALL r2r_xfer_opy_log(THREADID tid, ADDRINT addr,
                                                    uint32_t dst,
                                                    uint32_t src) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_REG_IDX(src, addr);
  bool tainted = is_any_reg_tainted(tid, src, 32) ||
                 is_any_reg_tainted(tid, dst, 32);

  if (tainted) {
    log_taint(addr);
  }

  r2r_xfer_opy(tid, dst, src);
}

static void PIN_FAST_ANALYSIS_CALL m2r_xfer_opb_u_log(THREADID tid,
                                                      ADDRINT addr,
                                                      uint32_t dst,
                                                      ADDRINT src) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_MEM_EA(src, addr);
  tag_t src_tag = MTAG(src);
  tag_t dst_tag = RTAG[dst][1];

  if (is_tainted(src_tag) || is_tainted(dst_tag)) {
    log_taint(addr);
  }

  m2r_xfer_opb_u(tid, dst, src);
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opb_l_log(THREADID tid, ADDRINT addr,
                                               uint32_t dst, ADDRINT src) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_MEM_EA(src, addr);
  tag_t src_tag = MTAG(src);
  tag_t dst_tag = RTAG[dst][0];

  if (is_tainted(src_tag) || is_tainted(dst_tag)) {
    log_taint(addr);
  }

  m2r_xfer_opb_l(tid, dst, src);
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opw_log(THREADID tid, ADDRINT addr,
                                             uint32_t dst, ADDRINT src) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_MEM_EA(src, addr);
  bool tainted = is_any_mem_tainted(src, 2) ||
                 is_any_reg_tainted(tid, dst, 2);

  if (tainted) {
    log_taint(addr);
  }

  m2r_xfer_opw(tid, dst, src);
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opl_log(THREADID tid, ADDRINT addr,
                                             uint32_t dst, ADDRINT src) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_MEM_EA(src, addr);
  bool tainted = is_any_mem_tainted(src, 4) ||
                 is_any_reg_tainted(tid, dst, 4);

  if (tainted) {
    log_taint(addr);
  }

  m2r_xfer_opl(tid, dst, src);
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opq_log(THREADID tid, ADDRINT addr,
                                             uint32_t dst, ADDRINT src) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_MEM_EA(src, addr);
  bool tainted = is_any_mem_tainted(src, 8) ||
                 is_any_reg_tainted(tid, dst, 8);

  if (tainted) {
    log_taint(addr);
  }

  m2r_xfer_opq(tid, dst, src);
}

static void PIN_FAST_ANALYSIS_CALL m2r_xfer_opx_log(THREADID tid, ADDRINT addr,
                                                    uint32_t dst,
                                                    ADDRINT src) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_MEM_EA(src, addr);
  bool tainted = is_any_mem_tainted(src, 16) ||
                 is_any_reg_tainted(tid, dst, 16);

  if (tainted) {
    log_taint(addr);
  }

  m2r_xfer_opx(tid, dst, src);
}

static void PIN_FAST_ANALYSIS_CALL m2r_xfer_opy_log(THREADID tid, ADDRINT addr,
                                                    uint32_t dst,
                                                    ADDRINT src) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_MEM_EA(src, addr);
  bool tainted = is_any_mem_tainted(src, 32) ||
                 is_any_reg_tainted(tid, dst, 32);

  if (tainted) {
    log_taint(addr);
  }

  m2r_xfer_opy(tid, dst, src);
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opb_u_log(THREADID tid,
                                                      ADDRINT addr,
                                                      ADDRINT dst,
                                                      uint32_t src) {
  LIBDFT_GUARD_REG_IDX(src, addr);
  LIBDFT_GUARD_MEM_EA(dst, addr);
  tag_t src_tag = RTAG[src][1];
  tag_t dst_tag = MTAG(dst);

  if (is_tainted(src_tag) || is_tainted(dst_tag)) {
    log_taint(addr);
  }

  r2m_xfer_opb_u(tid, dst, src);
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opb_l_log(THREADID tid,
                                                      ADDRINT addr,
                                                      ADDRINT dst,
                                                      uint32_t src) {
  LIBDFT_GUARD_REG_IDX(src, addr);
  LIBDFT_GUARD_MEM_EA(dst, addr);
  tag_t src_tag = RTAG[src][0];
  tag_t dst_tag = MTAG(dst);

  if (is_tainted(src_tag) || is_tainted(dst_tag)) {
    log_taint(addr);
  }

  r2m_xfer_opb_l(tid, dst, src);
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opw_log(THREADID tid, ADDRINT addr,
                                                    ADDRINT dst,
                                                    uint32_t src) {
  LIBDFT_GUARD_REG_IDX(src, addr);
  LIBDFT_GUARD_MEM_EA(dst, addr);
  bool tainted = is_any_reg_tainted(tid, src, 2) ||
                 is_any_mem_tainted(dst, 2);

  if (tainted) {
    log_taint(addr);
  }

  r2m_xfer_opw(tid, dst, src);
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opl_log(THREADID tid, ADDRINT addr,
                                                    ADDRINT dst,
                                                    uint32_t src) {
  LIBDFT_GUARD_REG_IDX(src, addr);
  LIBDFT_GUARD_MEM_EA(dst, addr);
  bool tainted = is_any_reg_tainted(tid, src, 4) ||
                 is_any_mem_tainted(dst, 4);

  if (tainted) {
    log_taint(addr);
  }

  r2m_xfer_opl(tid, dst, src);
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opq_log(THREADID tid, ADDRINT addr,
                                                    ADDRINT dst,
                                                    uint32_t src) {
  LIBDFT_GUARD_REG_IDX(src, addr);
  LIBDFT_GUARD_MEM_EA(dst, addr);
  bool tainted = is_any_reg_tainted(tid, src, 8) ||
                 is_any_mem_tainted(dst, 8);

  if (tainted) {
    log_taint(addr);
  }

  r2m_xfer_opq(tid, dst, src);
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opx_log(THREADID tid, ADDRINT addr,
                                                    ADDRINT dst,
                                                    uint32_t src) {
  LIBDFT_GUARD_REG_IDX(src, addr);
  LIBDFT_GUARD_MEM_EA(dst, addr);
  bool tainted = is_any_reg_tainted(tid, src, 16) ||
                 is_any_mem_tainted(dst, 16);

  if (tainted) {
    log_taint(addr);
  }

  r2m_xfer_opx(tid, dst, src);
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opy_log(THREADID tid, ADDRINT addr,
                                                    ADDRINT dst,
                                                    uint32_t src) {
  LIBDFT_GUARD_REG_IDX(src, addr);
  LIBDFT_GUARD_MEM_EA(dst, addr);
  bool tainted = is_any_reg_tainted(tid, src, 32) ||
                 is_any_mem_tainted(dst, 32);

  if (tainted) {
    log_taint(addr);
  }

  r2m_xfer_opy(tid, dst, src);
}

void PIN_FAST_ANALYSIS_CALL m2m_xfer_opb_log(ADDRINT addr, ADDRINT dst,
                                             ADDRINT src) {
  LIBDFT_GUARD_MEM_EA(dst, addr);
  LIBDFT_GUARD_MEM_EA(src, addr);
  tag_t src_tag = MTAG(src);
  tag_t dst_tag = MTAG(dst);

  if (is_tainted(src_tag) || is_tainted(dst_tag)) {
    log_taint(addr);
  }

  m2m_xfer_opb(dst, src);
}

void PIN_FAST_ANALYSIS_CALL m2m_xfer_opw_log(ADDRINT addr, ADDRINT dst,
                                             ADDRINT src) {
  LIBDFT_GUARD_MEM_EA(dst, addr);
  LIBDFT_GUARD_MEM_EA(src, addr);
  bool tainted = is_any_mem_tainted(src, 2) || is_any_mem_tainted(dst, 2);

  if (tainted) {
    log_taint(addr);
  }

  m2m_xfer_opw(dst, src);
}

void PIN_FAST_ANALYSIS_CALL m2m_xfer_opl_log(ADDRINT addr, ADDRINT dst,
                                             ADDRINT src) {
  LIBDFT_GUARD_MEM_EA(dst, addr);
  LIBDFT_GUARD_MEM_EA(src, addr);
  bool tainted = is_any_mem_tainted(src, 4) || is_any_mem_tainted(dst, 4);

  if (tainted) {
    log_taint(addr);
  }

  m2m_xfer_opl(dst, src);
}

void PIN_FAST_ANALYSIS_CALL m2m_xfer_opq_log(ADDRINT addr, ADDRINT dst,
                                             ADDRINT src) {
  LIBDFT_GUARD_MEM_EA(dst, addr);
  LIBDFT_GUARD_MEM_EA(src, addr);
  bool tainted = is_any_mem_tainted(src, 8) || is_any_mem_tainted(dst, 8);

  if (tainted) {
    log_taint(addr);
  }

  m2m_xfer_opq(dst, src);
}

static void PIN_FAST_ANALYSIS_CALL m2r_xfer_opq_h_log(THREADID tid,
                                                      ADDRINT addr,
                                                      uint32_t dst,
                                                      ADDRINT src) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_MEM_EA(src, addr);
  bool tainted = is_any_mem_tainted(src, 8) ||
                 is_reg_range_tainted(tid, dst, 8, 8);

  if (tainted) {
    log_taint(addr);
  }

  m2r_xfer_opq_h(tid, dst, src);
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opq_h_log(THREADID tid,
                                                      ADDRINT addr,
                                                      ADDRINT dst,
                                                      uint32_t src) {
  LIBDFT_GUARD_REG_IDX(src, addr);
  LIBDFT_GUARD_MEM_EA(dst, addr);
  bool tainted = is_reg_range_tainted(tid, src, 8, 8) ||
                 is_any_mem_tainted(dst, 8);

  if (tainted) {
    log_taint(addr);
  }

  r2m_xfer_opq_h(tid, dst, src);
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opbn_log(THREADID tid,
                                                     ADDRINT addr,
                                                     ADDRINT dst,
                                                     ADDRINT count,
                                                     ADDRINT eflags) {
  if (count == 0) {
    return;
  }

  size_t total = static_cast<size_t>(count);
  ADDRINT base = dst;
  if (EFLAGS_DF(eflags) != 0) {
    base = dst - total + 1;
  }

  LIBDFT_GUARD_MEM_EA(base, addr);
  tag_t src_tag = RTAG[DFT_REG_RAX][0];
  if (is_tainted(src_tag)) {
    log_taint(addr);
  }

  r2m_xfer_opbn(tid, dst, count, eflags);
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opwn_log(THREADID tid,
                                                     ADDRINT addr,
                                                     ADDRINT dst,
                                                     ADDRINT count,
                                                     ADDRINT eflags) {
  if (count == 0) {
    return;
  }

  size_t total = static_cast<size_t>(count) << 1;
  ADDRINT base = dst;
  if (EFLAGS_DF(eflags) != 0) {
    base = dst - total + 1;
  }

  LIBDFT_GUARD_MEM_EA(base, addr);
  bool src_tainted = is_any_reg_tainted(tid, DFT_REG_RAX, 2);
  if (src_tainted) {
    log_taint(addr);
  }

  r2m_xfer_opwn(tid, dst, count, eflags);
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opln_log(THREADID tid,
                                                     ADDRINT addr,
                                                     ADDRINT dst,
                                                     ADDRINT count,
                                                     ADDRINT eflags) {
  if (count == 0) {
    return;
  }

  size_t total = static_cast<size_t>(count) << 2;
  ADDRINT base = dst;
  if (EFLAGS_DF(eflags) != 0) {
    base = dst - total + 1;
  }

  LIBDFT_GUARD_MEM_EA(base, addr);
  bool src_tainted = is_any_reg_tainted(tid, DFT_REG_RAX, 4);
  if (src_tainted) {
    log_taint(addr);
  }

  r2m_xfer_opln(tid, dst, count, eflags);
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opqn_log(THREADID tid,
                                                     ADDRINT addr,
                                                     ADDRINT dst,
                                                     ADDRINT count,
                                                     ADDRINT eflags) {
  if (count == 0) {
    return;
  }

  size_t total = static_cast<size_t>(count) << 3;
  ADDRINT base = dst;
  if (EFLAGS_DF(eflags) != 0) {
    base = dst - total + 1;
  }

  LIBDFT_GUARD_MEM_EA(base, addr);
  bool src_tainted = is_any_reg_tainted(tid, DFT_REG_RAX, 8);
  if (src_tainted) {
    log_taint(addr);
  }

  r2m_xfer_opqn(tid, dst, count, eflags);
}

static void PIN_FAST_ANALYSIS_CALL _lea_opw_log(THREADID tid, ADDRINT addr,
                                                uint32_t dst, uint32_t base,
                                                uint32_t index) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_REG_IDX(base, addr);
  LIBDFT_GUARD_REG_IDX(index, addr);
  bool tainted = is_any_reg_tainted(tid, base, 2) ||
                 is_any_reg_tainted(tid, index, 2);

  if (tainted) {
    log_taint(addr);
  }

  _lea_opw(tid, dst, base, index);
}

static void PIN_FAST_ANALYSIS_CALL _lea_opl_log(THREADID tid, ADDRINT addr,
                                                uint32_t dst, uint32_t base,
                                                uint32_t index) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_REG_IDX(base, addr);
  LIBDFT_GUARD_REG_IDX(index, addr);
  bool tainted = is_any_reg_tainted(tid, base, 4) ||
                 is_any_reg_tainted(tid, index, 4);

  if (tainted) {
    log_taint(addr);
  }

  _lea_opl(tid, dst, base, index);
}

static void PIN_FAST_ANALYSIS_CALL _lea_opq_log(THREADID tid, ADDRINT addr,
                                                uint32_t dst, uint32_t base,
                                                uint32_t index) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_REG_IDX(base, addr);
  LIBDFT_GUARD_REG_IDX(index, addr);
  bool tainted = is_any_reg_tainted(tid, base, 8) ||
                 is_any_reg_tainted(tid, index, 8);

  if (tainted) {
    log_taint(addr);
  }

  _lea_opq(tid, dst, base, index);
}

// -------------------------- END LOGGING VERSIONS

void ins_xfer_op(INS ins) {
  REG reg_dst, reg_src;
  if (INS_MemoryOperandCount(ins) == 0) {
    reg_dst = INS_OperandReg(ins, OP_0);
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_dst)) {
      R2R_CALL_LOG(r2r_xfer_opq_log, reg_dst, reg_src);
    } else if (REG_is_gr32(reg_dst)) {
      R2R_CALL_LOG(r2r_xfer_opl_log, reg_dst, reg_src);
    } else if (REG_is_gr16(reg_dst)) {
      R2R_CALL_LOG(r2r_xfer_opw_log, reg_dst, reg_src);
    } else if (REG_is_xmm(reg_dst)) {
      R2R_CALL_LOG(r2r_xfer_opx_log, reg_dst, reg_src);
    } else if (REG_is_ymm(reg_dst)) {
      R2R_CALL_LOG(r2r_xfer_opy_log, reg_dst, reg_src);
    } else if (REG_is_mm(reg_dst)) {
      R2R_CALL_LOG(r2r_xfer_opq_log, reg_dst, reg_src);
    } else {
      if (REG_is_Lower8(reg_dst) && REG_is_Lower8(reg_src)) {
        R2R_CALL_LOG(r2r_xfer_opb_l_log, reg_dst, reg_src);
      } else if (REG_is_Upper8(reg_dst) && REG_is_Upper8(reg_src)) {
        R2R_CALL_LOG(r2r_xfer_opb_u_log, reg_dst, reg_src);
      } else if (REG_is_Lower8(reg_dst)) {
        R2R_CALL_LOG(r2r_xfer_opb_lu_log, reg_dst, reg_src);
      } else {
        R2R_CALL_LOG(r2r_xfer_opb_ul_log, reg_dst, reg_src);
      }
    }
  } else if (INS_OperandIsMemory(ins, OP_1)) {
    reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_dst)) {
      M2R_CALL_LOG(m2r_xfer_opq_log, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
      M2R_CALL_LOG(m2r_xfer_opl_log, reg_dst);
    } else if (REG_is_gr16(reg_dst)) {
      M2R_CALL_LOG(m2r_xfer_opw_log, reg_dst);
    } else if (REG_is_xmm(reg_dst)) {
      M2R_CALL_LOG(m2r_xfer_opx_log, reg_dst);
    } else if (REG_is_ymm(reg_dst)) {
      M2R_CALL_LOG(m2r_xfer_opy_log, reg_dst);
    } else if (REG_is_mm(reg_dst)) {
      M2R_CALL_LOG(m2r_xfer_opq_log, reg_dst);
    } else if (REG_is_Upper8(reg_dst)) {
      M2R_CALL_LOG(m2r_xfer_opb_u_log, reg_dst);
    } else {
      M2R_CALL_LOG(m2r_xfer_opb_l_log, reg_dst);
    }
  } else {
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_src)) {
      R2M_CALL_LOG(r2m_xfer_opq_log, reg_src);
    } else if (REG_is_gr32(reg_src)) {
      R2M_CALL_LOG(r2m_xfer_opl_log, reg_src);
    } else if (REG_is_gr16(reg_src)) {
      R2M_CALL_LOG(r2m_xfer_opw_log, reg_src);
    } else if (REG_is_xmm(reg_src)) {
      R2M_CALL_LOG(r2m_xfer_opx_log, reg_src);
    } else if (REG_is_ymm(reg_src)) {
      R2M_CALL_LOG(r2m_xfer_opy_log, reg_src);
    } else if (REG_is_mm(reg_src)) {
      R2M_CALL_LOG(r2m_xfer_opq_log, reg_src);
    } else if (REG_is_Upper8(reg_src)) {
      R2M_CALL_LOG(r2m_xfer_opb_u_log, reg_src);
    } else {
      R2M_CALL_LOG(r2m_xfer_opb_l_log, reg_src);
    }
  }
}

void ins_xfer_op_predicated(INS ins) {
  REG reg_dst, reg_src;
  if (INS_MemoryOperandCount(ins) == 0) {
    reg_dst = INS_OperandReg(ins, OP_0);
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_dst)) {
      R2R_CALL_P_LOG(r2r_xfer_opq_log, reg_dst, reg_src);
    } else if (REG_is_gr32(reg_dst)) {
      R2R_CALL_P_LOG(r2r_xfer_opl_log, reg_dst, reg_src);
    } else {
      R2R_CALL_P_LOG(r2r_xfer_opw_log, reg_dst, reg_src);
    }
  } else {
    reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_dst)) {
      M2R_CALL_P_LOG(m2r_xfer_opq_log, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
      M2R_CALL_P_LOG(m2r_xfer_opl_log, reg_dst);
    } else {
      M2R_CALL_P_LOG(m2r_xfer_opw_log, reg_dst);
    }
  }
}

void ins_push_op(INS ins) {
  REG reg_src;
  if (INS_OperandIsReg(ins, OP_0)) {
    reg_src = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_src)) {
      R2M_CALL_LOG(r2m_xfer_opq_log, reg_src);
    } else if (REG_is_gr32(reg_src)) {
      R2M_CALL_LOG(r2m_xfer_opl_log, reg_src);
    } else {
      R2M_CALL_LOG(r2m_xfer_opw_log, reg_src);
    }
  } else if (INS_OperandIsMemory(ins, OP_0)) {
    if (INS_MemoryWriteSize(ins) == BIT2BYTE(MEM_64BIT_LEN)) {
      M2M_CALL_LOG(m2m_xfer_opq_log);
    } else if (INS_MemoryWriteSize(ins) == BIT2BYTE(MEM_LONG_LEN)) {
      M2M_CALL_LOG(m2m_xfer_opl_log);
    } else {
      M2M_CALL_LOG(m2m_xfer_opw_log);
    }
  } else {
    INT32 n = INS_OperandWidth(ins, OP_0) / 8;
    M_CLEAR_N(n);
  }
}

void ins_pop_op(INS ins) {
  REG reg_dst;
  if (INS_OperandIsReg(ins, OP_0)) {
    reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_dst)) {
      M2R_CALL_LOG(m2r_xfer_opq_log, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
      M2R_CALL_LOG(m2r_xfer_opl_log, reg_dst);
    } else {
      M2R_CALL_LOG(m2r_xfer_opw_log, reg_dst);
    }
  } else if (INS_OperandIsMemory(ins, OP_0)) {
    if (INS_MemoryWriteSize(ins) == BIT2BYTE(MEM_64BIT_LEN)) {
      M2M_CALL_LOG(m2m_xfer_opq_log);
    } else if (INS_MemoryWriteSize(ins) == BIT2BYTE(MEM_LONG_LEN)) {
      M2M_CALL_LOG(m2m_xfer_opl_log);
    } else {
      M2M_CALL_LOG(m2m_xfer_opw_log);
    }
  }
}

void ins_stos_ins(INS ins, AFUNPTR fn) {
  INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)rep_predicate,
                             IARG_FAST_ANALYSIS_CALL, IARG_FIRST_REP_ITERATION,
                             IARG_END);
  INS_InsertThenPredicatedCall(
      ins, IPOINT_BEFORE, fn, IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
      IARG_MEMORYWRITE_EA, IARG_REG_VALUE, INS_RepCountRegister(ins),
      IARG_REG_VALUE, INS_OperandReg(ins, OP_4), IARG_END);
}

void ins_stos_ins_log(INS ins, AFUNPTR fn) {
  INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)rep_predicate,
                             IARG_FAST_ANALYSIS_CALL, IARG_FIRST_REP_ITERATION,
                             IARG_END);
  INS_InsertThenPredicatedCall(
      ins, IPOINT_BEFORE, fn, IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
      IARG_INST_PTR, IARG_MEMORYWRITE_EA, IARG_REG_VALUE,
      INS_RepCountRegister(ins), IARG_REG_VALUE, INS_OperandReg(ins, OP_4),
      IARG_END);
}

void ins_stosb(INS ins) {
  if (INS_RepPrefix(ins)) {
    ins_stos_ins_log(ins, (AFUNPTR)r2m_xfer_opbn_log);
  } else {
    R2M_CALL_LOG(r2m_xfer_opb_l_log, REG_AL);
  }
}

void ins_stosw(INS ins) {
  if (INS_RepPrefix(ins)) {
    ins_stos_ins_log(ins, (AFUNPTR)r2m_xfer_opwn_log);
  } else {
    R2M_CALL_LOG(r2m_xfer_opw_log, REG_AX);
  }
}

void ins_stosd(INS ins) {
  if (INS_RepPrefix(ins)) {
    ins_stos_ins_log(ins, (AFUNPTR)r2m_xfer_opln_log);
  } else {
    R2M_CALL_LOG(r2m_xfer_opw_log, REG_EAX);
  }
}

void ins_stosq(INS ins) {
  if (INS_RepPrefix(ins)) {
    ins_stos_ins_log(ins, (AFUNPTR)r2m_xfer_opqn_log);
  } else {
    R2M_CALL_LOG(r2m_xfer_opw_log, REG_RAX);
  }
}

void ins_movlp(INS ins) {
  if (INS_OperandIsMemory(ins, OP_0)) {
    REG reg_src = INS_OperandReg(ins, OP_1);
    R2M_CALL_LOG(r2m_xfer_opq_log, reg_src);
  } else {
    REG reg_dst = INS_OperandReg(ins, OP_0);
    M2R_CALL_LOG(m2r_xfer_opq_log, reg_dst);
  }
}

void ins_movhp(INS ins) {
  if (INS_OperandIsMemory(ins, OP_0)) {
    REG reg_src = INS_OperandReg(ins, OP_1);
    R2M_CALL_LOG(r2m_xfer_opq_h_log, reg_src);
  } else {
    REG reg_dst = INS_OperandReg(ins, OP_0);
    M2R_CALL_LOG(m2r_xfer_opq_h_log, reg_dst);
  }
}

void ins_lea(INS ins) {
  REG reg_base = INS_MemoryBaseReg(ins);
  REG reg_indx = INS_MemoryIndexReg(ins);
  REG reg_dst = INS_OperandReg(ins, OP_0);
  if (reg_base == REG_INVALID() && reg_indx == REG_INVALID()) {
    ins_clear_op(ins);
  }
  if (reg_base != REG_INVALID() && reg_indx == REG_INVALID()) {
    if (REG_is_gr64(reg_dst)) {
      R2R_CALL_LOG(r2r_xfer_opq_log, reg_dst, reg_base);
    } else if (REG_is_gr32(reg_dst)) {
      R2R_CALL_LOG(r2r_xfer_opl_log, reg_dst, reg_base);
    } else if (REG_is_gr16(reg_dst)) {
      R2R_CALL_LOG(r2r_xfer_opw_log, reg_dst, reg_base);
    }
  }
  if (reg_base == REG_INVALID() && reg_indx != REG_INVALID()) {
    if (REG_is_gr64(reg_dst)) {
      R2R_CALL_LOG(r2r_xfer_opq_log, reg_dst, reg_indx);
    } else if (REG_is_gr32(reg_dst)) {
      R2R_CALL_LOG(r2r_xfer_opl_log, reg_dst, reg_indx);
    } else if (REG_is_gr16(reg_dst)) {
      R2R_CALL_LOG(r2r_xfer_opw_log, reg_dst, reg_indx);
    }
  }
  if (reg_base != REG_INVALID() && reg_indx != REG_INVALID()) {
    if (REG_is_gr64(reg_dst)) {
      RR2R_CALL_LOG(_lea_opq_log, reg_dst, reg_base, reg_indx);
    } else if (REG_is_gr32(reg_dst)) {
      RR2R_CALL_LOG(_lea_opl_log, reg_dst, reg_base, reg_indx);
    } else if (REG_is_gr16(reg_dst)) {
      RR2R_CALL_LOG(_lea_opw_log, reg_dst, reg_base, reg_indx);
    }
  }
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opw_rev(THREADID tid, uint32_t dst,
                                             ADDRINT src) {
  for (size_t i = 0; i < 2; i++)
    RTAG[dst][i] = MTAG(src + (1 - i));
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opl_rev(THREADID tid, uint32_t dst,
                                             ADDRINT src) {
  for (size_t i = 0; i < 4; i++)
    RTAG[dst][i] = MTAG(src + (3 - i));
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opq_rev(THREADID tid, uint32_t dst,
                                             ADDRINT src) {
  for (size_t i = 0; i < 8; i++)
    RTAG[dst][i] = MTAG(src + (7 - i));
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opw_rev(THREADID tid, ADDRINT dst,
                                             uint32_t src) {
  tag_t *src_tags = RTAG[src];
  tagmap_setb(dst, src_tags[1]);
  tagmap_setb(dst + 1, src_tags[0]);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opl_rev(THREADID tid, ADDRINT dst,
                                             uint32_t src) {
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 4; i++)
    tagmap_setb(dst + (3 - i), src_tags[i]);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opq_rev(THREADID tid, ADDRINT dst,
                                             uint32_t src) {
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 8; i++)
    tagmap_setb(dst + (7 - i), src_tags[i]);
}

static void PIN_FAST_ANALYSIS_CALL m2r_xfer_opw_rev_log(THREADID tid,
                                                        ADDRINT addr,
                                                        uint32_t dst,
                                                        ADDRINT src) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_MEM_EA(src, addr);
  bool tainted = is_any_mem_tainted(src, 2) ||
                 is_any_reg_tainted(tid, dst, 2);

  if (tainted) {
    log_taint(addr);
  }

  m2r_xfer_opw_rev(tid, dst, src);
}

static void PIN_FAST_ANALYSIS_CALL m2r_xfer_opl_rev_log(THREADID tid,
                                                        ADDRINT addr,
                                                        uint32_t dst,
                                                        ADDRINT src) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_MEM_EA(src, addr);
  bool tainted = is_any_mem_tainted(src, 4) ||
                 is_any_reg_tainted(tid, dst, 4);

  if (tainted) {
    log_taint(addr);
  }

  m2r_xfer_opl_rev(tid, dst, src);
}

static void PIN_FAST_ANALYSIS_CALL m2r_xfer_opq_rev_log(THREADID tid,
                                                        ADDRINT addr,
                                                        uint32_t dst,
                                                        ADDRINT src) {
  LIBDFT_GUARD_REG_IDX(dst, addr);
  LIBDFT_GUARD_MEM_EA(src, addr);
  bool tainted = is_any_mem_tainted(src, 8) ||
                 is_any_reg_tainted(tid, dst, 8);

  if (tainted) {
    log_taint(addr);
  }

  m2r_xfer_opq_rev(tid, dst, src);
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opw_rev_log(THREADID tid,
                                                        ADDRINT addr,
                                                        ADDRINT dst,
                                                        uint32_t src) {
  LIBDFT_GUARD_REG_IDX(src, addr);
  LIBDFT_GUARD_MEM_EA(dst, addr);
  bool tainted = is_any_reg_tainted(tid, src, 2) ||
                 is_any_mem_tainted(dst, 2);

  if (tainted) {
    log_taint(addr);
  }

  r2m_xfer_opw_rev(tid, dst, src);
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opl_rev_log(THREADID tid,
                                                        ADDRINT addr,
                                                        ADDRINT dst,
                                                        uint32_t src) {
  LIBDFT_GUARD_REG_IDX(src, addr);
  LIBDFT_GUARD_MEM_EA(dst, addr);
  bool tainted = is_any_reg_tainted(tid, src, 4) ||
                 is_any_mem_tainted(dst, 4);

  if (tainted) {
    log_taint(addr);
  }

  r2m_xfer_opl_rev(tid, dst, src);
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opq_rev_log(THREADID tid,
                                                        ADDRINT addr,
                                                        ADDRINT dst,
                                                        uint32_t src) {
  LIBDFT_GUARD_REG_IDX(src, addr);
  LIBDFT_GUARD_MEM_EA(dst, addr);
  bool tainted = is_any_reg_tainted(tid, src, 8) ||
                 is_any_mem_tainted(dst, 8);

  if (tainted) {
    log_taint(addr);
  }

  r2m_xfer_opq_rev(tid, dst, src);
}

void ins_movbe_op(INS ins) {
  if (INS_OperandIsMemory(ins, OP_1)) {
    REG reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_dst)) {
      M2R_CALL_LOG(m2r_xfer_opq_rev_log, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
      M2R_CALL_LOG(m2r_xfer_opl_rev_log, reg_dst);
    } else if (REG_is_gr16(reg_dst)) {
      M2R_CALL_LOG(m2r_xfer_opw_rev_log, reg_dst);
    }
  } else {
    REG reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_src)) {
      R2M_CALL_LOG(r2m_xfer_opq_rev_log, reg_src);
    } else if (REG_is_gr32(reg_src)) {
      R2M_CALL_LOG(r2m_xfer_opl_rev_log, reg_src);
    } else if (REG_is_gr16(reg_src)) {
      R2M_CALL_LOG(r2m_xfer_opw_rev_log, reg_src);
    }
  }
}
