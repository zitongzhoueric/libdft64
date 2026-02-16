/*-
 * Copyright (c) 2010, Columbia University
 * All rights reserved.
 *
 * This software was developed by Vasileios P. Kemerlis <vpk@cs.columbia.edu>
 * at Columbia University, New York, NY, USA, in June 2010.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Columbia University nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "taint_log.h"
#include "libdft_api.h"
#include "tagmap.h"
#include <fstream>

extern thread_ctx_t *threads_ctx;

static std::ofstream trace_file;
static bool logging_enabled = false;

/*
 * Initialize taint logging system
 *
 * @log_path: path to the output trace file
 */
void taint_log_init(const std::string& log_path) {
  trace_file.open(log_path.c_str(), std::ios::out);
  logging_enabled = true;
}

/*
 * Cleanup taint logging system
 *
 * Close the trace file and free resources
 */
void taint_log_close() {
  if (trace_file.is_open()) {
    trace_file.close();
  }
}

/*
 * Enable taint logging at runtime
 */
void taint_log_enable() {
  logging_enabled = true;
}

/*
 * Disable taint logging at runtime
 */
void taint_log_disable() {
  logging_enabled = false;
}

/*
 * Log instruction address if logging is enabled
 *
 * @addr: instruction address to log
 */
void log_taint(ADDRINT addr) {
  if (logging_enabled) {
    trace_file << "0x" << std::hex << addr << std::endl;
  }
}

/*
 * Check if a tag is tainted (not empty)
 *
 * @tag: the tag to check
 *
 * returns: true if tainted, false otherwise
 */
bool is_tainted(tag_t const& tag) {
  return !tag_is_empty(tag);
}

/*
 * Check if any byte of a register is tainted
 *
 * @tid: thread id
 * @reg: register index
 * @num_bytes: number of bytes to check
 *
 * returns: true if any byte is tainted, false otherwise
 */
bool is_any_reg_tainted(THREADID tid, uint32_t reg, size_t num_bytes) {
  tag_t* reg_tags = threads_ctx[tid].vcpu.gpr[reg];
  for (size_t i = 0; i < num_bytes; i++) {
    if (is_tainted(reg_tags[i])) return true;
  }
  return false;
}

/*
 * Check if any byte of a memory region is tainted
 *
 * @addr: starting address
 * @num_bytes: number of bytes to check
 *
 * returns: true if any byte is tainted, false otherwise
 */
bool is_any_mem_tainted(ADDRINT addr, size_t num_bytes) {
  for (size_t i = 0; i < num_bytes; i++) {
    if (is_tainted(tagmap_getb(addr + i))) return true;
  }
  return false;
}

/*
 * Check if any byte in a register range is tainted
 *
 * @tid: thread id
 * @reg: register index
 * @start: starting byte offset
 * @num_bytes: number of bytes to check
 *
 * returns: true if any byte is tainted, false otherwise
 */
bool is_reg_range_tainted(THREADID tid, uint32_t reg, size_t start,
                          size_t num_bytes) {
  tag_t* reg_tags = threads_ctx[tid].vcpu.gpr[reg];
  for (size_t i = 0; i < num_bytes; i++) {
    if (is_tainted(reg_tags[start + i])) return true;
  }
  return false;
}
