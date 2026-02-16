/*-
 * Taint Tracer Tool
 *
 * A Pin tool that traces instructions that propagate taint.
 * Uses libdft64's taint tracking infrastructure with integrated taint logging.
 */

#include "pin.H"
#include <iostream>
#include <fstream>
#include <cstring>
#include "branch_pred.h"
#include "debug.h"
#include "libdft_api.h"
#include "libdft_core.h"
#include "syscall_desc.h"
#include "tagmap.h"
#include "taint_log.h"

/* tracks the number of tainted bytes on syscall entry and exit */
// static int syscall_taint_cnt = 0;

/* default path to taint trace output file */
static std::string taintlog_path = "taint_trace.txt";

/* Command line arguments */
static KNOB<std::string> taintlog(KNOB_MODE_WRITEONCE, "pintool", "t",
                                   "taint_trace.txt",
                                   "path to taint trace log file");

/*
 * Handler for __libdft_get_taint(void *p, size_t size)
 */
static VOID TestGetHandler(void *p, size_t size) {
  tag_t t = tagmap_getn((ADDRINT)p, size);
  std::cout << "[TAINT][GET] addr=" << p << " size=" << size
            << " lb=" << t << " taint=" << tag_sprint(t) << std::endl;
}

/*
 * Handler for __libdft_getval_taint(uint64_t v)
 */
static VOID TestGetValHandler(THREADID tid, uint64_t v) {
  tag_t t = tagmap_getn_reg(tid, X64_ARG0_REG, 8);
  std::cout << "[TAINT][GETVAL] v=" << v << " lb=" << t
            << " taint=" << tag_sprint(t) << std::endl;
}

/*
 * Handler for __libdft_set_taint(void *p, size_t size, unsigned int offset)
 */
static VOID TestSetHandler(void *p, size_t size, unsigned int offset) {
  tag_t t = tag_alloc<tag_t>(offset);
  tagmap_setn((ADDRINT)p, size, t);
  std::cout << "[TAINT] Manual taint set: addr=" << p
            << " size=" << size << " offset=" << offset << std::endl;
}

/*
 * Entry point - hook __libdft_set_taint in the target
 */
static VOID EntryPoint(VOID *v) {
  for (IMG img = APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img)) {
    RTN test_get_rtn = RTN_FindByName(img, "__libdft_get_taint");
    if (RTN_Valid(test_get_rtn)) {
      RTN_Open(test_get_rtn);
      RTN_InsertCall(test_get_rtn, IPOINT_BEFORE, (AFUNPTR)TestGetHandler,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                     IARG_END);
      RTN_Close(test_get_rtn);
      std::cout << "[TAINT] Hooked __libdft_get_taint" << std::endl;
    }

    RTN test_set_rtn = RTN_FindByName(img, "__libdft_set_taint");
    if (RTN_Valid(test_set_rtn)) {
      RTN_Open(test_set_rtn);
      RTN_InsertCall(test_set_rtn, IPOINT_BEFORE, (AFUNPTR)TestSetHandler,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                     IARG_END);
      RTN_Close(test_set_rtn);
      std::cout << "[TAINT] Hooked __libdft_set_taint" << std::endl;
    }

    RTN test_getval_rtn = RTN_FindByName(img, "__libdft_getval_taint");
    if (RTN_Valid(test_getval_rtn)) {
      RTN_Open(test_getval_rtn);
      RTN_InsertCall(test_getval_rtn, IPOINT_BEFORE, (AFUNPTR)TestGetValHandler,
                     IARG_THREAD_ID, IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                     IARG_END);
      RTN_Close(test_getval_rtn);
      std::cout << "[TAINT] Hooked __libdft_getval_taint" << std::endl;
    }
  }
}

/*
 * Fini callback - cleanup
 */
static void Fini(INT32 code, VOID *v) {
  taint_log_close();
  std::cout << "[TAINT] Trace written to: " << taintlog_path << std::endl;
}

/*
 * Main function
 */
int main(int argc, char **argv) {
  /* initialize symbol processing */
  PIN_InitSymbols();

  /* initialize Pin; optimized branch */
  if (unlikely(PIN_Init(argc, argv))) {
    std::cerr << "ERROR: PIN_Init failed" << std::endl;
    return 1;
  }

  /* initialize libdft */
  if (unlikely(libdft_init() != 0)) {
    std::cerr << "ERROR: libdft_init failed" << std::endl;
    return 1;
  }

  /* get taint log path from command line */
  taintlog_path = taintlog.Value();

  /* initialize taint logging */
  taint_log_init(taintlog_path);
  std::cout << "[TAINT] Logging taint propagation to: " << taintlog_path << std::endl;

  /* hook manual taint function in the target */
  PIN_AddApplicationStartFunction(EntryPoint, 0);

  /* register Fini callback */
  PIN_AddFiniFunction(Fini, NULL);

  std::cout << "[TAINT] Starting taint tracking..." << std::endl;

  /* start the program */
  PIN_StartProgram();

  /* unreachable */
  return 0;
}
