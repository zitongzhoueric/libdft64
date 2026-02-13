#include "branch_pred.h"
#include "debug.h"
#include "libdft_api.h"
#include "pin.H"
#include "syscall_hook.h"
#include <iostream>

// Handler for __libdft_get_taint(void *p, size_t size)
VOID TestGetHandler(void *p, size_t size) {
  tag_t t = tagmap_getn((ADDRINT)p, size);
  printf("[PIN][GET] addr: %p, size: %lu, lb: %d, taint: %s\n", p, size, t,
         tag_sprint(t).c_str());
}

// Handler for __libdft_getval_taint(uint64_t v)
VOID TestGetValHandler(THREADID tid, uint64_t v) {
  tag_t t = tagmap_getn_reg(tid, X64_ARG0_REG, 8);
  printf("[PIN][GETVAL] v: %lu, lb: %d, taint: %s\n", v, t,
         tag_sprint(t).c_str());
}

// Handler for __libdft_set_taint(void *p, size_t size, unsigned int offset)
VOID TestSetHandler(void *p, size_t size, unsigned int offset) {
  tag_t t = tag_alloc<tag_t>(offset);
  tagmap_setn((ADDRINT)p, size, t);  // Taint entire region
  printf("[PIN][SET] addr: %p, size: %lu, offset: %d, lb: %d, taint: %s\n",
         p, size, offset, t, tag_sprint(t).c_str());
}

VOID EntryPoint(VOID *v) {

  for (IMG img = APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img)) {
    RTN test_get_rtn = RTN_FindByName(img, "__libdft_get_taint");
    if (RTN_Valid(test_get_rtn)) {
      RTN_Open(test_get_rtn);
      RTN_InsertCall(test_get_rtn, IPOINT_BEFORE, (AFUNPTR)TestGetHandler,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // void *p
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // size_t size
                     IARG_END);
      RTN_Close(test_get_rtn);
    }

    RTN test_set_rtn = RTN_FindByName(img, "__libdft_set_taint");
    if (RTN_Valid(test_set_rtn)) {
      RTN_Open(test_set_rtn);
      RTN_InsertCall(test_set_rtn, IPOINT_BEFORE, (AFUNPTR)TestSetHandler,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // void *p
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // size_t size
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // unsigned int offset
                     IARG_END);
      RTN_Close(test_set_rtn);
    }

    RTN test_getval_rtn = RTN_FindByName(img, "__libdft_getval_taint");
    if (RTN_Valid(test_getval_rtn)) {
      RTN_Open(test_getval_rtn);

      RTN_InsertCall(test_getval_rtn, IPOINT_BEFORE, (AFUNPTR)TestGetValHandler,
                     IARG_THREAD_ID, IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                     IARG_END);
      RTN_Close(test_getval_rtn);
    }
  }
}

int main(int argc, char *argv[]) {

  PIN_InitSymbols();

  if (unlikely(PIN_Init(argc, argv))) {
    std::cerr
        << "Sth error in PIN_Init. Plz use the right command line options."
        << std::endl;
    return -1;
  }

  if (unlikely(libdft_init() != 0)) {
    std::cerr << "Sth error libdft_init." << std::endl;
    return -1;
  }

  PIN_AddApplicationStartFunction(EntryPoint, 0);

  // hook_file_syscall();  // Disabled - manual tainting only

  PIN_StartProgram();

  return 0;
}
