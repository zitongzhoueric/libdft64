/*-
 * instrace.cpp
 *
 * A simple Pin tool that prints every instruction executed by the target
 * application. This is useful for understanding program behavior and
 * debugging dynamic analysis tools.
 *
 * Usage:
 *   pin -t obj-intel64/instrace.so -- <target_binary> [args...]
 *
 * Output format:
 *   [IMG:addr] disassembly
 *
 * Example:
 *   [main:0x401234] mov rax, qword ptr [rbp-0x8]
 */

#include "pin.H"
#include <iostream>
#include <fstream>
#include <iomanip>

/* Output file stream for instruction trace */
static std::ofstream TraceFile;

/* Command line options */
KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "instrace.out", "Output file for instruction trace");

KNOB<BOOL> KnobFilterLibraries(KNOB_MODE_WRITEONCE, "pintool",
    "filter-libs", "1", "Filter out library instructions (only show main executable)");

KNOB<UINT64> KnobMaxInstructions(KNOB_MODE_WRITEONCE, "pintool",
    "maxcount", "0", "Maximum number of instructions to trace (0 = unlimited)");

/* Global counters */
static UINT64 instruction_count = 0;
static UINT64 max_instructions = 0;
static BOOL filter_libraries = true;

/*
 * Analysis routine called before each instruction
 *
 * This function is called at runtime for each instrumented instruction.
 * It prints the instruction address and disassembly to the output file.
 *
 * @addr:       instruction address
 * @disasm:     instruction disassembly string
 * @img_name:   name of the image (executable/library) containing the instruction
 * @routine:    name of the routine containing the instruction (if available)
 */
VOID PIN_FAST_ANALYSIS_CALL
PrintInstruction(ADDRINT addr, const std::string *disasm,
                 const std::string *img_name, const std::string *routine) {
    // Check if we've reached the maximum instruction count
    if (max_instructions > 0 && instruction_count >= max_instructions) {
        return;
    }

    instruction_count++;

    // Format: [image:routine+offset] address: disassembly
    TraceFile << "[" << *img_name << ":" << *routine << "+0x"
              << std::hex << addr << std::dec << "] "
              << *disasm << std::endl;

    // Stop tracing if we've hit the limit
    if (max_instructions > 0 && instruction_count >= max_instructions) {
        TraceFile << "\n[MAX INSTRUCTIONS REACHED: " << instruction_count << "]\n";
        TraceFile.close();
        exit(0);
    }
}

/*
 * Instrumentation routine called for each instruction
 *
 * This function is called at instrumentation time (when Pin first sees
 * an instruction). It inserts a call to PrintInstruction before the
 * instruction executes.
 *
 * @ins:    the instruction to instrument
 * @v:      callback value (unused)
 */
VOID InstructionInstrument(INS ins, VOID *v) {
    // Get instruction information
    ADDRINT addr = INS_Address(ins);

    // Get the image and routine information
    IMG img = IMG_FindByAddress(addr);
    RTN rtn = RTN_FindByAddress(addr);

    // Determine image name
    std::string *img_name = new std::string();
    if (IMG_Valid(img)) {
        *img_name = IMG_Name(img);

        // Filter out library instructions if requested
        if (filter_libraries && !IMG_IsMainExecutable(img)) {
            return;
        }

        // Extract just the filename from the full path
        size_t last_slash = img_name->find_last_of("/\\");
        if (last_slash != std::string::npos) {
            *img_name = img_name->substr(last_slash + 1);
        }
    } else {
        *img_name = "UNKNOWN";
        // Filter out UNKNOWN images when library filtering is enabled
        // (these are typically VDSO, early loader code, or JIT code)
        if (filter_libraries) {
            return;
        }
    }

    // Determine routine name
    std::string *routine_name = new std::string();
    if (RTN_Valid(rtn)) {
        *routine_name = RTN_Name(rtn);
    } else {
        *routine_name = "???";
    }

    // Get instruction disassembly
    std::string *disasm = new std::string(INS_Disassemble(ins));

    // Insert call to analysis routine before the instruction
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)PrintInstruction,
                   IARG_FAST_ANALYSIS_CALL,
                   IARG_ADDRINT, addr,
                   IARG_PTR, disasm,
                   IARG_PTR, img_name,
                   IARG_PTR, routine_name,
                   IARG_END);
}

/*
 * Called when the application exits
 *
 * Print summary statistics before the tool terminates.
 *
 * @code:   exit code
 * @v:      callback value (unused)
 */
VOID Fini(INT32 code, VOID *v) {
    TraceFile << "\n========================================\n";
    TraceFile << "Instruction Trace Summary\n";
    TraceFile << "========================================\n";
    TraceFile << "Total instructions traced: " << instruction_count << "\n";
    TraceFile << "Exit code: " << code << "\n";
    TraceFile.close();

    std::cerr << "[instrace] Total instructions traced: " << instruction_count << std::endl;
    std::cerr << "[instrace] Output written to: " << KnobOutputFile.Value() << std::endl;
}

/*
 * Print usage information
 */
INT32 Usage() {
    std::cerr << "instrace - Instruction Tracer for Pin" << std::endl;
    std::cerr << std::endl;
    std::cerr << "This tool prints every instruction executed by the target application." << std::endl;
    std::cerr << std::endl;
    std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
    std::cerr << std::endl;
    std::cerr << "Example usage:" << std::endl;
    std::cerr << "  pin -t obj-intel64/instrace.so -- /bin/ls" << std::endl;
    std::cerr << "  pin -t obj-intel64/instrace.so -o mytrace.txt -- ./myapp" << std::endl;
    std::cerr << "  pin -t obj-intel64/instrace.so -filter-libs 0 -- ./myapp" << std::endl;
    std::cerr << "  pin -t obj-intel64/instrace.so -max-ins 10000 -- ./myapp" << std::endl;
    std::cerr << std::endl;
    return -1;
}

/*
 * Main function - entry point for the Pin tool
 */
int main(int argc, char *argv[]) {
    // Initialize PIN symbol support
    PIN_InitSymbols();

    // Initialize PIN
    if (PIN_Init(argc, argv)) {
        return Usage();
    }

    // Parse command-line options
    filter_libraries = KnobFilterLibraries.Value();
    max_instructions = KnobMaxInstructions.Value();

    // Open output file
    TraceFile.open(KnobOutputFile.Value().c_str());
    if (!TraceFile.is_open()) {
        std::cerr << "[instrace] Error: Could not open output file: "
                  << KnobOutputFile.Value() << std::endl;
        return -1;
    }

    // Write header
    TraceFile << "========================================\n";
    TraceFile << "Instruction Trace Log\n";
    TraceFile << "========================================\n";
    TraceFile << "Filter libraries: " << (filter_libraries ? "YES" : "NO") << "\n";
    TraceFile << "Max instructions: ";
    if (max_instructions == 0) {
        TraceFile << "UNLIMITED";
    } else {
        TraceFile << max_instructions;
    }
    TraceFile << "\n";
    TraceFile << "========================================\n\n";

    std::cerr << "[instrace] Starting instruction trace..." << std::endl;
    std::cerr << "[instrace] Output file: " << KnobOutputFile.Value() << std::endl;
    std::cerr << "[instrace] Filter libraries: " << (filter_libraries ? "YES" : "NO") << std::endl;
    if (max_instructions > 0) {
        std::cerr << "[instrace] Max instructions: " << max_instructions << std::endl;
    }

    // Register instruction instrumentation callback
    INS_AddInstrumentFunction(InstructionInstrument, NULL);

    // Register program finish callback
    PIN_AddFiniFunction(Fini, NULL);

    // Start the program (never returns)
    PIN_StartProgram();

    return 0;
}
