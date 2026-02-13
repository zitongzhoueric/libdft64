# instrace - Instruction Tracer for Pin

## Overview

`instrace` is a simple but powerful Pin tool that prints every instruction executed by a target application. This tool is useful for:

- **Understanding program behavior**: See exactly what instructions are executed
- **Debugging dynamic analysis tools**: Verify instrumentation is working correctly
- **Learning x86-64 assembly**: Observe real-world instruction sequences
- **Reverse engineering**: Trace execution flow without source code

## Features

- ✅ Prints instruction address, disassembly, function name, and image name
- ✅ Optional library filtering (only show main executable instructions)
- ✅ Configurable maximum instruction count
- ✅ Human-readable output format
- ✅ Execution statistics

## Building

```bash
cd /workspaces/libdft64/tools
make obj-intel64/instrace.so
```

## Usage

### Basic Usage

Trace all instructions (main executable only):
```bash
pin -t obj-intel64/instrace.so -- /path/to/binary
```

### Command Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `-o <file>` | `instrace.out` | Output file for instruction trace |
| `-filter-libs <0\|1>` | `1` | Filter out library instructions (only show main executable) |
| `-maxcount <N>` | `0` | Maximum number of instructions to trace (0 = unlimited) |

### Examples

#### Example 1: Trace a simple program
```bash
# Compile test program
gcc -o myprogram myprogram.c

# Trace it
pin -t obj-intel64/instrace.so -o mytrace.txt -- ./myprogram

# View results
cat mytrace.txt
```

#### Example 2: Trace only first 1000 instructions
```bash
pin -t obj-intel64/instrace.so -maxcount 1000 -- /bin/ls
```

#### Example 3: Include library instructions
```bash
pin -t obj-intel64/instrace.so -filter-libs 0 -maxcount 5000 -- ./myapp
```

#### Example 4: Trace with the provided test program
```bash
# Build test program
gcc -o obj-intel64/instrace_test instrace_test.c

# Run trace
pin -t obj-intel64/instrace.so -o demo.out -maxcount 1000 -- obj-intel64/instrace_test

# View results
less demo.out
```

## Output Format

The output file contains:

### Header
```
========================================
Instruction Trace Log
========================================
Filter libraries: YES
Max instructions: 1000
========================================
```

### Instruction Traces
Each traced instruction is printed in the format:
```
[image:function+address] disassembly
```

Example output:
```
[myapp:main+0x401234] mov rax, qword ptr [rbp-0x8]
[myapp:main+0x401238] add rax, 0x10
[myapp:add+0x401169] push rbp
[myapp:add+0x40116a] mov rbp, rsp
[myapp:add+0x40116d] mov dword ptr [rbp-0x4], edi
[myapp:add+0x401170] mov eax, dword ptr [rbp-0x4]
[myapp:add+0x401173] add eax, dword ptr [rbp-0x8]
[myapp:add+0x401176] pop rbp
[myapp:add+0x401177] ret
```

### Footer
```
========================================
Instruction Trace Summary
========================================
Total instructions traced: 614
Exit code: 0
```

## Performance Considerations

**Warning**: This tool has **significant performance overhead** because it:
- Inserts a callback before every instruction
- Performs string operations for every instruction
- Writes to disk frequently

For a program that normally runs in 1 second, expect:
- **Without filtering**: 50-200x slowdown (tracing millions of instructions)
- **With filtering**: 10-50x slowdown (only main executable)
- **With maxcount=1000**: Minimal overhead if count is reached quickly

### Tips for Performance

1. **Use library filtering**: Set `-filter-libs 1` to ignore libc, loader, etc.
2. **Set a maximum count**: Use `-maxcount N` to limit traced instructions
3. **Redirect to fast storage**: Write output to `/tmp` or SSD
4. **Use for small programs**: Best suited for quick traces or specific execution paths

## Comparison with Other Tools

| Tool | Purpose | Overhead | Output Format |
|------|---------|----------|---------------|
| `instrace` | Every instruction | Very High | Human-readable disassembly |
| `nullpin` | Pin overhead measurement | Low | No output |
| `track` | Taint tracking | Medium-High | Taint information only |
| `gdb` | Interactive debugging | Medium | Interactive disassembly |
| `objdump -d` | Static disassembly | None | Static listing only |

## Example Test Program

The repository includes `instrace_test.c`, a simple test program that demonstrates:
- Function calls
- Arithmetic operations
- Loops
- Printf calls

Build and run it:
```bash
gcc -o obj-intel64/instrace_test instrace_test.c
pin -t obj-intel64/instrace.so -maxcount 1000 -- obj-intel64/instrace_test
```

## Implementation Details

### Architecture

```
┌─────────────────┐
│  Target Binary  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Intel Pin     │  Instrument every instruction
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   instrace.so   │  Insert PrintInstruction callback
└────────┬────────┘
         │
         ▼  (at runtime)
┌─────────────────┐
│PrintInstruction │  Log address + disassembly
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ instrace.out    │  Output file
└─────────────────┘
```

### Key Functions

- **InstructionInstrument(INS ins)**: Called at instrumentation time for each instruction
  - Extracts instruction address, disassembly, image name, function name
  - Inserts call to `PrintInstruction` before the instruction
  - Applies library filtering if enabled

- **PrintInstruction(...)**: Called at runtime before each instrumented instruction
  - Writes instruction information to output file
  - Increments instruction counter
  - Exits if max count reached

- **Fini(...)**: Called when application exits
  - Prints summary statistics
  - Closes output file

## Troubleshooting

### "duplicate option" error
If you see an error about duplicate options, it means Pin already has that option name.
Solution: The tool uses `-maxcount` instead of `-max-ins` to avoid conflicts.

### Empty output file
If the output file is empty or has very few instructions:
- Try setting `-filter-libs 0` to include library code
- Try increasing `-maxcount` value
- Check that the target program actually ran (check exit code)

### Program crashes immediately
- Ensure Pin is properly installed and in your PATH
- Verify the tool was compiled: `ls -l obj-intel64/instrace.so`
- Try with a simple program first: `pin -t obj-intel64/instrace.so -- /bin/echo hello`

### Output file too large
- Use `-maxcount` to limit traced instructions
- Enable `-filter-libs 1` to exclude library code
- Consider tracing only specific parts of execution

## Source Code

The tool is implemented in a single file: `instrace.cpp` (~230 lines)

Key features:
- Uses Pin's `INS_AddInstrumentFunction` for instruction-level instrumentation
- Uses Pin's `INS_Disassemble` to get human-readable instruction text
- Uses Pin's `IMG_FindByAddress` and `RTN_FindByAddress` for context information
- Minimal dependencies (only Pin API)

## License

Same as libdft64 (see top-level LICENSE file).

## Author

Created as a demo tool for libdft64 to demonstrate basic Pin instrumentation concepts.
