# Sample: hello_world

Round-trip decompilation example for the ESP32-P4 Ghidra plugin.

## What this demonstrates

The source (`input/hello.c`) implements two functions inlined by the compiler
into a single `hello_world` symbol:

- `fib(n)` — iterative Fibonacci
- `crc32_step(crc, byte)` — single-byte CRC-32 step (polynomial `0x04C11DB7`, MSB-first)
- `hello_world()` — combines both over 10 iterations, writes result to `g_result`

The compiler (`riscv32-esp-elf-gcc -O1`) inlined `fib` and `crc32_step` into
`hello_world`, so the ELF contains only 2 functions: `hello_world` and `_start`.

## Input files

| File | Description |
|------|-------------|
| `input/hello.c` | Original C source |
| `input/hello.ld` | Bare-metal linker script (flash @ 0x40000000, data @ 0x4FF00000) |
| `input/hello_esp32p4.elf` | ELF compiled with `-march=rv32imafc_zicsr_zifencei -mabi=ilp32f -O1 -g0 -nostdlib` |

## Output files (from RunFullPipeline.sh)

| File | Description |
|------|-------------|
| `output/firmware_decompiled.c` | Decompiled C — **compare against `input/hello.c`** |
| `output/firmware.h` | Type definitions + function prototypes (109 types, 1966 globals from SVD) |
| `output/globals.h` | `extern` declarations for globals referenced in decompiled bodies |
| `output/firmware.dot` | Graphviz call graph (2 nodes: `_start → hello_world`) |
| `output/MODULES.md` | Module table by connected component |
| `output/semantic_hints.json` | Pattern detection results (FUN_* functions only; none here — both named) |
| `output/pipeline.log` | Full analyzeHeadless log from the 7-phase run |

## Accuracy assessment

### Code recovery

The decompiler correctly reconstructed the CRC-32 loop body including:
- Polynomial constant `0x4c11db7` ✓
- MSB-first shift (`<< 1`) with conditional XOR ✓
- 8-iteration inner loop ✓
- Fibonacci sequence embedded in the outer loop ✓
- Final XOR inversion (`~uVar6`) → `g_result = acc ^ 0xFFFFFFFF` ✓

### What changed vs. the original

| Original | Decompiled | Reason |
|----------|-----------|--------|
| 3 separate functions | 1 function (`hello_world`) | Compiler inlined `fib` + `crc32_step` at `-O1` |
| Named variables: `acc`, `f`, `crc`, `byte` | Ghidra temps: `uVar6`, `uVar7`, `uVar3`… | No DWARF (compiled with `-g0`) |
| `uint32_t` types | `uint` / `int` (Ghidra defaults) | Resolved via `ghidra_types.h` |
| Two-loop structure | Single merged loop | Inlining collapsed both loops |

### Line count comparison

| File | Lines |
|------|-------|
| `input/hello.c` (original) | 49 |
| `output/firmware_decompiled.c` (decompiled) | 111 |

The decompiled output is ~2× longer due to explicit temp variables, Ghidra's
C style (braces on own lines, `while(true)` patterns), and the section/caller
header comments added by `ExportDecompiledC.java`.

## Recompile check

```bash
GCC="$HOME/.espressif/tools/riscv32-esp-elf/esp-15.2.0_20251204/riscv32-esp-elf/bin/riscv32-esp-elf-gcc"
$GCC -march=rv32imafc_zicsr_zifencei -mabi=ilp32f \
     -O0 -nostdlib \
     -include tools/ghidra_types.h \
     -include samples/hello_world/output/firmware.h \
     -c samples/hello_world/output/firmware_decompiled.c \
     -o /tmp/hello_reconstructed.o && echo "Recompile OK"
```

## Run the pipeline on this sample

```bash
bash tools/RunFullPipeline.sh \
  samples/hello_world/input/hello_esp32p4.elf \
  --out samples/hello_world/output
```
