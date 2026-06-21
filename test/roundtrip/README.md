# Round-trip validation

Validates the full pipeline: compile → decompile → recompile.

## Files

| File | Purpose |
|------|---------|
| `hello.c` | Bare-metal RISC-V source (fib + CRC32, no libc) |
| `hello.ld` | Linker script (text @ 0x40000000, data @ 0x4FF00000) |

## Running the round-trip

```bash
GCC=~/.espressif/tools/riscv32-esp-elf/esp-15.2.0_20251204/riscv32-esp-elf/bin/riscv32-esp-elf-gcc

# 1. Compile original
$GCC -march=rv32imafc_zicsr_zifencei -mabi=ilp32f -O1 -g \
     -nostdlib -nostartfiles -ffreestanding \
     -T hello.ld -o hello.elf hello.c

# 2. Decompile with Ghidra (ExportDecompiledC.java post-script)
analyzeHeadless /tmp/proj RoundtripTest \
  -import hello.elf \
  -processor "RISCV:LE:32:ESP32-P4" \
  -scriptPath ../../ghidra_scripts \
  -postScript ExportDecompiledC.java \
  -deleteProject

# 3. Recompile decompiled output
$GCC -march=rv32imafc_zicsr_zifencei -mabi=ilp32f -O0 \
     -nostdlib -nostartfiles -ffreestanding \
     -include ../../tools/ghidra_types.h \
     -c decompiled.c -o decompiled.o

# 4. Link rebuilt binary
$GCC -march=rv32imafc_zicsr_zifencei -mabi=ilp32f \
     -nostdlib -nostartfiles \
     -T hello.ld -o decompiled_rebuilt.elf decompiled.o
```

## Expected result

Both ELFs contain the same functions (`hello_world`, `_start`) at the
same load addresses.  The rebuilt binary is larger because decompiled C
is compiled at -O0 (no compression, stack-spilled locals); the
algorithm and memory layout are functionally identical.

| Metric | `hello.elf` | `decompiled_rebuilt.elf` |
|--------|-------------|--------------------------|
| `.text` | ~138 B | ~348 B |
| `.bss` | 4 B | 4 B |
| `g_result` | 0x4FF00000 | 0x4FF00000 |

## Known limitation

Ghidra's decompiler emits function bodies but not global variable
declarations.  Any global referenced in decompiled code must be
declared manually before the first use (e.g. `volatile uint g_result;`).
This is a Ghidra decompiler characteristic, not a plugin bug.
