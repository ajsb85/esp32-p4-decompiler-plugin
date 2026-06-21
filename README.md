# ESP32-P4 Ghidra Plugin

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Ghidra](https://img.shields.io/badge/Ghidra-12.x-orange.svg)](https://ghidra-sre.org)
[![RISC-V](https://img.shields.io/badge/arch-RISC--V%2032-green.svg)](https://riscv.org)
[![Java](https://img.shields.io/badge/Java-21%2B-red.svg)](https://adoptium.net)

Ghidra extension that adds first-class support for the **ESP32-P4** RISC-V
microcontroller. Provides a custom Sleigh processor definition covering the
full ISA (RV32IMAFC + Zicsr + Zifencei + Zmmul + Zaamo + Zalrsc + Zca + Zcf
+ xesploop + xespv2p2), peripheral memory-map labeling from the official SVD,
ROM symbol loading, ESP-IDF FIDB function identification, and an automated
decompiled-C export pipeline validated on real hardware.

---

## Features

- **Sleigh processor definition** — full ESP32-P4 ISA including xesploop
  hardware loops and xespv2p2 PIE SIMD (confirmed on P4 eco2)
- **Compiler spec** — `esp32p4.cspec` tuned for ilp32f ABI (FLEN=4,
  single-precision float only)
- **SVD peripheral map** — all 89 peripherals labeled from `esp32p4.svd`
  via `LoadESP32P4SVD.java`
- **ROM symbol loader** — `LoadESP32P4RomSymbols.java` imports function
  names from `esp32p4_rev0_rom.elf`
- **FIDB generator** — `GenerateESP32P4FIDB.java` guidance script for
  building ESP-IDF function-ID databases
- **Decompiled-C export** — `ExportDecompiledC.java` dumps all decompiled
  functions to a single `.c` file with three RISC-V artifacts fixed
  automatically (see [Decompilation Pipeline](#decompilation-pipeline))
- **Headless analysis** — `AnalyzeESP32P4Headless.py` pre-script for
  CI/batch workflows

---

## Requirements

| Dependency | Version |
|------------|---------|
| Ghidra | 12.1.2 or later |
| Java | 21 or later |
| Gradle | 8+ (wrapper included) |
| esp32p4.svd | Optional — from Espressif SDK |
| esp32p4_rev0_rom.elf | Optional — from Espressif SDK |

---

## Installation

### From release ZIP

1. Download `ghidra_12.1.2_PUBLIC_*_esp32p4-ghidra-plugin.zip` from
   [Releases](https://github.com/ajsb85/esp32-p4-decompiler-plugin/releases)
2. In Ghidra: **File → Install Extensions** → select the ZIP → restart

### Build from source

```bash
git clone https://github.com/ajsb85/esp32-p4-decompiler-plugin.git
cd esp32-p4-decompiler-plugin
gradle -PGHIDRA_INSTALL_DIR=/opt/ghidra_12.1.2_PUBLIC buildExtension
```

Install the ZIP from `dist/` via **File → Install Extensions**.

---

## Quick Start

1. Install the extension (see above) and restart Ghidra
2. **File → Import File** → select your ELF →
   **Options → Language** → `RISCV:LE:32:ESP32-P4` → OK
3. Run auto-analysis (**Analysis → Auto Analyze**)
4. _(Optional)_ **Window → Script Manager** → run `LoadESP32P4SVD.java`,
   point to your `esp32p4.svd`
5. _(Optional)_ Run `LoadESP32P4RomSymbols.java`, point to
   `esp32p4_rev0_rom.elf`

### Headless analysis

```bash
analyzeHeadless /tmp/proj MyProject \
  -import firmware.elf \
  -processor "RISCV:LE:32:ESP32-P4" \
  -preScript AnalyzeESP32P4Headless.py
```

---

## ISA Support

| Extension | Description | Status |
|-----------|-------------|--------|
| RV32IMAFC | Base + multiply + atomic + float | Full |
| Zicsr / Zifencei | CSR access / fence | Full |
| Zca / Zcf | Compressed base / float | Full |
| xesploop | Hardware loops (custom-1, 0x2B) | Full |
| xespv2p2 | PIE SIMD load/store (opcode 0x1F) | Partial |
| xespv2p2 | PIE SIMD arithmetic (opcode 0x1B) | Partial |

### PIE SIMD — confirmed ops on ESP32-P4 eco2

Verified via [FastLED #2535](https://github.com/FastLED/FastLED/issues/2535)
and [#2536](https://github.com/FastLED/FastLED/issues/2536):

`vld.128.ip` · `vst.128.ip` · `andq` · `orq` · `xorq` · `notq` ·
`zero.q` · `movi.32.q` · `vcmp.eq.s8` · `vunzip.8` · `vsl.32` ·
`vsr.u32` · `slci.2q` · `srci.2q` · `src.q.qup` · `cmul.s16`

Unconfirmed ops fall through to generic `esp.pie.arith` / `esp.pie.0x1f`
pcodeops and are still disassembled without crashing the decompiler.

---

## Ghidra Scripts

All scripts live in `ghidra_scripts/` and appear in Ghidra's Script Manager
under the **ESP32-P4** category.

### `ExportDecompiledC.java`

Exports every function's decompiled C to a single `.c` file and
automatically fixes three RISC-V / Ghidra artifacts that would otherwise
prevent the output from compiling (see
[Decompilation Pipeline](#decompilation-pipeline)).

**GUI mode** — Script Manager → run → pick an output file in the dialog.

**Headless mode** — pass the output path as a script argument:

```bash
analyzeHeadless /tmp/proj MyProject \
  -import firmware.elf \
  -processor "RISCV:LE:32:ESP32-P4" \
  -scriptPath ghidra_scripts \
  -postScript ExportDecompiledC.java /tmp/firmware_decompiled.c \
  -deleteProject
```

### `LoadESP32P4SVD.java`

Applies all peripheral register names and address ranges from
`esp32p4.svd` to the current program. Run this after auto-analysis to
get readable peripheral access patterns (e.g. `UART0->FIFO` instead of
raw hex offsets).

### `LoadESP32P4RomSymbols.java`

Imports function names from `esp32p4_rev0_rom.elf` into the current
program. Without this script, ROM calls appear as anonymous subroutines
at addresses in the ROM region.

### `GenerateESP32P4FIDB.java`

Guidance script for generating a Ghidra Function ID database from an
ESP-IDF build tree. Run this against a compiled IDF SDK to produce a
`.fidb` file that identifies library functions automatically.

### `AnalyzeESP32P4Headless.py`

Pre-script for headless Ghidra runs. Applies ESP32-P4-specific memory
map annotations before the standard auto-analysis pass runs, so memory
regions are correctly typed in the final project.

---

## Decompilation Pipeline

The plugin ships a complete pipeline for reconstructing compilable C from
an ESP32-P4 ELF. The pipeline is validated end-to-end on real hardware:
the reconstructed binary produces the same deterministic output as the
original firmware.

### Automatic artifact fixes

`ExportDecompiledC.java` applies three fixes before writing the output
file. No manual editing of decompiled C is required.

| # | Artifact | Example | Fix |
|---|----------|---------|-----|
| 1 | GP register assignment | `gp = 0x4ff2d380;` | Line stripped. The RISC-V global pointer is set once by startup code; Ghidra emits it as a C variable on every function entry, which is an undeclared-identifier compile error. |
| 2 | Void return-type mismatch | `void crc32_step(…)` called as `x = crc32_step(…)` | Signature promoted from `void` to `undefined4`. Detected by a two-pass scan: collect all void-declared names, then find any name used in an assignment RHS. |
| 3 | Bare `return;` in promoted function | `return;` inside a function now typed `undefined4` | Rewritten to `return param_1;`. In the RISC-V ilp32 ABI, the first parameter register `a0` doubles as the return register, so a bare return is semantically `return param_1;`. |

### `tools/ghidra_types.h`

Ghidra's decompiler emits C using type aliases (`undefined4`, `uint`,
`uchar`, …) that are not defined in any standard header. Include
`tools/ghidra_types.h` when compiling the exported file:

```bash
riscv32-esp-elf-gcc \
  -march=rv32imafc_zicsr_zifencei -mabi=ilp32f -O0 \
  -include tools/ghidra_types.h \
  -c firmware_decompiled.c -o firmware_decompiled.o
```

The header maps each Ghidra alias to the appropriate `<stdint.h>` type.

### Bare-metal round-trip (freestanding)

The `test/roundtrip/` fixture validates the pipeline without any RTOS or
libc dependency.

```bash
GCC=~/.espressif/tools/riscv32-esp-elf/esp-15.2.0_20251204/\
riscv32-esp-elf/bin/riscv32-esp-elf-gcc

# 1. Compile bare-metal original
$GCC -march=rv32imafc_zicsr_zifencei -mabi=ilp32f -O1 -g \
     -nostdlib -nostartfiles -ffreestanding \
     -T test/roundtrip/hello.ld \
     -o hello.elf test/roundtrip/hello.c

# 2. Decompile with Ghidra
analyzeHeadless /tmp/proj RoundtripTest \
  -import hello.elf \
  -processor "RISCV:LE:32:ESP32-P4" \
  -scriptPath ghidra_scripts \
  -postScript ExportDecompiledC.java /tmp/decompiled.c \
  -deleteProject

# 3. Recompile decompiled output
$GCC -march=rv32imafc_zicsr_zifencei -mabi=ilp32f -O0 \
     -nostdlib -nostartfiles -ffreestanding \
     -include tools/ghidra_types.h \
     -T test/roundtrip/hello.ld \
     -o decompiled_rebuilt.elf /tmp/decompiled.c
```

Expected: both ELFs contain the same functions at the same load
addresses. The rebuilt binary is larger (decompiled C compiled at -O0)
but functionally identical.

### ESP-IDF round-trip (on real hardware)

The same pipeline was validated on a real ESP32-P4 (revision v3.2) using
an ESP-IDF firmware with a deterministic CRC32 accumulator:

```
=== ESP32-P4 CRC Hello ===
g_result = 0xbe34bdfc
==========================
```

Both the original firmware and the fully-automatic reconstructed binary
(zero manual edits) produced this value when flashed via esptool.

### Known limitations

- **Global variable declarations** — Ghidra emits function bodies but not
  global variable definitions. Any global referenced in decompiled code
  must be declared manually before the first use (e.g.
  `volatile uint32_t g_result;`). This is a Ghidra decompiler
  characteristic, not a plugin bug.
- **Bare return heuristic** — Fix 3 replaces `return;` with
  `return param_1;` based on the RISC-V ABI convention that `a0` carries
  both the first argument and the return value. This is correct for
  single-result functions that thread the result through their first
  parameter. Functions that accumulate a result into a different local
  variable before returning may need the return expression adjusted
  manually.
- **PIE SIMD bodies** — xespv2p2 instructions lift to pcodeops, not
  C-level intrinsics. Functions that use PIE SIMD will decompile but the
  output will contain calls to opaque `esp_pie_*` operations rather than
  portable C.

---

## Project Structure

```
data/languages/     Sleigh processor definition (slaspec, sinc, cspec, ldefs,
                    dwarf register map)
ghidra_scripts/     Runnable Ghidra scripts (export, SVD loader, ROM symbols,
                    FIDB generator, headless pre-script)
src/main/java/      Plugin Java source (analyzer, memory map, UI panel)
test/roundtrip/     Bare-metal round-trip validation fixture
tools/              Recompilation helpers (ghidra_types.h)
dist/               Built extension ZIP  ← git-ignored, produced by Gradle
```

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

Upstream Sleigh files (`riscv.*.sinc`, `andestar_v5.instr.sinc`) originate
from the [Ghidra](https://github.com/NationalSecurityAgency/ghidra) project
(NSA) and are redistributed under the same Apache 2.0 license.

**Author:** Alexander Salas Bastidas &lt;ajsb85@firechip.dev&gt;
