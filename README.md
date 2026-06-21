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
  functions to a single `.c` file with four RISC-V artifact fixes, peripheral
  access annotations, section organization, and string constant extraction
  (see [Decompilation Pipeline](#decompilation-pipeline))
- **Semantic pattern detection** — `DetectSemanticPatterns.java` classifies
  functions by algorithm (CRC, popcount, sort, state machine, cipher, …) and
  emits a `semantic_hints.json` with suggested rename targets
- **Firmware header export** — `ExportFirmwareHeader.java` emits a compilable
  `firmware.h` with type definitions, `extern` prototypes, and volatile globals
- **Call graph export** — `ExportCallGraph.java` emits a Graphviz `.dot` call
  graph and `MODULES.md` table organized by IDF/app/unknown layer
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

Generates a Ghidra Function ID database from an ESP-IDF build tree.
Run this against a compiled IDF SDK to produce a `.fidb` file that
identifies library functions automatically via hash matching.

### `ExportFirmwareHeader.java`

Exports a compilable `firmware.h` containing:
- Topologically-sorted user-defined type definitions (structs, enums,
  typedefs via DFS post-order to handle forward references)
- `extern` function prototypes for all named functions
- `volatile` global variable declarations for peripheral-mapped globals

Include this header when recompiling the output of `ExportDecompiledC.java`.

### `ExportCallGraph.java`

Analyzes the full firmware call graph and exports two artifacts:

- **`firmware.dot`** — Graphviz call graph with nodes colored by layer:
  IDF layer (green), application layer (yellow), unknown (grey)
- **`MODULES.md`** — markdown table mapping each weakly-connected
  component to its estimated purpose and layer

Useful for understanding firmware architecture before diving into
individual function decompilation.

### `DetectSemanticPatterns.java`

Scans all decompiled function bodies for known algorithmic patterns and
exports `semantic_hints.json` with rename suggestions. Detects 20
pattern families including:

`crc32` · `crc16` · `popcount` · `bit_reverse` · `isqrt` · `ilog2` ·
`clz` · `sort_bubble` · `sort_insertion` · `state_machine` · `parser_packet` ·
`xor_cipher` · `aes_sbox` · `sha_schedule` · `memcpy_like` · `memset_like` ·
`strlen_like` · `printf_like` · `rng_lfsr` · `fifo_ring`

All evidence patterns must match (AND logic) to reduce false positives.

```bash
analyzeHeadless /tmp/proj MyProject \
  -import firmware.elf \
  -processor "RISCV:LE:32:ESP32-P4" \
  -scriptPath ghidra_scripts \
  -postScript DetectSemanticPatterns.java /tmp/semantic_hints.json \
  -deleteProject
```

### `InspectClangAST.java`

Prototype ClangAST walker. Walks the `ClangTokenGroup` tree for a
function and annotates return nodes, variable references, and type tokens.
Used as a research tool for implementing AST-level fixes in future sprints.

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

`ExportDecompiledC.java` applies four fixes before writing the output
file. No manual editing of decompiled C is required.

| # | Artifact | Example | Fix |
|---|----------|---------|-----|
| 1 | GP register assignment | `gp = 0x4ff2d380;` | Line stripped. The RISC-V global pointer is set once by startup code; Ghidra emits it as a C variable on every function entry, which is an undeclared-identifier compile error. |
| 2 | Void return-type mismatch | `void crc32_step(…)` called as `x = crc32_step(…)` | Signature promoted from `void` to `undefined4`. Detected by a two-pass scan: collect all void-declared names, then find any name used in an assignment RHS. |
| 3 | Bare `return;` in promoted function | `return;` inside a function now typed `undefined4` | Rewritten to `return <lastVar>;` where `lastVar` is the last Ghidra local variable assigned before the return (backwards scan of `uVar*`/`iVar*`/`param_*` assignments). Falls back to `param_1`. |
| 4 | Peripheral `DAT_` references | `DAT_50000000` in function body | Replaced with `static const char s_<addr>[]` string declarations when Ghidra has typed the address as a string data type. |

### Semantic enrichments

Beyond the four fixes, `ExportDecompiledC.java` also adds:

- **Peripheral access annotations** — inline `/* ← HP_SYS */`, `/* ← UART0 */`
  comments on lines that read/write known ESP32-P4 peripheral addresses (26
  peripheral ranges covered from the TRM)
- **Section organization** — when output crosses a memory region boundary
  (IRAM/DRAM/ROM/Flash/Peripheral), a decorative section header is emitted
- **String constant substitution** — `DAT_` references to addresses Ghidra
  has typed as string data are replaced with named `static const char[]` declarations

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

The `test/roundtrip/` directory contains five bare-metal test fixtures
that validate the pipeline without any RTOS or libc dependency.
Use the automation script for a full 6-phase run:

```bash
RISCV_GCC=~/.espressif/tools/riscv32-esp-elf/esp-14.2.0_20260121/\
riscv32-esp-elf/bin/riscv32-esp-elf-gcc \
GHIDRA_HEADLESS=/opt/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  ./test/roundtrip/run_roundtrip.sh
```

| Fixture | Algorithm exercises | `g_result` |
|---------|---------------------|------------|
| `hello.c` | CRC-32 accumulator | `0xBE34BDFC` |
| `test_sorting.c` | Bubble + insertion sort | `0x00000029` |
| `test_math.c` | Popcount / isqrt / bit-reverse / ilog2 / clz | `0x000000F9` |
| `test_state_machine.c` | 4-state packet parser FSM | `0x00000244` |
| `test_crypto.c` | XOR stream cipher + key schedule + CRC-8 | `0xABCD65DD` |

The automation script compares disassembled instruction mnemonics
between the original and reconstructed ELFs — a perfect round-trip
produces a zero-line diff.

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
