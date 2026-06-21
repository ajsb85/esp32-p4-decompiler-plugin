# ESP32-P4 Ghidra Plugin

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Ghidra](https://img.shields.io/badge/Ghidra-12.x-orange.svg)](https://ghidra-sre.org)
[![RISC-V](https://img.shields.io/badge/arch-RISC--V%2032-green.svg)](https://riscv.org)
[![Java](https://img.shields.io/badge/Java-21%2B-red.svg)](https://adoptium.net)

Ghidra extension that adds first-class support for the **ESP32-P4** RISC-V
microcontroller. Provides a custom Sleigh processor definition covering the
full ISA (RV32IMAFC + Zicsr + Zifencei + Zmmul + Zaamo + Zalrsc + Zca + Zcf
+ xesploop + xespv2p2), peripheral memory-map labeling from the official SVD,
ROM symbol loading, and ESP-IDF FIDB function identification.

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

## Project Structure

```
data/languages/     Sleigh processor definition (slaspec, sinc, cspec, ldefs)
ghidra_scripts/     Runnable Ghidra scripts (SVD loader, ROM symbols, FIDB)
src/main/java/      Plugin Java source (analyzer, memory map, UI panel)
dist/               Built extension ZIP  ← git-ignored, produced by Gradle
```

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

Upstream Sleigh files (`riscv.*.sinc`, `andestar_v5.instr.sinc`) originate
from the [Ghidra](https://github.com/NationalSecurityAgency/ghidra) project
(NSA) and are redistributed under the same Apache 2.0 license.

**Author:** Alexander Salas Bastidas &lt;ajsb85@firechip.dev&gt;
