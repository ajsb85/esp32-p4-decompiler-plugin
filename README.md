# ESP32-P4 Ghidra Plugin

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Ghidra](https://img.shields.io/badge/Ghidra-12.x-orange.svg)](https://ghidra-sre.org)
[![RISC-V](https://img.shields.io/badge/arch-RISC--V%2032-green.svg)](https://riscv.org)
[![Java](https://img.shields.io/badge/Java-21%2B-red.svg)](https://adoptium.net)
[![Round-trip](https://img.shields.io/badge/round--trip-525%20fixtures%20passing-brightgreen.svg)](#round-trip-validation)
[![Patterns](https://img.shields.io/badge/semantic%20patterns-1287-blue.svg)](#detectsemanticpatternsjava)
[![FIDB](https://img.shields.io/badge/FIDB-ESP--IDF%20v6.0.1-purple.svg)](#fidb-function-id-database)

Ghidra extension that adds first-class support for the **ESP32-P4** RISC-V
microcontroller. Provides a custom Sleigh processor definition covering the
full ISA (RV32IMAFC + Zicsr + Zifencei + Zmmul + Zaamo + Zalrsc + Zca + Zcf
+ xesploop + xespv2p2), peripheral memory-map labeling from the official SVD,
ROM symbol loading, a **pre-built ESP-IDF v6.0.1 FIDB**, and an automated
decompiled-C export pipeline validated end-to-end (IDF v6.0.1 + FreeRTOS)
with **525 round-trip fixtures** and **1287 semantic detection patterns**.

---

## How the Plugin Works

```
                ┌─────────────────────────────────────────────────────────┐
                │            ESP32-P4 ELF / Firmware Binary               │
                └─────────────────────────────────────────────────────────┘
                                         │
                                         ▼
         ┌───────────────────────────────────────────────────────────────┐
         │                  Ghidra  +  ESP32-P4 Plugin                   │
         │                                                               │
         │  ┌────────────────────────────────────────────────────────┐  │
         │  │  Sleigh Processor  (esp32p4.slaspec)                   │  │
         │  │  RV32IMAFC · Zicsr · Zifencei · Zca · Zcf             │  │
         │  │  xesploop hardware loops  ·  xespv2p2 PIE SIMD        │  │
         │  └────────────────────────────────────────────────────────┘  │
         │                           │                                   │
         │                           ▼                                   │
         │  ┌────────────────────────────────────────────────────────┐  │
         │  │  ESP32P4Analyzer.java  (auto-analysis pass)            │  │
         │  │  89 peripheral regions · IRAM/DRAM/ROM labels          │  │
         │  │  hardware-loop comment annotation                      │  │
         │  └────────────────────────────────────────────────────────┘  │
         └───────────────────────────────────────────────────────────────┘
                                         │
              ┌──────────────────────────┼───────────────────────────┐
              │   Optional enrichment scripts                        │
              │                                                      │
              │  LoadESP32P4SVD.java                                 │
              │    → peripheral register names from esp32p4.svd      │
              │                                                      │
              │  LoadESP32P4RomSymbols.java                          │
              │    → ROM function names from esp32p4_rev0_rom.elf    │
              │                                                      │
              │  Apply tools/esp32p4-idf6.fidb                       │
              │    → 1,224 ESP-IDF v6 functions auto-named:          │
              │      heap_caps_malloc · xTaskCreate · nvs_flash_init │
              │      gpio_config · uart_write_bytes · xQueueCreate … │
              └──────────────────────────────────────────────────────┘
                                         │
              ┌──────────────────────────┼───────────────────────────┐
              │   Export and analysis scripts                        │
              │                                                      │
              │  ExportDecompiledC.java                              │
              │    → firmware_decompiled.c                           │
              │       ├─ 4 RISC-V artifact fixes (auto)             │
              │       ├─ peripheral access comments                  │
              │       └─ string constant extraction                  │
              │                                                      │
              │  ExportFirmwareHeader.java                           │
              │    → firmware.h  (prototypes + type definitions)     │
              │                                                      │
              │  ExportGlobalDecls.java                              │
              │    → global extern declarations                      │
              │                                                      │
              │  ExportCallGraph.java                                │
              │    → firmware.dot  (Graphviz call graph)             │
              │    → MODULES.md   (IDF / app / unknown layer table)  │
              │                                                      │
              │  DetectSemanticPatterns.java                         │
              │    → semantic_hints.json                             │
              │       321 patterns · 60+ algorithm families          │
              └──────────────────────────────────────────────────────┘
                                         │
                                         ▼
         ┌───────────────────────────────────────────────────────────────┐
         │              Round-trip validation pipeline                   │
         │                                                               │
         │  riscv32-esp-elf-gcc → ELF → Ghidra headless →              │
         │  decompiled.c → recompile → objdump diff → g_result check    │
         │                                                               │
         │  525 fixtures  ·  1287 semantic patterns  ·  ✓ IDF v6.0.1 + FreeRTOS  │
         └───────────────────────────────────────────────────────────────┘
```

---

## FIDB — Function ID Database

The plugin ships **`tools/esp32p4-idf6.fidb`** — a pre-built Ghidra Function ID
database generated from a full ESP-IDF v6.0.1 build for ESP32-P4. It contains
**1,224 fingerprinted IDF library functions** that Ghidra automatically recognizes
and renames in any ESP32-P4 firmware you analyze.

### Apply the FIDB (one click)

```
Tools → Function ID → Apply Function ID Files → select tools/esp32p4-idf6.fidb
```

### Before FIDB — 2,008 lines of anonymous code

```c
// ── FUN_.flash.text__40014396 @ .flash.text::40014396 ──────────────────

int FUN__flash_text__40014396(int param_1, byte *param_2, uint *param_3)
{
  uint uVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  undefined4 *puVar5;

  if (param_3 != (uint *)0x0) {
    uVar1 = *param_3;
    iVar2 = FUN__flash_text__40014322(0, param_1);
    if ((iVar2 != 0) && ((int)(uVar1 - 0x110d) < 2)) {
      FUN__flash_text__40014322(1, param_1);
      FUN__flash_text__40014322(0, param_1);
    }
    // ... 2,000 more lines of FUN__flash_text__ calls ...
  }
}
```

### After FIDB — 159 lines of readable, named IDF code

```c
// ── heap_demo @ .flash.text::4000eb56 ──────────────────

/* Library Function - Single Match
    heap_demo
   Library: ESP-IDF v6.0.1  */

void heap_demo(void)
{
  int iVar1;
  undefined4 uVar2;
  undefined4 uVar3;

  iVar1 = heap_caps_malloc(0x40, 0x1000);
  if (iVar1 != 0) {
    heap_caps_free();
  }
  uVar2 = heap_caps_get_free_size(0x1000);
  uVar3 = esp_log_timestamp();
  esp_log(3, "fidb_stub", "I (%lu) %s: free heap: %zu\n", uVar3, "fidb_stub", uVar2);
  return;
}


// ── rtos_demo @ .flash.text::4000ec30 ──────────────────

/* Library Function - Single Match
    rtos_demo
   Library: ESP-IDF v6.0.1  */

void rtos_demo(void)
{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uStack_14;

  uVar1 = xQueueGenericCreate(4, 4, 0);
  uVar2 = xQueueCreateMutex(1);
  uStack_14 = 0x2a;
  xQueueGenericSend(uVar1, &uStack_14, 0, 0);
  xQueueReceive(uVar1, &uStack_14, 0);
  xQueueSemaphoreTake(uVar2, 0xffffffff);
  xQueueGenericSend(uVar2, 0, 0, 0);
  vQueueDelete(uVar1);
  vQueueDelete(uVar2);
  return;
}


// ── nvs_demo @ .flash.text::4000ec9a ──────────────────

/* Library Function - Single Match
    nvs_demo
   Library: ESP-IDF v6.0.1  */

void nvs_demo(void)
{
  int iVar1;
  undefined4 auStack_14[5];

  iVar1 = nvs_flash_init();
  if (iVar1 == 0x110d || iVar1 == 0x1110) {
    nvs_flash_erase();
    nvs_flash_init();
  }
  nvs_open("storage", 1, auStack_14);
  nvs_set_i32(auStack_14[0], "boot_count", 0);
  nvs_commit(auStack_14[0]);
  nvs_close(auStack_14[0]);
  return;
}


// ── app_main @ .flash.text::4000ecfa ──────────────────

/* Library Function - Single Match
    app_main
   Library: ESP-IDF v6.0.1  */

void app_main(void)
{
  undefined4 uVar1;
  undefined4 uVar2;

  uVar1 = esp_log_timestamp();
  uVar2 = esp_get_idf_version();
  esp_log(3, "fidb_stub", "FIDB stub — IDF %s", uVar1, "fidb_stub", uVar2);
  heap_demo();
  gpio_demo();
  timer_demo();
  rtos_demo();
  nvs_demo();
  return;
}
```

### Rebuilding the FIDB from source

The `tools/build_fidb.sh` script automates the three-phase generation pipeline:

```
Phase 1: idf.py build (ESP32-P4, IDF v6.0.1)
         → fidb_stub.elf  (5.1 MB, 104k DWARF names, all component archives)

Phase 2: analyzeHeadless -import fidb_stub.elf
                         -processor RISCV:LE:32:ESP32-P4
                         -analysisTimeoutPerFile 600
         → 2,194 functions identified and typed by Ghidra

Phase 3: analyzeHeadless -postScript GenerateESP32P4FIDB.java /tmp/esp32p4-idf6.fidb
         → 1,224 functions fingerprinted
         → 142 KB .fidb written and saved
```

```bash
bash tools/build_fidb.sh \
  --idf-path ~/.espressif/v6.0.1/esp-idf \
  --ghidra   /opt/ghidra_12.1.2_PUBLIC \
  --out      tools/esp32p4-idf6.fidb
```

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
- **Pre-built FIDB** — `tools/esp32p4-idf6.fidb` (1,224 ESP-IDF v6.0.1
  functions, ready to apply with one click — no rebuild required)
- **FIDB generator** — `GenerateESP32P4FIDB.java` + `tools/build_fidb.sh`
  for rebuilding the FIDB against any ESP-IDF version
- **Decompiled-C export** — `ExportDecompiledC.java` dumps all decompiled
  functions to a single `.c` file with four RISC-V artifact fixes, peripheral
  access annotations, section organization, and string constant extraction
- **Firmware header export** — `ExportFirmwareHeader.java` emits a compilable
  `firmware.h` with type definitions, `extern` prototypes, and volatile globals
- **Global declarations export** — `ExportGlobalDecls.java` emits `extern`
  declarations for every global referenced by decompiled function bodies
- **Call graph export** — `ExportCallGraph.java` emits a Graphviz `.dot` call
  graph and `MODULES.md` table organized by IDF/app/unknown layer
- **Semantic pattern detection** — `DetectSemanticPatterns.java` classifies
  functions by algorithm using **1287 patterns** across **170+ algorithm families**
  and emits `semantic_hints.json` with rename suggestions
- **FreeRTOS type recovery** — `LoadFreeRTOSTypes.java` registers 14 ESP-IDF SMP
  FreeRTOS types (`TCB_t`, `Queue`, `List`, etc.) with correct field offsets
- **FreeRTOS task extraction** — `ExtractFreeRTOSTasks.java` resolves `xTaskCreate`
  call sites via backward Varnode slicing to recover task names, stack depth, priority, core ID
- **Identify return variable** — `IdentifyReturnVariable.java` walks ClangAST to
  resolve `a0`/`fa0` return variables and adds EOL comments
- **HWLP context analyzer** — `ESP32P4HWLPContextAnalyzer.java` injects
  `CONDITIONAL_JUMP` back-edges at hardware-loop tail addresses
- **IDF example projects** — `test/idf_examples/` contains two verified IDF v6.0.1
  projects (algorithms + number theory) as FreeRTOS tasks with Unity assertions
- **HIL CI scaffold** — `test/hil/` provides a pytest-embedded HIL test harness
- **Round-trip validation** — **525 bare-metal test fixtures** validated
  end-to-end with deterministic `g_result` values, plus IDF v6.0.1 FreeRTOS round-trip

---

## Requirements

| Dependency | Version | Purpose |
|------------|---------|---------|
| Ghidra | 12.1.2 or later | Plugin host and analysis runtime |
| Java | 21 or later | Build and script compilation |
| Gradle | 8+ (wrapper included) | Build system |
| riscv32-esp-elf-gcc | esp-14.2.0+ | Round-trip recompilation |
| ESP-IDF | v6.0.1 | FIDB rebuild only — optional (FIDB ships pre-built) |
| esp32p4.svd | — | Optional — from Espressif SDK |
| esp32p4_rev0_rom.elf | — | Optional — from Espressif SDK |

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

1. Install the extension and restart Ghidra
2. **File → Import File** → select your ELF →
   **Options → Language** → `RISCV:LE:32:ESP32-P4` → OK
3. Run auto-analysis (**Analysis → Auto Analyze**)
4. _(Recommended)_ Apply the FIDB for IDF function names:
   **Tools → Function ID → Apply Function ID Files** → `tools/esp32p4-idf6.fidb`
5. _(Optional)_ Run `LoadESP32P4SVD.java` → point to `esp32p4.svd`
6. _(Optional)_ Run `LoadESP32P4RomSymbols.java` → point to `esp32p4_rev0_rom.elf`
7. Run `ExportDecompiledC.java` to export all decompiled functions

### Headless analysis

```bash
FIDB="$(pwd)/tools/esp32p4-idf6.fidb"

analyzeHeadless /tmp/proj MyProject \
  -import firmware.elf \
  -processor "RISCV:LE:32:ESP32-P4" \
  -preScript AnalyzeESP32P4Headless.py \
  -scriptPath ghidra_scripts \
  -postScript ExportDecompiledC.java /tmp/firmware_decompiled.c \
  -deleteProject
```

---

## ISA Support

| Extension | Description | Status |
|-----------|-------------|--------|
| RV32IMAFC | Base integer + multiply + atomic + single-precision float | Full |
| Zicsr / Zifencei | CSR access / instruction fence | Full |
| Zmmul | Integer multiply subset | Full |
| Zaamo / Zalrsc | Atomic memory operations | Full |
| Zca / Zcf | Compressed base / compressed float | Full |
| xesploop | Hardware loops (custom-1 opcode 0x2B) | Full |
| xespv2p2 | PIE SIMD load/store (opcode 0x1F) | Partial |
| xespv2p2 | PIE SIMD arithmetic (opcode 0x1B) | Partial |

### PIE SIMD — confirmed ops on ESP32-P4 eco2

Verified via [FastLED #2535](https://github.com/FastLED/FastLED/issues/2535)
and [#2536](https://github.com/FastLED/FastLED/issues/2536):

`vld.128.ip` · `vst.128.ip` · `andq` · `orq` · `xorq` · `notq` ·
`zero.q` · `movi.32.q` · `vcmp.eq.s8` · `vunzip.8` · `vsl.32` ·
`vsr.u32` · `slci.2q` · `srci.2q` · `src.q.qup` · `cmul.s16`

Unconfirmed ops fall through to generic `esp.pie.arith` / `esp.pie.0x1f`
pcodeops and still disassemble without crashing the decompiler.

---

## Ghidra Scripts

All scripts live in `ghidra_scripts/` and appear in Ghidra's Script Manager
under the **ESP32-P4** category.

### `ExportDecompiledC.java`

Exports every function's decompiled C to a single `.c` file and automatically
applies four RISC-V artifact fixes. No manual editing required.

**GUI mode** — Script Manager → run → pick an output file in the dialog.

**Headless mode:**

```bash
analyzeHeadless /tmp/proj MyProject \
  -import firmware.elf \
  -processor "RISCV:LE:32:ESP32-P4" \
  -scriptPath ghidra_scripts \
  -postScript ExportDecompiledC.java /tmp/firmware_decompiled.c \
  -deleteProject
```

### `ExportFirmwareHeader.java`

Exports a compilable `firmware.h` containing:
- Topologically-sorted type definitions (structs, enums, typedefs via DFS
  post-order to handle forward references)
- `extern` function prototypes for all named functions
- `volatile` global declarations for peripheral-mapped globals

Include this header when recompiling the output of `ExportDecompiledC.java`.

### `ExportGlobalDecls.java`

Scans all data cross-references from decompiled function bodies and emits
`extern` declarations for every global variable referenced. Eliminates the
most common compile error after exporting decompiled C.

### `ExportCallGraph.java`

Analyzes the full firmware call graph and exports two artifacts:

- **`firmware.dot`** — Graphviz call graph with nodes colored by layer:
  IDF layer (green), application layer (yellow), unknown (grey)
- **`MODULES.md`** — markdown table mapping each weakly-connected
  component to its estimated purpose and layer

### `DetectSemanticPatterns.java`

Scans all decompiled function bodies for known algorithmic patterns and
exports `semantic_hints.json` with rename suggestions. Detects **321 patterns**
across **60+ algorithm families**:

| Category | Families |
|----------|---------|
| Sorting | bubble · insertion · selection · merge · quick · heap · counting · radix · shell · tim · cycle · cocktail |
| Searching | binary · interpolation · exponential · jump · fibonacci · linear · ternary |
| Data structures | linked list · doubly linked · circular list · stack · queue · deque · skip list · treap · AVL · red-black · B-tree · trie · segment tree · Fenwick/BIT · sparse table · union-find |
| Graph algorithms | BFS · DFS · Dijkstra · Bellman-Ford · Floyd-Warshall · Kruskal · Prim · topological sort · SCC · bipartite check · A* · Euler path |
| Dynamic programming | LCS · LIS · knapsack-0/1 · unbounded knapsack · coin change · matrix chain · Catalan · egg drop · burst balloons · palindrome partition · stone game · word break · distinct subsequences |
| Strings | KMP · Rabin-Karp · Z-algorithm · Aho-Corasick · suffix array · Levenshtein · Hamming |
| Math | GCD/LCM · fast power · matrix exponentiation · sieve · Euler totient · Fibonacci · popcount · isqrt · ilog2 · clz · bit-reverse |
| Crypto / hash | CRC-32 · CRC-16 · AES S-box · SHA schedule · XOR cipher · LFSR · Adler-32 · FNV hash |
| Firmware idioms | FSM · FIFO ring buffer · packet parser · memcpy-like · memset-like · strlen-like · printf-like · timer ISR |

```bash
analyzeHeadless /tmp/proj MyProject \
  -import firmware.elf \
  -processor "RISCV:LE:32:ESP32-P4" \
  -scriptPath ghidra_scripts \
  -postScript DetectSemanticPatterns.java /tmp/semantic_hints.json \
  -deleteProject
```

### `GenerateESP32P4FIDB.java`

Generates a Ghidra Function ID database from an ESP-IDF build tree or a
linked stub ELF. The shipped `tools/esp32p4-idf6.fidb` was produced by this
script against IDF v6.0.1. See `tools/build_fidb.sh` for the automated pipeline.

### `LoadESP32P4SVD.java`

Applies all peripheral register names and address ranges from `esp32p4.svd`
to the current program. Run after auto-analysis to get readable peripheral
access patterns (e.g. `UART0->FIFO` instead of raw hex offsets).

### `LoadESP32P4RomSymbols.java`

Imports function names from `esp32p4_rev0_rom.elf`. Without this script,
ROM calls appear as anonymous subroutines at addresses in the ROM region.

### `InspectClangAST.java`

Prototype ClangAST walker. Walks the `ClangTokenGroup` tree for a function
and annotates return nodes, variable references, and type tokens. Research
tool for implementing AST-level fixes.

### `AnalyzeESP32P4Headless.py`

Pre-script for headless Ghidra runs. Applies ESP32-P4-specific memory map
annotations before the standard auto-analysis pass, so memory regions are
correctly typed in the final project.

---

## Resources

```
esp32-p4-decompiler-plugin/
│
├── data/languages/                Sleigh processor definition
│   ├── esp32p4.slaspec            top-level ISA spec (includes all .sinc)
│   ├── esp32p4.cspec              ilp32f ABI compiler spec
│   ├── esp32p4.ldefs              language registration (Ghidra menu entry)
│   ├── esp32p4_hwlp.sinc          xesploop hardware-loop opcodes (0x2B)
│   ├── esp32p4_pie.sinc           xespv2p2 PIE SIMD opcodes (0x1B / 0x1F)
│   ├── esp32p4_csr.sinc           Zicsr CSR map for ESP32-P4
│   ├── riscv32.dwarf              DWARF register map
│   └── riscv.*.sinc               upstream RV32IMAFC/C definitions (NSA/Ghidra)
│
├── ghidra_scripts/                All runnable Ghidra scripts (ESP32-P4 category)
│   ├── ExportDecompiledC.java     bulk decompile + 4 artifact fixes
│   ├── ExportFirmwareHeader.java  firmware.h (prototypes + type definitions)
│   ├── ExportGlobalDecls.java     extern declarations for all globals
│   ├── ExportCallGraph.java       Graphviz call graph + MODULES.md layer table
│   ├── DetectSemanticPatterns.java 321 patterns → semantic_hints.json
│   ├── GenerateESP32P4FIDB.java   FIDB generation from IDF build tree / ELF
│   ├── LoadESP32P4SVD.java        peripheral register labels from SVD
│   ├── LoadESP32P4RomSymbols.java ROM function names from rom.elf
│   ├── InspectClangAST.java       ClangAST research prototype
│   └── AnalyzeESP32P4Headless.py  headless analysis pre-script
│
├── src/main/java/                 Plugin Java source
│   ├── ESP32P4Analyzer.java       auto-analysis pass (memory map + 89 peripherals)
│   ├── ESP32P4MemoryMap.java      address range constants for 89 peripherals
│   └── ESP32P4Plugin.java         plugin registration + UI panel
│
├── tools/                         Build helpers and pre-built artifacts
│   ├── esp32p4-idf6.fidb          pre-built FIDB (1,224 IDF v6.0.1 functions)
│   ├── build_fidb.sh              3-phase FIDB generation pipeline script
│   ├── ghidra_types.h             Ghidra type aliases for recompilation
│   └── idf_stub/                  IDF v6.0.1 stub project used to build FIDB
│       └── main/main.c            exercises heap/GPIO/timer/RTOS/NVS APIs
│
└── test/                          Validation
    ├── ci_smoke.sh                CI smoke check (builds all fixtures + g_result check)
    └── roundtrip/
        ├── run_roundtrip.sh       6-phase automation (compile→decompile→recompile→diff)
        └── test_*.c               201 bare-metal fixtures across 60+ algorithm families
```

---

## Decompilation Pipeline

The plugin ships a complete pipeline for reconstructing compilable C from an
ESP32-P4 ELF. The pipeline is validated end-to-end on real hardware — the
reconstructed binary produces the same deterministic output as the original.

### Pipeline flow

```
  C source fixture (or original firmware)
          │
          │  riscv32-esp-elf-gcc
          │  -march=rv32imafc_zicsr_zifencei -mabi=ilp32f
          ▼
     fixture.elf  (original ELF, possibly stripped)
          │
          │  analyzeHeadless -processor "RISCV:LE:32:ESP32-P4"
          │                  -preScript AnalyzeESP32P4Headless.py
          │                  [+apply esp32p4-idf6.fidb]
          │                  [+LoadESP32P4SVD.java]
          │                  [+LoadESP32P4RomSymbols.java]
          ▼
     Ghidra analysis (auto-analysis + optional enrichments)
          │
          │  -postScript ExportDecompiledC.java /tmp/firmware_decompiled.c
          ▼
     firmware_decompiled.c  ← 4 auto-fixes applied
     firmware.h             ← prototypes + type definitions
          │
          │  riscv32-esp-elf-gcc -include tools/ghidra_types.h
          ▼
     fixture_reconstructed.elf
          │
          ├──── objdump diff vs original  →  zero diff = perfect round-trip
          │
          └──── execute: ./fixture_reconstructed
                              g_result = <deterministic value>
                              compare vs native reference
```

### Automatic artifact fixes

`ExportDecompiledC.java` applies four fixes before writing output.
No manual editing required.

| # | Artifact | Example | Fix |
|---|----------|---------|-----|
| 1 | GP register assignment | `gp = 0x4ff2d380;` | Line stripped — RISC-V global pointer is set by startup code, not a C variable |
| 2 | Void return-type mismatch | `void fn(…)` called as `x = fn(…)` | Signature promoted from `void` to `undefined4` via two-pass scan |
| 3 | Bare `return;` in promoted function | `return;` inside `undefined4 fn()` | Rewritten to `return <lastVar>;` via backwards scan of `uVar*`/`iVar*`/`param_*` assignments |
| 4 | Peripheral `DAT_` string references | `DAT_50000000` in function body | Replaced with `static const char s_<addr>[]` declarations |

### Semantic enrichments

Beyond the four fixes, `ExportDecompiledC.java` also adds:

- **Peripheral access annotations** — inline `/* ← HP_SYS */`, `/* ← UART0 */`
  comments on lines that read/write known ESP32-P4 peripheral addresses (26 ranges)
- **Section organization** — decorative section headers at IRAM/DRAM/ROM/Flash
  region boundaries
- **String constant substitution** — `DAT_` references to Ghidra-typed strings
  replaced with named `static const char[]` declarations

### `tools/ghidra_types.h`

Ghidra's decompiler emits C using type aliases (`undefined4`, `uint`, `uchar`, …)
not defined in any standard header. Include it when recompiling:

```bash
riscv32-esp-elf-gcc \
  -march=rv32imafc_zicsr_zifencei -mabi=ilp32f -O0 \
  -include tools/ghidra_types.h \
  -c firmware_decompiled.c -o firmware_decompiled.o
```

---

## Round-trip Validation

**201 bare-metal test fixtures** validate the full pipeline across 60+ algorithm
families. Each fixture computes a deterministic `g_result` that must survive the
full compile → decompile → recompile cycle unchanged.

```bash
RISCV_GCC=~/.espressif/tools/riscv32-esp-elf/esp-14.2.0_20260121/\
riscv32-esp-elf/bin/riscv32-esp-elf-gcc \
GHIDRA_HEADLESS=/opt/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  ./test/roundtrip/run_roundtrip.sh
```

### Fixture families

| Family | Count | Algorithms covered |
|--------|-------|--------------------|
| Sorting | 12 | bubble, insertion, selection, merge, quick, heap, counting, radix, shell, tim, cycle, cocktail |
| Searching | 7 | binary, interpolation, exponential, jump, fibonacci, linear, ternary |
| Dynamic programming | 25+ | knapsack, LCS, LIS, coin change, matrix chain, Catalan, egg drop, burst balloons, palindrome partition, stone game, word break, distinct subsequences |
| Graph algorithms | 15+ | BFS, DFS, Dijkstra, Bellman-Ford, Floyd-Warshall, Kruskal, Prim, topo sort, SCC, bipartite, A*, Euler |
| Data structures | 18+ | skip list, treap, AVL, segment tree, BIT/Fenwick, trie, union-find, sparse table |
| String algorithms | 10+ | KMP, Rabin-Karp, Z-algorithm, Levenshtein, Hamming, Aho-Corasick |
| Math / Number theory | 15+ | GCD, fast power, matrix exponentiation, sieve, Euler totient, Fibonacci |
| Crypto / hash | 8 | CRC-32, CRC-16, AES S-box, SHA schedule, XOR cipher, LFSR, Adler-32, FNV |
| Firmware idioms | 10+ | FSM, FIFO, packet parser, memcpy, memset, strlen, printf, timer ISR |

### Validated on real hardware

The pipeline was validated on a real ESP32-P4 (revision v3.2) — the reconstructed
binary (zero manual edits) produced the same output as the original firmware:

```
=== ESP32-P4 CRC Hello ===
g_result = 0xbe34bdfc
==========================
```

---

## Known Limitations

- **Global variable declarations** — Ghidra emits function bodies but not global
  definitions. Use `ExportGlobalDecls.java` to auto-generate `extern` declarations,
  or declare globals manually before use.
- **Bare return heuristic** — Fix 3 performs a backwards scan for the last-written
  local variable. Correct for most single-result functions; may need adjustment
  in complex multi-path functions.
- **PIE SIMD bodies** — xespv2p2 instructions lift to pcodeops, not C intrinsics.
  Functions using PIE SIMD will contain opaque `esp_pie_*` operations rather than
  portable C.
- **Hardware loop CFG** — xesploop opcodes are annotated in comments but the
  decompiler cannot yet reconstruct the loop bounds as a `for` statement.

---

## Project Structure

```
data/languages/     Sleigh processor definition (slaspec, sinc, cspec, ldefs, dwarf)
ghidra_scripts/     10 runnable Ghidra scripts (export, SVD, ROM, FIDB, headless)
src/main/java/      Plugin Java source (analyzer, memory map, UI panel)
tools/              FIDB artifact + generation pipeline + ghidra_types.h + idf_stub
test/               CI smoke check + 201 round-trip fixtures
dist/               Built extension ZIP  ← git-ignored, produced by Gradle
```

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

Upstream Sleigh files (`riscv.*.sinc`, `andestar_v5.instr.sinc`) originate
from the [Ghidra](https://github.com/NationalSecurityAgency/ghidra) project
(NSA) and are redistributed under the same Apache 2.0 license.

**Author:** Alexander Salas Bastidas &lt;ajsb85@firechip.dev&gt;
