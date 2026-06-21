# Contributing to ESP32-P4 Ghidra Plugin

Thank you for contributing. This document covers the development setup,
workflow, script authoring, commit conventions, sprint structure, and PR checklist.

---

## Development Setup

### Prerequisites

| Tool | Purpose | Minimum version |
|------|---------|-----------------|
| Ghidra | Plugin host and test runtime | 12.1.2 |
| Java JDK | Build and script compilation | 21 |
| Gradle | Build system (wrapper included) | 8 |
| riscv32-esp-elf-gcc | Round-trip recompilation | esp-14.2.0+ |
| ESP-IDF | ESP-IDF firmware builds (FIDB rebuild only) | v6.0.1 |
| esptool | Flashing to real hardware | 5.x |

### First-time build

```bash
git clone https://github.com/ajsb85/esp32-p4-decompiler-plugin.git
cd esp32-p4-decompiler-plugin
gradle -PGHIDRA_INSTALL_DIR=/opt/ghidra_12.1.2_PUBLIC buildExtension
```

The built ZIP lands in `dist/`. Install it with
**File → Install Extensions → select ZIP → restart Ghidra**.

### Rebuilding and reinstalling

After any change to Java sources or Sleigh files, rebuild and reinstall:

```bash
gradle -PGHIDRA_INSTALL_DIR=/opt/ghidra_12.1.2_PUBLIC buildExtension
```

Then in Ghidra: **File → Install Extensions** → remove old, install new,
restart. If Ghidra appears to load the old version, delete the OSGi
felix cache:

```bash
rm -rf ~/.config/ghidra/ghidra_12.1.2_PUBLIC/osgi/felixcache
```

---

## Repository Structure

```
esp32-p4-decompiler-plugin/
│
├── data/languages/                Sleigh processor definition
│   ├── esp32p4.slaspec            top-level ISA (includes all .sinc)
│   ├── esp32p4.cspec              ilp32f ABI compiler spec
│   ├── esp32p4.ldefs              language registration
│   ├── esp32p4_hwlp.sinc          xesploop hardware-loop opcodes
│   ├── esp32p4_pie.sinc           xespv2p2 PIE SIMD opcodes
│   ├── esp32p4_csr.sinc           Zicsr CSR map
│   └── riscv.*.sinc               upstream RV32 definitions (do not modify)
│
├── ghidra_scripts/                Runnable Ghidra scripts
│   ├── ExportDecompiledC.java     bulk decompile + 4 RISC-V artifact fixes
│   ├── ExportFirmwareHeader.java  firmware.h (prototypes + typedefs)
│   ├── ExportGlobalDecls.java     extern declarations for globals
│   ├── ExportCallGraph.java       Graphviz call graph + MODULES.md
│   ├── DetectSemanticPatterns.java 321 patterns → semantic_hints.json
│   ├── GenerateESP32P4FIDB.java   FIDB generation script
│   ├── LoadESP32P4SVD.java        peripheral labels from SVD
│   ├── LoadESP32P4RomSymbols.java ROM function names
│   ├── InspectClangAST.java       ClangAST research tool
│   └── AnalyzeESP32P4Headless.py  headless analysis pre-script
│
├── src/main/java/                 Plugin Java source
│   ├── ESP32P4Analyzer.java       auto-analysis pass
│   ├── ESP32P4MemoryMap.java      89 peripheral address constants
│   └── ESP32P4Plugin.java         plugin registration + UI panel
│
├── tools/                         Build helpers and pre-built artifacts
│   ├── esp32p4-idf6.fidb          pre-built FIDB (1,224 IDF v6.0.1 functions)
│   ├── build_fidb.sh              automated FIDB generation pipeline
│   ├── ghidra_types.h             Ghidra type aliases for recompilation
│   └── idf_stub/                  IDF v6.0.1 stub project (FIDB source)
│
└── test/                          Validation
    ├── ci_smoke.sh                CI smoke check
    └── roundtrip/
        ├── run_roundtrip.sh       6-phase round-trip automation
        └── test_*.c               201 bare-metal fixtures
```

---

## Development Model: Trunk-Based Development

`main` is the trunk and must always be deployable. All work lands on `main`
via short-lived branches — never directly.

| Branch prefix | Purpose | Max lifetime |
|---------------|---------|--------------|
| `feature/<kebab-name>` | New functionality | 1–2 days |
| `fix/<kebab-name>` | Bug fixes | 1 day |
| `docs/<kebab-name>` | Documentation only | 1 day |
| `test/<kebab-name>` | New round-trip fixtures | 1 day |

There are **no long-running release branches**. Releases are tags on `main`.

### Branch lifecycle

```bash
# 1. Branch off main
git checkout main && git pull
git checkout -b feature/add-kmp-fixture

# 2. Make small, focused commits (see Conventional Commits below)
git commit -S -m "test: add KMP string search fixture (Sprint 42)"

# 3. Push and open a PR
git push -u origin feature/add-kmp-fixture
# → squash-merge into main → delete branch
```

Keep PRs small. If a feature takes more than two days, split it or use a
feature flag in the Java plugin layer.

All commits and tags must be GPG-signed (`-S` for commits, `git tag -s`
for release tags).

---

## Commit Messages — Conventional Commits

Format: `type(scope): description` with the **subject line ≤ 72 characters**.
Body and footer lines wrapped at **72 characters**.

```
type(scope): short imperative description         ← ≤72 chars
<blank line>
Optional body — explain WHY, not what.
Wrap at 72 chars.
<blank line>
Optional footer: Closes #42, BREAKING CHANGE: …
```

### Types

| Type | When to use |
|------|-------------|
| `feat` | New instruction, script, or feature |
| `fix` | Bug in Sleigh pattern, Java, or script |
| `docs` | README, CONTRIBUTING, comments |
| `build` | Gradle, extension manifest, packaging |
| `refactor` | Code restructure with no behavior change |
| `test` | Round-trip fixtures or headless test scripts |
| `chore` | Dependency bumps, file renames |
| `perf` | Performance improvement |
| `style` | Whitespace / formatting only |
| `ci` | GitHub Actions or workflow files |

### Scopes

| Scope | Covers |
|-------|--------|
| `lang` | Sleigh files (`.sinc`, `.slaspec`, `.cspec`, `.ldefs`) |
| `plugin` | Java plugin source (`src/main/java/`) |
| `scripts` | Ghidra scripts (`ghidra_scripts/`) |
| `tools` | Recompilation helpers and FIDB artifacts (`tools/`) |
| `test` | Round-trip fixtures (`test/`) |
| `fixtures` | Batch of new round-trip test cases |
| `fidb` | FIDB database files or generation scripts |
| `docs` | Documentation files |
| `build` | Build system (`build.gradle`, `settings.gradle`) |
| `ci` | Workflow / automation |

### Examples

```
feat(lang): add xespv2p2 PIE arithmetic patterns for 0x1B opcode
fix(lang): correct vst.128.ip op2531 field to 0x41
feat(scripts): add ExportGlobalDecls.java for extern declarations
fix(scripts): auto-fix bare return in void-promoted functions
fix(plugin): null-check in ESP32P4Analyzer peripheral lookup
feat(fidb): ship ESP-IDF v6.0.1 FIDB for ESP32-P4 (1,224 functions)
feat(fixtures): Sprint 106 — matrix chain + Catalan + 3 patterns
docs: add FIDB before/after comparison to README
build: include riscv32.dwarf in extension zip
test: add round-trip validation fixture for KMP string search
```

### Breaking changes

Add `!` after the type/scope, or include a `BREAKING CHANGE:` footer:

```
feat(lang)!: rename ESP32-P4 language ID to RISCV:LE:32:ESP32P4

BREAKING CHANGE: existing Ghidra projects must be re-imported with
the new language ID.
```

---

## Sprint Structure — Adding Fixtures and Patterns

The plugin grows through autonomous sprints. Each sprint typically adds:
- **2 new round-trip fixtures** (`test/roundtrip/test_<name>.c`)
- **3 new semantic patterns** in `DetectSemanticPatterns.java`

### Current state

| Metric | Count |
|--------|-------|
| Round-trip fixtures | **201** |
| Semantic detection patterns | **321** |
| Pattern algorithm families | **60+** |
| FIDB fingerprinted functions | **1,224** |

### Fixture requirements

Every `test/roundtrip/test_<name>.c` must:

1. **Compute a unique `g_result`** — a deterministic 32-bit value encoded as
   `(n_tests << 16) | (metric_a << 8) | metric_b` where all three component
   bytes are non-zero and unique across all 201+ existing fixtures.

2. **Be freestanding** — no libc, no RTOS, no ESP-IDF. Only `<stdint.h>` and
   `<string.h>` are allowed. The fixture runs bare-metal under
   `riscv32-esp-elf-gcc -nostartfiles`.

3. **Compile cleanly** — zero warnings with `-Wall -Wextra -Werror`.

4. **Use `static` helpers before `#define CHECK`** — all recursive/helper
   functions must be declared `static` and placed before the `CHECK` macro
   definition to avoid forward-reference issues after decompilation.

5. **Exercise real algorithmic structure** — the fixture must produce enough
   control flow (loops, conditionals, recursion, arrays) to generate interesting
   decompilation output. Trivial single-op tests are not useful.

### Pattern requirements

Every `PatternDef` in `DetectSemanticPatterns.java` must:

1. Have a unique `name` and `category` slug.
2. Specify two distinct regex evidence strings (AND logic — both must match).
3. Include a comma-separated `aliases` list for alternative naming.
4. Set `confidence` to `"high"`, `"medium"`, or `"low"`.

### Fixture template

```c
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_<name>.c — <algorithm description>
 *
 * g_result = (n_tests << 16) | (metric_a << 8) | metric_b
 *          = 0x<XXXXXXXX>
 */
#include <stdint.h>
#include <string.h>

volatile uint32_t g_result;

#define CHECK(expr) do { if (!(expr)) { g_result = 0xDEAD0000; return; } } while (0)

/* --- algorithm implementation --- */

static int my_algorithm(int x) {
    /* ... */
    return x;
}

/* --- test entry point --- */

void _start(void) {
    int n_tests = 3;
    int metric_a = /* ... */;
    int metric_b = /* ... */;

    CHECK(my_algorithm(/* ... */) == /* expected */);
    /* ... more checks ... */

    g_result = ((uint32_t)n_tests << 16) | ((uint32_t)(metric_a & 0xFF) << 8) | (uint32_t)(metric_b & 0xFF);
}
```

### Verifying a new fixture natively before committing

```bash
# Compile for native x86 to verify g_result
gcc -O2 -o /tmp/test_name test/roundtrip/test_name.c && /tmp/test_name
echo "g_result = 0x$(python3 -c "import ctypes; print(hex(ctypes.CDLL(None).g_result))")"

# Or: link with a main() wrapper that prints g_result
gcc -O2 -DNATIVE_TEST -o /tmp/test_name test/roundtrip/test_name.c && /tmp/test_name
```

### Registering a new fixture in CI

After adding `test/roundtrip/test_name.c`, add the expected `g_result` to
`test/ci_smoke.sh`:

```bash
# In test/ci_smoke.sh
run_fixture test_name 0xXXXXXXXX
```

---

## Writing Ghidra Scripts

All scripts live in `ghidra_scripts/` and extend `GhidraScript`. Every
file must carry the Apache 2.0 SPDX header (copy from any existing script).

### Headless compatibility

Scripts used in headless (`analyzeHeadless`) mode must not call interactive
methods. Use `getScriptArgs()` instead of dialog methods:

```java
String[] args = getScriptArgs();
File outFile;
if (args != null && args.length > 0 && !args[0].isEmpty()) {
    outFile = new File(args[0]);
} else {
    outFile = askFile("Save output to", "Save");  // GUI mode only
}
```

### Passing arguments headlessly

```bash
analyzeHeadless /tmp/proj MyProject \
  -import firmware.elf \
  -processor "RISCV:LE:32:ESP32-P4" \
  -scriptPath ghidra_scripts \
  -postScript MyScript.java arg1 arg2 \
  -deleteProject
```

`getScriptArgs()` returns `["arg1", "arg2"]` inside the script.

### Script categories

```java
// @category ESP32-P4
// @menupath Analysis.ESP32-P4.My Script Name
```

---

## Decompilation Pipeline — How It Works

`ExportDecompiledC.java` implements a three-pass pipeline over Ghidra's
decompiler output. Understanding it is necessary before extending the script.

### Pass 1 — Decompile all functions

All functions are decompiled via `DecompInterface` and stored in memory as
raw C strings keyed by `"funcName@address"`. Failures are recorded but do
not abort the export.

### Pass 2 — Detect promotion candidates

Two regex patterns scan every decompiled function:

- `VOID_SIG` — collects all function names declared `void funcName(`
- `CALL_ASSIGN` — finds any `var = name(` pattern (assignment from a call)

Any name that appears in both sets is promoted: Ghidra declared it `void`
but a caller uses its return value.

### Pass 3 — Write with fixes

Each function is written line-by-line through four filters:

1. **GP strip** — lines matching `gp = 0x[hex];` are dropped.
2. **Void promotion** — the `void funcName(` signature of any promoted
   function is rewritten to `undefined4 funcName(`.
3. **Bare return fix** — inside a promoted function, `return;` is rewritten
   to `return <lastVar>;` via a backwards scan for the most recently assigned
   `uVar*`, `iVar*`, or `param_*` local variable.
4. **DAT_ string substitution** — `DAT_` references to addresses Ghidra has
   typed as string data are replaced with `static const char s_<addr>[]`
   declarations.

### Adding a new fix

1. Declare a `private static final Pattern` constant with a clear name.
2. Add a detection pass (if needed) before Pass 3.
3. Add an `if` block inside the per-line loop in Pass 3.
4. Add a counter, increment when the fix fires, include in `println` summary.
5. Update the fix table in `README.md`.

---

## FIDB — Function ID Database

The pre-built `tools/esp32p4-idf6.fidb` contains 1,224 fingerprinted
ESP-IDF v6.0.1 functions. This section explains how it was generated and
how to regenerate it.

### Generation pipeline

```
Phase 1  idf.py build (ESP32-P4 target, IDF v6.0.1)
         Produces: build/fidb_stub.elf  (5.1 MB, 104k DWARF names)
                   build/esp-idf/*/lib*.a  (122 component archives)

Phase 2  analyzeHeadless -import fidb_stub.elf
                         -processor "RISCV:LE:32:ESP32-P4"
                         -analysisTimeoutPerFile 600
         Produces: Ghidra project with 2,194 functions typed

Phase 3  analyzeHeadless -process "fidb_stub.elf" -noanalysis
                         -postScript GenerateESP32P4FIDB.java /tmp/out.fidb
         Produces: /tmp/out.fidb  (142 KB, 1,224 functions fingerprinted)
```

### Key discovery: `saveDatabase()` is required

The FID Java API requires an explicit `fidDB.saveDatabase(msg, monitor)` call
before `fidDB.close()`. Without it, the packed format is never committed and
the resulting file is 672 bytes (empty header only). This is the most common
FIDB generation failure mode.

```java
// MUST call saveDatabase before close to commit data to packed format
fidDB.saveDatabase("Saving ESP-IDF FIDB", monitor);
// ...
fidDB.close();  // in finally block
```

### Key discovery: WSL path limitation

Ghidra's Java DB framework fails to open `.fidb` files at `/mnt/c/` paths
in WSL. Always write to `/tmp/` first, then copy to the repo:

```bash
analyzeHeadless ... -postScript GenerateESP32P4FIDB.java /tmp/esp32p4-idf6.fidb
cp /tmp/esp32p4-idf6.fidb tools/esp32p4-idf6.fidb
```

### Rebuilding

```bash
bash tools/build_fidb.sh \
  --idf-path ~/.espressif/v6.0.1/esp-idf \
  --ghidra   /opt/ghidra_12.1.2_PUBLIC \
  --out      tools/esp32p4-idf6.fidb
```

---

## Round-trip Validation

Before merging any change to `ExportDecompiledC.java`, `ghidra_types.h`, or
any Sleigh file, run the automated round-trip script to confirm the pipeline
still produces compilable, correct output.

```bash
# One-line automated run (Phases 1–6: compile → decompile → recompile → diff → patterns → optional flash)
RISCV_GCC=~/.espressif/tools/riscv32-esp-elf/esp-14.2.0_20260121/\
riscv32-esp-elf/bin/riscv32-esp-elf-gcc \
GHIDRA_HEADLESS=/opt/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  ./test/roundtrip/run_roundtrip.sh

# Also flash rebuilt ELFs to hardware on COM12 and verify g_result:
./test/roundtrip/run_roundtrip.sh --flash COM12
```

### CI smoke check

The lighter `test/ci_smoke.sh` builds all 201 fixtures natively and verifies
their `g_result` values without requiring Ghidra or a RISC-V toolchain:

```bash
bash test/ci_smoke.sh
```

### Selected fixture expected values

| Fixture | Exercises | `g_result` |
|---------|-----------|------------|
| `hello.c` | CRC-32 accumulator | `0xBE34BDFC` |
| `test_sorting.c` | Bubble sort + insertion sort | `0x00000029` |
| `test_math.c` | Popcount, isqrt, bit-reverse, ilog2, clz32 | `0x000000F9` |
| `test_state_machine.c` | 4-state packet parser FSM | `0x00000244` |
| `test_crypto.c` | XOR stream cipher + key schedule + CRC-8 | `0xABCD65DD` |
| `test_skip_list.c` | Skip list insert + search | `0x0003021E` |
| `test_treap.c` | Treap split + merge + insert | `0x00020F0A` |

(201 fixtures total — see `test/ci_smoke.sh` for complete list.)

---

## `tools/ghidra_types.h`

Ghidra's decompiler emits C using type aliases not in any standard header
(`undefined4`, `uint`, `uchar`, etc.). The file `tools/ghidra_types.h`
maps each alias to the appropriate `<stdint.h>` type.

Include it when recompiling any exported decompiled C:

```bash
riscv32-esp-elf-gcc \
  -march=rv32imafc_zicsr_zifencei -mabi=ilp32f -O0 \
  -include tools/ghidra_types.h \
  -c firmware_decompiled.c
```

When Ghidra introduces a new type alias not yet in the header, add it.
Map to the smallest standard integer type that matches the bit-width suffix
(e.g. `undefined6` → `uint64_t`).

---

## Pull Request Checklist

Before requesting review, confirm every item:

- [ ] Branch name matches `feature/`, `fix/`, `docs/`, or `test/` prefix
- [ ] All commit subjects follow Conventional Commits (≤ 72 chars) and
      are GPG-signed
- [ ] Sleigh compiles without new warnings **in our files**:
      `cd data/languages && sleigh -a .`
      (upstream `riscv.*.sinc` warnings are pre-existing and expected)
- [ ] Java compiles without new warnings:
      `gradle compileJava`
- [ ] Headless import succeeds with no new ERRORs:
      `analyzeHeadless … -processor "RISCV:LE:32:ESP32-P4" -noanalysis`
- [ ] CI smoke check passes:
      `bash test/ci_smoke.sh`
- [ ] If `ExportDecompiledC.java`, `ghidra_types.h`, or Sleigh files
      changed — full round-trip test passes with zero compile errors
- [ ] New Ghidra scripts work in both GUI mode and headless mode
      (no `askFile()` / `askString()` calls in headless code paths)
- [ ] New fixtures have unique `g_result` values (no collision with
      existing 201 fixtures in `test/ci_smoke.sh`)
- [ ] Every new source file carries the Apache 2.0 SPDX header
- [ ] Upstream files (`riscv.*.sinc`, `andestar_v5.instr.sinc`) are
      **not modified** unless strictly necessary
- [ ] `dist/` and `*.sla` are **not committed** (covered by `.gitignore`)
- [ ] `README.md` updated if a new script, tool, or fixture family was added

---

## Open Improvements

The following are not yet implemented. All are well-scoped and self-contained.

### Decompilation pipeline

- [ ] **Global variable export** — emit `extern` declarations for every
      global referenced in decompiled function bodies automatically.
      `ExportGlobalDecls.java` handles this but it's not yet integrated
      into the default `ExportDecompiledC.java` workflow.
- [ ] **`ghidra_types.h` auto-discovery** — scan the decompiled output
      for undeclared identifiers and auto-generate missing type aliases
      rather than maintaining the header manually.
- [ ] **Per-function file output** — add a `--split` script argument that
      writes one `.c` file per function for large firmware.
- [ ] **Struct/enum export** — emit recovered struct and enum definitions
      above the function bodies that use them (via `DataTypeManager`).

### Language support

- [ ] **Full xespv2p2 arithmetic lift** — implement p-code semantics for
      the remaining unconfirmed PIE SIMD opcodes so they decompile to
      pseudo-intrinsics rather than opaque `esp.pie.arith` pcodeops.
- [ ] **ESP32-P5 variant** — add a `esp32p5.slaspec` that extends the P4
      definition for any ISA differences in the P5 silicon.
- [ ] **CSR symbolic names** — map all ESP32-P4-specific CSR addresses in
      `riscv.csr.sinc` to human-readable names from the TRM.
- [ ] **Hardware loop CFG lifting** — implement full `xesploop` pcode
      semantics so Ghidra reconstructs hardware-looped code as `for` loops
      instead of `goto` tangles.

### Tooling

- [ ] **SVD bundling** — bundle `esp32p4.svd` in the extension ZIP (pending
      Espressif license clarification) so `LoadESP32P4SVD.java` works
      out of the box.
- [ ] **OpenOCD / JTAG launch integration** — add a Ghidra plugin panel
      that starts OpenOCD for the ESP32-P4 JTAG interface and attaches
      GDB so live debugging is one click from the Ghidra UI.
- [ ] **ROM ELF bundling** — ship `esp32p4_rev0_rom.elf` or a stripped
      symbols-only variant as a release artifact.

### Quality

- [ ] **Sleigh unit tests** — add pattern-match tests for every xesploop
      and xespv2p2 opcode using Ghidra's `PatternTest` framework.
- [ ] **ClangAST Fix 4** — use `InspectClangAST.java` findings to implement
      a proper data-flow-based bare-return variable selector (currently uses
      a backwards text scan).

---

## Releases

Releases follow [SemVer](https://semver.org): `vMAJOR.MINOR.PATCH`.

Only maintainers create release tags:

```bash
git tag -s v1.0.0 -m "release: v1.0.0"
git push origin v1.0.0
```

GitHub Releases are created from the tag with the built ZIP attached.
The ZIP is produced by:

```bash
gradle -PGHIDRA_INSTALL_DIR=/path/to/ghidra buildExtension
```

Release artifacts include:
- `ghidra_12.1.2_PUBLIC_*_esp32p4-ghidra-plugin.zip` — the Ghidra extension
- `tools/esp32p4-idf6.fidb` — pre-built FIDB (also ships inside the ZIP)

---

## Getting Started

See [README.md](README.md) for build instructions, requirements, and
installation steps. Once you can run `gradle buildExtension` and the
headless import test passes, you are ready to contribute.

Good first issues for new contributors:
- Add a new round-trip fixture for an algorithm not yet covered (see the
  60+ existing families for inspiration)
- Add new semantic patterns to `DetectSemanticPatterns.java`
- Improve peripheral coverage in `LoadESP32P4SVD.java`
- Write a Sleigh pattern-match test for an xesploop opcode

---

## Code of Conduct

Be respectful and constructive. Critique ideas, not people. Harassment,
discrimination, or personal attacks will not be tolerated and may result
in removal from the project.
