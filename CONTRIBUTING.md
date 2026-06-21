# Contributing to ESP32-P4 Ghidra Plugin

Thank you for contributing. This document covers the development setup,
workflow, script authoring, commit conventions, and PR checklist.

---

## Development Setup

### Prerequisites

| Tool | Purpose | Minimum version |
|------|---------|-----------------|
| Ghidra | Plugin host and test runtime | 12.1.2 |
| Java JDK | Build and script compilation | 21 |
| Gradle | Build system (wrapper included) | 8 |
| riscv32-esp-elf-gcc | Round-trip recompilation | esp-15.x |
| ESP-IDF | ESP-IDF firmware builds | v6.0 |
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

## Development Model: Trunk-Based Development

`main` is the trunk and must always be deployable. All work lands on `main`
via short-lived branches — never directly.

| Branch prefix | Purpose | Max lifetime |
|---------------|---------|--------------|
| `feature/<kebab-name>` | New functionality | 1–2 days |
| `fix/<kebab-name>` | Bug fixes | 1 day |
| `docs/<kebab-name>` | Documentation only | 1 day |

There are **no long-running release branches**. Releases are tags on `main`.

### Branch lifecycle

```bash
# 1. Branch off main
git checkout main && git pull
git checkout -b feature/add-esp32p5-variant

# 2. Make small, focused commits (see Conventional Commits below)
git commit -S -m "feat(lang): add RV32.pspec variant for ESP32-P5"

# 3. Push and open a PR
git push -u origin feature/add-esp32p5-variant
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
| `tools` | Recompilation helpers (`tools/`) |
| `test` | Round-trip fixtures (`test/`) |
| `docs` | Documentation files |
| `build` | Build system (`build.gradle`, `settings.gradle`) |
| `ci` | Workflow / automation |

### Examples

```
feat(lang): add xespv2p2 PIE arithmetic patterns for 0x1B opcode
fix(lang): correct vst.128.ip op2531 field to 0x41
feat(scripts): add LoadESP32P4SVD peripheral label script
fix(scripts): auto-fix bare return in void-promoted functions
fix(plugin): null-check in ESP32P4Analyzer peripheral lookup
docs: add PIE SIMD confirmed-ops table to README
build: include riscv32.dwarf in extension zip
chore(scripts): update LoadESP32P4SVD default SVD path
test: add round-trip validation fixture
```

### Breaking changes

Add `!` after the type/scope, or include a `BREAKING CHANGE:` footer:

```
feat(lang)!: rename ESP32-P4 language ID to RISCV:LE:32:ESP32P4

BREAKING CHANGE: existing Ghidra projects must be re-imported with
the new language ID.
```

---

## Writing Ghidra Scripts

All scripts live in `ghidra_scripts/` and extend `GhidraScript`. Every
file must carry the Apache 2.0 SPDX header (copy the header from any
existing script).

### Headless compatibility

Scripts that will be used in headless (`analyzeHeadless`) mode must not
call interactive methods:

- Do **not** use `askFile()`, `askString()`, or similar dialog methods in
  code paths that run headlessly. Use `getScriptArgs()` instead.
- If you want GUI mode to fall back to a dialog, guard it:

```java
String[] args = getScriptArgs();
File outFile;
if (args != null && args.length > 0 && !args[0].isEmpty()) {
    outFile = new File(args[0]);
} else {
    outFile = askFile("Save output to", "Save");
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

The `@category` annotation places the script in the Script Manager tree.
Use `ESP32-P4` for all scripts in this plugin:

```java
// @category ESP32-P4
// @menupath Analysis.ESP32-P4.My Script Name
```

---

## Decompilation Pipeline — How It Works

`ExportDecompiledC.java` implements a three-pass pipeline over the Ghidra
decompiler output. Understanding it is necessary before extending or
modifying the script.

### Pass 1 — Decompile all functions

All functions in the program are decompiled via `DecompInterface` and
stored in memory as raw C strings, keyed by `"funcName@address"`.
Failures are recorded but do not abort the export.

### Pass 2 — Detect promotion candidates

Two regex patterns scan every decompiled function:

- `VOID_SIG` — collects all function names declared `void funcName(`
- `CALL_ASSIGN` — finds any `var = name(` pattern (assignment from a call)

Any name that appears in both sets is promoted: Ghidra declared it `void`
but a caller uses its return value.

### Pass 3 — Write with fixes

Each function is written line-by-line through three filters:

1. **GP strip** — lines matching `gp = 0x[hex];` are dropped. The RISC-V
   global pointer is initialized by startup code; Ghidra incorrectly emits
   it as a C variable assignment on every function entry.

2. **Void promotion** — the `void funcName(` signature line of any
   promoted function is rewritten to `undefined4 funcName(`.

3. **Bare return fix** — inside a promoted function, `return;` (bare,
   no value) is rewritten to `return param_1;`. This is correct under the
   RISC-V ilp32 ABI: the first parameter (`a0`) doubles as the return
   register. A bare `return` in the decompiler output means the value
   already in `a0` — which is `param_1` — is the intended return value.

### Adding a new fix

To add a fourth artifact fix, follow the established pattern:

1. Declare a `private static final Pattern` constant with a clear name.
2. Add a detection pass (if needed) before Pass 3.
3. Add an `if` block inside the per-line loop in Pass 3.
4. Add a counter, increment it when the fix fires, and include it in the
   `println` summary at the end.
5. Update the file-header comment block and the fix table in `README.md`.

---

## `tools/ghidra_types.h`

Ghidra's decompiler emits C using type aliases that are not in any
standard header (`undefined4`, `uint`, `uchar`, etc.). The file
`tools/ghidra_types.h` maps each alias to the appropriate `<stdint.h>`
type.

Include it when recompiling any exported decompiled C:

```bash
riscv32-esp-elf-gcc \
  -march=rv32imafc_zicsr_zifencei -mabi=ilp32f -O0 \
  -include tools/ghidra_types.h \
  -c firmware_decompiled.c
```

When Ghidra introduces a new type alias that is not yet in the header,
add it here. Map to the smallest standard integer type that matches the
alias's bit-width suffix (e.g. `undefined6` → `uint64_t` is acceptable
as a safe approximation until a proper type is known).

---

## Round-trip Validation

Before merging any change that touches `ExportDecompiledC.java`,
`ghidra_types.h`, or the Sleigh processor definition, run the automated
round-trip script to confirm the pipeline still produces compilable,
correct output.

```bash
# One-line automated run (Phases 1–5: compile → decompile → recompile → diff → patterns)
RISCV_GCC=~/.espressif/tools/riscv32-esp-elf/esp-14.2.0_20260121/\
riscv32-esp-elf/bin/riscv32-esp-elf-gcc \
GHIDRA_HEADLESS=/opt/ghidra_12.1.2_PUBLIC/support/analyzeHeadless \
  ./test/roundtrip/run_roundtrip.sh

# Optional: also flash rebuilt ELFs to hardware on COM12 and verify g_result
./test/roundtrip/run_roundtrip.sh --flash COM12
```

### Test fixtures and expected `g_result` values

| Fixture | Exercises | `g_result` |
|---------|-----------|------------|
| `hello.c` | CRC-32 accumulator | `0xBE34BDFC` |
| `test_sorting.c` | Bubble sort + insertion sort, nested loops | `0x00000029` |
| `test_math.c` | Popcount, isqrt, bit-reverse, ilog2, clz32 | `0x000000F9` |
| `test_state_machine.c` | Packet parser FSM (4-state switch/case) | `0x00000244` |
| `test_crypto.c` | XOR stream cipher + key schedule + CRC-8 MAC | `0xABCD65DD` |

Each `g_result` is computed deterministically at compile time (verified
against a native reference implementation). The round-trip validates that
`g_result` is the same between the original and the recompiled binary.

See `test/roundtrip/run_roundtrip.sh --help` for all options.

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
- [ ] If `ExportDecompiledC.java`, `ghidra_types.h`, or Sleigh files
      changed — round-trip test passes with zero compile errors
- [ ] New Ghidra scripts work in both GUI mode and headless mode
      (no `askFile()` / `askString()` calls in headless code paths)
- [ ] Every new source file carries the Apache 2.0 SPDX header
- [ ] Upstream files (`riscv.*.sinc`, `andestar_v5.instr.sinc`) are
      **not modified** unless strictly necessary
- [ ] `dist/` and `*.sla` are **not committed** (covered by `.gitignore`)
- [ ] `README.md` updated if a new script, fix, or tool was added

---

## Nice-to-Have Features

The following improvements are not yet implemented. Pick one up and open a
`feature/` branch — all are well-scoped and self-contained.

### Decompilation pipeline

- [ ] **Global variable export** — emit `extern` declarations for every
      global symbol referenced in decompiled function bodies. Currently
      callers must add these manually.
- [x] **Multi-return bare-return fix** — Fix 3 now backwards-scans the
      function body for the last-written Ghidra local variable
      (`uVar*`, `iVar*`, `param_*`) and uses that as the return value
      instead of always emitting `return param_1;`.
- [ ] **`ghidra_types.h` auto-discovery** — scan the decompiled output
      for undeclared identifiers and auto-generate any missing type aliases
      rather than maintaining the header manually.
- [ ] **Per-function file output** — add a `--split` script argument that
      writes one `.c` file per function (useful for large firmware where
      a single file is unwieldy).
- [ ] **Struct/enum export** — emit recovered struct and enum definitions
      above the function bodies that use them.

### Language support

- [ ] **Full xespv2p2 arithmetic lift** — implement p-code semantics for
      the remaining unconfirmed PIE SIMD opcodes so they decompile to
      pseudo-intrinsics rather than opaque `esp.pie.arith` pcodeops.
- [ ] **ESP32-P5 variant** — add a `esp32p5.slaspec` that extends the P4
      definition for any ISA differences in the P5 silicon.
- [ ] **CSR symbolic names** — map all ESP32-P4-specific CSR addresses in
      `riscv.csr.sinc` to human-readable names from the TRM.

### Tooling

- [x] **Automated round-trip test script** — `test/roundtrip/run_roundtrip.sh`
      runs all six phases (compile, headless decompile, recompile, objdump diff,
      pattern detection, optional hardware flash) and exits non-zero on failure.
      Covers five test fixtures with deterministic `g_result` values.
- [ ] **FIDB database artifact** — ship a pre-built `esp32p4-idf6.fidb`
      alongside the extension so users do not need to run
      `GenerateESP32P4FIDB.java` themselves.
- [ ] **SVD bundling** — bundle `esp32p4.svd` in the extension ZIP (pending
      Espressif license clarification) so `LoadESP32P4SVD.java` works
      out of the box without a local SDK.
- [ ] **OpenOCD / JTAG launch integration** — add a Ghidra plugin panel
      that starts OpenOCD for the ESP32-P4 JTAG interface and attaches
      GDB so live debugging is one click from the Ghidra UI.

### Quality

- [ ] **Sleigh unit tests** — add pattern-match tests for every
      xesploop and xespv2p2 opcode using Ghidra's `PatternTest` framework.
- [ ] **Headless smoke test** — a short `analyzeHeadless` run against
      the round-trip fixture ELF that fails the build if any ERRORs appear
      in the Ghidra log.

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

---

## Getting Started

See [README.md](README.md) for build instructions, requirements, and
installation steps. Once you can run `gradle buildExtension` and the
headless import test passes, you are ready to contribute.

---

## Code of Conduct

Be respectful and constructive. Critique ideas, not people. Harassment,
discrimination, or personal attacks will not be tolerated and may result
in removal from the project.
