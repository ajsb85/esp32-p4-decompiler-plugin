# Round-Trip Validation

Validates the full decompiler pipeline: **compile → decompile → recompile → verify**.

The suite ships 19 bare-metal RISC-V fixtures covering a broad range of algorithm
families. Each fixture stores its result in `volatile uint32_t g_result` so the
hardware flash-and-verify path can read it from a known address via serial output.

---

## Fixtures

| Fixture | Algorithms / Patterns | Expected `g_result` | HW only? |
|---------|----------------------|---------------------|----------|
| `hello.c` | Fibonacci, CRC-32, bare startup | `0xBE34BDFC` | |
| `test_sorting.c` | Bubble sort, insertion sort | `0x00000029` | |
| `test_math.c` | Popcount, integer sqrt (Newton), bit reverse, `ilog2`, `clz` | `0x000000F9` | |
| `test_state_machine.c` | 4-state FSM, packet parser, ring buffer | `0x00000244` | |
| `test_crypto.c` | XOR stream cipher, key schedule, Poly-1305-style MAC, CRC-8 | `0xABCD65DD` | |
| `test_linked_list.c` | Static-pool singly-linked list, push/pop, XOR checksum | `0x0000781E` | |
| `test_matrix.c` | 3×3 matrix multiply, cofactor determinant, element XOR | `0x0000003A` | |
| `test_lfsr.c` | Galois LFSR (0x80200003), Fibonacci LFSR, bit collection | `0x2F34BC35` | |
| `test_fifo_queue.c` | Lock-free FIFO (head/tail modulo), enqueue/dequeue XOR | `0x00000000` | |
| `test_bitops.c` | GCD (Euclidean), byte-swap, nibble-swap, parity, Gray code, sat-add, Kernighan popcount | `0x87A97826` | |
| `test_hash.c` | DJB2, FNV-1a, polynomial rolling hash | `0x21708D55` | |
| `test_string.c` | `strlen`, `memcmp`, `strchr` count, brute-force substring search | `0x00001014` | |
| `test_pie_simd.c` | xespv2p2 PIE: `esp.vld.128.ip`, `esp.vst.128.ip` (raw `.word`) | `0x0000109A` | ✓ |
| `test_hwlp.c` | xesploop: `esp.lp.setup` 3-instruction counted sum loop (raw `.word`) | `0x00000824` | ✓ |
| `test_bst.c` | Binary search tree: static-pool insert + in-order traversal XOR | `0x0000320A` | |
| `test_heap.c` | Min-heap: array-based insert + extract-min × 8, sift-up / sift-down | `0x00002707` | |
| `test_rle.c` | Run-length encoding: encode {1,1,2,2,2,3,1,1,1,1,4,4} + decode | `0x000A0C01` | |
| `test_base64.c` | Base64 encoding: "Hello!" → "SGVsbG8h", 6-bit extraction + table lookup | `0x00000844` | |
| `test_avl.c` | AVL tree: LL/RR/LR/RL rotations; insert {3,1,4,5,9,2,6}; in-order XOR+sum | `0x00071E0E` | |

`test_pie_simd` compiles for any RV32 target but requires real **ESP32-P4 ECO2**
hardware to execute the PIE SIMD instructions. Use `--flash <port>` to validate it.

---

## Quick start

### CI smoke (no Ghidra, no hardware)

Validates Java script compilation, Sleigh compilation, gcc cross-compilation of all
fixtures, and native reference values — in under 30 s on a typical workstation.

```bash
# From the repo root:
GHIDRA_INSTALL_DIR=/opt/ghidra_12.1.2_PUBLIC \
RISCV_GCC=~/.espressif/tools/riscv32-esp-elf/esp-14.2.0_20260121/riscv32-esp-elf/bin/riscv32-esp-elf-gcc \
bash test/ci_smoke.sh
```

Exit 0 = all pass. Phases that require a missing tool are silently skipped (SKIP,
not FAIL) so CI works in environments without a cross-compiler or Ghidra install.

### Full round-trip (Ghidra headless required)

```bash
# From the repo root:
bash test/roundtrip/run_roundtrip.sh
```

Options:

```
--ghidra-project /tmp/rt-proj   Override project directory (default /tmp/esp32p4-roundtrip-proj)
--flash COM12                    Flash each recompiled ELF and read g_result from serial
```

The script runs six phases:

| Phase | What it does |
|-------|-------------|
| 1 | Compile originals with `riscv32-esp-elf-gcc -O2` |
| 2 | Ghidra headless decompile → `.c` via `ExportDecompiledC.java` |
| 3 | Recompile decompiled `.c` with `-O0 -include ghidra_types.h` |
| 4 | `objdump` mnemonic diff (normalised, ignoring addresses) |
| 5 | Pattern detection via `DetectSemanticPatterns.java` → `*_hints.json` |
| 6 | Optional hardware flash + serial `g_result` read (requires `--flash`) |

### Manual single-fixture run

```bash
GCC=~/.espressif/tools/riscv32-esp-elf/esp-14.2.0_20260121/riscv32-esp-elf/bin/riscv32-esp-elf-gcc
CFLAGS="-march=rv32imafc_zicsr_zifencei -mabi=ilp32f -O2 -ffreestanding -nostdlib"
LD=test/roundtrip/hello.ld

# 1. Compile
$GCC $CFLAGS -T$LD test/roundtrip/test_hash.c -o /tmp/test_hash.elf

# 2. Decompile (Ghidra headless)
analyzeHeadless /tmp/proj RT_hash \
  -import /tmp/test_hash.elf \
  -processor "RISCV:LE:32:ESP32-P4" \
  -scriptPath ghidra_scripts \
  -postScript ExportDecompiledC.java /tmp/test_hash_decompiled.c \
  -deleteProject

# 3. Recompile decompiled C
$GCC -march=rv32imafc_zicsr_zifencei -mabi=ilp32f -O0 -ffreestanding -nostdlib \
     -include tools/ghidra_types.h -T$LD \
     /tmp/test_hash_decompiled.c -o /tmp/test_hash_rebuilt.elf

# 4. Compare (mnemonic diff)
riscv32-esp-elf-objdump -d /tmp/test_hash.elf     > /tmp/orig.dis
riscv32-esp-elf-objdump -d /tmp/test_hash_rebuilt.elf > /tmp/rebuilt.dis
diff /tmp/orig.dis /tmp/rebuilt.dis | head -40
```

---

## Semantic pattern detection

`DetectSemanticPatterns.java` classifies decompiled function bodies against
51 algorithm patterns using multi-regex heuristics. Run it as a Ghidra post-script
and it emits `semantic_hints.json` alongside the decompiled `.c`:

```bash
analyzeHeadless /tmp/proj RT_hash \
  -import /tmp/test_hash.elf \
  -processor "RISCV:LE:32:ESP32-P4" \
  -scriptPath ghidra_scripts \
  -postScript DetectSemanticPatterns.java /tmp/test_hash_hints.json \
  -deleteProject
```

Pattern families currently covered (51 patterns):

| Family | Patterns |
|--------|---------|
| Sorting | bubble, insertion, selection, quick, merge |
| Math | bitwise tricks, Newton sqrt, bit-reverse, ilog2, clz |
| Crypto-like | XOR cipher, CRC-8/32, Poly-1305 MAC |
| State machine | FSM sync-byte, ring buffer |
| Linked list | traverse, push/pop (static pool) |
| Matrix | 3×N multiply (triple nested `for`) |
| LFSR | Galois (mask XOR shift), Fibonacci (multi-tap XOR) |
| FIFO | modulo-indexed head/tail |
| Bit operations | GCD Euclidean, endian swap, Gray encode/decode, sat-add |
| Hash | DJB2, FNV-1a, polynomial rolling |
| String | `strlen` loop, `memcmp`, substring search |
| PIE SIMD | `vld/vst.128.ip` loops, `zero.q`, bitwise Q ops, SIMD loop |
| xesploop | HWLP setup detection (`hwlp_setup`), counted loop reconstruction (`hwlp_counted_loop`) |
| Data structures | BST insert / in-order traverse, min-heap insert / extract-min, AVL rotate / balance |
| Codecs | RLE encode/decode run scanning, Base64 6-bit extraction + table |

---

## Prerequisites

| Tool | Version | Role |
|------|---------|------|
| `riscv32-esp-elf-gcc` | esp-14.2.0+ | Cross-compile fixtures and decompiled C |
| Ghidra | 12.1.2+ | Headless decompile (phases 2, 5) |
| `gcc` (host) | any | Native reference-value verifier (ci_smoke Phase 4) |
| `esptool.py` | 4.x+ | Flash to hardware (phase 6, optional) |
| `python3` + `pyserial` | any | Read `g_result` from serial (phase 6, optional) |

Set `RISCV_GCC` or `GHIDRA_INSTALL_DIR` to override default paths.

---

## Linker script (`hello.ld`)

All fixtures share a single linker script:

| Section | Address | Notes |
|---------|---------|-------|
| `.text` | `0x40000000` | Flash IROM — execute-in-place |
| `.data` | `0x4FF00000` | HP-SRAM (IRAM on ESP32-P4) |
| `g_result` | `0x4FF00000` | First 4 bytes of `.data`; read by flash verifier |

The `g_result` address is stable across all fixtures, so a serial read script
can poll that one address regardless of which firmware is flashed.

---

## Adding a new fixture

1. Create `test/roundtrip/test_<name>.c` with `volatile uint32_t g_result = 0;`
   at global scope and a `void _start(void)` that sets it and loops.
2. Compute the expected `g_result` with a host-native verifier:
   ```bash
   gcc -O2 -o /tmp/verify test/roundtrip/test_<name>.c && /tmp/verify
   ```
   *(Strip the bare-metal parts — `_start` / `while(1)` — for the host build.)*
3. Add the fixture to `run_roundtrip.sh` (`EXPECTED_RESULT` map + `TESTS` array).
4. Add a `CHECK()` call to `ci_smoke.sh` Phase 4 native verifier heredoc.
5. Consider adding a `PatternDef` to `DetectSemanticPatterns.java` if the fixture
   exercises an algorithm not yet covered.
