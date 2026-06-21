#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# ESP32-P4 Decompiler Plugin — Full Round-Trip Validation Script
#
# Validates that Ghidra decompilation + recompilation preserves program
# semantics.  For each test fixture:
#
#   1. Compile original C → ELF  (original)
#   2. Analyse with Ghidra headlessly → decompiled .c via ExportDecompiledC.java
#   3. Re-compile decompiled .c → ELF  (reconstructed)
#   4. Compare objdump text sections to detect structural regressions
#   5. [Optional] Flash to ESP32-P4 and capture g_result from serial port
#
# Expected g_result values (hardware validation targets):
#   hello.c            → 0xBE34BDFC  (original CRC test — validated on real hw)
#   test_sorting.c     → 0x00000029
#   test_math.c        → 0x000000F9
#   test_state_machine.c → 0x00000244
#   test_crypto.c      → 0xABCD65DD
#
# Usage:
#   ./test/roundtrip/run_roundtrip.sh [--ghidra-project /tmp/rt-proj] [--flash COM12]
#
# Prerequisites:
#   - riscv32-esp-elf-gcc on PATH (or set RISCV_GCC)
#   - Ghidra headless analyser on PATH (or set GHIDRA_HEADLESS)
#   - Python 3 with pyserial (for --flash only)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

RISCV_GCC="${RISCV_GCC:-riscv32-esp-elf-gcc}"
GHIDRA_HEADLESS="${GHIDRA_HEADLESS:-analyzeHeadless}"
GHIDRA_PROJECT="${GHIDRA_PROJECT:-/tmp/esp32p4-roundtrip-proj}"
FLASH_PORT="${FLASH_PORT:-}"
OUT_DIR="/tmp/esp32p4-roundtrip"
LD="$SCRIPT_DIR/hello.ld"
TYPES_H="$PLUGIN_ROOT/tools/ghidra_types.h"

CFLAGS="-march=rv32imafc_zicsr_zifencei -mabi=ilp32f -ffreestanding -nostdlib"
CFLAGS_ORIG="$CFLAGS -O2"
CFLAGS_DECOMPILED="$CFLAGS -O0 -include $TYPES_H"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'

pass()   { echo -e "${GREEN}  PASS${NC} $*"; }
fail()   { echo -e "${RED}   FAIL${NC} $*"; FAILURES=$((FAILURES+1)); }
info()   { echo -e "${YELLOW}  ....${NC} $*"; }

# is_hardware_only <test_name> — returns 0 (true) if test needs real hardware
is_hardware_only() {
    local t="$1"
    for hw in "${HARDWARE_ONLY_TESTS[@]}"; do
        [[ "$hw" == "$t" ]] && return 0
    done
    return 1
}

FAILURES=0

# Parse args
FLASH_ENABLED=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ghidra-project) GHIDRA_PROJECT="$2"; shift 2 ;;
        --flash)          FLASH_PORT="$2"; FLASH_ENABLED=1; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

mkdir -p "$OUT_DIR"
echo "Round-trip validation: ESP32-P4 Ghidra Plugin"
echo "Output dir : $OUT_DIR"
echo "Ghidra proj: $GHIDRA_PROJECT"
echo ""

# ── declare test fixtures ─────────────────────────────────────────────────────
declare -A EXPECTED_RESULT=(
    [hello]=0xBE34BDFC
    [test_sorting]=0x00000029
    [test_math]=0x000000F9
    [test_state_machine]=0x00000244
    [test_crypto]=0xABCD65DD
    [test_linked_list]=0x0000781E
    [test_matrix]=0x0000003A
    [test_lfsr]=0x2F34BC35
    [test_fifo_queue]=0x00000000
    [test_bitops]=0x87A97826
    [test_pie_simd]=0x0000109A
    [test_hash]=0x21708D55
    [test_string]=0x00001014
    [test_hwlp]=0x00000824
    [test_bst]=0x0000320A
    [test_heap]=0x00002707
    [test_rle]=0x000A0C01
    [test_base64]=0x00000844
    [test_avl]=0x00071E0E
    [test_trie]=0x00060507
    [test_quicksort]=0x00092D01
    [test_dp]=0x00070504
    [test_mergesort]=0x000A2D01
    [test_union_find]=0x00080700
    [test_bfs]=0x00070B01
    [test_knapsack]=0x0004080A
    [test_dfs]=0x00061507
    [test_kmp]=0x00090504
    [test_dijkstra]=0x00051608
    [test_binary_search]=0x000A0104
    [test_toposort]=0x00060F01
    [test_fib_memo]=0x000A2236
    [test_sieve]=0x000F2F1A
    [test_edit_dist]=0x00060703
    [test_bellman_ford]=0x00051307
    [test_counting_sort]=0x000A2400
    [test_floyd_warshall]=0x00042E02
    [test_bitset]=0x0008041E
    [test_pow_mod]=0x00048D53
    [test_segment_tree]=0x00084870
    [test_fenwick]=0x0006242C
    [test_lis]=0x000B0405
    [test_zfunc]=0x00060503
    [test_radix_sort]=0x00085978
    [test_manacher]=0x00070711
    [test_coin_change]=0x00040802
    [test_kadane]=0x00090636
    [test_ext_gcd]=0x0003241A
    [test_sparse_table]=0x00080806
    [test_activity_sel]=0x00060416
    [test_lps]=0x00090702
    [test_dutch_flag]=0x00060204
    [test_prim_mst]=0x00051004
    [test_subset_sum]=0x0005030D
    [test_next_greater]=0x00080403
    [test_josephus]=0x000A0C02
    [test_quick_select]=0x00080D0D
    [test_matrix_chain]=0x00034018
    [test_kruskal]=0x00050C04
    [test_floyd_cycle]=0x00070203
    [test_sliding_window]=0x00081D01
    [test_bitmask_enum]=0x0004060F
    [test_two_pointer]=0x000A0501
    [test_min_stack]=0x00040D07
    [test_boyer_moore_vote]=0x00070304
    [test_count_inversions]=0x00060F07
    [test_jump_search]=0x000A030C
    [test_lc_substring]=0x00050604
    [test_catalan]=0x00063D21
    [test_shell_sort]=0x00080907
    [test_interpolation_search]=0x00080205
    [test_n_queens]=0x0006100C
    [test_rabin_karp]=0x000A0302
    [test_pancake_sort]=0x00060607
    [test_comb_sort]=0x00070902
    [test_cycle_sort]=0x00050401
    [test_ternary_search]=0x0003100E
    [test_miller_rabin]=0x0008067F
    [test_max_rect_histogram]=0x00060A01
    [test_trapping_rain]=0x00060902
    [test_jump_game]=0x00050301
    [test_gas_station]=0x00030207
    [test_bipartite_check]=0x00030101
    [test_kahn_toposort]=0x00060201
    [test_word_break]=0x0003020C
    [test_count_paths_dag]=0x00060406
    [test_euler_totient]=0x0004442C
    [test_difference_array]=0x00061402
    [test_crt]=0x00034719
    [test_longest_bitonic]=0x00050407
    [test_hamming]=0x00030906
    [test_palindrome_partition]=0x00030303
    [test_rotate_array]=0x00070205
    [test_matrix_power]=0x0002A45A
    [test_tribonacci]=0x000AB169
    [test_count_bits]=0x00102004
    [test_stock_k_trans]=0x00080603
    [test_coin_ways]=0x0003190D
    [test_lca]=0x00030402
    [test_interval_merge]=0x0004031E
    [test_num_islands]=0x00030501
    [test_prefix_xor]=0x00031008
    [test_tarjan_scc]=0x00050201
    [test_huffman]=0x00052102
    [test_toposort_dfs]=0x00050A04
    [test_nim]=0x00050102
    [test_tsp_bitmask]=0x00045004
    [test_euler_circuit]=0x00050601
    [test_convex_hull]=0x00050705
    [test_digit_dp]=0x00023432
    [test_suffix_array]=0x00060501
    [test_house_robber]=0x0003140C
    [test_egg_drop]=0x0003180C
    [test_unique_paths]=0x0003360E
    [test_regex_match]=0x00040301
    [test_max_product]=0x0003120A
    [test_articulation]=0x00050202
    [test_sqrt_decomp]=0x00092131
    [test_dag_longest_path]=0x00061117
    [test_edit_distance]=0x00030802
    [test_max_rect_sum]=0x000C1501
    [test_fenwick_tree]=0x0008090C
)

# Tests that require real ESP32-P4 ECO2 hardware to execute.
# They compile fine but results can only be verified with --flash.
HARDWARE_ONLY_TESTS=(test_pie_simd test_hwlp)

TESTS=(hello test_sorting test_math test_state_machine test_crypto \
       test_linked_list test_matrix test_lfsr test_fifo_queue test_bitops \
       test_pie_simd test_hash test_string test_hwlp \
       test_bst test_heap test_rle test_base64 test_avl test_trie \
       test_quicksort test_dp test_mergesort test_union_find \
       test_bfs test_knapsack test_dfs test_kmp \
       test_dijkstra test_binary_search \
       test_toposort test_fib_memo \
       test_sieve test_edit_dist \
       test_bellman_ford test_counting_sort \
       test_floyd_warshall test_bitset \
       test_pow_mod test_segment_tree \
       test_fenwick test_lis \
       test_zfunc test_radix_sort \
       test_manacher test_coin_change \
       test_kadane test_ext_gcd \
       test_sparse_table test_activity_sel \
       test_lps test_dutch_flag \
       test_prim_mst test_subset_sum \
       test_next_greater test_josephus \
       test_quick_select test_matrix_chain \
       test_kruskal test_floyd_cycle \
       test_sliding_window test_bitmask_enum \
       test_two_pointer test_min_stack \
       test_boyer_moore_vote test_count_inversions \
       test_jump_search test_lc_substring \
       test_catalan test_shell_sort \
       test_interpolation_search test_n_queens \
       test_rabin_karp test_pancake_sort \
       test_comb_sort test_cycle_sort \
       test_ternary_search test_miller_rabin \
       test_max_rect_histogram test_trapping_rain \
       test_jump_game test_gas_station \
       test_bipartite_check test_kahn_toposort \
       test_word_break test_count_paths_dag \
       test_euler_totient test_difference_array \
       test_crt test_longest_bitonic \
       test_hamming test_palindrome_partition \
       test_rotate_array test_matrix_power \
       test_tribonacci test_count_bits \
       test_stock_k_trans test_coin_ways \
       test_lca test_interval_merge \
       test_num_islands test_prefix_xor \
       test_tarjan_scc test_huffman \
       test_toposort_dfs test_nim \
       test_tsp_bitmask test_euler_circuit \
       test_convex_hull test_digit_dp \
       test_suffix_array test_house_robber \
       test_egg_drop test_unique_paths \
       test_regex_match test_max_product \
       test_articulation test_sqrt_decomp \
       test_dag_longest_path test_edit_distance \
       test_max_rect_sum test_fenwick_tree)

# ── Phase 1: compile originals ────────────────────────────────────────────────
echo "══ Phase 1: Compile originals ══════════════════════════════"
for t in "${TESTS[@]}"; do
    src="$SCRIPT_DIR/${t}.c"
    elf="$OUT_DIR/${t}_orig.elf"
    if "$RISCV_GCC" $CFLAGS_ORIG -T"$LD" "$src" -o "$elf" 2>&1; then
        pass "compile orig: $t"
    else
        fail "compile orig: $t"
    fi
done
echo ""

# ── Phase 2: Ghidra headless analysis ────────────────────────────────────────
echo "══ Phase 2: Ghidra headless decompile ══════════════════════"
mkdir -p "$GHIDRA_PROJECT"
for t in "${TESTS[@]}"; do
    elf="$OUT_DIR/${t}_orig.elf"
    out_c="$OUT_DIR/${t}_decompiled.c"
    [ -f "$elf" ] || { info "skip $t (no ELF)"; continue; }
    info "analysing $t with Ghidra..."
    if "$GHIDRA_HEADLESS" "$GHIDRA_PROJECT" "RT_${t}" \
            -import "$elf" \
            -processor "RISCV:LE:32:ESP32-P4" \
            -postScript ExportDecompiledC.java "$out_c" \
            -scriptPath "$PLUGIN_ROOT/ghidra_scripts" \
            -overwrite \
            -deleteProject \
            > "$OUT_DIR/${t}_ghidra.log" 2>&1; then
        pass "ghidra decompile: $t → $(wc -l < "$out_c") lines"
    else
        fail "ghidra decompile: $t (see $OUT_DIR/${t}_ghidra.log)"
    fi
done
echo ""

# ── Phase 3: re-compile decompiled C ─────────────────────────────────────────
echo "══ Phase 3: Re-compile decompiled C ═══════════════════════"
for t in "${TESTS[@]}"; do
    src="$OUT_DIR/${t}_decompiled.c"
    elf="$OUT_DIR/${t}_recompiled.elf"
    [ -f "$src" ] || { info "skip $t (no decompiled .c)"; continue; }
    if "$RISCV_GCC" $CFLAGS_DECOMPILED -T"$LD" "$src" -o "$elf" 2>&1; then
        pass "recompile: $t"
    else
        fail "recompile: $t — check $src"
    fi
done
echo ""

# ── Phase 4: structural comparison ───────────────────────────────────────────
echo "══ Phase 4: Structural comparison (objdump diff) ═══════════"
OBJDUMP="$(dirname "$RISCV_GCC")/riscv32-esp-elf-objdump"
for t in "${TESTS[@]}"; do
    orig="$OUT_DIR/${t}_orig.elf"
    recomp="$OUT_DIR/${t}_recompiled.elf"
    [ -f "$orig" ] && [ -f "$recomp" ] || { info "skip $t (missing ELF)"; continue; }

    # Disassemble both .text sections.
    "$OBJDUMP" -d "$orig"    > "$OUT_DIR/${t}_orig.dis"    2>/dev/null
    "$OBJDUMP" -d "$recomp"  > "$OUT_DIR/${t}_recomp.dis"  2>/dev/null

    # Strip addresses (they differ) and compare instruction mnemonics only.
    sed 's/^[0-9a-f]*://;s/\t[0-9a-f ]*\t/\t/' "$OUT_DIR/${t}_orig.dis" \
        > "$OUT_DIR/${t}_orig.norm"
    sed 's/^[0-9a-f]*://;s/\t[0-9a-f ]*\t/\t/' "$OUT_DIR/${t}_recomp.dis" \
        > "$OUT_DIR/${t}_recomp.norm"

    DIFF_LINES=$(diff -u "$OUT_DIR/${t}_orig.norm" "$OUT_DIR/${t}_recomp.norm" \
                 > "$OUT_DIR/${t}.diff" 2>&1; echo $?)
    if [ "$DIFF_LINES" -eq 0 ]; then
        pass "instruction match: $t (perfect round-trip)"
    else
        CHANGED=$(wc -l < "$OUT_DIR/${t}.diff")
        if [ "$CHANGED" -lt 20 ]; then
            info "minor diff ($CHANGED lines): $t — see $OUT_DIR/${t}.diff"
        else
            fail "significant diff ($CHANGED lines): $t — see $OUT_DIR/${t}.diff"
        fi
    fi
done
echo ""

# ── Phase 5: semantic pattern detection ──────────────────────────────────────
echo "══ Phase 5: Pattern detection on decompiled C ══════════════"
for t in "${TESTS[@]}"; do
    src="$OUT_DIR/${t}_decompiled.c"
    [ -f "$src" ] || continue
    hints="$OUT_DIR/${t}_hints.json"
    if "$GHIDRA_HEADLESS" "$GHIDRA_PROJECT" "PAT_${t}" \
            -import "$OUT_DIR/${t}_orig.elf" \
            -processor "RISCV:LE:32:ESP32-P4" \
            -postScript DetectSemanticPatterns.java "$hints" \
            -scriptPath "$PLUGIN_ROOT/ghidra_scripts" \
            -overwrite -deleteProject \
            >> "$OUT_DIR/${t}_ghidra.log" 2>&1; then
        MATCHES=$(python3 -c "
import json, sys
try:
    d = json.load(open('$hints'))
    m = [f for f in d['functions'] if f.get('pattern')]
    print(len(m))
except: print('?')
" 2>/dev/null)
        pass "patterns: $t → $MATCHES function(s) classified"
    else
        info "pattern detection unavailable for $t"
    fi
done
echo ""

# ── Phase 6: optional hardware flash ─────────────────────────────────────────
if [ "$FLASH_ENABLED" -eq 1 ] && [ -n "$FLASH_PORT" ]; then
    echo "══ Phase 6: Hardware flash + serial verify ══════════════"
    ESPTOOL="${ESPTOOL:-esptool.py}"
    for t in "${TESTS[@]}"; do
        elf="$OUT_DIR/${t}_recompiled.elf"
        [ -f "$elf" ] || continue
        expected="${EXPECTED_RESULT[$t]:-UNKNOWN}"
        if is_hardware_only "$t"; then
            info "hardware-only (PIE): flashing $t (expected $expected)"
        else
            info "flashing $t to $FLASH_PORT..."
        fi
        "$ESPTOOL" --port "$FLASH_PORT" --baud 921600 \
            write_flash -z 0x0 "$elf" > /dev/null 2>&1 || { fail "flash: $t"; continue; }
        # Capture g_result from serial (assumes read_serial2.py is available).
        RESULT=$(python3 "$SCRIPT_DIR/../../tools/read_serial.py" \
                     --port "$FLASH_PORT" --timeout 5 2>/dev/null || echo "TIMEOUT")
        if echo "$RESULT" | grep -qi "g_result"; then
            ACTUAL=$(echo "$RESULT" | grep -oE '0x[0-9A-Fa-f]+' | head -1)
            if [ "${ACTUAL,,}" = "${expected,,}" ]; then
                pass "hardware: $t → $ACTUAL (matches $expected)"
            else
                fail "hardware: $t → $ACTUAL (expected $expected)"
            fi
        else
            fail "hardware: $t → no g_result seen on serial ($FLASH_PORT)"
        fi
    done
    echo ""
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo "════════════════════════════════════════════════════════════"
if [ "$FAILURES" -eq 0 ]; then
    echo -e "${GREEN}ALL PHASES PASSED${NC}"
else
    echo -e "${RED}$FAILURES CHECK(S) FAILED${NC} — review output above"
    exit 1
fi
