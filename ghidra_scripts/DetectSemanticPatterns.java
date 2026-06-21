/* SPDX-License-Identifier: Apache-2.0
 *
 * ESP32-P4 Ghidra Plugin
 * Copyright 2026 Alexander Salas Bastidas <ajsb85@firechip.dev>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Pattern-based semantic reconstruction engine.
//
// Decompiles every function and applies a library of heuristic pattern
// matchers to infer a semantic category and a suggested name prefix.
// Results are written to a JSON file (semantic_hints.json) that can be used
// by other tools to rename functions or annotate the Ghidra database.
//
// ── Pattern catalogue ────────────────────────────────────────────────────────
//
//  The patterns are applied in PRIORITY order. The first match wins.
//
//  ID               Heuristic                            Example name
//  ────────────── ──────────────────────────────────── ──────────────────────
//  crc_poly        XOR with known CRC polynomial        crc32_step
//  crc_loop        8-iteration bit loop + conditional   crc_byte_step
//  checksum_xor    loop accumulating ^ (XOR) result     checksum_xor
//  checksum_add    loop accumulating + result           checksum_add
//  popcount        Hamming-weight bit magic              popcount
//  bit_reverse     Multiple AND+shift with 0xAAAA/0x55  bit_reverse
//  isqrt           Newton–Raphson sqrt idiom             isqrt
//  ilog2           Right-shift until zero loop           ilog2
//  memset_zero     Assign 0 to consecutive addresses     memset_like
//  memcpy_loop     Loop copying with two pointer vars    memcpy_like
//  xor_cipher      Loop applying ^ from key variable     xor_cipher
//  sort_bubble     Nested loops with swap                bubble_sort_like
//  sort_insert     Shift-right inner loop + assignment   insert_sort_like
//  state_machine   switch with 3+ cases + state var      state_machine
//  parser_packet   0xAA/0x55 sync byte detection        packet_parser
//  ring_buffer     % modulo on index                    ring_buf_op
//  fibonacci       Self-recursive call                  fibonacci_like
//  init_struct     Multiple field zero-assignments       init_struct
//  uart_write      Write to UART FIFO address           uart_write
//  gpio_toggle     Read-modify-write on GPIO reg        gpio_toggle
//  linked_list_traverse  ->next pointer-following while   linked_list_op
//  matrix_multiply Triple nested for + [i][j] += a*b   matrix_mul
//  lfsr_galois     >>1 + polynomial XOR + LSB test      lfsr_galois_step
//  lfsr_fibonacci  >>1 + multiple tap XOR + <<31 inject lfsr_fib_step
//  gray_code       XOR-decode while(mask) loop          gray_code_op
//  gcd_euclid      while(b) + modulo + swap pattern     gcd_euclid
//  sat_arith       0xFFFFFFFF + overflow check           sat_add_or_sub
//  endian_swap     0xFF000000 byte masks + <<24 / >>24  bswap
//  pie_vld_vst     q? = *ptr / *ptr = q? pcode output   pie_vld_vst
//  pie_zero_q      q? = 0 (zero.q real pcode output)    pie_zero_q
//  pie_bitwise     q? &|^ + andq/orq/xorq pcodeop name  pie_bitwise_q
//  pie_simd_loop   Q register + for loop + ld/st        pie_simd_loop
//  hwlp_setup      HWLP0_COUNT= or esp_lp_setup() call  hwlp_loop
//  hwlp_counted_loop HWLP COUNT+START+END writes present hwlp_counted
//  bst_insert        .left/.right + recursive insert call bst_insert
//  bst_inorder       .left/.right + inorder name in body  bst_traverse
//  min_heap          2*i+1/2 child-index + sift idiom     heap_op
//  heap_extract      extract_min + sift_down call          heap_extract
//  rle_encode        run counter + emit count to output    rle_encode
//  rle_decode        expand (count,value) pairs into buf   rle_decode
//  base64_encode     6-bit mask + shift extraction + table base64_enc
//  base64_table      full base64 alphabet in string literal base64_op
//
// ── Output format ────────────────────────────────────────────────────────────
//
//  {
//    "program": "firmware.elf",
//    "language": "RISCV:LE:32:ESP32-P4",
//    "functions": [
//      {
//        "address": "0x4FF00100",
//        "ghidra_name": "FUN_4ff00100",
//        "pattern": "crc_poly",
//        "suggested_name": "crc32_step_4ff00100",
//        "confidence": "high",
//        "evidence": ["XOR with 0x04C11DB7", "8-iteration bit loop"]
//      },
//      ...
//    ]
//  }
//
// ── Usage ────────────────────────────────────────────────────────────────────
//
//  GUI:     Script Manager → ESP32-P4 → Detect Semantic Patterns
//  Headless:
//    analyzeHeadless /project Prog \
//      -postScript DetectSemanticPatterns.java /out/semantic_hints.json
//
// @category ESP32-P4
// @menupath Analysis.ESP32-P4.Detect Semantic Patterns

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

import java.io.*;
import java.util.*;
import java.util.regex.*;
import java.util.stream.*;

public class DetectSemanticPatterns extends GhidraScript {

    private static final int DECOMPILE_TIMEOUT_SECS = 30;

    // ── Pattern definitions ───────────────────────────────────────────────────
    // Each entry: {id, suggested_prefix, confidence, evidence_patterns[]}
    // Evidence patterns are matched against the full decompiled function text.
    // ALL evidence patterns must match for the pattern to fire.
    private static final PatternDef[] PATTERNS = {

        new PatternDef("crc_poly", "crc32_step", "high",
            "0x04[Cc]11[Dd][Bb]7",          // CRC-32 polynomial
            "\\^\\s*0x04[Cc]11"             // XOR with it
        ),
        new PatternDef("crc_poly_alt", "crc_step", "high",
            "0x[Ee][Dd][Bb]88320",           // CRC-32C reversed polynomial
            "\\^\\s*0x[Ee][Dd][Bb]"
        ),
        new PatternDef("crc_loop", "crc_byte_step", "medium",
            "for\\s*\\(.*[iI]\\s*[<>]=?\\s*8",    // exactly 8 iterations
            "0x80000000",                           // MSB test
            "<<\\s*1"                               // left shift 1
        ),
        new PatternDef("checksum_xor", "checksum_xor", "medium",
            "for\\s*\\(",                    // has a loop
            "\\^=",                          // XOR-accumulate
            "return\\s+\\w"                  // returns a value
        ),
        new PatternDef("checksum_add", "checksum_add", "medium",
            "for\\s*\\(",
            "\\+=",                          // ADD-accumulate (not XOR)
            "return\\s+\\w"
        ),
        new PatternDef("popcount", "popcount", "high",
            "0x55555555",                    // Hamming weight magic constant
            "0x33333333",
            "0x0[Ff]0[Ff]0[Ff]0[Ff]"
        ),
        new PatternDef("bit_reverse", "bit_reverse", "high",
            "0x[Aa][Aa][Aa][Aa][Aa][Aa][Aa][Aa]",   // 0xAAAAAAAA
            "0x55555555",
            ">>\\s*1"
        ),
        new PatternDef("isqrt", "isqrt", "high",
            ">>\\s*1",                       // right-shift (Newton step)
            "while\\s*\\(.*<",               // convergence test
            "/"                              // integer divide
        ),
        new PatternDef("ilog2", "ilog2", "medium",
            "while\\s*\\(.*>\\s*[01]",       // shift until <=1
            ">>=\\s*1"                       // right shift count
        ),
        new PatternDef("memset_zero", "memset_like", "medium",
            "for\\s*\\(",
            "=\\s*0\\s*;",                   // assign zero in loop
            "\\[.*\\]\\s*="                  // array subscript write
        ),
        new PatternDef("memcpy_loop", "memcpy_like", "medium",
            "for\\s*\\(",
            "\\[.*\\]\\s*=\\s*.*\\[",        // arr_a[i] = arr_b[i]
            "\\+\\+"                         // increment index
        ),
        new PatternDef("xor_cipher", "xor_cipher", "medium",
            "for\\s*\\(",
            "\\^=",                          // XOR in-place
            "(?:key|Key|KEY|cipher|Cipher)"  // key-like variable name
        ),
        new PatternDef("sort_bubble", "bubble_sort_like", "high",
            "for\\s*\\(.*for\\s*\\(",        // nested for loops
            "if\\s*\\(.*>",                  // comparison
            "=.*[;,]\\s*\\n.*=.*[;,]\\s*\\n.*=\\s*" // three-line swap
        ),
        new PatternDef("sort_insert", "insert_sort_like", "medium",
            "for\\s*\\(",
            "while\\s*\\(",
            "\\[.*[+-]1\\s*\\]\\s*="         // shift element
        ),
        new PatternDef("state_machine", "state_machine", "high",
            "switch\\s*\\(",
            "case\\s+\\d+",                  // at least one numeric case
            "case\\s+\\d+.*\\n.*case\\s+\\d+" // at least two cases
        ),
        new PatternDef("parser_packet", "packet_parser", "high",
            "0x[Aa][Aa]",                    // sync byte 0xAA
            "switch\\s*\\(",
            "state"                          // state variable
        ),
        new PatternDef("ring_buffer", "ring_buf_op", "medium",
            "%\\s*\\w",                      // modulo operation
            "(?:head|tail|buf|ring|queue)",  // buffer naming
            "\\+\\+"                         // increment
        ),
        new PatternDef("fibonacci", "fibonacci_like", "high",
            "return\\s+fibonacci|return\\s+fib", // direct recursion (named)
            ""                               // second pattern intentionally empty — override below
        ),
        new PatternDef("init_struct", "init_struct", "medium",
            "\\.\\w+\\s*=\\s*0",             // struct.field = 0
            "\\.\\w+\\s*=\\s*0",
            "\\.\\w+\\s*=\\s*0"             // at least 3 zero-inits
        ),
        new PatternDef("uart_write", "uart_write", "high",
            "0x400[89][0-9A-Fa-f]{4}",       // UART register address range
            "(?:FIFO|fifo|tx_buf|write|WRITE)"
        ),
        new PatternDef("gpio_toggle", "gpio_toggle", "medium",
            "0x400[Aa][0-9A-Fa-f]{4}",       // GPIO register range
            "\\|=|&=|\\^=",                  // bitwise modify
            "(?:GPIO|gpio|pin|PIN)"
        ),

        // ── New patterns (Sprint 15) ──────────────────────────────────────
        new PatternDef("linked_list_traverse", "linked_list_op", "high",
            "->next",                         // pointer-following
            "while\\s*\\(.*!?=?\\s*0",        // while (cur != NULL) or while (p)
            "->\\w"                           // struct member access via pointer
        ),
        new PatternDef("matrix_multiply", "matrix_mul", "high",
            "for\\s*\\(.*for\\s*\\(.*for\\s*\\(",  // triple nested for
            "\\+=.*\\*",                           // accumulate: += a * b
            "\\[\\w+\\]\\[\\w+\\]"                 // 2D array indexing
        ),
        new PatternDef("lfsr_galois", "lfsr_galois_step", "high",
            ">>\\s*1",                        // right shift by 1
            "0x80200003|0xB8|0xD008|0xB400",  // common LFSR polynomials
            "if\\s*\\(.*&\\s*1"               // LSB test
        ),
        new PatternDef("lfsr_fibonacci", "lfsr_fib_step", "high",
            ">>\\s*1",                        // right shift by 1
            ">>\\s*\\d+.*\\^",                // multiple taps XOR'd
            "<<\\s*31"                        // inject feedback bit at MSB
        ),
        new PatternDef("gray_code", "gray_code_op", "medium",
            ">>\\s*1",
            "\\^=.*>>=",                      // decode loop: g ^= mask; mask >>= 1
            "while\\s*\\(.*mask\\|m\\b"       // while(mask) pattern
        ),
        new PatternDef("gcd_euclid", "gcd_euclid", "high",
            "while\\s*\\(",                   // while loop
            "%",                              // modulo remainder
            "=.*[ab].*%;\\s*\\n.*=\\s*[ab]"  // swap pattern: t=b; b=a%b; a=t
        ),
        new PatternDef("sat_arith", "sat_add_or_sub", "medium",
            "0xffffffff|0xFFFFFFFF",          // saturation ceiling
            "if\\s*\\(.*<",                   // overflow check
            "return\\s+0x[Ff][Ff]"            // return saturated value
        ),
        new PatternDef("endian_swap", "bswap", "high",
            "0xFF000000",                     // byte-swap masks
            "0x00FF0000",
            "<<\\s*24|>>\\s*24"              // extreme byte shift
        ),

        // ── PIE (xespv2p2) SIMD patterns ─────────────────────────────────────
        // Detected after Ghidra decompiles firmware with real Q-register pcode.
        // The decompiler emits pseudo-C using q0-q7 as 16-byte lvalues.
        new PatternDef("pie_vld_vst", "pie_vld_vst", "high",
            "q[0-7]\\s*=\\s*\\*",            // q? = *ptr (128-bit load pcode output)
            "\\*.*=\\s*q[0-7]"               // *ptr = q? (128-bit store pcode output)
        ),
        new PatternDef("pie_zero_q", "pie_zero_q", "high",
            "q[0-7]\\s*=\\s*0",              // q? = 0 (zero.q pcode output)
            "q[0-7]"                          // at least one Q register reference
        ),
        new PatternDef("pie_bitwise", "pie_bitwise_q", "medium",
            "q[0-7]\\s*[&|^]",               // q? & / q? | / q? ^
            "q[0-7]",                         // at least one Q register reference
            "esp_(?:andq|orq|xorq|notq)"     // pcodeop name in decompiled output
        ),
        new PatternDef("pie_simd_loop", "pie_simd_loop", "medium",
            "q[0-7]",                         // Q register use
            "for\\s*\\(",                     // vectorised loop
            "\\*\\s*q[0-7]|q[0-7]\\s*=\\s*\\*" // vector ld/st in loop body
        ),
        new PatternDef("djb2_hash", "hash_djb2", "high",
            "5381",                           // DJB2 magic seed
            "<<\\s*5.*hash\\s*\\^",           // (hash<<5)+hash ^ byte
            "\\^=.*[Bb]yte|hash.*\\^.*s\\[i\\]"
        ),
        new PatternDef("fnv1a_hash", "hash_fnv1a", "high",
            "2166136261|0x811c9dc5",          // FNV offset basis
            "16777619|0x1000193",             // FNV prime
            "\\^=.*\\*="                      // XOR then multiply pattern
        ),
        new PatternDef("poly_hash", "poly_hash_eval", "medium",
            "hash\\s*\\*.*base\\s*\\+|\\*=.*base",
            "for\\s*\\(",
            "hash.*\\+.*s\\[i\\]|\\+.*byte"
        ),
        new PatternDef("strlen_loop", "strlen_op", "high",
            "!=\\s*0\\s*\\)|!=\\s*'\\\\0'|\\*s\\+\\+",
            "\\+\\+.*len|len\\+\\+|n\\+\\+",
            "while\\s*\\("
        ),
        new PatternDef("memcmp_pattern", "memcmp_op", "high",
            "a\\[i\\]\\s*!=\\s*b\\[i\\]|\\*a\\s*!=\\s*\\*b",
            "return.*i\\s*\\+\\s*1|return.*pos",
            "for\\s*\\(.*<.*n\\b"
        ),
        new PatternDef("substring_search", "string_search", "medium",
            "for\\s*\\(.*<=.*hlen|for\\s*\\(.*<.*hlen",
            "for\\s*\\(.*<.*nlen",
            "return.*[ij]\\b|0xFFFFFFFF"
        ),

        // ── xesploop hardware loop patterns ───────────────────────────────────
        // After callotherfixup replaces the opaque pcodeop, the decompiler emits
        // HWLP0_COUNT / HWLP0_END writes that are visible in the decompiled C.
        // Without the fixup, the decompiled output shows esp_lp_setup(...) calls.
        new PatternDef("hwlp_setup", "hwlp_loop", "high",
            "HWLP[01]_COUNT\\s*=|esp_lp_setup\\s*\\(",   // count assignment (fixup or raw)
            "HWLP[01]_(?:START|END)\\s*=|esp_lp_setup"   // setup visible in any form
        ),
        new PatternDef("hwlp_counted_loop", "hwlp_counted", "medium",
            "HWLP[01]_COUNT\\s*=",                        // count register write
            "HWLP[01]_END\\s*=",                          // end address write (callotherfixup)
            "HWLP[01]_START\\s*="                         // start address write
        ),

        // ── Data-structure patterns ───────────────────────────────────────────
        // Detected from decompiled C produced by Ghidra after analysing BST and
        // heap fixtures.  Characteristic idioms survive decompilation faithfully.
        new PatternDef("bst_insert", "bst_insert", "high",
            "\\.left|->left",                             // left child field dereference
            "\\.right|->right",                           // right child field dereference
            "bst_insert|binsert|insert.*left.*right"      // recursive insert call or pattern
        ),
        new PatternDef("bst_inorder", "bst_traverse", "medium",
            "\\.left|->left",                             // left child
            "\\.right|->right",                           // right child
            "inorder|traverse|in_order"                   // traversal function name
        ),
        new PatternDef("min_heap", "heap_op", "high",
            "2\\s*\\*\\s*[ij]\\s*\\+\\s*[12]",           // 2*i+1 or 2*i+2 child index
            "[ij]\\s*-\\s*1\\s*\\)\\s*/\\s*2|\\(i-1\\)/2",  // (i-1)/2 parent index
            "sift_down|sift_up|heap_arr|heap_sz"          // heap maintenance idiom
        ),
        new PatternDef("heap_extract", "heap_extract", "high",
            "extract_min|heap_extract|sift_down",         // extract operation
            "2\\s*\\*\\s*[ij]\\s*\\+",                   // child index formula
            "heap_arr|heap_sz|heap\\["                    // array-based heap
        ),

        // ── Codec patterns ────────────────────────────────────────────────────
        new PatternDef("rle_encode", "rle_encode", "high",
            "count\\+\\+|count\\s*=\\s*1",               // run counter increment
            "out\\[.*\\]\\s*=.*count|enc\\[.*count",     // emit run count to output
            "while\\s*\\(.*==.*count|for.*count.*<"      // run-scanning loop
        ),
        new PatternDef("rle_decode", "rle_decode", "high",
            "count\\s*=\\s*enc\\[|count\\s*=\\s*rle",    // decode count from buffer
            "for\\s*\\(.*count|while.*count--",           // repeat-value expansion loop
            "out\\[.*\\]\\s*=.*val|dec\\[.*val"          // value written to output
        ),
        new PatternDef("base64_encode", "base64_enc", "high",
            "0x3[Ff]|&\\s*63",                            // 6-bit mask (0x3F or &63)
            ">>\\s*2|>>\\s*4|>>\\s*6",                   // 6-bit group extraction shifts
            "B64_TABLE|b64_table|b64\\[|base64.*table"   // table lookup
        ),
        new PatternDef("base64_table", "base64_op", "medium",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",                 // uppercase base64 alphabet
            "abcdefghijklmnopqrstuvwxyz",                 // lowercase base64 alphabet
            "0123456789\\+/|0123456789\\+\\-"            // digit + symbol segment
        ),

        // ── AVL tree (51, 52) ────────────────────────────────────────────────
        new PatternDef("avl_rotate", "avl_rotate", "high",
            "\\.right\\s*=.*\\.left|\\.left\\s*=.*\\.right", // child pointer swap
            "\\.height\\s*=.*\\?.*:\\s*.*\\+\\s*1",          // height = max(hl,hr)+1
            "rotate_right|rotate_left|avl_r[lr]"             // rotation function names
        ),
        new PatternDef("avl_balance", "avl_balance", "high",
            "bal\\s*>\\s*1|bal\\s*<\\s*-1|balance.*>.*1",    // balance-factor threshold
            "LL|RR|LR|RL|left.*heavy|right.*heavy",           // rotation-case labels
            "height.*left.*-.*height.*right|avl_balance"      // balance-factor formula
        ),

        // ── Prefix trie (53, 54) ──────────────────────────────────────────────
        new PatternDef("trie_insert", "trie_insert", "high",
            "\\.children\\[|children\\s*\\[.*-\\s*'a'",      // children array indexed by char
            "is_end\\s*=\\s*1|tpool.*is_end|trie.*end",       // mark end-of-word flag
            "trie_alloc|tnode_alloc|alloc.*trie"              // node allocator call
        ),
        new PatternDef("trie_search", "trie_search", "high",
            "\\.children\\[.*<\\s*0|children.*==\\s*-1",      // child-miss check
            "is_end|trie.*return.*0|return.*is_end",           // search-failure or result
            "trie_search|trie_find|prefix_search"             // search function names
        ),

        // ── Quicksort (55, 56) ────────────────────────────────────────────────
        new PatternDef("quicksort_partition", "qs_partition", "high",
            "pivot|a\\[hi\\]|a\\[high\\]",                    // pivot selection (Lomuto/Hoare)
            "a\\[i\\].*=.*a\\[j\\]|swap.*pivot",              // partition swap
            "qs_part|partition|lomuto|hoare"                  // partition function names
        ),
        new PatternDef("quicksort_recurse", "quicksort", "high",
            "quicksort|qsort_r|quick_sort",                   // recursive call name
            "lo\\s*<\\s*hi|low\\s*<\\s*high|left.*<.*right",  // recursion bounds check
            "p\\s*-\\s*1|pivot.*-.*1|p\\s*\\+\\s*1"          // sub-range split after partition
        ),

        // ── Dynamic Programming (57, 58) ─────────────────────────────────────
        new PatternDef("dp_2d_table", "dp_fill", "high",
            "dp\\[i\\]\\[j\\]|dp\\[.*\\]\\[.*\\]",           // 2D DP table access
            "dp\\[i-1\\]\\[j-1\\]|dp\\[i\\]\\[j-1\\]",       // diagonal or left neighbor
            "dp\\[i-1\\]\\[j\\]|dp\\[i\\]\\[j-1\\]"          // up or left access
        ),
        new PatternDef("lcs_pattern", "lcs_op", "high",
            "a\\[i.*-.*1\\]\\s*==\\s*b\\[j.*-.*1\\]",        // character equality check
            "dp\\[i-1\\]\\[j-1\\]\\s*\\+\\s*1",              // diagonal + 1 (match)
            "left.*>.*up|up.*>.*left|dp.*>.*dp"               // max(left, up) for mismatch
        ),

        // ── Merge sort (59, 60) ───────────────────────────────────────────────
        new PatternDef("mergesort_merge", "merge_step", "high",
            "tmp\\[k\\+\\+\\]|ms_tmp|merge_tmp",              // temporary buffer write
            "a\\[i\\].*<=.*a\\[j\\]|left.*<=.*right",         // two-pointer comparison
            "while.*i.*<=.*mid|while.*j.*<=.*hi"              // merge drain loops
        ),
        new PatternDef("mergesort_recurse", "mergesort", "high",
            "mid\\s*=\\s*\\(lo.*hi\\).*2|mid.*=.*(lo.*hi)/2", // mid-point calculation
            "mergesort\\(|merge_sort\\(|sort.*lo.*mid",        // recursive call on half
            "merge_step\\(|merge\\(.*lo.*mid.*hi"             // merge call after recursion
        ),

        // ── Disjoint Set Union / Union-Find (61, 62) ─────────────────────────
        new PatternDef("union_find_path", "uf_find", "high",
            "parent\\[root\\].*!=.*root|uf_parent.*!=.*x",    // root-finding loop
            "parent\\[x\\]\\s*=\\s*root|uf_parent.*=.*root",  // path compression write
            "uf_find|union_find|dsu_find"                      // function name
        ),
        new PatternDef("union_find_rank", "uf_union", "high",
            "rank\\[a\\]\\s*<\\s*rank\\[b\\]|uf_rank.*<",    // rank comparison swap
            "rank\\[a\\]\\s*==\\s*rank\\[b\\]|rank.*==.*rank", // equal-rank bump condition
            "uf_union|union_sets|dsu_union"                    // union function name
        ),

        // ── BFS (63, 64) ──────────────────────────────────────────────────────
        new PatternDef("bfs_queue", "bfs_enqueue", "high",
            "queue\\[tail\\+\\+\\]|bfs_queue|q\\[.*\\+\\+\\]", // enqueue into BFS queue
            "head\\s*<\\s*tail|qh\\s*<\\s*qt",                 // queue-not-empty check
            "v\\s*=\\s*queue\\[head\\+\\+\\]|v=q\\[qh\\+\\+\\]" // dequeue from BFS queue
        ),
        new PatternDef("bfs_visited", "bfs_relax", "high",
            "dist\\[u\\]\\s*<\\s*0|visited\\[u\\]\\s*==\\s*0", // unvisited check
            "dist\\[u\\]\\s*=\\s*dist\\[v\\]\\s*\\+\\s*1",    // BFS distance relaxation
            "gadj|adj\\[v\\]\\[u\\]|adj_matrix"               // adjacency matrix access
        ),

        // ── 0/1 Knapsack DP (65, 66) ─────────────────────────────────────────
        new PatternDef("knapsack_reverse", "knapsack_inner", "high",
            "for.*j.*=.*cap.*j.*>=.*w|j.*downto|j.*>=.*weight", // reverse inner loop
            "dp\\[j.*-.*w|ks_dp.*j.*-.*weight",                 // backward table access
            "with_item|dp\\[j\\].*<.*dp\\[j.*-"               // max comparison
        ),
        new PatternDef("knapsack_0_1", "knapsack", "high",
            "knapsack|0.1.*knapsack|01.*knapsack",             // function/comment name
            "dp\\[j.*-.*w\\[i\\]\\].*\\+.*v\\[i\\]",          // dp[j-w[i]] + v[i]
            "if.*with_item.*>.*dp|dp\\[j\\].*=.*with_item"    // value update condition
        ),

        // ── DFS (67, 68) ──────────────────────────────────────────────────────
        new PatternDef("dfs_recursive", "dfs_visit", "high",
            "dfs_visited|visited\\[v\\].*=.*1",                // visited-mark write
            "for.*u.*<.*N|for.*u.*adj|for.*neighbor",          // neighbor iteration loop
            "if.*adj.*&&.*!.*visited|if.*edge.*!.*vis"        // unvisited neighbor check
        ),
        new PatternDef("dfs_finish_time", "dfs_postorder", "medium",
            "dfs_finish|finish_time|finish\\[v\\]",            // finish-time array
            "\\+\\+.*timer|timer\\+\\+|post.*order",           // incrementing timer
            "dfs_finish\\[v\\].*=|f\\[v\\].*=.*\\+\\+t"       // post-order assignment
        ),

        // ── KMP string search (69, 70) ────────────────────────────────────────
        new PatternDef("kmp_failure", "kmp_prefix", "high",
            "fail\\[k.*-.*1\\]|failure.*k.*-.*1",              // failure function backtrack
            "fail\\[i\\]\\s*=\\s*k|kf\\[i\\].*=",             // failure table assignment
            "kmp_failure|build_fail|prefix_func"              // function name
        ),
        new PatternDef("kmp_match", "kmp_search", "high",
            "k\\s*=\\s*fail\\[k.*-.*1\\]|k=kf\\[k-1\\]",     // KMP mismatch backtrack
            "if.*k\\s*==\\s*m|if.*kk\\s*==.*pat_len",         // full-match detection
            "kmp_search|kmp_find|pattern_search"              // search function name
        ),

        // ── Dijkstra SSSP (71, 72) ────────────────────────────────────────────
        new PatternDef("dijkstra_relax", "dijkstra_update", "high",
            "dist\\[u\\].*\\+.*weight|nd.*=.*dist\\[u\\].*\\+",  // relaxation sum
            "if.*nd.*<.*dist\\[v\\]|if.*dist.*<.*dist\\[",        // relax condition
            "dijkstra_dist|dijkstra_vis|sssp"                    // SSSP state arrays
        ),
        new PatternDef("dijkstra_pick", "dijkstra_minscan", "medium",
            "for.*!.*vis|for.*!dijkstra_vis",                    // unvisited loop
            "dist.*<.*dijkstra_dist|dist.*<.*min",               // minimum test
            "dijkstra|sssp_pick|pick.*unvisited"                 // function/variable name
        ),

        // ── Binary search range count (73, 74) ───────────────────────────────
        new PatternDef("binary_search_lo_hi", "bsearch_frame", "high",
            "int lo.*=.*0.*hi.*=.*n|lo\\s*=\\s*0.*hi\\s*=",    // lo/hi init
            "mid.*=.*\\(lo.*\\+.*hi\\).*\\/.*2|mid=\\(lo\\+hi\\)/2",  // midpoint
            "while.*lo.*<=.*hi|while.*lo.*hi"                   // search loop
        ),
        new PatternDef("binary_search_range", "bsearch_first_last", "high",
            "result.*=.*mid.*hi.*=.*mid.*-.*1|hi.*=.*mid.*-.*1.*first", // leftmost
            "result.*=.*mid.*lo.*=.*mid.*\\+.*1|lo.*=.*mid.*\\+.*1.*last", // rightmost
            "bs_first|bs_last|first_occ|last_occ"               // function names
        ),

        // ── Topological sort — Kahn's (75, 76) ───────────────────────────────
        new PatternDef("toposort_kahn", "kahn_indegree", "high",
            "--indeg|indeg\\[v\\]--",                            // in-degree decrement
            "if.*indeg.*==.*0.*queue|queue.*tail.*=.*v",         // add newly-zero to queue
            "kahn_sort|topo_indeg|topological"                  // naming
        ),
        new PatternDef("toposort_queue", "kahn_bfs", "high",
            "while.*head.*<.*tail|while.*head.*tail",            // BFS main loop
            "topo_order|topo\\[.*n_sorted|topo\\[.*n\\+\\+\\]", // topo output array
            "topo_queue|kahn_queue|toposort"                    // queue name
        ),

        // ── Fibonacci memoization (77, 78) ───────────────────────────────────
        new PatternDef("fib_memoization", "fib_cache_check", "high",
            "fib_cache|memo\\[n\\]|fib.*cache",                  // cache array reference
            "if.*cache.*>=.*0|if.*memo.*>=.*0",                  // cache hit check
            "return.*cache|return.*memo"                        // return cached value
        ),
        new PatternDef("fib_recursive", "fib_topdown", "medium",
            "fib.*n.*-.*1.*\\+.*fib.*n.*-.*2|fib\\(n-1\\).*fib\\(n-2\\)", // recursive sum
            "cache\\[n\\].*=.*fib|memo\\[n\\].*=",              // memoize before return
            "fib_cache\\[n\\].*=|fib_memo\\[n\\].*="           // cache write
        ),

        // ── Sieve of Eratosthenes (79, 80) ───────────────────────────────────
        new PatternDef("sieve_mark", "sieve_outer", "high",
            "for.*i.*i.*<=.*N|i\\s*\\*\\s*i\\s*<=.*LIMIT",     // outer: i*i bound
            "for.*j.*=.*i.*\\*.*i|j\\s*=\\s*i\\s*\\*\\s*i",    // inner: j starts at i*i
            "sieve\\[j\\].*=.*0|is_prime\\[j\\]"               // mark composite
        ),
        new PatternDef("sieve_count", "sieve_prime_scan", "medium",
            "sieve\\[0\\].*=.*0|sieve\\[1\\].*=.*0",           // exclude 0 and 1
            "for.*i.*sieve\\[i\\]|if.*sieve\\[i\\].*prime",    // prime scan
            "n_primes|last_prime|eratosthenes"                 // naming
        ),

        // ── Levenshtein edit distance (81, 82) ───────────────────────────────
        new PatternDef("edit_dist_dp", "levenshtein_fill", "high",
            "dp_ed|dp.*i-1.*j-1|edit.*dist",                   // dp table name / diagonal
            "1.*\\+.*min3|1.*\\+.*min.*dp.*i-1|cost.*=.*1",    // substitute cost = 1+min3
            "s1.*i-1.*==.*s2.*j-1|a\\[i-1\\].*==.*b\\[j-1\\]" // character comparison
        ),
        new PatternDef("edit_dist_min3", "levenshtein_3way", "medium",
            "min3|min.*a.*b.*c|int ab.*=.*a.*<.*b",             // 3-way minimum helper
            "dp.*i-1.*j.*dp.*i.*j-1.*dp.*i-1.*j-1",           // three dp cells in min
            "edit_dist|levenshtein|lev_dp"                     // function/var name
        ),

        // ── Bellman-Ford SSSP (83, 84) ────────────────────────────────────────
        new PatternDef("bellman_ford_relax", "bf_edge_relax", "high",
            "for.*pass.*<.*BF_N|for.*p.*<.*n.*-.*1",           // n-1 pass outer loop
            "bf_dist.*\\+.*w.*<.*bf_dist|d\\[u\\].*\\+.*w.*<.*d\\[v\\]", // relaxation cond
            "if.*bf_dist.*!.*INF|if.*dist.*!=.*INF"           // INF guard
        ),
        new PatternDef("bellman_ford_neg", "bf_negcycle", "medium",
            "for.*e.*<.*BF_E|for.*e.*<.*n_edges",              // final pass edge scan
            "return.*1.*negative|neg.*cycle|neg_cycle",        // cycle return flag
            "bellman_ford|bf_edges|BF_INF"                    // naming
        ),

        // ── Counting sort (85, 86) ────────────────────────────────────────────
        new PatternDef("counting_sort_count", "csort_freq", "high",
            "cs_count|count\\[arr\\[i\\]\\]|freq\\[arr\\[",    // freq array indexed by value
            "count.*\\+\\+|cs_count.*arr.*\\+\\+",             // increment by value
            "counting_sort|count_sort|csort"                   // function name
        ),
        new PatternDef("counting_sort_stable", "csort_output", "high",
            "for.*i.*=.*n.*-.*1.*i.*>=.*0",                    // right-to-left loop
            "--cs_count.*arr|--count\\[arr\\[i\\]\\]",         // pre-decrement index
            "cs_out.*--.*count|out.*--.*count.*arr"            // stable output write
        ),

        // ── Floyd-Warshall all-pairs SP (87, 88) ─────────────────────────────
        new PatternDef("floyd_warshall_k", "fw_intermediate", "high",
            "for.*k.*<.*FW_N|for.*k.*=.*0.*k.*<.*n",          // k outer loop (intermediate)
            "fw_d.*i.*k.*fw_d.*k.*j|d\\[i\\]\\[k\\].*d\\[k\\]\\[j\\]", // 2D access pattern
            "floyd_warshall|fw_d|all_pairs"                   // naming
        ),
        new PatternDef("floyd_warshall_relax", "fw_relax", "high",
            "via_k.*=.*fw_d.*i.*k.*\\+|via.*=.*d.*\\+.*d",    // via_k intermediate sum
            "if.*via_k.*<.*fw_d|if.*d.*i.*j.*k.*<.*d",        // relaxation condition
            "FW_INF|fw_init|fw_n"                             // INF constant / naming
        ),

        // ── Bitset word operations (89, 90) ──────────────────────────────────
        new PatternDef("bitset_set_bit", "bitset_membership", "high",
            "\\*bs.*\\|=.*1u.*<<.*pos|bs.*|=.*1.*<<",         // set bit with shift
            "\\(\\*bs\\).*>>.*pos.*&.*1|bs.*>>.*b.*&.*1",     // test bit with shift
            "bs_set|bs_test|bitset"                           // function names
        ),
        new PatternDef("bitset_ops", "bitset_wordops", "medium",
            "union_bs|bitset_a.*|.*bitset_b",                  // union variable
            "isect_bs|bitset_a.*&.*bitset_b",                  // intersection variable
            "bs_popcount|pop_union|pop_isect"                  // popcount result
        ),

        // ── Fast modular exponentiation (91, 92) ─────────────────────────────
        new PatternDef("pow_mod_square", "powmod_squaremul", "high",
            "if.*exp.*&.*1.*result.*base.*%.*mod",             // odd-bit multiply
            "exp.*>>=.*1|exp.*=.*exp.*>>.*1",                  // exponent right shift
            "base.*=.*base.*\\*.*base.*%|base.*base.*mod"     // squaring step
        ),
        new PatternDef("pow_mod_loop", "powmod_whileloop", "high",
            "while.*exp.*>.*0|while.*e.*>.*0",                 // main while loop
            "result.*=.*1.*base.*%=.*mod|result\\s*=\\s*1u",  // init: result=1, base%=mod
            "pow_mod|fast_pow|modpow"                         // function name
        ),

        // ── Segment tree range sum (93, 94) ──────────────────────────────────
        new PatternDef("segment_tree_build", "segtree_build", "high",
            "for.*i.*=.*n.*-.*1.*i.*>=.*1",                    // bottom-up loop i=n-1..1
            "seg_tree.*2.*\\*.*i.*\\+.*seg_tree.*2.*\\*.*i.*\\+.*1", // tree[2i]+tree[2i+1]
            "seg_tree|segtree|segment_tree_build"             // naming
        ),
        new PatternDef("segment_tree_query", "segtree_query", "high",
            "if.*l.*&.*1.*sum.*tree.*l\\+\\+|if.*l.*&.*1",    // left boundary odd check
            "if.*r.*&.*1.*sum.*tree.*--r|if.*r.*&.*1",        // right boundary odd check
            "l.*>>=.*1.*r.*>>=.*1|l>>1.*r>>1"                 // halving step
        ),

        // ── Fenwick tree / BIT (95, 96) ───────────────────────────────────────
        new PatternDef("fenwick_update", "bit_update", "high",
            "i\\s*\\+=\\s*i\\s*&\\s*\\(-i\\)|i.*\\+.*i.*&.*-i", // advance: i+=i&(-i)
            "while.*i.*<=.*BIT_N|while.*i.*<=.*n",             // update loop bound
            "bit_update|bit\\[i\\].*\\+=|fenwick.*update"     // naming
        ),
        new PatternDef("fenwick_query", "bit_prefix", "high",
            "i\\s*-=\\s*i\\s*&\\s*\\(-i\\)|i.*-=.*i.*&.*-i",  // subtract: i-=i&(-i)
            "while.*i.*>.*0|while.*i\\s*>\\s*0",               // query loop bound
            "bit_prefix|sum.*\\+=.*bit\\[i\\]|fenwick.*query" // naming
        ),

        // ── LIS patience sort (97, 98) ────────────────────────────────────────
        new PatternDef("lis_patience", "lis_piles", "high",
            "lis_piles|piles\\[lo\\].*=.*v|piles\\[lo\\].*=",  // piles array write
            "if.*lo.*==.*np.*np\\+\\+|lo.*==.*np.*np\\+\\+",  // extend new pile
            "lis_length|patience_sort|lis_piles"              // function/var name
        ),
        new PatternDef("lis_bsearch", "lis_bisect", "high",
            "piles\\[m\\].*<.*v|lis_piles.*<.*arr",            // patience binary search condition
            "lo.*=.*m.*\\+.*1|lo=m\\+1",                       // lower bound advance
            "lis.*lo.*hi|int lo.*=.*0.*hi.*=.*np"             // lo/hi init with np
        ),

        // ── Z-function (99, 100) ─────────────────────────────────────────────
        new PatternDef("zfunc_window", "zfunc_lr_window", "high",
            "if.*i.*<.*r.*z|if.*i\\s*<\\s*r",                 // [l,r) window branch
            "s\\[z\\[i\\]\\].*==.*s\\[i.*\\+.*z|s.*z.*==.*s.*i.*z",  // extend compare
            "z_function|z_func|zfunc"                         // naming
        ),
        new PatternDef("zfunc_extend", "zfunc_extloop", "high",
            "i.*\\+.*z\\[i\\].*>.*r|i\\+z.*>.*r",             // extend: update [l,r)
            "l\\s*=\\s*i|l=i",                                 // l=i; r=i+z[i] window update
            "z\\[i\\]\\+\\+|z.*extend|z_function"            // z[i]++ in extend loop
        ),

        // ── LSD radix sort (101, 102) ─────────────────────────────────────────
        new PatternDef("radix_sort_nibble", "radix_nibble_pass", "high",
            "arr.*\\[i\\].*&.*0xF|&\\s*0xf|&\\s*0xF",        // low-nibble key
            "radix_tmp.*>>.*4|tmp.*>>.*4|>>\\s*4",            // high-nibble key
            "radix_sort|radix_tmp|radix_out"                 // naming
        ),
        new PatternDef("radix_sort_stable", "radix_stable_pass", "high",
            "for.*i.*=.*n.*-.*1.*i.*>=.*0|i.*=.*n.*-.*1",    // right-to-left stable scan
            "out\\[--cnt|tmp\\[--cnt|--cnt\\[",               // stable output: --cnt[key]
            "cnt\\[i\\].*\\+=.*cnt\\[i.*-.*1\\]|cnt.*\\+=.*cnt"  // prefix sum
        ),

        // ── Manacher's palindrome (103, 104) ─────────────────────────────────
        new PatternDef("manacher_window", "manacher_cr_window", "high",
            "mirror.*=.*2.*\\*.*c.*-.*i|2\\*c.*-.*i",          // mirror index: 2*c-i
            "if.*i.*<.*r.*p\\[i\\].*=|if.*i.*<.*r",           // [c,r) window init
            "manacher|man_p|palindrome_radius"                // naming
        ),
        new PatternDef("manacher_expand", "manacher_centre_expand", "high",
            "t\\[i.*-.*p\\[i\\].*-.*1\\].*==.*t\\[i.*\\+.*p\\[i\\].*\\+.*1\\]",  // expand compare
            "p\\[i\\]\\+\\+|p\\[centre\\]\\+\\+",             // centre expansion
            "if.*i.*\\+.*p.*>.*r.*c.*=.*i|c\\s*=\\s*i.*r\\s*="  // window advance
        ),

        // ── Coin change DP (105, 106) ─────────────────────────────────────────
        new PatternDef("coin_change_dp", "coinchange_min", "high",
            "dp\\[i\\].*=.*CC_LIMIT|dp\\[0\\].*=.*0.*dp.*=.*BIG|cc_dp.*=.*CC_LIMIT",  // init sentinel
            "if.*i.*>=.*coins.*dp\\[i.*-.*coins|dp.*i.*-.*c.*\\+.*1.*<.*dp\\[i\\]",  // min(dp[i], dp[i-c]+1)
            "coin_change|cc_dp|coin_change_dp"               // naming
        ),
        new PatternDef("coin_change_inner", "coinchange_loop", "high",
            "for.*j.*=.*0.*j.*<.*nc|for.*j.*<.*CC_COINS",    // loop over denominations
            "i.*>=.*coins\\[j\\]|i.*>=.*c",                  // feasibility check
            "dp\\[i\\].*=.*dp\\[i.*-|min.*dp.*coins"        // recurrence body
        ),

        // ── Kadane's max-subarray (107, 108) ─────────────────────────────────
        new PatternDef("kadane_extend", "kadane_restart", "high",
            "cur_sum.*\\+.*arr|if.*cur_sum.*\\+.*arr.*>.*arr",  // extend-or-restart
            "cur_sum.*=.*arr|tmp_start.*=.*i",                 // restart branch
            "kadane|max_sum|cur_sum"                          // naming
        ),
        new PatternDef("kadane_global_max", "kadane_maxupdate", "high",
            "if.*cur_sum.*>.*max_sum|if.*kc.*>.*ks",          // global max test
            "max_sum.*=.*cur_sum|ms.*=.*tmp_start|me.*=.*i",  // update max
            "kadane|max_subarray|max_sum"                    // naming
        ),

        // ── Extended Euclidean GCD (109, 110) ─────────────────────────────────
        new PatternDef("ext_gcd_unwind", "extgcd_bezout", "high",
            "if.*b.*==.*0.*\\*x.*=.*1.*\\*y.*=.*0|if.*b.*==.*0",  // base case
            "\\*x.*=.*y1|\\*y.*=.*x1.*-.*a.*b.*\\*.*y1",    // Bezout unwind
            "ext_gcd|egcd|gcd.*x.*y"                        // naming
        ),
        new PatternDef("ext_gcd_recurse", "extgcd_recurse", "high",
            "ext_gcd.*b.*a.*%.*b|egcd.*b.*a.*%.*b",           // recursive call
            "a.*%.*b.*&.*x1.*&.*y1|a.*%.*b.*x1.*y1",         // a%b passed
            "g.*=.*ext_gcd|g.*=.*egcd"                      // result capture
        ),

        // ── Sparse table RMQ (111, 112) ───────────────────────────────────────
        new PatternDef("sparse_table_build", "sparse_build", "high",
            "st.*j.*-.*1.*i.*st.*j.*-.*1.*i.*1.*<<|1.*<<.*j.*-.*1",  // st[j-1][i+(1<<(j-1))]
            "for.*j.*=.*1.*j.*<=.*LOG|for.*j.*<=.*ST_LOG",    // outer j loop
            "sparse_build|sparse_table|rmq_build"            // naming
        ),
        new PatternDef("sparse_table_query", "sparse_query", "high",
            "ilog2.*r.*-.*l|k.*=.*ilog2|k.*=.*log2",          // k = ilog2(r-l+1)
            "r.*-.*1.*<<.*k.*\\+.*1|r.*-.*\\(1.*<<.*k\\).*\\+.*1",  // r-(1<<k)+1 index
            "sparse_query|rmq_query|sparse_table"            // naming
        ),

        // ── Activity selection greedy (113, 114) ─────────────────────────────
        new PatternDef("activity_sel_sort", "acts_end_sort", "high",
            "acts.*j.*\\.end.*>.*key\\.end|acts.*\\.end.*>.*acts.*\\.end",  // sort by .end
            "acts.*j.*\\+.*1.*=.*acts.*j|acts.*swap.*end",    // element swap
            "acts_sort|activity.*sort|acts_sort_by_end"      // naming
        ),
        new PatternDef("activity_sel_greedy", "acts_greedy", "high",
            "acts.*i.*\\.start.*>=.*last_end|start.*>=.*last_end",  // feasibility: start≥last_end
            "count\\+\\+.*last_end.*=.*acts.*\\.end|last_end.*=.*acts.*end",  // pick + advance
            "activity_select|acts_select|count.*last_end"   // naming
        ),

        // ── LPS interval DP (115, 116) ────────────────────────────────────────
        new PatternDef("lps_diagonal_fill", "lps_dp_fill", "high",
            "for.*len.*=.*2.*len.*<=.*n|for.*len.*=.*2.*len.*<=.*LPS_N",  // diagonal-fill outer loop
            "j.*=.*i.*\\+.*len.*-.*1|j\\s*=\\s*i\\s*\\+\\s*len",  // j = i+len-1
            "lps_dp|lps_compute|lps.*interval"             // naming
        ),
        new PatternDef("lps_recurrence", "lps_case", "high",
            "s\\[i\\].*==.*s\\[j\\]|lps_s.*i.*==.*lps_s.*j",     // character equality
            "lps_dp.*i.*\\+.*1.*j.*-.*1.*\\+.*2|dp.*i\\+1.*j-1.*\\+.*2",  // +2 palindrome extend
            "max.*dp.*i.*\\+.*1.*j.*dp.*i.*j.*-.*1|max.*i\\+1.*j.*i.*j-1"  // max of sub-problems
        ),

        // ── Dutch National Flag (117, 118) ────────────────────────────────────
        new PatternDef("dutch_flag_3way", "dnf_3way_partition", "high",
            "while.*mid.*<=.*hi|while.*mid\\s*<=\\s*hi",          // 3-way while loop
            "if.*arr.*mid.*<.*pivot|dnf_arr.*mid.*<.*pivot",      // less-than branch
            "dnf_partition|dutch_flag|3way.*partition"           // naming
        ),
        new PatternDef("dutch_flag_branches", "dnf_branches", "high",
            "swap.*lo.*mid.*lo\\+\\+.*mid\\+\\+|lo\\+\\+.*mid\\+\\+",  // <pivot branch
            "swap.*mid.*hi.*hi--|hi--",                           // >pivot branch: hi--
            "else.*if.*==.*pivot|elif.*==.*pivot"               // equality branch
        ),

        // ── Prim's MST (119, 120) ─────────────────────────────────────────────
        new PatternDef("prim_min_key", "prim_mst_pick", "high",
            "u.*==.*-1.*prim_key.*v.*<.*prim_key.*u|u.*==.*-1.*key.*v.*<.*key.*u",  // min-key selection
            "if.*!prim_in_mst.*v|if.*!in_mst.*v",               // not-yet-in-MST guard
            "prim_mst|prim_key|mst_weight"                     // naming
        ),
        new PatternDef("prim_relax", "prim_mst_relax", "high",
            "prim_adj.*u.*v.*&&.*!prim_in_mst|adj.*u.*v.*&&.*!in_mst",  // relax: adj&&!mst
            "prim_key.*v.*=.*prim_adj|key.*v.*=.*adj",          // key[v] = adj[u][v]
            "prim_mst|prim.*relax|mst.*update"                 // naming
        ),

        // ── Subset sum boolean DP (121, 122) ─────────────────────────────────
        new PatternDef("subset_sum_dp", "subset_sum_fill", "high",
            "for.*j.*=.*SS_LIMIT.*j.*>=.*v|for.*j.*=.*limit.*j.*>=.*v",  // reverse inner loop
            "ss_dp\\[j\\].*\\|=.*ss_dp\\[j.*-.*v\\]|dp\\[j\\].*\\|=.*dp\\[j.*-",  // DP update
            "subset_sum|ss_dp|subset.*dp"                      // naming
        ),
        new PatternDef("subset_sum_query", "subset_sum_check", "high",
            "if.*ss_dp.*targets|if.*dp.*targets|ss_dp\\[.*\\]",  // reachability check
            "count_found\\+\\+|xor_found.*\\^=",               // found accumulation
            "subset_sum_build|ss_dp|targets.*dp"              // naming
        ),

        // ── Sprint 42: Next Greater Element (monotonic stack) ───────────────
        new PatternDef("nge_mono_stack", "next_greater_element", "high",
            "while.*top.*>=.*0.*arr.*stack.*<.*arr",           // monotone pop condition
            "nge.*stack.*top--|stack.*top--.*=.*arr",          // pop + assign NGE
            "stack.*\\+\\+top|nge_result|next_greater"        // index-stack push / naming
        ),
        new PatternDef("nge_index_push", "mono_stack_push", "medium",
            "stack\\[\\+\\+top\\].*=.*i|nge_stack.*=.*i",    // push index onto stack
            "top.*>=.*0|nge_result.*\\[.*\\].*=",             // top guard / assign
            "nge_stack|mono.*stack|next.*greater"             // naming
        ),

        // ── Sprint 42: Josephus recurrence ──────────────────────────────────
        new PatternDef("josephus_recurrence", "josephus_problem", "high",
            "pos.*=.*\\(.*pos.*\\+.*k.*\\).*%.*i",            // pos=(pos+k)%i recurrence
            "for.*i.*=.*2.*i.*<=.*n|for.*i.*<.*=.*n.*pos",   // i from 2 to n loop
            "josephus|survivor|pos.*\\+.*1"                  // naming / +1 adjustment
        ),

        // ── Sprint 43: QuickSelect ───────────────────────────────────────────
        new PatternDef("quick_select_pivot", "quick_select", "high",
            "if.*p.*==.*k.*return|pivot_idx.*==.*k",          // early-exit on pivot==k
            "k.*<.*p.*hi.*=|lo.*=.*p.*\\+.*1",               // one-sided recurse
            "quick_select|qs_partition|kth_smallest"         // naming
        ),

        // ── Sprint 43: Matrix Chain Multiplication DP ───────────────────────
        new PatternDef("matrix_chain_dp", "matrix_chain_mult", "high",
            "for.*l.*=.*2.*l.*<=.*n",                         // outer length loop
            "mc_dp.*\\[i\\].*\\[j\\].*=.*0x7f|INT_MAX",      // sentinel init
            "mc_dp|dims.*\\[i\\].*dims.*\\[k.*\\+.*1\\]"    // cost formula / naming
        ),
        new PatternDef("matrix_chain_cost", "matrix_chain_inner", "medium",
            "cost.*mc_dp.*\\[i\\].*\\[k\\].*mc_dp.*\\[k",    // dp[i][k]+dp[k+1][j] sum
            "dims.*\\[.*\\].*\\*.*dims.*\\[.*\\].*\\*.*dims", // triple dims product
            "matrix_chain|mc_dp|chain_mult"                  // naming
        ),

        // ── Sprint 44: Kruskal's MST ─────────────────────────────────────────
        new PatternDef("kruskal_union_find", "kruskal_mst", "high",
            "find.*u.*!=.*find.*v|kr_find.*!=.*kr_find",      // find(u)!=find(v) check
            "union.*u.*v|kr_union.*edges",                    // union call on edge
            "kruskal|mst_weight|mst_edges|kr_edges"          // naming
        ),
        new PatternDef("kruskal_path_compress", "path_compression", "medium",
            "parent.*\\[x\\].*=.*parent.*\\[parent.*\\[x\\]\\]", // path halving
            "while.*parent.*x.*!=.*x|parent.*\\[x\\].*!=.*x",   // root-find loop
            "kr_find|kr_parent|path_comp"                    // naming
        ),

        // ── Sprint 44: Floyd's Cycle Detection ───────────────────────────────
        new PatternDef("floyd_cycle_detect", "tortoise_hare", "high",
            "do.*slow.*=.*f.*fast.*=.*f.*f|slow.*fast.*=.*next.*next", // phase 1 loop
            "slow.*!=.*fast|while.*slow.*!=.*fast",                    // meet condition
            "floyd|tortoise|hare|cycle_start|cycle_len"      // naming
        ),
        new PatternDef("floyd_cycle_length", "cycle_length_count", "medium",
            "len.*=.*1.*fast.*=.*f.*slow",                   // len=1; fast=f(slow)
            "while.*fast.*!=.*slow.*fast.*=.*f.*fast.*len\\+\\+", // count loop
            "cycle_len|cycle_length|floyd_cycle"             // naming
        ),

        // ── Sprint 45: Sliding Window Maximum ───────────────────────────────
        new PatternDef("sliding_window_deque", "sliding_window_max", "high",
            "while.*head.*<.*tail.*arr.*deq.*tail.*-.*1.*<=.*arr", // pop-back condition
            "while.*head.*<.*tail.*deq.*head.*<.*i.*-.*w",         // pop-front stale evict
            "sw_deq|sw_max|sliding_window|window_max"             // naming
        ),
        new PatternDef("sliding_window_assign", "window_max_emit", "medium",
            "if.*i.*>=.*w.*-.*1.*sw_max|if.*i.*>=.*w.*max.*=.*arr.*deq", // emit condition
            "sw_max.*=.*arr.*sw_deq|max_out.*=.*arr.*deq.*head",          // assign from front
            "sw_max|window_max|sliding_max"                       // naming
        ),

        // ── Sprint 45: Bitmask Enumeration ──────────────────────────────────
        new PatternDef("bitmask_subset_enum", "bitmask_enumeration", "high",
            "for.*mask.*=.*0.*mask.*<.*1.*<<.*n",              // outer loop 1<<n bound
            "mask.*&.*1.*<<.*b.*sum.*\\+=",                    // bit test + accumulate
            "bitmask|mask.*items|subset.*enum"                // naming
        ),
        new PatternDef("bitmask_divisibility", "bitmask_div_filter", "medium",
            "sum.*%.*k.*==.*0|sum.*%.*BM_K.*==",              // divisibility check
            "count\\+\\+.*max_sum|if.*sum.*>.*max",           // count and track max
            "bitmask_enum|div_filter|max_sum"                 // naming
        ),

        // ── Sprint 46: Two-pointer pair sum ─────────────────────────────────
        new PatternDef("two_pointer_pairs", "two_pointer_sum", "high",
            "lo.*<.*hi.*arr.*lo.*\\+.*arr.*hi|two_ptr.*lo.*hi", // lo/hi convergence + sum
            "lo\\+\\+.*hi--|s.*==.*target.*lo\\+\\+",           // simultaneous advance on match
            "two_pointer|lo_val|pair_sum|two_ptr"             // naming
        ),

        // ── Sprint 46: Minimum Stack ─────────────────────────────────────────
        new PatternDef("min_stack_push", "min_stack_dual", "high",
            "ms_min.*ms_top.*=.*x.*<.*ms_min.*ms_top.*-.*1",  // dual-array: min[top]=min(x,prev)
            "ms_main.*ms_top.*=.*x|main.*top.*=.*x",          // main stack write
            "ms_min|ms_main|min_stk|aux_min"                 // naming
        ),
        new PatternDef("min_stack_query", "min_stack_get", "medium",
            "ms_min.*ms_top.*-.*1|min_stk.*top.*-.*1",        // read from min_stk[top-1]
            "ms_top--|--.*ms_top",                             // single decrement for both
            "ms_get_min|getMin|ms_min"                        // naming
        ),

        // ── Sprint 47: Boyer-Moore Majority Vote ─────────────────────────────
        new PatternDef("boyer_moore_vote", "majority_vote", "high",
            "count.*==.*0.*candidate.*=.*arr|bmcnt.*==.*0.*bmcand", // reset branch
            "arr.*==.*candidate.*count\\+\\+|else.*count--",        // vote up/down
            "boyer_moore|bmcand|candidate|majority"          // naming
        ),

        // ── Sprint 47: Count Inversions (merge sort) ─────────────────────────
        new PatternDef("merge_inversion_count", "count_inversions", "high",
            "cnt.*\\+=.*mid.*-.*i|count.*\\+=.*mid.*-.*left", // key: cnt+=mid-i
            "merge_count|merge_inv|if.*arr.*i.*>.*arr.*j",    // merge idiom
            "inv_count|merge_count|count_inversions"         // naming
        ),

        // ── Sprint 48: Jump Search ───────────────────────────────────────────
        new PatternDef("jump_search_block", "jump_search", "high",
            "step.*\\+=.*block|step.*\\+=.*sqrt|prev.*=.*step.*step.*\\+=", // block advance
            "arr.*step.*-.*1.*<.*key|arr.*prev.*-.*1.*<.*key",               // overshoot test
            "jump_search|block.*search|isqrt_js"              // naming
        ),
        new PatternDef("jump_search_linear", "jump_search_scan", "medium",
            "for.*prev.*<.*limit.*arr.*prev.*==.*key",        // linear backward scan
            "if.*arr.*prev.*>.*key.*break",                   // early-exit on overshoot
            "jump_search|linear.*scan|js_prev"               // naming
        ),

        // ── Sprint 48: Longest Common Substring DP ───────────────────────────
        new PatternDef("lc_substring_reset", "lc_substring_dp", "high",
            "lcs_dp.*=.*lcs_dp.*-.*1.*-.*1.*\\+.*1",         // dp[i][j]=dp[i-1][j-1]+1
            "else.*lcs_dp.*=.*0|else.*dp.*\\[.*\\].*=.*0",   // key: reset to 0 on mismatch
            "lcs_dp|lc_substr|max_len.*lcs"                  // naming
        ),

        // ── Sprint 49: Catalan Numbers DP ───────────────────────────────────
        new PatternDef("catalan_inner_product", "catalan_dp", "high",
            "cat.*\\[k\\].*\\+=.*cat.*\\[i\\].*cat.*\\[k.*-.*1.*-.*i\\]", // inner product
            "for.*i.*=.*0.*i.*<.*k.*cat|cat.*\\[.*\\].*\\+=", // accumulation loop
            "catalan|cat_dp|cat\\[k\\]"                      // naming
        ),

        // ── Sprint 49: Shell Sort ────────────────────────────────────────────
        new PatternDef("shell_sort_gap", "shell_sort", "high",
            "gap.*=.*n.*\\/.*2.*gap.*>.*0.*gap.*\\/=.*2",    // outer gap-halving loop
            "j.*-=.*gap|arr.*j.*=.*arr.*j.*-.*gap",          // gap-strided shift
            "shell_sort|shell_arr|gap.*halv"                 // naming
        ),
        new PatternDef("shell_sort_insertion", "shell_insert_pass", "medium",
            "while.*j.*>=.*gap.*arr.*j.*-.*gap.*>.*tmp",     // condition with gap subtraction
            "arr.*j.*=.*arr.*j.*-.*gap.*j.*-=.*gap",         // shift + stride back
            "shell_sort|gap.*insert|j.*gap"                  // naming
        ),

        // ── Sprint 50: Interpolation Search ─────────────────────────────────
        new PatternDef("interp_search_probe", "interpolation_search", "high",
            "pos.*=.*lo.*\\+.*key.*-.*arr.*lo.*\\*.*hi.*-.*lo.*\\/.*arr.*hi.*-.*arr.*lo", // value-weighted probe
            "lo.*<=.*hi.*&&.*key.*>=.*arr.*lo.*&&.*key.*<=.*arr.*hi", // range guard
            "interp_search|interpolation|interp.*probe"      // naming
        ),

        // ── Sprint 50: N-Queens Backtracking ────────────────────────────────
        new PatternDef("n_queens_backtrack", "n_queens_backtracking", "high",
            "nq_col.*nq_d1.*nq_d2|col_used.*diag1.*diag2",  // three-array marking
            "nq_col.*=.*1.*nq_d|col_used.*=.*1.*diag.*=.*1", // triple simultaneous set
            "n_queens|nq_solve|nq_col"                       // naming
        ),
        new PatternDef("n_queens_diagonal", "queens_diagonal_index", "medium",
            "row.*-.*c.*\\+.*n.*-.*1|row.*-.*col.*\\+.*n.*-.*1", // anti-diagonal index shift
            "d2.*=.*row.*-.*c|diag2.*=.*row.*-",             // anti-diag assignment
            "nq_d2|diag2|anti_diag"                          // naming
        ),

        // ── Sprint 51: Rabin-Karp Rolling Hash ──────────────────────────────
        new PatternDef("rabin_karp_rolling", "rolling_hash_search", "high",
            "h_pow.*=.*1.*for.*h_pow.*=.*h_pow.*\\*.*RK_BASE|h_pow.*BASE.*MOD", // h_pow init loop
            "h_txt.*=.*h_txt.*-.*lead.*\\*.*h_pow|h.*MOD.*-.*lead.*h_pow.*BASE", // remove-and-slide
            "rabin_karp|rolling_hash|rk_txt|h_pow"          // naming
        ),

        // ── Sprint 51: Pancake Sort ──────────────────────────────────────────
        new PatternDef("pancake_sort_flip", "pancake_sort", "high",
            "for.*size.*=.*n.*size.*>.*1.*size--",           // outer shrink loop
            "ps_flip.*mi.*ps_flip.*size.*-.*1|flip.*mi.*flip.*size", // double-flip pattern
            "pancake_sort|ps_flip|pancake"                   // naming
        ),
        new PatternDef("pancake_find_max", "pancake_max_scan", "medium",
            "mi.*=.*0.*for.*i.*=.*1.*i.*<.*size.*arr.*i.*>.*arr.*mi.*mi.*=.*i", // find-max in shrinking range
            "if.*mi.*==.*size.*-.*1.*continue",              // skip-if-in-place guard
            "pancake_sort|mi.*size|ps_arr"                   // naming
        ),

        // ── Sprint 52: Comb Sort ─────────────────────────────────────────────
        new PatternDef("comb_sort_gap", "comb_sort", "high",
            "gap.*=.*gap.*\\*.*10.*\\/.*13|gap.*=.*gap.*10.*13", // 1.3 shrink in integer arithmetic
            "while.*gap.*>.*1.*||.*!.*sorted|gap.*>.*1.*sorted", // outer while with both conditions
            "comb_sort|comb_arr|comb_gap"                    // naming
        ),

        // ── Sprint 52: Cycle Sort ────────────────────────────────────────────
        new PatternDef("cycle_sort_position", "cycle_sort", "high",
            "pos.*=.*cs.*for.*i.*=.*cs.*\\+.*1.*arr.*i.*<.*item.*pos\\+\\+", // position count
            "while.*pos.*!=.*cs.*pos.*=.*cs.*for.*i.*=.*cs.*\\+.*1", // nested cycle rotation
            "cycle_sort|writes|cycleStart|cs.*pos"           // naming
        ),
        new PatternDef("cycle_skip_duplicates", "cycle_skip_dup", "medium",
            "while.*item.*==.*arr.*pos.*pos\\+\\+",          // skip-duplicates guard
            "arr.*pos.*=.*item.*writes\\+\\+|tmp.*arr.*pos.*arr.*pos.*=.*item", // write + count
            "cycle_sort|writes|cs.*dup"                      // naming
        ),

        // ── Sprint 53: Ternary Search ────────────────────────────────────────
        new PatternDef("ternary_search_midpoints", "ternary_search", "high",
            "m1.*=.*lo.*\\+.*hi.*-.*lo.*\\/.*3.*m2.*=.*hi.*-.*hi.*-.*lo.*\\/.*3", // two midpoints
            "hi.*-.*lo.*>.*2|while.*hi.*-.*lo.*>.*2",       // outer condition
            "ternary_search|ts_find|m1.*m2.*tgt"            // naming
        ),

        // ── Sprint 53: Miller-Rabin ──────────────────────────────────────────
        new PatternDef("miller_rabin_witness", "miller_rabin_primality", "high",
            "d.*>>=.*1.*s\\+\\+|while.*d.*%.*2.*==.*0.*d.*s", // extract 2^s factor
            "x.*=.*x.*\\*.*x.*%.*n.*n.*-.*1|x.*%.*n.*n.*-.*1", // squaring loop
            "miller_rabin|mr_pow|witness"                    // naming
        ),
        new PatternDef("miller_rabin_composite", "mr_composite_check", "medium",
            "if.*r.*==.*s.*return.*0|r.*==.*s.*composite",  // composite verdict
            "for.*r.*=.*1.*r.*<.*s.*x.*=.*x.*\\*.*x.*%.*n", // squaring iteration
            "miller_rabin|r.*==.*s|witness"                 // naming
        ),

        // ── Sprint 54: Max Rectangle in Histogram ───────────────────────────
        new PatternDef("max_rect_histogram_stack", "max_rect_histogram", "high",
            "while.*top.*>=.*0.*&&.*h.*mrh_stk.*top.*>=.*cur", // pop-while-taller
            "top.*<.*0.*?.*i.*:.*i.*-.*mrh_stk.*top.*-.*1",  // width formula: sentinel or stack-top
            "mrh_stk|max_rect|max_area.*hist"                // naming
        ),

        // ── Sprint 54: Trapping Rain Water ──────────────────────────────────
        new PatternDef("trap_rain_two_pointer", "trapping_rain_water", "high",
            "if.*h.*left.*<.*h.*right|h\\[left\\].*<.*h\\[right\\]", // advance-shorter-side
            "water.*+=.*max_l.*-.*h.*left|water.*+=.*max_r.*-.*h.*right", // accumulation
            "trap_rain|rain_h|max_l.*max_r|trapping"        // naming
        ),
        new PatternDef("trap_rain_running_max", "rain_running_max", "medium",
            "max_l.*=.*h.*left.*max_l.*:.*max_l|h.*left.*>=.*max_l.*max_l.*=", // running max update
            "water.*+=.*max_l|water.*+=.*max_r",             // water accumulation
            "trap_rain|max_l|max_r"                          // naming
        ),

        // ── Sprint 55: Jump Game ─────────────────────────────────────────────
        new PatternDef("jump_game_greedy", "jump_game_reachability", "high",
            "if.*i.*>.*max_reach.*return.*0|i.*>.*max_reach",  // early-exit pruning
            "if.*i.*\\+.*arr.*i.*>.*max_reach.*max_reach.*=.*i.*\\+.*arr.*i", // greedy update
            "jump_game|max_reach|jump_arr"                   // naming
        ),

        // ── Sprint 55: Gas Station ───────────────────────────────────────────
        new PatternDef("gas_station_greedy", "gas_station_circuit", "high",
            "tank.*\\+=.*gas.*i.*-.*cost.*i|tank.*diff|total.*diff", // running tank + total
            "if.*tank.*<.*0.*start.*=.*i.*\\+.*1.*tank.*=.*0", // greedy reset pattern
            "gas_station|start.*tank|total.*tank"            // naming
        ),
        new PatternDef("gas_station_feasibility", "gas_circuit_feasible", "medium",
            "return.*total.*<.*0.*?.*-1|if.*total.*<.*0.*return.*-1", // infeasibility check
            "total.*<.*0.*-1.*:.*start|total.*gas.*cost",    // total feasibility
            "gas_station|total.*cost|circuit"                // naming
        ),

        // ── Sprint 56: Bipartite Check ───────────────────────────────────────
        new PatternDef("bipartite_2coloring", "bipartite_check_bfs", "high",
            "color.*v.*=.*3.*-.*color.*u|3.*-.*color.*color", // 3-color swap trick
            "color.*v.*==.*color.*u.*return.*0|if.*color.*conflict", // same-color conflict
            "bipartite|is_bipartite|bp_color"                // naming
        ),

        // ── Sprint 56: Kahn's Topological Sort ──────────────────────────────
        new PatternDef("kahn_indegree_seed", "kahn_toposort_bfs", "high",
            "for.*i.*<.*n.*in_deg.*i.*==.*0.*enqueue|for.*in_deg.*==.*0.*q.*=.*i", // seed queue
            "if.*--.*in_deg.*v.*==.*0.*q.*back|--kt_indeg.*==.*0", // decrement-and-enqueue
            "kahn.*sort|kt_indeg|in_deg.*0"                  // naming
        ),
        new PatternDef("kahn_cycle_check", "kahn_cycle_detection", "medium",
            "if.*processed.*<.*n.*cycle|processed.*==.*n",   // cycle check post-BFS
            "processed\\+\\+|order.*processed",              // process counter
            "kahn_sort|kt_order|processed"                   // naming
        ),

        // ── Sprint 57: Word Break DP ─────────────────────────────────────────
        new PatternDef("word_break_dp", "word_break_segmentation", "high",
            "dp\\[0\\].*=.*1|dp.*0.*=.*1.*empty.*prefix",    // empty-prefix seed
            "dp.*i.*wlen.*&&|if.*dp.*i.*wlen.*match",        // backward dp access
            "word_break|wb_dp|dp.*slen"                      // naming
        ),

        // ── Sprint 57: Counting Paths in DAG ────────────────────────────────
        new PatternDef("dag_paths_memoized", "dag_path_count_dp", "high",
            "if.*u.*==.*dst.*return.*1|u.*==.*dst.*return",  // base case: at destination
            "if.*memo.*>=.*0.*return|memo.*=.*total",        // cache hit + memoize-before-return
            "count_paths|cp_memo|dag.*path"                  // naming
        ),
        new PatternDef("dag_paths_accumulate", "dag_edge_accumulate", "medium",
            "total.*\\+=.*count_paths|total.*\\+=.*adj",     // accumulate over out-edges
            "for.*outdeg.*count_paths|cp_adj.*cp_outdeg",    // iterate adjacency
            "cp_adj|cp_outdeg|count_paths"                   // naming
        ),

        // ── Sprint 58: Euler's Totient ───────────────────────────────────────
        new PatternDef("euler_totient_strip", "euler_totient_prime_factor", "high",
            "while.*%.*p.*==.*0|while.*n.*%.*p.*n.*=.*n",   // strip prime factor loop
            "result.*-=.*result.*p|result.*result.*p.*1",   // phi multiply step
            "euler.*totient|euler_phi|totient"              // naming
        ),

        // ── Sprint 58: Difference Array ─────────────────────────────────────
        new PatternDef("difference_array_update", "difference_array_range", "high",
            "\\[l\\].*\\+=|da_D.*l.*\\+=|diff.*l.*\\+=",    // range update lo bound
            "\\[r.*\\+.*1\\].*-=|da_D.*r.*1.*-=|diff.*r.*1.*-=", // range update hi+1
            "da_range|da_D|difference_array"                // naming
        ),
        new PatternDef("difference_array_reconstruct", "prefix_sum_reconstruct", "medium",
            "acc.*\\+=.*D.*i|acc.*\\+=.*da_D|prefix.*sum.*D", // prefix sum accumulate
            "A.*i.*=.*acc|da_A.*i.*=.*acc|arr.*i.*=.*acc",  // assign reconstructed
            "da_reconstruct|reconstruct|da_A"               // naming
        ),

        // ── Sprint 59: Chinese Remainder Theorem ─────────────────────────────
        new PatternDef("crt_partial_product", "chinese_remainder_theorem", "high",
            "M.*=.*M.*m.*i|Mi.*=.*M.*m.*i|M_i.*=.*M.*m",   // compute partial product
            "mod_inv.*Mi.*m|crt_inv.*M.*m|inv.*=.*mod_inv", // modular inverse call
            "crt_solve|chinese_remainder|crt"               // naming
        ),

        // ── Sprint 59: Longest Bitonic Subsequence ───────────────────────────
        new PatternDef("longest_bitonic_lis_lds", "bitonic_subsequence_dp", "high",
            "lb_lis.*j.*\\+.*1.*>.*lb_lis.*i|lis.*j.*1.*lis.*i", // forward LIS update
            "lb_lds.*j.*\\+.*1.*>.*lb_lds.*i|lds.*j.*1.*lds.*i", // backward LDS update
            "longest_bitonic|lb_lis|lb_lds"                // naming
        ),
        new PatternDef("bitonic_combine", "bitonic_lbs_combine", "medium",
            "lb_lis.*i.*\\+.*lb_lds.*i.*-.*1|lis.*i.*lds.*i.*1", // LIS+LDS-1 combine
            "if.*lbs.*>.*max_lbs|max_lbs.*=.*lbs|max_lbs", // track global max
            "lbs|max_lbs|bitonic_combine"                   // naming
        ),

        // ── Sprint 60: Hamming Distance ──────────────────────────────────────
        new PatternDef("hamming_distance_xor", "hamming_distance_popcount", "high",
            "hd_popcount.*a.*\\^.*b|popcount.*a.*\\^.*b|\\^.*b.*popcount", // popcount of XOR
            "for.*bit.*<.*32|cnt1.*=.*0.*bit|count1.*n.*-.*count1", // bit-position loop
            "hamming|hd_popcount|hamming_dist"              // naming
        ),

        // ── Sprint 60: Palindrome Partition ──────────────────────────────────
        new PatternDef("palindrome_partition_dp", "min_palindrome_cuts", "high",
            "pp_pal.*i.*\\+.*1.*j.*-.*1|is_pal.*i.*1.*j.*1",       // expand-from-ends
            "pp_dp.*j.*-.*1.*\\+.*1.*<.*pp_dp.*i|dp.*j.*1.*dp.*i", // min-cut update
            "min_pal_cuts|pp_dp|palindrome_partition"       // naming
        ),
        new PatternDef("palindrome_precompute", "palindrome_table", "medium",
            "pp_pal.*i.*i.*=.*1|pal.*i.*i.*=.*1",           // single-char palindrome
            "s.*i.*==.*s.*j.*&&.*pp_pal|s.*i.*==.*s.*j.*pp_pal", // expand condition
            "pp_pal|pal_table|is_pal"                       // naming
        ),

        // ── Sprint 61: Array Rotation (3-reversal) ───────────────────────────
        new PatternDef("rotate_reversal", "array_rotation_reversal", "high",
            "ra_reverse.*0.*n.*-.*k.*-.*1|reverse.*0.*n.*k", // reverse left part
            "while.*l.*<.*r.*t.*=.*arr|while.*l.*<.*r.*swap", // swap-while-l<r body
            "ra_reverse|rotate_array|test_rotate"           // naming
        ),

        // ── Sprint 61: Matrix Fast Exponentiation ────────────────────────────
        new PatternDef("matrix_power_square", "matrix_fast_exponentiation", "high",
            "n.*%.*2.*==.*1.*result.*=.*mat_mul|n.*%.*2.*result.*=", // odd-exp branch
            "base.*=.*mat_mul.*base.*base|mat_mul22.*base.*base",    // square base
            "mat_pow22|matrix_power|mat_pow"                // naming
        ),
        new PatternDef("matrix_multiply_2x2", "matrix_multiply", "medium",
            "C\\.v.*i.*j.*=.*0|v.*i.*j.*=.*0.*for.*k.*<.*2", // C[i][j] zero-init
            "A\\.v.*i.*k.*\\*.*B\\.v.*k.*j|v.*i.*k.*v.*k.*j", // A[i][k]*B[k][j]
            "mat_mul22|matmul_2x2|Mat22"                    // naming
        ),
        // ── Sprint 62 ─────────────────────────────────────────────────────────
        new PatternDef("tribonacci_recurrence", "tribonacci_dp", "high",
            "t\\[i\\].*=.*t\\[i-1\\].*\\+.*t\\[i-2\\].*\\+.*t\\[i-3\\]|trib.*i-1.*i-2.*i-3",
            "t\\[0\\].*=.*0.*t\\[1\\].*=.*1.*t\\[2\\].*=.*1|trib_vals.*seed",
            "tribonacci|trib_|three_term_recurrence"
        ),
        new PatternDef("kernighan_popcount", "bit_count_kernighan", "high",
            "x.*&=.*x.*-.*1.*count\\+\\+|while.*x.*x.*&.*x.*-.*1",
            "count.*\\+\\+.*while.*x|cb_popcount|bit_count_loop",
            "popcount|count_bits|bit_count|kernighan"
        ),
        new PatternDef("total_set_bits_range", "count_bits_range", "medium",
            "for.*i.*<.*CB_N.*total.*\\+=.*popcount|total.*\\+=.*c.*for.*i.*<.*n",
            "xor_counts.*\\^=.*c|for.*i.*<.*n.*bits.*i|accumulate.*bit.*count",
            "total_bits|set_bits_range|count_all_bits|cb_total"
        ),
        // ── Sprint 63 ─────────────────────────────────────────────────────────
        new PatternDef("stock_state_machine", "stock_k_transactions", "high",
            "buy1.*=.*sk_max.*buy1.*-.*p|buy1.*max.*buy1.*-.*price",
            "sell2.*=.*sk_max.*sell2.*buy2.*\\+.*p|sell2.*max.*sell2.*buy2.*price",
            "buy1.*sell1.*buy2.*sell2|stock.*trans|best_profit"
        ),
        new PatternDef("coin_change_ways", "coin_change_count_ways", "high",
            "cw_dp\\[0\\].*=.*1.*for.*ci.*for.*j.*=.*cw_coins|dp.*0.*=.*1.*for.*coin",
            "cw_dp\\[j\\].*\\+=.*cw_dp\\[j.*-.*cw_coins|dp.*j.*\\+=.*dp.*j.*coin",
            "coin_ways|ways_to_make|change_ways|cw_dp"
        ),
        new PatternDef("unbounded_knapsack_ways", "dp_unbounded_knapsack", "medium",
            "for.*ci.*for.*j.*=.*coins.*ci.*j.*<=.*CW_AMT.*\\+=|for.*coin.*j.*coin.*amount.*\\+=",
            "dp\\[j\\].*\\+=.*dp\\[j.*-.*coins|cw_dp.*j.*cw_dp.*j.*cw_coins",
            "unbounded_knapsack|coin_count|dp_ways|cw_coins"
        ),
        // ── Sprint 64 ─────────────────────────────────────────────────────────
        new PatternDef("lca_depth_leveling", "lowest_common_ancestor", "high",
            "while.*lca_depth.*a.*>.*lca_depth.*b.*a.*=.*lca_par|while.*dep.*u.*>.*dep.*v.*parent",
            "while.*a.*!=.*b.*a.*=.*lca_par.*a.*b.*=.*lca_par.*b|lca.*walk.*up",
            "lca|lowest_common_ancestor|lca_par.*lca_depth"
        ),
        new PatternDef("interval_merge_extend", "merge_overlapping_intervals", "high",
            "if.*im_starts.*i.*<=.*cur_e.*cur_e.*=.*im_ends|if.*starts.*i.*<=.*cur_end.*extend",
            "else.*im_ms.*n_merged.*=.*cur_s.*im_me.*n_merged.*=.*cur_e|else.*emit.*start.*end",
            "interval_merge|im_ms|im_me|merge_overlap"
        ),
        new PatternDef("interval_merge_flush", "interval_merge_final", "medium",
            "im_ms.*n_merged.*=.*cur_s.*im_me.*n_merged.*=.*cur_e.*n_merged\\+\\+",
            "ms.*n_merged.*cur_s.*me.*n_merged.*cur_e.*n_merged.*\\+\\+|flush.*last.*interval",
            "n_merged.*\\+\\+|interval.*emit.*final|interval_merge_flush"
        ),
        // ── Sprint 65 ─────────────────────────────────────────────────────────
        new PatternDef("flood_fill_dfs", "number_of_islands_dfs", "high",
            "if.*r.*<.*0.*r.*>=.*ni_R.*c.*<.*0.*c.*>=.*ni_C.*return|bounds.*grid.*vis.*return",
            "ni_vis.*r.*c.*=.*1.*ni_dfs.*r.*-.*1.*c.*ni_dfs.*r.*\\+.*1|vis.*1.*dfs.*neighbors",
            "num_islands|flood_fill|ni_dfs|ni_count"
        ),
        new PatternDef("islands_count_loop", "grid_component_count", "medium",
            "if.*ni_grid.*r.*c.*&&.*!ni_vis.*r.*c.*ni_dfs.*r.*c.*cnt\\+\\+",
            "for.*r.*R.*for.*c.*C.*grid.*r.*c.*vis.*r.*c.*dfs.*cnt",
            "ni_count|island_count|grid_bfs|cnt\\+\\+"
        ),
        new PatternDef("prefix_xor_build", "prefix_xor_query", "high",
            "px_table.*i.*\\+.*1.*=.*px_table.*i.*\\^.*px_arr.*i|px.*i.*=.*px.*i.*\\^.*arr.*i",
            "r.*=.*px_table.*px_qr.*i.*\\+.*1.*\\^.*px_table.*px_ql.*i|range.*xor.*px",
            "prefix_xor|px_table|range_xor|xorRange"
        ),
        new PatternDef("tarjan_scc_low_link", "tarjan_strongly_connected", "high",
            "low.*v.*=.*min.*low.*v.*disc.*u|if.*disc.*u.*<.*low.*v.*low.*v.*=.*disc.*u",
            "if.*low.*v.*==.*disc.*v.*scc|pop.*stack.*until.*v.*scc_size",
            "tarjan|tj_low|tj_disc|tj_scc|low_link"
        ),
        new PatternDef("huffman_merge_min", "huffman_tree_build", "high",
            "huf_find_min.*huf_active|find_min.*active.*freq",
            "nn.*=.*huf_n_nodes.*huf_nodes.*nn.*freq.*=.*huf_nodes.*a.*freq.*\\+.*huf_nodes.*b.*freq",
            "huffman|huf_nodes|huf_active|huf_find_min"
        ),
        new PatternDef("huffman_code_len", "huffman_dfs_assign", "medium",
            "huf_dfs.*node.*depth|if.*left.*==.*-1.*huf_code_len.*node.*=.*depth",
            "total_bits.*\\+=.*freqs.*i.*\\*.*huf_code_len.*i|weighted.*code.*length",
            "huf_dfs|huf_code_len|total_bits|huffman_code"
        ),
        new PatternDef("dfs_toposort_stack", "topological_sort_dfs_postorder", "high",
            "td_vis.*v.*=.*1.*for.*td_deg.*v.*if.*!td_vis|visited.*=.*1.*recurse.*neighbor",
            "td_stk.*td_top\\+\\+.*=.*v.*after.*recursion|stack.*push.*after.*all.*neighbors",
            "td_dfs|toposort_dfs|dfs_topo|td_stk"
        ),
        new PatternDef("nim_xor_strategy", "nim_game_sprague_grundy", "high",
            "nim_xor.*=.*pile.*0.*\\^.*pile.*1|x.*\\^=.*piles.*g.*i",
            "if.*nim_xor.*==.*0.*lose|if.*xv.*!=.*0.*n_wins",
            "nim_xor|nim_game|sprague_grundy|pile.*xor"
        ),
        new PatternDef("nim_winning_move", "nim_reduce_pile", "medium",
            "pile.*i.*\\^.*xv.*<.*pile.*i.*reduce_to|piles.*\\^.*xor.*<.*piles",
            "reduce_to.*=.*pile.*i.*\\^.*xv|winning_pile.*=.*pile.*\\^.*nim_xor",
            "reduce_to|winning_move|nim_move|pile.*xor.*reduce"
        ),
        new PatternDef("tsp_bitmask_dp", "travelling_salesman_held_karp", "high",
            "dp.*mask.*\\|.*1.*<<.*j.*j.*=.*min.*dp.*mask.*i.*\\+.*cost.*i.*j",
            "for.*mask.*for.*i.*mask.*&.*1.*<<.*i.*for.*j.*!.*mask.*&.*1.*<<.*j",
            "tsp_dp|bitmask_dp|held_karp|TSP_N"
        ),
        new PatternDef("euler_circuit_hierholzer", "hierholzer_euler_circuit", "high",
            "ec_used.*v.*i.*=.*1.*mark.*reverse.*edge|used.*v.*i.*=.*1.*reverse",
            "if.*!found.*circuit.*ec_clen.*=.*ec_stk.*--stop|pop.*to.*circuit.*when.*stuck",
            "hierholzer|euler_circuit|ec_clen|ec_circuit"
        ),
        new PatternDef("euler_all_even_degree", "euler_circuit_existence", "medium",
            "if.*ec_deg.*i.*%.*2.*!=.*0.*has_euler|all.*degrees.*even.*euler.*circuit",
            "has_euler.*=.*0.*deg.*odd|for.*i.*<.*EC_N.*deg.*%.*2.*has_euler",
            "has_euler|all_even|euler_exists|ec_deg.*%.*2"
        ),
        new PatternDef("convex_hull_cross", "graham_scan_cross_product", "high",
            "ch_cross.*oi.*ai.*bi.*px.*ai.*-.*px.*oi.*py.*bi.*-.*py.*oi|cross.*a.*-.*o.*b.*-.*o",
            "while.*ch_htop.*>=.*2.*ch_cross.*ch_hull.*ch_htop.*-.*2.*<=.*0.*ch_htop--",
            "graham_scan|ch_cross|ch_hull|ch_htop|convex_hull"
        ),
        new PatternDef("digit_dp_tight", "digit_dp_bounded", "high",
            "int.*lim.*=.*tight.*\\?.*digits.*pos.*:.*9|limit.*tight.*digit",
            "cnt.*\\+=.*dd_solve.*pos.*\\+.*1.*rem.*\\+.*d.*%.*dd_k.*tight.*&&.*d.*==.*lim",
            "dd_solve|digit_dp|dd_memo|dd_tight|dd_digits"
        ),
        new PatternDef("digit_dp_memo", "digit_dp_memoize", "medium",
            "dd_memo_set.*pos.*rem.*tight|if.*dd_memo_set.*return.*dd_memo",
            "dd_memo.*pos.*rem.*tight.*=.*cnt.*dd_memo_set.*pos.*rem.*tight.*=.*1",
            "dd_memo|digit_dp_cache|memo_set|dp_digits"
        ),
        /* Sprint 70 — suffix array + house robber */
        new PatternDef("suffix_array_sort", "suffix_array_build", "high",
            "while.*j.*>=.*0.*strcmp.*sa.*\\+.*sa.*j.*sa.*\\+.*key.*>.*0.*sa.*j.*1.*=.*sa.*j",
            "sa_cmp_suffix.*a.*b|strcmp.*sa_str.*\\+.*a.*sa_str.*\\+.*b",
            "suffix_array|sa_idx|sa_cmp|build_sa"
        ),
        new PatternDef("house_robber_rolling", "house_robber_dp", "high",
            "cur.*=.*prev2.*\\+.*arr.*i.*>.*prev1.*prev2.*\\+.*arr.*i.*:.*prev1",
            "prev2.*=.*prev1.*prev1.*=.*cur.*for.*i.*<.*n",
            "house_robber|hr_rob|rob_linear|prev2.*prev1"
        ),
        new PatternDef("suffix_array_init", "suffix_array_index_init", "medium",
            "for.*i.*=.*0.*i.*<.*n.*sa.*i.*=.*i|sa_idx.*i.*=.*i.*suffix.*init",
            "insertion.*sort.*suffix.*cmp|suffix.*sort.*index",
            "sa_idx|suffix_idx|sa_init"
        ),
        /* Sprint 71 — egg drop + unique paths */
        new PatternDef("egg_drop_dp", "egg_drop_floor_count", "high",
            "dp.*t.*e.*=.*dp.*t.*-.*1.*e.*-.*1.*\\+.*dp.*t.*-.*1.*e.*\\+.*1",
            "for.*t.*=.*1.*t.*<=.*MAX_T.*for.*ee.*=.*2.*dp.*t.*ee",
            "egg_drop|ed_dp|min_trials|dp.*eggs"
        ),
        new PatternDef("unique_paths_grid_dp", "grid_path_counting", "high",
            "up_dp.*i.*j.*=.*i.*==.*0.*||.*j.*==.*0.*?.*1.*:.*up_dp.*i.*-.*1.*j.*\\+.*up_dp.*i.*j.*-.*1",
            "for.*i.*<.*m.*for.*j.*<.*n.*dp.*i.*j.*=.*dp.*i.*-.*1.*j.*\\+.*dp.*i.*j.*-.*1",
            "unique_paths|up_dp|grid_dp|paths_grid"
        ),
        new PatternDef("egg_drop_scan", "egg_drop_min_trials_scan", "medium",
            "for.*t.*=.*1.*dp.*t.*e.*>=.*n.*return.*t|min_trials.*dp.*e.*>=.*n",
            "egg_min_trials.*n.*e.*for.*t.*<=.*MAX_T.*if.*dp.*t.*e.*>=.*n",
            "egg_min_trials|min_trials_scan|egg_floor"
        ),
        /* Sprint 72 — regex match + max product subarray */
        new PatternDef("regex_match_dp", "regex_star_dot_dp", "high",
            "if.*p.*j.*-.*1.*==.*'\\*'.*dp.*i.*j.*=.*dp.*i.*j.*-.*2",
            "dp.*i.*-.*1.*j.*&.*s.*i.*-.*1.*==.*p.*j.*-.*2.*||.*p.*j.*-.*2.*==.*'\\.'",
            "regex_dp|rm_dp|star_match|regex_match"
        ),
        new PatternDef("max_product_subarray", "max_product_min_max_dp", "high",
            "new_max.*=.*mp_max3.*arr.*i.*a.*b|max_h.*=.*new_max.*min_h.*=.*new_min",
            "int.*a.*=.*max_h.*\\*.*arr.*i.*int.*b.*=.*min_h.*\\*.*arr.*i",
            "max_product|max_h.*min_h|mp_max3|product_subarray"
        ),
        new PatternDef("regex_dp_star_init", "regex_dp_star_base_case", "medium",
            "dp.*0.*j.*=.*dp.*0.*j.*-.*2.*&&.*p.*j.*-.*1.*==.*'\\*'",
            "for.*j.*=.*2.*j.*<=.*lp.*if.*p.*j.*-.*1.*==.*'\\*'.*dp.*0.*j.*=.*dp.*0.*j.*-.*2",
            "regex_init|dp_star_zero|empty_match"
        ),
        /* Sprint 73 — articulation points + sqrt decomposition */
        new PatternDef("articulation_point_tarjan", "cut_vertex_detection", "high",
            "if.*ap_par.*u.*==.*-1.*&&.*child_cnt.*>.*1.*ap_is_ap.*u.*=.*1",
            "if.*ap_par.*u.*!=.*-1.*&&.*ap_low.*v.*>=.*ap_disc.*u.*ap_is_ap.*u.*=.*1",
            "articulation|cut_vertex|ap_is_ap|ap_disc.*ap_low"
        ),
        new PatternDef("sqrt_decomp_query", "sqrt_decomposition_range", "high",
            "for.*b.*=.*bl.*\\+.*1.*b.*<.*br.*sum.*\\+=.*sq_blk.*b|full.*blocks.*block.*sum",
            "for.*i.*=.*br.*\\*.*SQ_BS.*i.*<=.*r.*sum.*\\+=.*sq_arr.*i|partial.*right.*block",
            "sqrt_decomp|sq_blk|block_sum|sq_query"
        ),
        new PatternDef("sqrt_decomp_update", "sqrt_block_point_update", "medium",
            "sq_blk.*idx.*SQ_BS.*\\+=.*val.*-.*sq_arr.*idx|block.*i.*block_sz.*\\+=.*delta",
            "sq_arr.*idx.*=.*val.*sq_blk.*idx.*SQ_BS.*\\+=",
            "sq_update|sqrt_update|block_point_update"
        ),
        // ── Sprint 74: DAG longest path + edit distance ───────────────────────
        new PatternDef("dag_longest_path", "dag_dp_longest", "high",
            "if.*dp.*u.*\\+.*w.*>.*dp.*v.*dp.*v.*=.*dp.*u.*\\+.*w|dp.*dlp_eu.*dlp_ev.*dlp_ew",
            "for.*e.*<.*DLP_NE.*dlp_eu.*dlp_ev.*dlp_ew|topo.*dp.*relax.*edge",
            "dag_longest|dp.*topo|longest_path_dag"
        ),
        new PatternDef("edit_distance_dp", "levenshtein_distance", "high",
            "dp.*i.*j.*=.*1.*\\+.*ed_min3.*dp.*i-1.*j.*dp.*i.*j-1.*dp.*i-1.*j-1",
            "dp.*0.*j.*=.*j.*dp.*i.*0.*=.*i.*base.*case.*edit",
            "edit_distance|levenshtein|ed_dp"
        ),
        new PatternDef("edit_distance_match", "levenshtein_char_match", "medium",
            "if.*s1.*i-1.*==.*s2.*j-1.*dp.*i.*j.*=.*dp.*i-1.*j-1",
            "cost.*s1.*i.*!=.*s2.*j.*dp.*i.*j.*min.*substitution",
            "char_match|substitution_cost|edit_match"
        ),
        // ── Sprint 75: max rect sum + fenwick tree ────────────────────────────
        new PatternDef("max_rect_sum_compress", "max_rectangle_sum_2d", "high",
            "for.*l.*=.*0.*MR_COLS.*for.*r.*=.*l.*MR_COLS.*for.*i.*=.*0.*MR_ROWS.*temp.*i.*\\+=",
            "kadane1d.*temp.*MR_ROWS|max_here.*a.*i.*max_so_far",
            "max_rect_sum|2d_kadane|col_compress"
        ),
        new PatternDef("fenwick_update", "binary_indexed_tree", "high",
            "for.*i\\+\\+.*i.*<=.*FW_N.*i.*\\+=.*i.*&.*-i.*fw_bit.*i.*\\+=.*delta",
            "fw_bit.*i.*\\+=.*delta.*i.*\\+=.*i.*&.*\\(-i\\)",
            "fenwick|bit.*update|binary_indexed"
        ),
        new PatternDef("fenwick_query", "bit_prefix_sum", "medium",
            "for.*i\\+\\+.*i.*>.*0.*i.*-=.*i.*&.*-i.*s.*\\+=.*fw_bit",
            "fw_query.*i.*-.*1|range.*query.*fw_range",
            "bit_query|fenwick_query|prefix_sum_bit"
        ),
        // ── Sprint 76: sliding window max + count distinct window ─────────────
        new PatternDef("sliding_window_deque_max", "monotonic_deque_max", "high",
            "if.*front.*<=.*back.*dq.*front.*<=.*i.*-.*SWM_K.*front\\+\\+",
            "while.*front.*<=.*back.*swm_arr.*dq.*back.*<=.*swm_arr.*i.*back--",
            "sliding_max|deque_max|window_max"
        ),
        new PatternDef("sliding_distinct_freq", "count_distinct_sliding_window", "high",
            "freq.*cdw_arr.*i.*\\+\\+.*if.*freq.*cdw_arr.*i.*==.*1.*distinct\\+\\+",
            "freq.*cdw_arr.*i.*-.*CDW_K.*--.*if.*freq.*cdw_arr.*i.*-.*CDW_K.*==.*0.*distinct--",
            "count_distinct|freq_window|distinct_slide"
        ),
        new PatternDef("sliding_window_pattern", "sliding_window_generic", "medium",
            "if.*i.*>=.*CDW_K.*freq.*cdw_arr.*i.*-.*CDW_K.*--|if.*i.*>=.*k.*remove.*arr.*i.*-.*k",
            "if.*i.*>=.*k.*-.*1.*sum.*\\+=.*out_len\\+\\+|window.*emit.*after.*k.*elements",
            "sliding_window|window_slide|sw_generic"
        ),
        // ── Sprint 77: GCD array + primorial ─────────────────────────────────
        new PatternDef("gcd_euclidean_array", "gcd_lcm_array_reduction", "high",
            "while.*b.*int.*t.*=.*b.*b.*=.*a.*%.*b.*a.*=.*t.*return.*a|ga_gcd.*euclidean",
            "for.*i.*=.*1.*n.*tg.*=.*ga_gcd.*tg.*arr.*i.*tl.*=.*ga_lcm.*tl.*arr.*i",
            "gcd_array|lcm_array|gcd_reduce"
        ),
        new PatternDef("primorial_compute", "primorial_prime_product", "high",
            "prim.*=.*prim.*\\*.*\\(uint32_t\\)primes.*k|primorial.*product.*primes",
            "for.*n.*=.*2.*pc.*<.*5.*n\\+\\+.*if.*pr_is_prime.*n.*primes.*pc\\+\\+.*=.*n",
            "primorial|prime_product|first_k_primes"
        ),
        new PatternDef("trial_division_prime", "is_prime_trial_division", "medium",
            "for.*i.*=.*2.*i.*\\*.*i.*<=.*n.*i\\+\\+.*if.*n.*%.*i.*==.*0.*return.*0",
            "if.*n.*<.*2.*return.*0.*trial.*division|pr_is_prime.*trial",
            "is_prime|trial_division|prime_check"
        ),
        /* Sprint 78: Gray Code + Fisher-Yates */
        new PatternDef("gray_code_xor_shift", "gray_code_generate", "high",
            "G.*i.*=.*i.*\\^.*i.*>>.*1|gc_code.*i.*=.*i.*\\^.*i.*>>.*1",
            "popcount.*G.*i.*\\^.*G.*i.*1.*==.*1|single.*bit.*transition.*gray",
            "gray_code|gc_code|G.*i.*xor.*shift"
        ),
        new PatternDef("gray_code_property", "gray_code_single_bit_differ", "medium",
            "diff.*=.*gc_code.*i.*\\^.*gc_code.*i.*1|xor.*consecutive.*gray.*code",
            "diff.*&.*diff.*-.*1.*!=.*0.*invalid|single_bit.*differ.*check",
            "gray_valid|gray_diff|single_bit_differ"
        ),
        new PatternDef("fisher_yates_shuffle", "knuth_shuffle_deterministic", "high",
            "for.*i.*=.*0.*n.*-.*2.*j.*=.*i.*\\+.*.*%.*n.*-.*i.*swap.*arr.*i.*arr.*j",
            "int.*t.*=.*arr.*i.*arr.*i.*=.*arr.*j.*arr.*j.*=.*t|swap.*permute.*inplace",
            "fisher_yates|knuth_shuffle|fy_arr"
        ),
        /* Sprint 79: Partition Equal Sum + Jump Game II */
        new PatternDef("partition_equal_sum_dp", "subset_sum_boolean_dp", "high",
            "dp.*0.*=.*1.*for.*num.*for.*j.*=.*target.*down.*num.*dp.*j.*|=.*dp.*j.*-.*num",
            "total.*%.*2.*!=.*0.*impossible|odd_total.*not_partition",
            "partition_equal|subset_sum_dp|pe_dp"
        ),
        new PatternDef("jump_game_greedy", "min_jumps_greedy", "high",
            "far.*=.*max.*far.*i.*\\+.*arr.*i|if.*i.*\\+.*arr.*i.*>.*far.*far.*=.*i.*arr.*i",
            "if.*i.*==.*cur_end.*jumps.*\\+\\+.*cur_end.*=.*far",
            "jump_game2|min_jumps|jg2_min"
        ),
        new PatternDef("jump_game_bound", "greedy_current_range", "medium",
            "cur_end.*=.*0.*far.*=.*0.*jumps.*=.*0|init.*greedy.*jump.*range",
            "for.*i.*=.*0.*n.*-.*1.*if.*far.*>=.*n.*-.*1.*break",
            "cur_end.*far|greedy_range|jump_bound"
        ),
        /* Sprint 80: Perfect Squares + Interleaving Strings */
        new PatternDef("perfect_squares_dp", "min_perfect_squares", "high",
            "for.*j.*=.*1.*j.*\\*.*j.*<=.*i.*j\\+\\+.*dp.*i.*=.*min.*dp.*i.*dp.*i.*-.*j.*j.*1",
            "dp.*0.*=.*0.*for.*i.*=.*1.*dp.*i.*=.*INF|PS_INF.*init.*dp",
            "perfect_squares|ps_dp|min_sq"
        ),
        new PatternDef("interleave_dp", "interleaving_string_dp", "high",
            "dp.*i.*j.*=.*dp.*i-1.*j.*&&.*s1.*i-1.*==.*s3.*i\\+j-1.*||.*dp.*i.*j-1.*&&.*s2.*j-1.*==.*s3.*i\\+j-1",
            "dp.*0.*0.*=.*1.*dp.*i.*0.*=.*dp.*i-1.*0.*&&.*s1.*i-1.*==.*s3.*i-1",
            "interleave_dp|is_interleave|il_dp"
        ),
        new PatternDef("interleave_base_case", "interleaving_init", "medium",
            "for.*j.*=.*1.*n2.*dp.*0.*j.*=.*dp.*0.*j-1.*&&.*s2.*j-1.*==.*s3.*j-1",
            "dp.*0.*0.*=.*1.*base.*case.*interleave|empty.*prefix.*init",
            "il_base|interleave_init|dp_0_0"
        ),
        /* Sprint 81: Activity Selection + Bipartite Matching */
        new PatternDef("activity_selection_greedy", "interval_scheduling_greedy", "high",
            "if.*start.*i.*>=.*last_end.*count.*\\+\\+.*last_end.*=.*end.*i|as_start.*>=.*ale",
            "sort.*by.*end.*time.*last_end.*-INF.*count.*=.*0|greedy.*earliest.*end",
            "activity_select|interval_sched|as_start"
        ),
        new PatternDef("bipartite_matching_augment", "hungarian_augmenting_path", "high",
            "bpm_try.*u.*for.*i.*<.*BPM_R.*v.*=.*bpm_adj.*u.*i.*if.*!bpm_vis.*v",
            "if.*bpm_match_r.*v.*==.*-1.*||.*bpm_try.*bpm_match_r.*v.*bpm_match_r.*v.*=.*u",
            "bipartite_match|augmenting_path|bpm_try"
        ),
        new PatternDef("max_matching_driver", "maximum_matching_count", "medium",
            "for.*u.*=.*0.*BPM_L.*for.*i.*<.*BPM_R.*bpm_vis.*i.*=.*0.*if.*bpm_try.*u.*match.*\\+\\+",
            "max_match.*=.*0.*for.*u.*left.*vis.*zero.*try.*augment",
            "max_match|matching_count|bpm_driver"
        ),
        /* Sprint 82: Modular Exponentiation + Extended GCD */
        new PatternDef("modular_exponentiation", "fast_binary_power", "high",
            "while.*exp.*>.*0.*if.*exp.*&.*1.*result.*=.*result.*\\*.*base.*%.*mod.*base.*=.*base.*\\*.*base.*%.*mod.*exp.*>>=.*1",
            "result.*=.*1.*base.*%=.*mod|me_pow.*binary.*exponent",
            "mod_exp|me_pow|binary_power|modpow"
        ),
        new PatternDef("extended_euclidean", "bezout_coefficients", "high",
            "if.*b.*==.*0.*\\*x.*=.*1.*\\*y.*=.*0.*return.*a|ge_ext.*base.*case",
            "\\*x.*=.*y1.*\\*y.*=.*x1.*-.*a.*b.*\\*.*y1|bezout.*coefficient.*update",
            "gcd_ext|ge_ext|bezout|extended_gcd"
        ),
        new PatternDef("extended_gcd_coefficients", "modular_inverse_via_ext_gcd", "medium",
            "a.*\\*.*x.*\\+.*b.*\\*.*y.*==.*g|bezout.*identity.*verify",
            "inv_mod.*=.*x.*%.*mod.*if.*inv_mod.*<.*0.*inv_mod.*\\+.*mod|modular.*inverse",
            "inv_mod|mod_inverse|bezout_identity"
        ),
        /* Sprint 83: Matrix Exponentiation + Derangements */
        new PatternDef("matrix_exponentiation_2x2", "fibonacci_matrix_power", "high",
            "mat_mul.*res.*A.*res.*mat_mul.*A.*A.*A.*n.*>>=.*1|while.*n.*>.*0.*mat.*mul.*power",
            "res.*0.*0.*=.*1.*0.*0.*1.*A.*0.*0.*=.*1.*1.*1.*0|identity.*matrix.*init",
            "mat_exp|matrix_power|fib_mat|me2_fib"
        ),
        new PatternDef("matrix_multiply_2x2", "2x2_matrix_multiply_modular", "medium",
            "t.*i.*j.*=.*t.*i.*j.*\\+.*a.*i.*k.*\\*.*b.*k.*j.*%.*mod|2x2.*matmul",
            "for.*i.*<.*2.*for.*j.*<.*2.*for.*k.*<.*2|double.*loop.*matrix.*product",
            "mat_mul|me2_mul|matrix_multiply"
        ),
        new PatternDef("derangement_recurrence", "subfactorial_dp", "high",
            "dp.*n.*=.*n.*-.*1.*\\*.*dp.*n.*-.*1.*\\+.*dp.*n.*-.*2|dr_dp.*recurrence",
            "dp.*0.*=.*1.*dp.*1.*=.*0.*derangement.*base|subfactorial.*base.*case",
            "derange|subfactorial|dr_dp|no_fixed_point"
        ),
        /* Sprint 84: Stirling Numbers + Bell Numbers */
        new PatternDef("stirling_second_kind", "set_partition_stirling", "high",
            "st.*n.*k.*=.*k.*\\*.*st.*n-1.*k.*\\+.*st.*n-1.*k-1|stirling.*recurrence",
            "st.*0.*0.*=.*1.*st.*n.*0.*=.*0.*for.*n.*>.*0|stirling.*base.*case",
            "stirling2|st.*n.*k|set_partition"
        ),
        new PatternDef("bell_triangle", "bell_number_compute", "high",
            "bell.*i.*0.*=.*bell.*i-1.*i-1|start.*row.*from.*last.*diagonal",
            "bell.*i.*j.*=.*bell.*i.*j-1.*\\+.*bell.*i-1.*j-1|bell.*triangle.*recurrence",
            "bell_num|bn_bell|bell_triangle"
        ),
        /* Sprint 85: Min Window Substring + Max Gap */
        new PatternDef("min_window_substring", "sliding_window_coverage", "high",
            "cnt_s.*right.*\\+\\+.*if.*cnt_s.*==.*cnt_t.*formed.*\\+\\+|window.*expand.*right",
            "while.*formed.*==.*required.*if.*right.*-.*left.*\\+.*1.*<.*min_len|shrink.*left",
            "min_window|mw_cnt_s|sliding_coverage"
        ),
        new PatternDef("max_gap_linear", "maximum_consecutive_gap", "medium",
            "for.*i.*=.*1.*n.*if.*arr.*i.*-.*arr.*i-1.*>.*mg.*mg.*=.*arr.*i.*-.*arr.*i-1",
            "sort.*first.*then.*linear.*scan.*gap|mg_max_gap",
            "max_gap|mg_max|consecutive_gap"
        ),
        /* Sprint 86: SOS DP + Inclusion-Exclusion */
        new PatternDef("sum_over_subsets_dp", "bitmask_subset_sum", "high",
            "for.*i.*<.*n.*for.*mask.*<.*M.*if.*mask.*&.*1.*<<.*i.*f.*mask.*\\+=.*f.*mask.*\\^.*1.*<<.*i",
            "f.*mask.*=.*a.*mask.*init.*sos.*dp|sum.*over.*subsets.*bitmask",
            "sos_dp|sos_f|subset_sum_mask"
        ),
        new PatternDef("inclusion_exclusion_count", "count_divisible_union", "high",
            "N/2.*\\+.*N/3.*\\+.*N/5.*-.*N/6.*-.*N/10.*-.*N/15.*\\+.*N/30|incl_excl.*formula",
            "\\|A.*\\|.*\\+.*\\|B.*\\|.*-.*\\|A.*B.*\\||inclusion.*exclusion.*principle",
            "inclusion_excl|incl_excl|union_count"
        ),
        /* Sprint 87: Roman to Int + Next Permutation */
        new PatternDef("roman_numeral_decode", "roman_to_integer", "high",
            "if.*rval.*s.*i.*<.*rval.*s.*i.*1.*result.*-=.*rval|subtraction.*rule.*roman",
            "switch.*I.*=.*1.*V.*=.*5.*X.*=.*10.*L.*=.*50.*C.*=.*100|roman.*value.*table",
            "roman_to_int|rval|roman_decode"
        ),
        new PatternDef("next_permutation_inplace", "lexicographic_next_permutation", "high",
            "i.*=.*n-2.*while.*i.*>=.*0.*&&.*arr.*i.*>=.*arr.*i.*1.*i--|find.*rightmost.*ascent",
            "j.*=.*n-1.*while.*arr.*j.*<=.*arr.*i.*j--.*swap.*arr.*i.*arr.*j|find.*swap.*point",
            "next_perm|np_next|next_permutation"
        ),
        new PatternDef("next_perm_reverse_suffix", "permutation_suffix_reverse", "medium",
            "lo.*=.*i.*\\+.*1.*hi.*=.*n.*-.*1.*while.*lo.*<.*hi.*swap.*arr.*lo.*arr.*hi.*lo\\+\\+.*hi--|reverse.*suffix",
            "reverse.*arr.*i.*1.*arr.*n-1|suffix.*reversal.*permutation",
            "np_reverse|perm_suffix|reverse_tail"
        ),
        /* Sprint 88: LCS DP + LCA Subarray */
        new PatternDef("longest_common_subsequence", "lcs_dp_classic", "high",
            "if.*s1.*i-1.*==.*s2.*j-1.*dp.*i.*j.*=.*dp.*i-1.*j-1.*\\+.*1.*else.*dp.*i.*j.*=.*max",
            "dp.*0.*j.*=.*0.*dp.*i.*0.*=.*0.*lcs.*init|lcs_dp.*base.*case",
            "lcs_dp|lcs_len|longest_common_subseq"
        ),
        new PatternDef("longest_common_subarray_dp", "contiguous_match_dp", "high",
            "dp.*i.*j.*=.*a1.*i-1.*==.*a2.*j-1.*?.*dp.*i-1.*j-1.*\\+.*1.*:.*0|lcsa.*contiguous",
            "if.*dp.*i.*j.*>.*max_len.*max_len.*=.*dp.*i.*j|track.*max.*subarray.*len",
            "lca_subarray|lcsa_dp|longest_common_subarray"
        ),
        /* Sprint 89: Merge Intervals + Wiggle Sort */
        new PatternDef("merge_overlapping_intervals", "interval_merge_sweep", "high",
            "if.*iv.*i.*s.*<=.*res.*cnt.*e.*if.*iv.*i.*e.*>.*res.*cnt.*e.*res.*cnt.*e.*=.*iv.*i.*e|overlap.*extend",
            "else.*res.*cnt\\+\\+.*=.*iv.*i|non.*overlap.*append",
            "merge_intervals|merge_ivl|mi_res"
        ),
        new PatternDef("wiggle_sort_inplace", "alternating_hi_lo_sort", "high",
            "if.*i.*&.*1.*&&.*arr.*i.*<.*arr.*i-1.*swap|odd.*index.*must.*be.*peak",
            "else.*if.*!.*i.*&.*1.*&&.*arr.*i.*>.*arr.*i-1.*swap|even.*index.*must.*be.*valley",
            "wiggle_sort|ws_arr|alternating_sort"
        ),
        /* Sprint 86: Longest Common Prefix + Power Set */
        new PatternDef("longest_common_prefix", "lcp_vertical_scan", "high",
            "for.*col.*=.*0.*for.*each.*str.*if.*str.*col.*!=.*c.*return.*col",
            "c.*=.*strs.*0.*col.*for.*i.*=.*1.*n.*if.*strs.*i.*col.*!=.*c",
            "lcp|longest_common_prefix|lcp_len"
        ),
        new PatternDef("power_set_bitmask", "subset_enumeration_bitmask", "high",
            "for.*mask.*=.*0.*mask.*<.*1.*<<.*n.*mask.*\\+\\+",
            "for.*i.*=.*0.*i.*<.*n.*i.*\\+\\+.*if.*mask.*&.*1.*<<.*i",
            "power_set|subset_enum|bitmask_subset"
        ),
        new PatternDef("subset_size_popcount", "subset_element_count", "medium",
            "popcount.*mask|__builtin_popcount.*mask|count_bits.*mask",
            "subset_size.*=.*0.*for.*i.*mask.*&.*1.*<<.*i.*size.*\\+\\+",
            "subset_size|popcount_mask|bit_count_mask"
        ),
        /* Sprint 87: Maximal Square + Bucket Sort */
        new PatternDef("maximal_square_dp", "largest_square_of_ones", "high",
            "dp.*i.*j.*=.*MS_MIN3.*dp.*i-1.*j.*dp.*i.*j-1.*dp.*i-1.*j-1.*\\+.*1",
            "if.*mat.*i.*j.*==.*1.*if.*i.*==.*0.*||.*j.*==.*0.*dp.*i.*j.*=.*1",
            "maximal_square|max_side|dp_sq"
        ),
        new PatternDef("bucket_sort_integer", "counting_bucket_sort", "high",
            "for.*i.*=.*0.*i.*<.*range.*i.*\\+\\+.*bucket.*i.*=.*0",
            "for.*i.*=.*0.*i.*<.*n.*i.*\\+\\+.*bucket.*arr.*i.*\\+\\+",
            "bucket_sort|bucket_cnt|counting_sort"
        ),
        new PatternDef("bucket_rebuild_sorted", "bucket_sort_scatter", "medium",
            "for.*i.*=.*0.*i.*<.*range.*while.*bucket.*i.*--.*>.*0.*arr.*idx.*\\+\\+.*=.*i",
            "idx.*=.*0.*for.*i.*=.*0.*range.*while.*bucket.*i.*>.*0",
            "bucket_rebuild|scatter_sorted|sort_idx"
        ),
        /* Sprint 88: Subarray XOR + Valid Parentheses */
        new PatternDef("subarray_xor_count", "prefix_xor_frequency", "high",
            "px.*\\^=.*arr.*i.*res.*\\+=.*freq.*px.*\\^.*k",
            "freq.*0.*=.*1.*for.*i.*=.*0.*n.*px.*\\^=.*arr.*i",
            "subarray_xor|xor_count|px_freq"
        ),
        new PatternDef("valid_parentheses_stack", "bracket_matching_stack", "high",
            "if.*c.*==.*\\(.*||.*c.*==.*\\[.*||.*c.*==.*\\{.*stk.*top.*\\+\\+.*=.*c",
            "if.*top.*==.*0.*return.*0.*char.*t.*=.*stk.*top.*-.*1",
            "valid_paren|bracket_match|is_valid_paren"
        ),
        new PatternDef("stack_mismatch_check", "closing_bracket_validation", "medium",
            "if.*c.*==.*\\).*&&.*t.*!=.*\\(.*||.*c.*==.*\\].*&&.*t.*!=.*\\[",
            "return.*top.*==.*0.*empty.*stack.*means.*all.*matched",
            "paren_mismatch|close_check|bracket_valid"
        ),
        /* Sprint 89: Count Rooms + Dependency Order */
        new PatternDef("count_rooms_dfs", "grid_component_count_dfs", "high",
            "if.*r.*<.*0.*||.*r.*>=.*R.*||.*c.*<.*0.*||.*c.*>=.*C.*return",
            "if.*!cr_grid.*r.*c.*||.*cr_vis.*r.*c.*return.*cr_vis.*r.*c.*=.*1",
            "count_rooms|grid_dfs|connected_components"
        ),
        new PatternDef("dependency_order_kahn", "topological_sort_bfs", "high",
            "for.*i.*=.*0.*i.*<.*n.*i.*\\+\\+.*if.*indeg.*i.*==.*0.*q.*back.*\\+\\+.*=.*i",
            "if.*--indeg.*v.*==.*0.*q.*back.*\\+\\+.*=.*v",
            "dependency_order|kahn_bfs|topo_sort"
        ),
        new PatternDef("toposort_order_validate", "dag_order_position_check", "medium",
            "pos.*order.*i.*=.*i.*for.*i.*=.*0.*cnt",
            "if.*pos.*edges.*0.*>=.*pos.*edges.*1.*valid.*=.*0",
            "topo_validate|pos_check|dag_valid"
        ),
        /* Sprint 90: Trie Ops + Chain Pairs */
        new PatternDef("trie_insert_search", "trie_array_node_ops", "high",
            "if.*!tr_ch.*cur.*c.*int.*nn.*=.*tr_sz.*\\+\\+.*tr_ch.*cur.*c.*=.*nn",
            "cur.*=.*tr_ch.*cur.*c.*for.*s.*s.*\\+\\+.*c.*=.*\\*s.*-.*a",
            "trie_insert|tr_ch|trie_ops"
        ),
        new PatternDef("trie_exact_search", "trie_end_flag_lookup", "high",
            "if.*!tr_ch.*cur.*c.*return.*0.*cur.*=.*tr_ch.*cur.*c",
            "return.*tr_end.*cur.*exact.*word.*match.*requires.*end.*flag",
            "trie_search|tr_end|trie_exact"
        ),
        new PatternDef("chain_pairs_greedy", "longest_pair_chain_greedy", "high",
            "if.*pa.*i.*>.*last_b.*chain.*\\+\\+.*xb.*\\^=.*pb.*i.*last_b.*=.*pb.*i",
            "insertion.*sort.*pb.*j.*>.*kb.*pa.*j\\+1.*=.*pa.*j.*pb.*j\\+1.*=.*pb.*j",
            "chain_pairs|longest_chain|greedy_chain"
        ),
        /* Sprint 91: Circular Buffer + Spiral Matrix */
        new PatternDef("circular_buffer_ops", "ring_buffer_head_tail", "high",
            "buf.*tail.*=.*v.*tail.*=.*tail.*\\+.*1.*%.*cap",
            "val.*=.*buf.*head.*head.*=.*head.*\\+.*1.*%.*cap",
            "circular_buffer|ring_buf|head_tail"
        ),
        new PatternDef("spiral_matrix_boundary", "spiral_traversal_shrink", "high",
            "for.*c.*=.*left_b.*c.*<=.*right_b.*spiral.*idx.*\\+\\+.*=.*mat.*top.*c.*top.*\\+\\+",
            "for.*r.*=.*top.*r.*<=.*bot.*spiral.*idx.*\\+\\+.*=.*mat.*r.*right_b.*right_b.*--",
            "spiral_matrix|boundary_shrink|top_bot_left_right"
        ),
        new PatternDef("spiral_inner_guards", "spiral_direction_guards", "medium",
            "if.*top.*<=.*bot.*for.*c.*=.*right_b.*c.*>=.*left_b.*bot.*--",
            "if.*left_b.*<=.*right_b.*for.*r.*=.*bot.*r.*>=.*top.*left_b.*\\+\\+",
            "spiral_guard|inner_spiral|spiral_reverse"
        ),
        /* Sprint 92: Max XOR Pair + Rotate Image */
        new PatternDef("max_xor_pair_brute", "pairwise_xor_top2", "high",
            "for.*i.*<.*n.*for.*j.*=.*i\\+1.*j.*<.*n.*v.*=.*arr.*i.*\\^.*arr.*j",
            "if.*v.*>.*mx.*mx2.*=.*mx.*mx.*=.*v.*else.*if.*v.*>.*mx2.*mx2.*=.*v",
            "max_xor|pairwise_xor|xor_pair"
        ),
        new PatternDef("rotate_image_90cw", "transpose_then_row_reverse", "high",
            "for.*i.*<.*n.*for.*j.*=.*i\\+1.*j.*<.*n.*swap.*m.*i.*j.*m.*j.*i",
            "for.*i.*<.*n.*lo.*=.*0.*hi.*=.*n-1.*while.*lo.*<.*hi.*swap.*m.*i.*lo.*m.*i.*hi",
            "rotate_image|transpose_reverse|rotate_90cw"
        ),
        new PatternDef("rotate_diagonal_sum", "post_rotation_main_diagonal", "medium",
            "for.*i.*<.*n.*diag.*\\+=.*m.*i.*i",
            "g_result.*n.*<<.*16.*diag.*<<.*8.*m.*0.*0",
            "rotate_diag|post_rotate_check|diag_sum"
        ),
        /* Sprint 93: Meeting Rooms + Decode Ways */
        new PatternDef("meeting_rooms_sort_check", "interval_attend_all", "high",
            "for.*i.*=.*1.*i.*<.*3.*if.*ss.*i.*<.*se.*i-1.*can_attend.*=.*0",
            "insertion.*sort.*ss.*j.*>.*ks.*ss.*j\\+1.*=.*ss.*j.*se.*j\\+1.*=.*se.*j",
            "meeting_rooms|can_attend|interval_attend"
        ),
        new PatternDef("decode_ways_dp", "string_digit_decode_dp", "high",
            "dp.*0.*=.*1.*dp.*1.*=.*str.*0.*!=.*0.*?.*1.*:.*0",
            "if.*str.*i-1.*!=.*0.*dp.*i.*\\+=.*dp.*i-1.*t.*=.*str.*i-2.*-.*0.*\\*.*10.*\\+.*str.*i-1.*-.*0",
            "decode_ways|digit_dp|string_decode"
        ),
        new PatternDef("decode_ways_two_char", "two_char_decode_range", "medium",
            "if.*t.*>=.*10.*&&.*t.*<=.*26.*dp.*i.*\\+=.*dp.*i-2",
            "t.*=.*str.*i-2.*-.*48.*\\*.*10.*\\+.*str.*i-1.*-.*48",
            "two_char_decode|valid_two_digit|dp_two_char"
        ),
        /* Sprint 94: Two Sum Pairs + Task Scheduler */
        new PatternDef("two_sum_two_pointer", "sorted_pair_sum_scan", "high",
            "lo.*=.*0.*hi.*=.*n.*-.*1.*while.*lo.*<.*hi.*s.*=.*arr.*lo.*\\+.*arr.*hi",
            "if.*s.*==.*t.*cnt.*\\+\\+.*lo.*\\+\\+.*hi.*--.*else.*if.*s.*<.*t.*lo.*\\+\\+.*else.*hi.*--",
            "two_sum_pairs|two_pointer_sum|pair_sum_count"
        ),
        new PatternDef("task_scheduler_idle", "cpu_task_cooldown_formula", "high",
            "slots.*=.*maxf.*-.*1.*\\*.*cooldown.*\\+.*1.*\\+.*count_maxf",
            "result.*=.*slots.*>.*total.*?.*slots.*:.*total",
            "task_scheduler|idle_slots|cpu_cooldown"
        ),
        new PatternDef("max_freq_count", "frequency_max_and_count", "medium",
            "for.*i.*<.*ntasks.*if.*freq.*i.*>.*maxf.*maxf.*=.*freq.*i",
            "for.*i.*<.*ntasks.*if.*freq.*i.*==.*maxf.*count_maxf.*\\+\\+",
            "max_freq|count_maxfreq|freq_peak"
        ),
        /* Sprint 95: Consecutive Seq + Dice Combinations */
        new PatternDef("longest_consecutive_seq", "consecutive_run_scan", "high",
            "for.*j.*<.*n.*if.*arr.*j.*==.*arr.*i.*-.*1.*is_start.*=.*0.*break",
            "while.*go.*go.*=.*0.*for.*j.*<.*n.*if.*arr.*j.*==.*cur.*len.*\\+\\+.*cur.*\\+\\+",
            "consecutive_seq|longest_run|lcs_scan"
        ),
        new PatternDef("dice_combinations_dp", "dice_target_sum_2d_dp", "high",
            "dp.*0.*0.*=.*1.*for.*i.*=.*1.*i.*<=.*d.*for.*j.*=.*i.*j.*<=.*i\\*f",
            "for.*k.*=.*1.*k.*<=.*f.*&&.*k.*<=.*j.*dp.*i.*j.*\\+=.*dp.*i-1.*j-k",
            "dice_combinations|dice_dp|target_sum_dp"
        ),
        new PatternDef("dice_dp_bounds_guard", "dice_dp_face_upper_bound", "medium",
            "j.*<=.*i\\*f.*&&.*j.*<=.*target.*k.*<=.*f.*&&.*k.*<=.*j",
            "dp.*i-1.*j-k.*accumulate.*from.*previous.*dice.*count",
            "dice_bounds|face_limit|dp_dice_guard"
        ),
        /* Sprint 96: Max Points on Line + Palindrome Number */
        new PatternDef("max_points_on_line", "cross_product_collinearity", "high",
            "long.*dx.*\\*.*dy2.*==.*long.*dx2.*\\*.*dy",
            "dx.*=.*px.*j.*-.*px.*i.*dy.*=.*py.*j.*-.*py.*i.*for.*k.*!=.*i.*!=.*j",
            "max_points_line|cross_product|collinear_check"
        ),
        new PatternDef("palindrome_number_rev", "digit_reversal_palindrome", "high",
            "if.*n.*<.*0.*return.*0.*rev.*=.*0.*orig.*=.*n",
            "while.*n.*>.*0.*rev.*=.*rev.*\\*.*10.*\\+.*n.*%.*10.*n.*/=.*10",
            "palindrome_num|digit_reverse|num_palindrome"
        ),
        new PatternDef("palindrome_rev_compare", "reversed_digit_equality", "medium",
            "return.*long.*orig.*==.*rev",
            "xr.*\\^=.*uint32_t.*nums.*i.*count.*\\+\\+.*if.*is_pal_num",
            "pal_compare|rev_equal|num_pal_check"
        ),
        /* Sprint 97: Balanced Partition + Anagram Groups */
        new PatternDef("balanced_partition_dp", "equal_subset_sum_knapsack", "high",
            "if.*sum.*&.*1.*bal.*=.*0.*continue.*t.*=.*sum.*2",
            "for.*i.*<.*n.*for.*j.*=.*t.*j.*>=.*arr.*i.*j.*--.*if.*dp.*j.*-.*arr.*i.*dp.*j.*=.*1",
            "balanced_partition|subset_sum_equal|partition_dp"
        ),
        new PatternDef("anagram_group_freq", "anagram_detection_freq_vector", "high",
            "for.*c.*=.*words.*i.*\\*c.*freq.*\\*c.*-.*a.*\\+\\+.*for.*c.*=.*words.*j.*\\*c.*freq.*\\*c.*-.*a.*--",
            "for.*k.*<.*26.*if.*freq.*k.*is_ana.*=.*0.*break",
            "anagram_groups|freq_vector|anagram_detect"
        ),
        new PatternDef("group_size_tracking", "word_group_size_max_xor", "medium",
            "gsz.*\\+\\+.*matched.*j.*=.*1.*group_sizes.*ng.*\\+\\+.*=.*gsz",
            "for.*i.*<.*ng.*if.*group_sizes.*i.*>.*maxg.*maxg.*=.*group_sizes.*i",
            "group_sizes|word_groups|anagram_cluster"
        ),
        // Sprint 98 — skip list / treap
        new PatternDef("skip_list_two_level", "skip_list_express_base", "high",
            "express_idx.*\\[.*\\].*base.*\\[.*\\].*prev_base.*e.*<.*N_EXPRESS",
            "base_scan.*start_idx.*target.*for.*i.*=.*start_idx.*i.*<.*N_ELEM",
            "skip_list|express_lane|two_level_search"
        ),
        new PatternDef("skip_list_express_lane", "skip_list_forward_pointer", "high",
            "for.*e.*=.*0.*e.*<.*N_EXPRESS.*idx.*=.*express_idx.*e.*base.*idx.*>.*target.*break",
            "if.*base.*idx.*==.*target.*return.*1.*prev_base.*=.*idx",
            "skip_list_fwd|express_search|skip_forward"
        ),
        new PatternDef("skip_list_fallback_scan", "skip_list_base_lane_scan", "medium",
            "return.*base_scan.*prev_base.*target|base_scan.*after.*express.*lane",
            "for.*i.*=.*start_idx.*i.*<.*N_ELEM.*if.*base.*i.*==.*target.*return.*1",
            "base_scan|fallback_scan|skip_linear"
        ),
        // Sprint 99 — turbulent subarray / min cost staircase
        new PatternDef("turbulent_subarray_dp", "alternating_dp_inc_dec", "high",
            "dp_inc.*i.*=.*dp_dec.*i.*-.*1.*\\+.*1.*arr.*i.*>.*arr.*i.*-.*1",
            "dp_dec.*i.*=.*dp_inc.*i.*-.*1.*\\+.*1.*arr.*i.*<.*arr.*i.*-.*1",
            "turbulent|dp_inc.*dp_dec|alternating_dp"
        ),
        new PatternDef("min_cost_staircase", "minimum_cost_climb_dp", "high",
            "dp.*i.*=.*cost.*i.*\\+.*prev.*dp.*i.*-.*1.*dp.*i.*-.*2",
            "return.*dp.*n.*-.*1.*<.*dp.*n.*-.*2.*dp.*n.*-.*1.*dp.*n.*-.*2",
            "min_cost_stair|staircase_dp|climb_cost"
        ),
        new PatternDef("turbulent_equal_reset", "turbulent_equal_element_break", "medium",
            "dp_inc.*i.*=.*dp_dec.*i.*=.*1.*arr.*i.*==.*arr.*i.*-.*1",
            "equal.*arr.*i.*==.*arr.*i.*-.*1.*reset.*dp_inc.*dp_dec.*1",
            "turbulent_reset|equal_reset|turbulent_equal"
        ),
        // Sprint 100 — longest valid parens / count digit 1s
        new PatternDef("longest_valid_parens_dp", "valid_parens_dp_stack", "high",
            "if.*s.*i.*==.*')'.*s.*i.*-.*1.*==.*'('.*dp.*i.*=.*dp.*i.*-.*2.*\\+.*2",
            "if.*dp.*i.*-.*1.*>.*0.*j.*=.*i.*-.*dp.*i.*-.*1.*-.*1.*s.*j.*==.*'('",
            "valid_parens|longest_parens_dp|paren_dp"
        ),
        new PatternDef("count_digit_ones", "count_1s_digit_position", "high",
            "for.*pos.*=.*1.*pos.*<=.*n.*pos.*\\*=.*10.*higher.*=.*n.*pos.*\\*.*10",
            "if.*current.*>.*1.*count.*\\+=.*higher.*\\+.*1.*pos|if.*current.*==.*1.*lower",
            "count_digit_1|digit_ones_pos|ones_each_pos"
        ),
        new PatternDef("digit_position_hcl", "higher_current_lower_formula", "medium",
            "higher.*=.*n.*pos.*10.*current.*=.*n.*pos.*%.*10.*lower.*=.*n.*%.*pos",
            "current.*>.*1.*higher.*\\+.*1.*pos|current.*==.*1.*higher.*pos.*lower.*1",
            "digit_hcl|higher_current_lower|pos_digit_formula"
        ),
        // Sprint 101 — Pascal's triangle / largest divisible subset
        new PatternDef("pascals_triangle_row", "pascals_row_inplace_update", "high",
            "row.*0.*=.*1.*for.*i.*=.*0.*n.*for.*j.*=.*i.*\\+.*1.*j.*>=.*1.*j.*--",
            "row.*j.*\\+=.*row.*j.*-.*1.*in.*place.*binomial|row.*j.*\\+=.*row.*j.*-.*1",
            "pascals_row|pascal_triangle|binomial_row"
        ),
        new PatternDef("largest_div_subset_dp", "divisible_subset_sort_dp", "high",
            "if.*arr.*i.*%.*arr.*j.*==.*0.*dp.*j.*\\+.*1.*>.*dp.*i.*dp.*i.*=.*dp.*j.*\\+.*1",
            "sort.*arr.*dp.*i.*=.*1.*parent.*i.*=.*-1.*for.*j.*<.*i.*arr.*i.*%.*arr.*j",
            "div_subset|largest_div|divisible_dp"
        ),
        new PatternDef("div_subset_reconstruct", "divisible_subset_trace_parent", "medium",
            "idx.*=.*best_idx.*while.*idx.*!=.*-1.*xor_sub.*\\^=.*arr.*idx.*idx.*=.*parent.*idx",
            "trace.*back.*subset.*via.*parent.*array|reconstruct.*divisible.*subset",
            "div_trace|subset_reconstruct|trace_div"
        ),
        /* Sprint 102 — subarray_sum_k + max_circular_subarray */
        new PatternDef("subarray_sum_k_prefix", "prefix_sum_hashmap_count", "high",
            "prefix.*\\+=.*a.*i.*count.*\\+=.*hget.*prefix.*-.*k.*hadd.*prefix.*1",
            "hclear.*hadd.*0.*1.*prefix.*=.*0.*count.*=.*0.*for.*prefix.*-.*k",
            "subarray_sum_k|prefix_hashmap|count_subarray"
        ),
        new PatternDef("circular_subarray_max", "max_circular_total_minus_min", "high",
            "total.*-.*mn.*>.*0.*imax.*mx.*total.*-.*mn.*:.*mx|circular.*total.*min",
            "kadane_max.*kadane_min.*total_sum.*total.*-.*mn",
            "circular_max|total_minus_min|circular_kadane"
        ),
        new PatternDef("kadane_min_variant", "min_subarray_kadane_variant", "medium",
            "cur.*=.*imin.*a.*i.*cur.*\\+.*a.*i.*mn.*=.*imin.*mn.*cur",
            "min_subarray.*kadane|running.*minimum.*subarray.*variant",
            "kadane_min|min_kadane|min_subarray"
        ),
        /* Sprint 103 — serialize_bst + count_primes */
        new PatternDef("serialize_bst_preorder", "bst_preorder_serialize", "high",
            "preorder.*root.*arr.*idx|arr.*\\*idx.*\\+\\+.*=.*n.*val.*preorder.*n.*left.*preorder.*n.*right",
            "deserialize.*arr.*idx.*sz.*lo.*hi|reconstruct.*bst.*bounds.*range",
            "serialize_bst|preorder_serialize|bst_serialize"
        ),
        new PatternDef("sieve_eratosthenes", "prime_sieve_eratosthenes", "high",
            "sieve.*0.*=.*sieve.*1.*=.*0|memset.*sieve.*1.*sieve.*0.*=.*sieve.*1.*=.*0",
            "for.*p.*=.*2.*p.*\\*.*p.*<.*n.*if.*sieve.*p.*for.*j.*=.*p.*\\*.*p.*j.*<.*n.*j.*\\+=.*p.*sieve.*j.*=.*0",
            "sieve|eratosthenes|prime_sieve"
        ),
        new PatternDef("bst_deserialize_bounds", "bst_range_deserialize", "medium",
            "if.*\\*idx.*>=.*sz.*||.*arr.*\\*idx.*<.*lo.*||.*arr.*\\*idx.*>.*hi.*return.*NULL",
            "n.*=.*alloc_node.*arr.*\\*idx.*\\(\\*idx\\)\\+\\+.*left.*=.*deserialize.*lo.*n.*val.*-.*1.*right.*=.*deserialize.*n.*val.*\\+.*1.*hi",
            "bst_bounds|deserialize_range|bst_reconstruct"
        ),
        /* Sprint 104 — min_falling_path + k_closest_points */
        new PatternDef("min_falling_path_dp", "falling_path_grid_dp", "high",
            "mn.*=.*dp.*i.*-.*1.*j.*if.*j.*>.*0.*&&.*dp.*i.*-.*1.*j.*-.*1.*<.*mn.*mn.*=.*dp.*i.*-.*1.*j.*-.*1",
            "dp.*i.*j.*=.*mn.*\\+.*grid.*i.*j.*for.*i.*=.*1.*n.*for.*j.*=.*0.*n",
            "falling_path|falling_dp|grid_fall"
        ),
        new PatternDef("k_closest_sort", "k_closest_points_dist_sq", "high",
            "dist_sq.*=.*p.*x.*p.*x.*\\+.*p.*y.*p.*y|dsq.*=.*x.*x.*\\+.*y.*y",
            "qsort.*pts.*sizeof.*Point.*cmp_pts|sort.*by.*distance.*squared.*k.*closest",
            "k_closest|closest_points|dist_sq_sort"
        ),
        new PatternDef("falling_path_boundary", "falling_path_edge_guard", "medium",
            "if.*j.*>.*0.*&&.*dp.*i.*-.*1.*j.*-.*1.*<.*mn|if.*j.*<.*n.*-.*1.*&&.*dp.*i.*-.*1.*j.*\\+.*1.*<.*mn",
            "boundary.*check.*j.*0.*j.*n.*-.*1.*falling.*path.*grid",
            "falling_boundary|path_edge|grid_boundary"
        ),
        /* Sprint 105 — lcs + monotonic_queue */
        new PatternDef("lcs_dp_2d", "longest_common_subseq_dp", "high",
            "s1.*i.*-.*1.*==.*s2.*j.*-.*1.*dp.*i.*j.*=.*dp.*i.*-.*1.*j.*-.*1.*\\+.*1",
            "dp.*i.*j.*=.*imax.*dp.*i.*-.*1.*j.*dp.*i.*j.*-.*1",
            "lcs|common_subseq|longest_common"
        ),
        new PatternDef("monotonic_deque_max", "sliding_window_monotonic_deque", "high",
            "while.*head.*<.*tail.*&&.*arr.*dq.*tail.*-.*1.*<=.*arr.*i.*tail--|dq.*tail\\+\\+.*=.*i",
            "while.*head.*<.*tail.*&&.*dq.*head.*<=.*i.*-.*k.*head\\+\\+|window.*full.*maxes.*=.*arr.*dq.*head",
            "monotonic_queue|deque_max|sliding_max_deque"
        ),
        new PatternDef("lcs_init_base", "lcs_dp_base_case_init", "medium",
            "for.*i.*=.*0.*m.*dp.*i.*0.*=.*0|for.*j.*=.*0.*n.*dp.*0.*j.*=.*0",
            "lcs.*base.*case.*empty.*string.*zero|dp.*0.*j.*=.*dp.*i.*0.*=.*0",
            "lcs_base|lcs_init|dp_base_zero"
        ),
        new PatternDef("burst_balloons_last", "burst_balloons_interval_last_dp", "high",
            "dp.*i.*j.*=.*max.*k.*dp.*i.*k.*\\+.*dp.*k.*j.*\\+.*b.*i.*\\*.*b.*k.*\\*.*b.*j",
            "sentinel.*1.*both.*ends.*k.*is.*last.*balloon.*burst.*interval",
            "burst_balloons|balloon_last|burst_interval"
        ),
        new PatternDef("burst_sentinel_ends", "balloon_sentinel_boundary", "medium",
            "b.*0.*=.*1.*b.*n.*\\+.*1.*=.*1|sentinel.*1.*at.*both.*ends.*balloon",
            "interval.*dp.*k.*last.*burst.*coins.*b.*i.*b.*k.*b.*j",
            "balloon_sentinel|burst_boundary|sentinel_ends"
        ),
        new PatternDef("stone_game_minimax", "stone_game_interval_minimax", "high",
            "dp.*i.*j.*=.*max.*a.*i.*-.*dp.*i.*1.*j.*a.*j.*-.*dp.*i.*j.*-.*1",
            "dp.*i.*i.*=.*a.*i.*stone.*game.*take.*from.*either.*end",
            "stone_game|minimax_ends|stone_dp"
        ),
        new PatternDef("distinct_subseq_dp", "distinct_subsequences_count_dp", "high",
            "if.*s.*i.*-.*1.*==.*t.*j.*-.*1.*dp.*i.*j.*=.*dp.*i.*-.*1.*j.*-.*1.*\\+.*dp.*i.*-.*1.*j",
            "else.*dp.*i.*j.*=.*dp.*i.*-.*1.*j.*count.*subsequences",
            "distinct_subseq|subseq_count|subseq_dp"
        ),
        new PatternDef("russian_doll_sort", "russian_doll_sort_then_lis", "high",
            "sort.*by.*width.*asc.*height.*desc.*same.*width|cmp.*w.*!=.*w.*return.*w.*-.*w.*h.*-.*h",
            "lis.*on.*heights.*after.*sort.*russian.*doll.*envelopes",
            "russian_doll|envelope_lis|doll_sort"
        ),
        new PatternDef("patience_sort_lis", "patience_sort_lis_nlogn", "medium",
            "tails.*lo.*=.*e.*h.*if.*lo.*==.*sz.*sz\\+\\+.*patience.*sort",
            "binary.*search.*tails.*array.*lis.*patience.*sort.*O.*n.*log.*n",
            "patience_sort|lis_nlogn|lis_binary"
        ),
        new PatternDef("palindrome_min_cuts", "min_cuts_palindrome_partition", "high",
            "cuts.*i.*=.*i.*for.*j.*=.*1.*i.*if.*pal.*j.*i.*cuts.*j.*-.*1.*\\+.*1.*<.*cuts.*i",
            "pal.*0.*i.*cuts.*i.*=.*0.*whole.*prefix.*palindrome.*no.*cut",
            "palindrome_cuts|min_partition|pal_partition"
        ),
        new PatternDef("interval_stick_cut", "stick_cutting_interval_dp", "high",
            "dp.*i.*j.*=.*INF.*for.*k.*=.*i.*1.*j.*-.*1.*cost.*=.*dp.*i.*k.*\\+.*dp.*k.*j.*\\+.*arr.*j.*-.*arr.*i",
            "insert.*endpoints.*0.*and.*len.*sort.*interval.*dp.*cut.*cost",
            "stick_cut|cut_interval|min_cut_dp"
        ),
        new PatternDef("palindrome_precompute_2d", "palindrome_2d_table_precompute", "medium",
            "for.*i.*=.*0.*n.*pal.*i.*i.*=.*1.*for.*i.*=.*0.*i.*1.*<.*n.*pal.*i.*i.*1.*=.*s.*i.*==.*s.*i.*1",
            "for.*len.*=.*3.*len.*<=.*n.*pal.*i.*j.*=.*s.*i.*==.*s.*j.*&&.*pal.*i.*1.*j.*-.*1",
            "palindrome_2d|pal_precompute|palindrome_table"
        ),
        new PatternDef("bfs_word_transform", "word_ladder_bfs_transform", "high",
            "for.*i.*=.*0.*nd.*if.*visited.*i.*||.*one_diff.*cur.*dict.*i.*continue",
            "bfs.*word.*transform.*one.*letter.*at.*a.*time.*shortest.*path",
            "word_ladder|bfs_transform|word_bfs"
        ),
        new PatternDef("one_letter_diff", "one_character_difference_check", "medium",
            "while.*a.*i.*&&.*b.*i.*if.*a.*i.*!=.*b.*i.*diff\\+\\+.*return.*diff.*==.*1",
            "one_diff.*single.*char.*different.*same.*length.*word.*transform",
            "one_diff|char_diff|letter_diff"
        ),
        new PatternDef("uncrossed_lcs_int", "uncrossed_lines_lcs_int_array", "high",
            "dp.*i.*j.*=.*a.*i.*-.*1.*==.*b.*j.*-.*1.*dp.*i.*-.*1.*j.*-.*1.*\\+.*1.*imax.*dp.*i.*-.*1.*j.*dp.*i.*j.*-.*1",
            "lcs.*integer.*arrays.*uncrossed.*lines.*dp",
            "uncrossed_lines|lcs_int|int_lcs"
        ),
        /* Sprint 110 — Dinic's max flow */
        new PatternDef("dinic_bfs_level", "dinic_bfs_level_graph", "high",
            "mf_level.*v.*=.*mf_level.*u.*\\+.*1|level.*v.*=.*level.*u.*\\+.*1.*cap.*>.*0",
            "q.*back\\+\\+.*=.*s.*while.*front.*<.*back.*u.*=.*q.*front\\+\\+",
            "dinic|max_flow|level_graph|mf_level"
        ),
        new PatternDef("dinic_dfs_iter", "dinic_dfs_blocking_flow", "high",
            "mf_iter.*u.*=.*mf_nxt.*i|iter.*u.*=.*nxt.*i.*dead.*end.*advance",
            "mf_cap.*i.*\\^.*1.*\\+=.*f|cap.*i.*\\^.*1.*\\+=.*f.*reverse.*edge",
            "dinic_dfs|blocking_flow|iter_advance"
        ),
        new PatternDef("dinic_main_loop", "dinic_outer_bfs_dfs_cycle", "medium",
            "while.*mf_bfs.*s.*t|while.*bfs.*s.*t.*level.*graph",
            "for.*i.*=.*0.*MF_NODES.*mf_iter.*i.*=.*mf_head.*i|iter.*=.*head.*reset",
            "dinic_outer|max_flow_loop|bfs_dfs_cycle"
        ),
        /* Sprint 110 — Line segment intersection */
        new PatternDef("cross2d_product", "cross_product_2d_wedge", "high",
            "ax.*\\*.*by.*-.*ay.*\\*.*bx|cross2d.*=.*ax.*by.*-.*ay.*bx",
            "d1.*=.*cross2d|d1.*=.*cross.*bx.*-.*ax.*by.*-.*ay",
            "cross2d|wedge_product|line_cross"
        ),
        new PatternDef("seg_intersect_proper", "segment_proper_intersection", "high",
            "sign_of.*d1.*!=.*sign_of.*d2.*&&.*d1.*!=.*0.*&&.*d2.*!=.*0",
            "d3.*=.*cross2d.*d4.*=.*cross2d.*sign.*d3.*!=.*sign.*d4",
            "seg_intersect|proper_cross|line_segment_test"
        ),
        new PatternDef("seg_sign_check", "segment_orientation_signs", "medium",
            "sign_of.*x.*=.*x.*>.*0.*-.*x.*<.*0|signum.*ax.*by.*ay.*bx",
            "d1.*d2.*d3.*d4.*cross.*orientation.*CCW|segment_orientation",
            "sign_of|orientation|ccw_cw"
        ),
        /* Sprint 110 — Modular multiplicative inverse (more specific) */
        new PatternDef("mod_inv_normalize", "modular_inverse_normalization", "high",
            "x.*%.*m.*\\+.*m.*%.*m|norm.*=.*x.*%.*m.*\\+.*m.*%.*m",
            "if.*g.*!=.*1.*return.*-1|return.*-1.*not.*coprime.*inverse.*absent",
            "mod_inv|modinv|modular_inverse"
        ),
        new PatternDef("mod_inv_ext_gcd_call", "modinv_via_extgcd_bezout", "medium",
            "mi_ext_gcd.*a.*m.*&.*x.*&.*y|ext_gcd.*a.*m.*x.*y.*modinv",
            "g.*=.*mi_ext_gcd|g.*=.*ext_gcd.*m.*x.*y.*g.*!=.*1",
            "mi_ext_gcd|modinv_gcd|ext_gcd_inv"
        ),
        /* Sprint 110 — Treap (randomised BST with heap priority) */
        new PatternDef("treap_rotate_right", "treap_right_rotation", "high",
            "temp.*=.*root.*left.*root.*left.*=.*temp.*right.*temp.*right.*=.*root",
            "right_rotate.*treap|rotate_right.*bst.*priority|temp.*=.*node.*left",
            "treap_rrot|right_rotate|rotate_right"
        ),
        new PatternDef("treap_rotate_left", "treap_left_rotation", "high",
            "temp.*=.*root.*right.*root.*right.*=.*temp.*left.*temp.*left.*=.*root",
            "left_rotate.*treap|rotate_left.*bst.*priority|temp.*=.*node.*right",
            "treap_lrot|left_rotate|rotate_left"
        ),
        new PatternDef("treap_insert_priority", "treap_insert_heap_rebalance", "high",
            "if.*key.*<.*root.*key.*root.*left.*=.*insert|if.*key.*>.*root.*key.*root.*right.*=.*insert",
            "if.*root.*left.*&&.*root.*left.*priority.*>.*root.*priority.*right_rotate",
            "treap_insert|treap_priority|bst_heap_insert"
        ),

        // ── Kosaraju's two-pass SCC ─────────────────────────────────────────
        new PatternDef("kosaraju_finish_push", "kosaraju_dfs1_finish_order", "high",
            "stk.*stk_top\\+\\+.*=.*u|finish_stack.*push.*node.*post.order",
            "visited.*u.*=.*1.*for.*v.*g\\[u\\]\\[v\\].*dfs1|dfs1.*post.order",
            "kosaraju|scc_dfs1|finish_order_push"
        ),
        new PatternDef("kosaraju_transpose_dfs", "kosaraju_dfs2_transposed_graph", "high",
            "gt\\[v\\]\\[u\\].*=.*1|transposed.*adjacency.*for.*u.*for.*v.*g\\[u\\]\\[v\\]",
            "dfs2.*u.*id.*scc_sizes.*id\\+\\+|scc_label.*transposed",
            "kosaraju_dfs2|scc_transpose|gt_adj"
        ),
        new PatternDef("kosaraju_reverse_stack", "kosaraju_reverse_finish_order_scan", "medium",
            "u.*=.*stk.*--stk_top|u.*=.*stack.*--top.*reverse.finish.order",
            "while.*stk_top.*>.*0.*pop.*scc_count\\+\\+",
            "scc_reverse_stack|kosaraju_pass2|stk_top_decrement"
        ),

        // ── Point-in-Polygon (ray casting) ─────────────────────────────────
        new PatternDef("pip_crossing_test", "point_in_polygon_ray_cast", "high",
            "yi.*>.*py.*!=.*yj.*>.*py|vy.*i.*>.*py.*!=.*vy.*j.*>.*py",
            "inside.*\\^=.*1|crossing_count.*toggle.*parity",
            "point_in_polygon|ray_cast|pip_crossing"
        ),
        new PatternDef("pip_division_free", "pip_division_free_cross_check", "high",
            "dy.*>.*0.*lhs.*>.*rhs.*lhs.*<.*rhs|dy.*yi.*yj.*lhs.*xi.*xj.*py.*yj",
            "xi.*xj.*py.*yj.*px.*xj.*dy|division.free.*x.intersect",
            "pip_no_div|ray_cast_int|lhs_rhs_dy"
        ),
        new PatternDef("pip_vertex_pair_loop", "point_polygon_consecutive_vertex_loop", "medium",
            "for.*i.*=.*0.*j.*=.*n.*-.*1.*i.*<.*n.*j.*=.*i\\+\\+",
            "vx.*i.*vy.*i.*vx.*j.*vy.*j.*consecutive.*vertices",
            "vertex_pair_loop|j_follows_i|polygon_edge_iterate"
        ),

        // ── Möbius function via linear sieve ────────────────────────────────
        new PatternDef("mobius_sieve_init", "mobius_linear_sieve_init", "high",
            "mu.*1.*=.*1.*mu.*i.*=.*-1.*prime|mu\\[1\\].*=.*1.*primes.*cnt",
            "is_composite.*primes.*cnt.*mu.*-1.*for.*i.*2.*<=.*N",
            "mobius_mu|linear_sieve_mu|mu_init"
        ),
        new PatternDef("mobius_squared_factor", "mobius_squared_prime_factor_zero", "high",
            "if.*i.*%.*primes.*j.*==.*0.*mu.*x.*=.*0.*break|squared.prime.*mu.*=.*0",
            "i.*%.*primes.*j.*==.*0.*mu.*ip.*=.*0|p_squared_divides.*mobius_zero",
            "mu_zero_squared|mobius_break|squarefull_zero"
        ),
        new PatternDef("mobius_negate_parent", "mobius_negate_parent_parity", "high",
            "mu.*x.*=.*-mu.*i|mu.*ip.*=.*-mu.*i.*one.more.prime",
            "else.*mu.*x.*=.*-mu.*i.*distinct.prime|mobius_parity_flip",
            "mu_negate|mobius_alternating|distinct_prime_mu"
        ),

        // ── Shoelace (polygon area) ─────────────────────────────────────────
        new PatternDef("shoelace_cross_sum", "shoelace_polygon_area_formula", "high",
            "sum.*\\+=.*vx.*j.*\\*.*vy.*i.*-.*vx.*i.*\\*.*vy.*j|cross.*acc.*x.*y.*polygon",
            "sl_vx.*j.*sl_vy.*i.*sl_vx.*i.*sl_vy.*j|shoelace.*2.*area",
            "shoelace|polygon_area|gauss_area"
        ),
        new PatternDef("shoelace_abs_half", "shoelace_abs_and_half_area", "medium",
            "return.*sum.*<.*0.*?.*-sum.*:.*sum|abs.*two_area.*>>.*1",
            "two_area.*>>.*1.*area|shoelace.*area.*half",
            "shoelace_abs|area_positive|two_area_halve"
        ),
        new PatternDef("shoelace_vertex_pair", "shoelace_consecutive_vertex_pair", "medium",
            "for.*i.*=.*0.*j.*=.*SL_N.*-.*1|for.*i.*j.*n.*-.*1.*j.*=.*i\\+\\+.*polygon",
            "sl_vx.*sl_vy.*consecutive.*j.*=.*i|vertex.*pair.*cross.*accumulate",
            "shoelace_pair|polygon_vertex_loop|gauss_pair"
        ),

        // ── Segment tree with lazy propagation ─────────────────────────────
        new PatternDef("lazy_segtree_pushdown", "lazy_segtree_push_down_propagate", "high",
            "if.*!.*lazy.*node.*return|lst_lazy.*node.*==.*0.*return.*push",
            "tree.*lc.*\\+=.*lazy.*node.*\\*.*mid.*-.*l.*\\+.*1|lazy_propagate_child",
            "lazy_push_down|segtree_lazy|defer_propagate"
        ),
        new PatternDef("lazy_segtree_bulk_update", "lazy_segtree_range_add_bulk", "high",
            "tree.*node.*\\+=.*val.*\\*.*r.*-.*l.*\\+.*1|bulk.*update.*lazy.*\\+=.*val",
            "lst_update.*ql.*<=.*l.*&&.*r.*<=.*qr.*tree.*node.*\\+=.*val|range_add_lazy",
            "lazy_bulk_add|segtree_range_add|lst_update"
        ),
        new PatternDef("lazy_segtree_merge", "lazy_segtree_child_merge_after_update", "medium",
            "tree.*node.*=.*tree.*2.*node.*\\+.*tree.*2.*node.*\\+.*1|segtree.*merge.*after.*update",
            "lst_tree.*2.*node.*\\+.*lst_tree.*2.*node.*\\+.*1|child.sum.merge",
            "segtree_merge|tree_sum_children|lst_merge"
        ),

        // ── Aho-Corasick multi-pattern search ───────────────────────────────
        new PatternDef("ac_trie_insert", "aho_corasick_trie_insert", "high",
            "ac_goto.*cur.*c.*==.*-1.*ac_new_node|goto.*\\[cur\\]\\[c\\].*=.*new_node",
            "for.*pat.*i.*c.*=.*pat.*i.*-.*a.*goto.*cur.*c.*ac_insert",
            "ac_insert|trie_insert|aho_corasick_build"
        ),
        new PatternDef("ac_fail_link_bfs", "aho_corasick_failure_link_bfs", "high",
            "fail.*v.*=.*ac_goto.*fail.*u.*c|ac_fail.*v.*=.*goto.*fail.*u.*c",
            "output.*v.*\\|=.*output.*fail.*v|ac_output.*merge.*fail.link",
            "ac_fail|failure_link|ac_bfs_build"
        ),
        new PatternDef("ac_goto_complete", "aho_corasick_goto_completion", "medium",
            "ac_goto.*u.*c.*=.*ac_goto.*fail.*u.*c|goto.*u.*c.*=.*goto.*fail.*u.*c.*missing",
            "if.*v.*==.*-1.*goto.*u.*c.*=.*goto.*fail|ac_redirect_missing",
            "ac_goto_fill|ac_goto_complete|aho_corasick_search"
        ),
        /* ── Z-function (Z-algorithm) ─────────────────────────────────────── */
        new PatternDef("z_window_advance", "z_function_window_extension", "high",
            "if.*i.*<.*r.*z\\[i.*-.*l\\].*r.*-.*i|zi.*=.*z.*i.*-.*l.*zi.*>.*r.*-.*i",
            "l.*=.*i.*r.*=.*i.*+.*zi|if.*i.*\\+.*zi.*>.*r.*l.*=.*i",
            "z_function|z_algorithm|z_array"
        ),
        new PatternDef("z_prefix_extend", "z_prefix_match_extension_loop", "high",
            "while.*s\\[zi\\].*==.*s\\[i.*\\+.*zi\\]|while.*zi.*<.*n.*s.*zi.*==.*s.*i.*zi",
            "zi\\+\\+.*z\\[i\\].*=.*zi|z_extend.*while.*prefix",
            "z_function|prefix_match|z_extend"
        ),
        new PatternDef("z_sum_max_metric", "z_sum_and_max_Z_values", "medium",
            "sum_z.*\\+=.*z\\[i\\]|for.*i.*sum.*\\+=.*zf_z",
            "if.*z\\[i\\].*>.*max_z.*max_z.*=.*z\\[i\\]|max_z.*z_function",
            "z_sum|z_max|z_metric"
        ),
        /* ── Sparse table (static RMQ) ────────────────────────────────────── */
        new PatternDef("sparse_table_log2_precompute", "sparse_table_floor_log2_sieve", "high",
            "log2.*i.*=.*log2.*i.*2.*\\+.*1|st_log2.*i.*=.*st_log2.*i.*\\/.*2.*\\+.*1",
            "for.*i.*2.*log2.*i.*log.*i.*2.*1|precompute.*log.*sparse",
            "sparse_table|rmq|log2_table"
        ),
        new PatternDef("sparse_table_doubling_build", "sparse_table_doubling_construction", "high",
            "st_table.*k.*i.*=.*st_table.*k.*-.*1.*i|table\\[k\\]\\[i\\].*=.*min.*table.*k-1.*i.*half",
            "for.*k.*1.*1.*<<.*k.*<=.*n.*for.*i.*table.*k.*i.*min",
            "sparse_table|doubling|range_min"
        ),
        new PatternDef("sparse_rmq_overlap_query", "sparse_table_overlapping_interval_rmq", "high",
            "k.*=.*log2.*r.*-.*l.*\\+.*1|st_log2\\[r.*-.*l.*\\+.*1\\]",
            "min.*table\\[k\\]\\[l\\].*table\\[k\\]\\[r.*-.*1.*<<.*k.*\\+.*1\\]|rmq.*overlap.*two.*intervals",
            "sparse_rmq|range_minimum|overlap_query"
        ),
        /* ── Euler's totient sieve ────────────────────────────────────────── */
        new PatternDef("euler_phi_identity_init", "euler_phi_initialize_identity", "high",
            "phi\\[i\\].*=.*i|et_phi.*i.*=.*i.*for.*i.*0.*limit",
            "for.*i.*0.*<=.*limit.*phi.*i.*=.*i|initialize.*phi.*identity",
            "euler_phi|totient|phi_sieve"
        ),
        new PatternDef("euler_phi_prime_detect_sieve", "euler_phi_prime_detect_via_unchanged", "high",
            "if.*phi\\[i\\].*==.*i.*for.*j.*=.*i.*j.*<=.*limit.*j.*\\+=.*i|phi.*==.*i.*prime",
            "phi\\[j\\].*-=.*phi\\[j\\].*\\/.*i|et_phi.*j.*-=.*et_phi.*j.*\\/.*i",
            "euler_phi|prime_detection|phi_sieve"
        ),
        new PatternDef("euler_phi_prime_check", "euler_phi_prime_identification_p_minus_1", "medium",
            "if.*phi\\[i\\].*==.*i.*-.*1|et_phi.*i.*==.*i.*-.*1.*prime",
            "n_primes.*\\+\\+.*sum_phi.*\\+=.*phi\\[i\\]|count_primes.*phi.*p.*minus.*1",
            "euler_phi|prime_count|phi_prime"
        ),

        // ── 2-SAT via Tarjan SCC ────────────────────────────────────────────
        new PatternDef("twosat_implication", "2sat_clause_to_implication_pair", "high",
            "ts_g.*a.*\\^.*1.*b.*=.*1.*ts_g.*b.*\\^.*1.*a.*=.*1|add_clause.*a.*b.*not_a.*b",
            "g.*na.*b.*=.*1.*g.*nb.*a.*=.*1|implication.*clause.*a.*xor.*1",
            "2sat_clause|implication_graph|not_a_implies_b"
        ),
        new PatternDef("twosat_sat_check", "2sat_scc_satisfiability_check", "high",
            "ts_comp.*2.*k.*==.*ts_comp.*2.*k.*\\+.*1|comp.*2k.*==.*comp.*2k1.*unsat",
            "if.*comp.*2k.*==.*comp.*2k1.*is_sat.*=.*0|scc_containment",
            "2sat_unsat|scc_same_comp|comp_equality"
        ),
        new PatternDef("twosat_assignment", "2sat_assignment_from_scc_order", "medium",
            "comp.*2.*k.*<.*comp.*2.*k.*\\+.*1.*assignment.*\\|=.*1.*<<.*k",
            "ts_comp.*2.*k.*<.*ts_comp.*2.*k.*\\+.*1|xk_true_lower_comp",
            "2sat_assign|scc_order_assign|comp_lt_true"
        ),

        // ── Huffman encoding (min-heap greedy) ─────────────────────────────
        new PatternDef("huffman_heap_merge", "huffman_min_heap_merge_step", "high",
            "huf_w.*merged.*=.*huf_w.*a.*\\+.*huf_w.*b|weight.*merged.*=.*weight.*a.*weight.*b",
            "a.*=.*heap_pop.*b.*=.*heap_pop.*node_cnt\\+\\+|two_min_merge",
            "huffman_merge|huf_merge|min_heap_huffman"
        ),
        new PatternDef("huffman_total_cost", "huffman_optimal_code_length", "high",
            "total_cost.*\\+=.*huf_w.*merged|total.*\\+=.*weight.*merged.*internal",
            "while.*huf_hsz.*>.*1.*heap_pop.*heap_push.*total_cost",
            "huffman_cost|prefix_code_length|total_merged_weight"
        ),

        // ── 2D Binary Indexed Tree (Fenwick) ────────────────────────────────
        new PatternDef("bit2d_update", "2d_fenwick_point_update", "high",
            "for.*i.*=.*x.*i.*<=.*N.*i.*\\+=.*i.*&.*-i.*for.*j.*=.*y.*j.*\\+=.*j.*&.*-j",
            "bit2.*i.*j.*\\+=.*v.*doubly.nested.fenwick|2d_point_update_fenwick",
            "bit2d_update|fenwick_2d|2d_point_add"
        ),
        new PatternDef("bit2d_query", "2d_fenwick_prefix_rect_query", "high",
            "for.*i.*=.*x.*i.*>.*0.*i.*-=.*i.*&.*-i.*for.*j.*=.*y.*j.*-=.*j.*&.*-j",
            "s.*\\+=.*bit2.*i.*j.*nested.prefix.query|2d_fenwick_rect_sum",
            "bit2d_query|fenwick_2d_sum|2d_prefix_rect"
        ),

        // ── String period via KMP failure function ─────────────────────────
        new PatternDef("kmp_period_formula", "kmp_failure_function_period", "high",
            "period.*=.*n.*-.*fail.*n.*-.*1|n.*-.*sp_fail.*n.*-.*1.*period",
            "n.*%.*period.*==.*0.*exact|fail.*n.*-.*1.*period.*exact.check",
            "kmp_period|string_period|failure_period"
        ),
        new PatternDef("kmp_backtrack_while", "kmp_failure_function_backtrack", "high",
            "while.*j.*>.*0.*&&.*s.*j.*!=.*s.*i.*j.*=.*fail.*j.*-.*1",
            "while.*j.*>.*0.*s\\[j\\].*!=.*s\\[i\\].*j.*=.*sp_fail.*j.*-.*1",
            "kmp_fail|prefix_fail|kmp_backtrack"
        ),

        // ── Inversion count via Fenwick ─────────────────────────────────────
        new PatternDef("inv_bit_precount", "inversion_count_fenwick_precount", "high",
            "inv_cnt.*\\+=.*inv_query.*a.*i.*-.*1.*inv_update.*a.*i.*1",
            "cnt.*\\+=.*iqry.*a.*i.*-.*1.*iupd.*a.*i.*1|inversions.*before.*insert",
            "inversion_bit|count_inversions_fenwick|inv_count"
        ),

        // ── Matrix chain multiplication (memoized) ─────────────────────────
        new PatternDef("mcm_memo_check", "matrix_chain_memoized_base_check", "high",
            "if.*mc_memo.*i.*j.*>=.*0.*return.*mc_memo.*i.*j|if.*memo.*i.*j.*>=.*0.*return",
            "mc_memo\\[i\\]\\[j\\].*>=.*0.*return|memoized.*matrix.*chain.*dp",
            "matrix_chain_memo|mcm_dp|chain_memoize"
        ),
        new PatternDef("mcm_dimension_product", "matrix_chain_dimension_product_cost", "high",
            "mc_p.*i.*\\*.*mc_p.*k.*\\+.*1.*\\*.*mc_p.*j.*\\+.*1|p.*i.*p.*k.*1.*p.*j.*1.*cost",
            "cost.*=.*mcs.*i.*k.*\\+.*mcs.*k.*\\+.*1.*j.*\\+.*p.*i.*p.*k.*p.*j",
            "mcm_cost|dimension_product|chain_split_cost"
        ),

        // ── Pollard's rho factorization ─────────────────────────────────────
        new PatternDef("pollard_quad_poly", "pollard_rho_quadratic_polynomial", "high",
            "x.*\\*.*x.*\\+.*c.*%.*n|pr_f.*x.*c.*n.*long.*long.*x.*x.*c.*mod.*n",
            "return.*long.long.*x.*x.*\\+.*c.*%.*n|pollard.*f.*x.*quadratic",
            "pollard_rho|rho_poly|x_sq_plus_c"
        ),
        new PatternDef("pollard_floyd_cycle", "pollard_rho_floyd_double_step", "high",
            "y.*=.*pr_f.*pr_f.*y.*c.*n.*c.*n|y.*=.*f.*f.*y.*hare.*double.step",
            "d.*=.*pr_gcd.*pr_abs.*x.*-.*y.*n|floyd.cycle.rho",
            "pollard_floyd|hare_tortoise_rho|double_step_rho"
        ),

        // ── Balloon Burst interval DP ───────────────────────────────────────
        new PatternDef("balloon_burst_product", "balloon_burst_three_boundary_product", "high",
            "b_p.*l.*\\*.*b_p.*k.*\\*.*b_p.*r|p.*l.*p.*k.*p.*r.*balloon.*burst",
            "coins.*=.*bpa.*l.*bpa.*k.*bpa.*r.*\\+.*bs.*l.*k.*\\+.*bs.*k.*r",
            "balloon_burst|interval_dp_coins|boundary_product"
        ),
        new PatternDef("balloon_last_burst", "balloon_burst_last_popped_idiom", "medium",
            "for.*k.*=.*l.*\\+.*1.*k.*<.*r.*b_p.*l.*b_p.*k.*b_p.*r|k.*last.*burst.*open.*interval",
            "b_dp.*l.*r.*=.*best.*last.balloon.burst.interval",
            "balloon_memo|burst_last|interval_dp_last"
        ),

        // ── Number Theoretic Transform (NTT) ────────────────────────────────
        new PatternDef("ntt_primitive_root", "ntt_primitive_root_of_unity", "high",
            "ntt_pow.*NTT_W.*k.*j.*NTT_P|ntt_pow.*13.*k.*j.*17",
            "sum.*=.*ntt_a.*j.*\\*.*ntt_pow.*w.*k.*j.*p|dft.*primitive.root.unity",
            "ntt_w|primitive_root_unity|ntt_modular"
        ),
        new PatternDef("ntt_outer_inner_loop", "ntt_dft_outer_k_inner_j", "high",
            "for.*k.*0.*NTT_N.*for.*j.*0.*NTT_N.*sum.*\\+=|outer.*k.*inner.*j.*modular.dft",
            "ntt_X.*k.*=.*sum.*modular.*ntt_a.*j.*ntt_pow.*w.*k.*j",
            "ntt_loop|dft_loop|ntt_outer_k"
        ),

        // ── van Emde Boas tree ──────────────────────────────────────────────
        new PatternDef("veb_cluster_index", "veb_high_low_cluster_split", "high",
            "hi.*=.*x.*>>.*4|lo.*=.*x.*&.*0xF|cluster.*=.*x.*>>.*sqrt|position.*=.*x.*&.*mask",
            "x.*>>.*VEB_SQT|hi.*=.*x.*sqrt_u|veb.*cluster.*index",
            "veb_hi|veb_lo|cluster_split|sqrt_decomp_index"
        ),
        new PatternDef("veb_summary_bit", "veb_summary_cluster_nonempty_bit", "high",
            "summary.*\\|=.*1u.*<<.*hi|summary.*&=.*~.*1.*<<.*hi|summary.*bit.*cluster",
            "v.*summary.*\\|=.*1u.*<<|v.*->summary.*&=.*~.*1u.*<<.*hi",
            "veb_summary|cluster_nonempty_bit|veb_bit_set"
        ),
        new PatternDef("veb_succ_scan", "veb_successor_cluster_scan", "high",
            "c.*=.*hi.*\\+.*1.*while.*c.*<.*VEB_SQT.*summary.*>>.*c.*&.*1|next.*cluster.*scan",
            "while.*c.*<.*VEB_SQT.*if.*summary.*&.*1u.*<<.*c.*return.*c.*<<.*4|succ.*cluster",
            "veb_succ|successor_cluster|next_nonempty_cluster"
        ),

        // ── Baby-step Giant-step (BSGS) ─────────────────────────────────────
        new PatternDef("bsgs_baby_steps", "bsgs_precompute_baby_step_table", "high",
            "for.*j.*=.*0.*j.*<.*m.*j\\+\\+.*ht_insert.*gj.*j|gj.*=.*mod_mul.*gj.*g.*p",
            "baby.*step.*precompute|ht_insert.*g_to_j|bsgs_table.*fill",
            "bsgs_baby|baby_step_table|gj_mod_p"
        ),
        new PatternDef("bsgs_giant_step", "bsgs_giant_step_inverse_scan", "high",
            "gm_inv.*=.*mod_pow.*g.*p.*-.*1.*-.*m|val.*=.*mod_mul.*val.*gm_inv.*p",
            "giant.*step.*g.*neg_m.*mod|bsgs.*g_inv_m.*scan|val.*\\*=.*gm_inv",
            "bsgs_giant|giant_step_inv|gm_inv_scan"
        ),
        new PatternDef("bsgs_hash_probe", "bsgs_hash_table_linear_probe", "high",
            "idx.*=.*key.*\\*.*2654435761u.*>>.*23|idx.*&=.*BSGS_HT_SIZE.*-.*1",
            "while.*ht.*idx.*val.*!=.*-1.*&&.*ht.*idx.*key.*!=.*key.*idx.*=.*idx.*\\+.*1",
            "bsgs_hash|knuth_multiplicative_hash|linear_probe_bsgs"
        ),

        // ── Wavelet tree ────────────────────────────────────────────────────
        new PatternDef("wavelet_build_level", "wavelet_tree_level_stable_partition", "high",
            "for.*lv.*=.*LEVELS.*-.*1.*lv.*>=.*0.*lv--|for.*i.*=.*0.*i.*<.*N.*bmap.*lv.*i",
            "wt_bmap.*lv.*i.*=.*tmp.*i.*&.*bit.*?.*1.*:.*0|wavelet.*level.*partition",
            "wt_build|wavelet_partition|wavelet_level_bmap"
        ),
        new PatternDef("wavelet_cnt0_prefix", "wavelet_tree_prefix_zero_count", "high",
            "wt_cnt0.*lv.*i\\+1.*=.*wt_cnt0.*lv.*i.*\\+.*wt_bmap.*lv.*i.*==.*0",
            "cnt0.*lv.*i.*\\+.*1.*=.*cnt0.*lv.*i.*\\+.*1.*-.*bit|prefix.*zero.*count.*wavelet",
            "wt_cnt0|prefix_zero_count|wavelet_prefix_bits"
        ),
        new PatternDef("wavelet_freq_navigate", "wavelet_tree_freq_query_navigate", "high",
            "if.*v.*&.*bit.*nlo.*=.*zeros_total.*\\+.*lo.*-.*cnt0.*lv.*lo|go.*right.*left.*wavelet",
            "lo.*=.*wt_cnt0.*lv.*lo.*hi.*=.*wt_cnt0.*lv.*hi|wavelet.*freq.*go.*left",
            "wt_freq|wavelet_navigate|wavelet_range_query"
        ),

        // ── Gaussian elimination ────────────────────────────────────────────
        new PatternDef("gauss_pivot_swap", "gauss_elimination_partial_pivot_swap", "high",
            "for.*k.*=.*i.*\\+.*1.*k.*<.*GE_N.*gabs.*ga.*k.*i.*>.*gabs.*ga.*max_row.*i|pivot_find",
            "for.*c.*=.*0.*c.*<=.*GE_N.*t.*=.*ga.*i.*c.*ga.*i.*c.*=.*ga.*max_row.*c|row_swap",
            "gauss_pivot|partial_pivot|row_swap_augmented"
        ),
        new PatternDef("gauss_elim_cross_mul", "gauss_cross_multiply_integer_elim", "high",
            "ga.*j.*c.*=.*ga.*j.*c.*\\*.*pivot.*-.*factor.*\\*.*ga.*i.*c|cross_multiply_elim",
            "ga.*j.*c.*=.*ga.*j.*c.*\\*.*p.*-.*f.*\\*.*ga.*i.*c|integer_gauss",
            "gauss_cross_mul|elimination_integer|augmented_row_elim"
        ),
        new PatternDef("gauss_back_sub", "gauss_back_substitution", "high",
            "val.*-=.*ga.*i.*c.*\\*.*sol.*c|v.*-=.*ga.*i.*c.*sol.*c.*back.sub",
            "sol.*i.*=.*val.*\\/.*ga.*i.*i|back_substitution.*augmented",
            "gauss_back|back_substitution|sol_divide_pivot"
        ),

        // ── Top-k min-heap ─────────────────────────────────────────────────
        new PatternDef("topk_evict_min", "topk_heap_evict_minimum_element", "high",
            "if.*x.*>.*tk_heap.*0.*tk_heap.*0.*=.*x.*sift_down|if.*x.*>.*heap_min.*replace",
            "x.*>.*tk_heap.*\\[0\\].*\\{.*tk_heap.*\\[0\\].*=.*x.*tk_sift_down|top_k_evict",
            "topk_evict|heap_min_replace|topk_sift"
        ),
        new PatternDef("topk_fill_phase", "topk_heap_fill_phase_k_elements", "medium",
            "if.*tk_hsz.*<.*K.*tk_heap.*tk_hsz\\+\\+.*=.*x.*tk_sift_up|fill.*heap.*k.*elements",
            "if.*tk_hsz.*<.*TK_K.*tk_heap.*\\[tk_hsz\\+\\+\\]|topk_fill_phase",
            "topk_fill|heap_fill_k|tk_hsz_check"
        ),

        // ── Stoer-Wagner minimum cut ────────────────────────────────────────
        new PatternDef("stoer_wagner_tight", "stoer_wagner_most_tightly_connected", "high",
            "if.*!swmrg.*v.*&&.*!inA.*v.*&&.*w.*v.*>.*max_w|most.tightly.connected.vertex",
            "z.*=.*v.*mx.*=.*w.*v.*tightest.*connection.*A|sw_tight_vertex",
            "stoer_wagner|sw_tightest|min_cut_tight"
        ),
        new PatternDef("stoer_wagner_merge", "stoer_wagner_merge_s_t_into_super", "high",
            "swadj.*s.*v.*\\+=.*swadj.*t.*v.*swadj.*v.*s.*\\+=.*swadj.*v.*t|merge.*s.*t.*edge",
            "sw_merged.*t.*=.*1.*merge.*last.*phase.*vertex|sw_merge_vertex",
            "sw_merge|merge_vertex|supernode_edges"
        ),
        new PatternDef("stoer_wagner_phase_cut", "stoer_wagner_phase_minimum_cut", "medium",
            "if.*cut.*<.*min_cut.*min_cut.*=.*cut|cut.*=.*w.*t.*sw_phase.*min.*cut.*record",
            "cut.*<.*mc.*mc.*=.*cut.*sw_phase.*global.min.cut",
            "sw_min_cut|phase_cut_record|global_min_cut"
        ),

        // ── LCP array (Kasai) ────────────────────────────────────────────────
        new PatternDef("lcp_kasai_rank_advance", "lcp_kasai_rank_based_k_advance", "high",
            "inv.*sa.*inv.*-.*1|rank.*sa.*rank.*-.*1|lcp.*inv.*i.*=.*k",
            "while.*i.*\\+.*k.*<.*n.*&&.*j.*\\+.*k.*<.*n.*&&.*s.*i.*k.*==.*s.*j.*k",
            "kasai_lcp|lcp_array_build|suffix_rank_lcp"
        ),
        new PatternDef("lcp_k_decrement", "lcp_kasai_k_decrement_after_suffix", "medium",
            "if.*k.*>.*0.*k--|lcp.*k.*decrement|kasai_k_minus",
            "if.*inv.*i.*==.*0.*k.*=.*0.*continue|if.*rank.*i.*==.*0",
            "lcp_k_dec|kasai_decrement|lcp_k_step"
        ),
        new PatternDef("lcp_root_skip", "lcp_kasai_root_suffix_skip", "medium",
            "if.*inv.*i.*==.*0.*continue|if.*rank.*i.*==.*0.*k.*=.*0",
            "inv.*root.*==.*0.*k.*reset|kasai_root_skip",
            "lcp_root_skip|kasai_root|rank_zero_skip"
        ),

        // ── Monotone queue (sliding window) ─────────────────────────────────
        new PatternDef("deque_push_back_mono", "monotone_deque_pop_back_before_push", "high",
            "while.*!dq_empty.*&&.*a.*dq_back.*<=.*a.*i|while.*deque_back.*<=.*arr.*idx",
            "pop_back.*push_back.*i|d.*tail--.*d.*data.*d.*tail.*=.*i",
            "monotone_deque|sliding_window_deque|mono_queue_push"
        ),
        new PatternDef("deque_front_expire", "monotone_deque_expire_front_element", "high",
            "while.*!dq_empty.*&&.*dq_front.*<=.*i.*-.*k|while.*deque_front.*<.*i.*-.*window",
            "dq_pop_front|head\\+\\+|deque.*head.*window.*expire",
            "deque_front_expire|window_expire|sliding_expire"
        ),
        new PatternDef("window_max_collect", "sliding_window_max_collect_after_fill", "medium",
            "if.*i.*>=.*k.*-.*1.*sum.*\\+=.*a.*dq_front|if.*i.*>=.*w.*-.*1.*ans.*\\+=",
            "window.*full.*collect|i.*>=.*k.*1.*append|ans.*deque_front.*window_filled",
            "window_max_collect|swm_collect|window_result"
        ),

        // ── Heavy-Light Decomposition ────────────────────────────────────────
        new PatternDef("hld_chain_ascent", "hld_path_query_chain_ascent_loop", "high",
            "while.*head_chain.*u.*!=.*head_chain.*v|while.*chain_top.*u.*!=.*chain_top.*v",
            "res.*\\+=.*fen_range.*pos.*head_chain.*u.*pos.*u|sum.*range.*chain_head.*to.*u",
            "hld_chain_ascent|hld_path_query|heavy_light_path"
        ),
        new PatternDef("hld_depth_swap", "hld_depth_controlled_node_swap", "medium",
            "if.*depth.*head_chain.*u.*<.*depth.*head_chain.*v.*tmp.*=.*u.*u.*=.*v|hld_swap_deeper",
            "depth_head_u.*<.*depth_head_v.*swap|make_u_deeper.*hld",
            "hld_swap|hld_depth_swap|hld_chain_swap"
        ),
        new PatternDef("hld_lca_segment", "hld_lca_final_segment_query", "high",
            "if.*depth.*u.*>.*depth.*v.*tmp.*=.*u.*u.*=.*v|same_chain.*depth_normalize.*u.*v",
            "res.*\\+=.*fen_range.*pos.*u.*pos.*v|ans.*range_query.*same_chain",
            "hld_lca_segment|hld_final_range|hld_same_chain"
        ),

        // ── Burnside's lemma (necklace counting) ────────────────────────────
        new PatternDef("burnside_divisor_sum", "burnside_divisor_enumeration_sum", "high",
            "for.*d.*=.*1.*d.*<=.*n.*d\\+\\+.*if.*n.*%.*d.*==.*0.*total.*\\+=|divisor_sum_euler_phi",
            "total.*\\+=.*bsn_euler_phi.*d.*\\*.*bsn_int_pow.*k.*n.*\\/.*d|burnside_sum",
            "burnside_divisor|phi_pow_sum|necklace_total"
        ),
        new PatternDef("burnside_average", "burnside_orbit_count_division", "medium",
            "return.*total.*\\/.*n|n_distinct.*=.*total.*\\/.*n.*burnside.*average",
            "return.*total.*divided.*n.*orbit.counting|burnside.*necklace.*count",
            "burnside_avg|orbit_count|necklace_averaging"
        ),
        new PatternDef("euler_phi_trial", "euler_totient_trial_division_reduction", "high",
            "result.*-=.*result.*\\/.*p|if.*n.*%.*p.*==.*0.*while.*n.*%.*p.*==.*0.*n.*\\/=.*p",
            "for.*p.*=.*2.*p.*\\*.*p.*<=.*n.*p\\+\\+.*if.*n.*%.*p.*euler.*phi",
            "euler_phi|totient_trial|prime_reduction_phi"
        ),

        // ── Garner's algorithm (mixed-radix CRT) ────────────────────────────
        new PatternDef("garner_mixed_radix", "garner_triangular_mixed_radix_update", "high",
            "for.*k.*=.*0.*k.*<.*n.*k\\+\\+.*a.*k.*=.*r.*k.*for.*j.*=.*0.*j.*<.*k|garner_triangular",
            "a.*k.*=.*gar_inv.*m.*j.*m.*k.*\\*.*a.*k.*-.*a.*j.*%.*m.*k|mixed_radix_coeff",
            "garner|crt_mixed_radix|garner_triangular_loop"
        ),
        new PatternDef("garner_neg_normalize", "garner_normalize_negative_residue", "medium",
            "if.*a.*k.*<.*0.*a.*k.*\\+=.*m.*k|normalize.*negative.*residue.*modulus",
            "a\\[k\\].*<.*0.*\\{.*a\\[k\\].*\\+=.*m\\[k\\]|negative_mod_normalize",
            "garner_neg|neg_residue|mod_normalize"
        ),
        new PatternDef("garner_reconstruct", "garner_horner_like_reconstruction", "high",
            "x.*\\+=.*a.*k.*\\*.*prod.*prod.*\\*=.*m.*k|prod.*cumulative.*moduli.*garner",
            "for.*k.*<.*n.*x.*\\+=.*a\\[k\\].*\\*.*prod.*prod.*\\*=.*m\\[k\\]|garner_crt",
            "garner_reconstruct|crt_product|mixed_radix_expand"
        ),

        // ── Square-root decomposition ────────────────────────────────────────
        new PatternDef("sqrt_block_update", "sqrt_decomp_block_sum_point_update", "high",
            "sq_blk.*idx.*\\/.*SQ_BS.*\\+=.*val.*-.*sq_arr.*idx|block.*i.*\\/.*bs.*\\+=.*delta",
            "block\\[i.*\\/.*block_sz\\].*\\+=.*val.*-.*arr\\[i\\]|sq_blk.*update",
            "sqrt_block_update|block_point_update|sqrt_delta_block"
        ),
        new PatternDef("sqrt_query_partial", "sqrt_decomp_partial_block_range_query", "high",
            "for.*b.*=.*bl.*\\+.*1.*b.*<.*br.*b\\+\\+.*sum.*\\+=.*sq_blk.*b|full.*middle.*blocks",
            "for.*i.*=.*l.*i.*<.*bl.*\\+.*1.*\\*.*SQ_BS.*sum.*\\+=.*sq_arr|partial_left_block",
            "sqrt_partial_query|sqrt_range_decomp|block_range_query"
        ),
        new PatternDef("sqrt_same_block", "sqrt_decomp_single_block_special_case", "medium",
            "if.*bl.*==.*br.*for.*i.*=.*l.*i.*<=.*r.*sum.*\\+=.*sq_arr|same_block_iterate",
            "bl.*==.*br.*\\{.*for.*i.*l.*to.*r.*sq_arr|sqrt_same_block_scan",
            "sqrt_same_block|single_block_case|sqrt_trivial_range"
        ),

        // ── Treap (rotation-based insert) ────────────────────────────────────
        new PatternDef("treap_right_rot", "treap_right_rotation_priority_fix", "high",
            "pool.*r.*left.*=.*pool.*l.*right.*pool.*l.*right.*=.*r.*return.*l|right_rotation_treap",
            "l.*=.*pool.*r.*left.*pool.*r.*left.*=.*pool.*l.*right.*pool.*l.*right.*=.*r",
            "treap_right_rot|right_rotation|treap_priority_heapify"
        ),
        new PatternDef("treap_left_rot", "treap_left_rotation_priority_fix", "high",
            "pool.*r.*right.*=.*pool.*ri.*left.*pool.*ri.*left.*=.*r.*return.*ri|left_rotation_treap",
            "ri.*=.*pool.*r.*right.*pool.*r.*right.*=.*pool.*ri.*left|treap_left_rot",
            "treap_left_rot|left_rotation|treap_pri_fix"
        ),
        new PatternDef("treap_insert_rot", "treap_bst_insert_with_rotation", "high",
            "if.*key.*<.*pool.*r.*key.*pool.*r.*left.*=.*treap_insert.*left.*key|treap_bst_insert",
            "if.*pool.*pool.*r.*left.*\\.pri.*>.*pool.*r.*\\.pri.*r.*=.*right_rot|treap_heapify_up",
            "treap_insert|treap_bst_rot|treap_priority_insert"
        ),

        // ── Stern-Brocot tree ───────────────────────────────────────────────
        new PatternDef("sb_mediant_step", "stern_brocot_mediant_computation", "high",
            "mn.*=.*ln.*\\+.*rn",
            "md.*=.*ld.*\\+.*rd",
            "mediant"
        ),
        new PatternDef("sb_boundary_update", "stern_brocot_boundary_update_on_compare", "high",
            "mn.*\\*.*q.*<.*p.*\\*.*md",
            "ln.*=.*mn",
            "rn.*=.*mn"
        ),
        new PatternDef("sb_depth_count", "stern_brocot_depth_counter_increment", "medium",
            "depth\\+\\+",
            "mn.*==.*p",
            "md.*==.*q"
        ),

        // ── Barrett modular reduction ────────────────────────────────────────
        new PatternDef("barrett_factor_precompute", "barrett_reciprocal_factor_precompute", "high",
            "factor.*1ULL.*<<.*32",
            "barrett_init"
        ),
        new PatternDef("barrett_q_shift", "barrett_approximate_quotient_right_shift", "high",
            ">>.*32",
            "factor.*\\*.*x|x.*\\*.*factor",
            "barrett_reduce"
        ),
        new PatternDef("barrett_correction", "barrett_single_subtraction_correction", "medium",
            "r.*=.*x.*-.*q.*m",
            "if.*r.*>=.*m.*r.*-=.*m"
        ),

        // ── Cantor expansion ─────────────────────────────────────────────────
        new PatternDef("cantor_factoradic_digit", "cantor_count_smaller_right_factoradic", "high",
            "p\\[j\\].*<.*p\\[i\\]",
            "rank.*\\+=.*cnt.*\\*.*fact",
            "cantor_encode"
        ),
        new PatternDef("cantor_decode_select", "cantor_decode_select_kth_unused_element", "high",
            "idx.*=.*rank.*\\/.*f",
            "rank.*=.*rank.*%.*f",
            "used\\[v\\]"
        ),
        new PatternDef("cantor_factorial_weight", "cantor_expansion_factorial_position_weight", "medium",
            "fact.*n.*-.*1.*-.*i",
            "cantor_decode",
            "used.*=.*1"
        ),

        // ── Persistent segment tree ──────────────────────────────────────────
        new PatternDef("pst_clone_node", "persistent_segtree_clone_node_on_update", "high",
            "ps_l.*n.*=.*ps_l.*t.*ps_r.*n.*=.*ps_r.*t.*ps_s.*n.*=.*ps_s.*t.*\\+.*delta|clone.*old.*node",
            "n.*=.*ps_new.*ps_l\\[n\\].*=.*ps_l\\[t\\].*ps_r\\[n\\].*=.*ps_r\\[t\\]|persistent_clone",
            "pst_clone|persistent_node_copy|segtree_version"
        ),
        new PatternDef("pst_version_chain", "persistent_segtree_version_root_array", "high",
            "ps_root.*ver.*\\+.*1.*=.*ps_update.*ps_root.*ver|root.*\\[.*\\+.*1.*\\].*=.*update.*root.*ver",
            "root_array.*version.*chain|ps_root.*\\[.*\\].*ps_update|version_chain",
            "pst_version|version_root|functional_segtree"
        ),
        new PatternDef("pst_old_query", "persistent_segtree_historical_query", "medium",
            "ps_query.*ps_root.*old_ver|query.*version.*1.*vs.*version.*3|historical_range",
            "ps_root\\[1\\].*query.*ps_root\\[3\\]|old_version.*query.*new_version",
            "pst_query_old|historical_sum|immutable_version_query"
        ),

        // ── Mo's algorithm (offline range queries) ───────────────────────────
        new PatternDef("mo_distinct_add", "mo_algorithm_add_increment_distinct", "high",
            "if.*\\+\\+mo_freq.*x.*==.*1.*mo_distinct\\+\\+|if.*\\+\\+freq.*x.*==.*1.*n_distinct\\+\\+",
            "freq\\[x\\].*==.*1.*\\{.*distinct\\+\\+|count_distinct_add.*freq_one",
            "mo_add_distinct|distinct_inc|freq_new_element"
        ),
        new PatternDef("mo_distinct_remove", "mo_algorithm_remove_decrement_distinct", "high",
            "if.*--mo_freq.*x.*==.*0.*mo_distinct--|if.*--freq.*x.*==.*0.*n_distinct--",
            "freq\\[x\\].*==.*0.*\\{.*distinct--|remove.*count.*zero.*distinct_dec",
            "mo_remove_distinct|distinct_dec|freq_zero_remove"
        ),
        new PatternDef("mo_block_sort", "mo_algorithm_block_sorted_query_order", "high",
            "ba.*=.*a.*l.*\\/.*MO_B.*bb.*=.*b.*l.*\\/.*MO_B.*if.*ba.*!=.*bb|block_sort_queries",
            "l.*\\/.*MO_B.*!=.*l.*\\/.*MO_B.*r.*sort|mo_block_cmp.*a.*r.*b.*r",
            "mo_sort|block_query_sort|mo_offline_order"
        ),
        new PatternDef("mo_window_expand", "mo_algorithm_expand_shrink_window", "high",
            "while.*cur_r.*<.*r.*mo_add.*\\+\\+cur_r|while.*cur_l.*>.*l.*mo_add.*--cur_l",
            "cur_r.*<.*r.*\\).*mo_add.*mo_arr.*\\+\\+cur_r|expand_right.*expand_left",
            "mo_expand|mo_window|sliding_window_mo"
        ),

        // ── Tarjan bridge finding ────────────────────────────────────────────
        new PatternDef("bridge_low_disc", "tarjan_bridge_low_disc_assignment", "high",
            "br_disc.*u.*=.*br_low.*u.*=.*\\+\\+br_timer|disc\\[u\\].*=.*low\\[u\\].*=.*\\+\\+timer",
            "low\\[u\\].*=.*disc\\[u\\].*=.*\\+\\+t|bridge_timer_assign.*disc.*low",
            "bridge_disc_low|tarjan_bridge_timer|low_disc_equal"
        ),
        new PatternDef("bridge_detection", "tarjan_bridge_strict_low_check", "high",
            "if.*br_low.*v.*>.*br_disc.*u.*br_n_bridges\\+\\+|if.*low.*v.*>.*disc.*u.*n_bridges",
            "low\\[v\\].*>.*disc\\[u\\].*\\{.*n_bridges\\+\\+|strict_low_greater_disc.*bridge",
            "bridge_check|tarjan_bridge|low_gt_disc"
        ),
        new PatternDef("bridge_parent_skip", "tarjan_bridge_skip_parent_edge", "medium",
            "if.*v.*==.*parent.*continue|if.*v.*==.*par.*continue.*bridge",
            "v.*!=.*parent.*\\{.*br_low.*update|skip_tree_parent.*bridge",
            "bridge_parent_skip|parent_edge_skip|bridge_undirected"
        ),

        // ── Berlekamp-Massey GF(2) LFSR synthesis ────────────────────────
        new PatternDef("bm_discrepancy", "berlekamp_massey_discrepancy_xor_accumulate", "high",
            "d.*\\^=.*seq.*i.*-.*j",
            "C.*>>.*j.*&.*1",
            "discrepancy"
        ),
        new PatternDef("bm_poly_xor_shift", "berlekamp_massey_connection_poly_xor_shift_update", "high",
            "C.*\\^=.*B.*<<.*m",
            "T.*=.*C",
            "B.*=.*T"
        ),
        new PatternDef("bm_length_change", "berlekamp_massey_lfsr_length_increase_on_nonzero", "medium",
            "L.*=.*i.*\\+.*1.*-.*L",
            "2.*\\*.*L.*<=.*i"
        ),

        // ── Tarjan offline LCA ────────────────────────────────────────────
        new PatternDef("tarjan_lca_ancestor_set", "tarjan_offline_lca_ancestor_assign_after_dsu_union", "high",
            "ancestor.*dsu_find.*u.*=.*u",
            "dsu_union.*u.*v",
            "ancestor\\["
        ),
        new PatternDef("tarjan_lca_visited_check", "tarjan_offline_lca_answer_when_peer_visited", "high",
            "visited.*other",
            "ancestor.*dsu_find.*other"
        ),
        new PatternDef("tarjan_lca_query_adj", "tarjan_offline_lca_query_adjacency_list_per_node", "medium",
            "qlist.*u.*qlist_cnt.*u",
            "qu.*idx.*=.*u",
            "qv.*idx.*=.*v"
        ),

        // ── Divide-and-Conquer DP optimisation ───────────────────────────
        new PatternDef("dc_dp_midpoint", "divide_conquer_dp_midpoint_column_bisection", "high",
            "mid.*=.*col_lo.*\\+.*col_hi.*>>.*1",
            "dc_solve.*col_lo.*mid",
            "dc_solve.*mid.*col_hi"
        ),
        new PatternDef("dc_dp_opt_monotone", "divide_conquer_dp_monotone_opt_range_constraint", "high",
            "opt_lo.*best_k",
            "best_k.*opt_hi",
            "opt.*i.*j.*=.*best_k"
        ),
        new PatternDef("dc_dp_diagonal_fill", "divide_conquer_dp_diagonal_interval_cost_recurrence", "medium",
            "dp.*i.*k.*\\+.*dp.*k\\+1.*j",
            "cost.*i.*j",
            "len.*=.*2"
        ),

        // ── Li Chao tree (minimum linear functions) ─────────────────────────
        new PatternDef("lichao_mid_dominance", "lichao_midpoint_dominance_test_and_swap", "high",
            "mid_new.*=.*m.*mid.*b.*<.*lc_eval.*nd.*mid|m.*mid.*\\+.*b.*<.*lc_m.*nd.*mid.*\\+.*lc_b.*nd",
            "if.*mid_new.*\\{.*tm.*=.*lc_m.*nd.*tb.*=.*lc_b|swap.*stored.*new.*lichao",
            "lichao_mid|lichao_swap|lichao_dominance"
        ),
        new PatternDef("lichao_loser_recurse", "lichao_recurse_loser_to_correct_half", "high",
            "if.*lo_new.*!=.*mid_new.*lc_add.*2.*nd.*lo.*mid|if.*left.*!=.*med.*recurse.*left",
            "else.*lc_add.*2.*nd.*\\+.*1.*mid.*\\+.*1.*hi|loser_goes_right_half",
            "lichao_loser|lichao_recurse|lichao_half"
        ),
        new PatternDef("lichao_first_insert", "lichao_first_line_direct_store", "medium",
            "if.*!lc_has.*nd.*lc_m.*nd.*=.*m.*lc_b.*nd.*=.*b.*lc_has.*nd.*=.*1.*return",
            "if.*!has.*nd.*store.*line.*return|lichao_first_insert",
            "lichao_empty|lichao_init|lichao_first_store"
        ),
        new PatternDef("lichao_query_min", "lichao_query_minimum_over_ancestors", "high",
            "res.*=.*lc_has.*nd.*?.*lc_eval.*nd.*x.*:.*0x7FFFFFFF|res.*lc_m.*nd.*\\*.*x.*\\+.*lc_b.*nd",
            "return.*res.*<.*child.*?.*res.*:.*child|min.*ancestor.*line.*query",
            "lichao_query|lichao_min|lichao_traverse"
        ),

        // ── Meet-in-the-middle ───────────────────────────────────────────────
        new PatternDef("mitm_mask_enum", "mitm_bitmask_subset_enumeration", "high",
            "for.*mask.*=.*0.*mask.*<.*1.*<<.*HALF.*mask\\+\\+|for.*mask.*<.*1.*<<.*MITM_H",
            "for.*b.*=.*0.*b.*<.*HALF.*b\\+\\+.*if.*mask.*>>.*b.*&.*1.*s.*\\+=|bitmask_subset_sum",
            "mitm_enum|subset_bitmask|mask_sum_enum"
        ),
        new PatternDef("mitm_sort_search", "mitm_sort_left_binary_search_right", "high",
            "mitm_isort.*mitm_lsums.*half|isort.*left_sums.*1.*<<.*HALF",
            "need.*=.*MITM_T.*-.*mitm_rsums.*i.*if.*need.*>=.*0.*cnt.*\\+=.*mitm_count",
            "mitm_sort|mitm_search|mitm_binary_search"
        ),
        new PatternDef("mitm_count_occurrences", "mitm_lower_upper_bound_count", "high",
            "while.*lo.*<.*hi.*m.*=.*lo.*\\+.*hi.*\\/.*2.*if.*a.*m.*<.*v.*lo.*=.*m.*\\+.*1.*else.*hi",
            "lo.*-.*lb|upper_bound.*-.*lower_bound.*count.*occurrences",
            "mitm_count|lb_ub_count|binary_range_count"
        ),

        // ── Centroid decomposition ────────────────────────────────────────────
        new PatternDef("centroid_find", "centroid_decomp_find_centroid_heavy_child", "high",
            "subtree_size.*>.*tree_sz.*\\/.*2|sz.*>.*n.*\\/.*2|heavy_child.*centroid",
            "find_centroid.*v.*u.*tree_sz|recurse.*centroid.*subtree",
            "return.*find_centroid|return.*u.*centroid"
        ),
        new PatternDef("centroid_removed", "centroid_decomp_removed_flag_skip", "high",
            "removed.*\\[.*\\]|cent_removed|decomp_removed",
            "if.*removed.*v.*continue|if.*removed.*skip",
            "removed.*c1.*=.*1|removed.*centroid.*=.*1|mark.*removed"
        ),
        new PatternDef("centroid_subtree_sz", "centroid_decomp_subtree_size_dfs", "medium",
            "int32_t.*subtree_size|int.*sz.*=.*1.*subtree",
            "sz.*\\+=.*subtree_size.*v|sz.*\\+=.*dfs.*sz",
            "return.*sz.*subtree|subtree.*size.*return"
        ),

        // ── K-D tree ──────────────────────────────────────────────────────────
        new PatternDef("kd_tree_build", "kd_tree_recursive_median_split_build", "high",
            "partition_median|sort.*axis|median.*split.*dim",
            "split_dim.*=.*depth.*%.*DIM|split_dim.*%.*dim|cycling.*dimension",
            "nodes.*idx.*\\.pt|left.*=.*build.*lo.*mid|right.*=.*build.*mid"
        ),
        new PatternDef("kd_tree_nn_search", "kd_tree_nearest_neighbour_backtrack_search", "high",
            "best_dist2|best_dist.*=|nn.*dist.*<.*best",
            "first.*=.*diff.*<=.*0.*\\?.*left.*:.*right|first.*second.*backtrack",
            "diff.*\\*.*diff.*<.*best_dist2|if.*diff.*\\*.*diff.*<.*best"
        ),
        new PatternDef("kd_tree_dist2", "kd_tree_squared_euclidean_distance", "medium",
            "dx.*=.*a.*x.*0.*-.*b.*x.*0|dx.*=.*a.*re.*-.*b.*re|dist.*sq.*eucl",
            "dx.*\\*.*dx.*\\+.*dy.*\\*.*dy|squared.*euclidean|dist2.*return",
            "dist2.*Point|dist2.*KDNode|squared.*dist.*2D"
        ),

        // ── Hungarian algorithm (Kuhn-Munkres) ───────────────────────────────
        new PatternDef("hungarian_potential", "hungarian_row_col_potential_initialise", "high",
            "u.*\\[.*\\].*=.*0|row.*potential.*init|u.*i.*=.*0.*v.*j.*=.*0",
            "p.*\\[.*j.*\\].*=.*0|col.*assignment.*init|way.*\\[.*\\]",
            "for.*i.*=.*1.*i.*<=.*n|hungarian.*init.*potential"
        ),
        new PatternDef("hungarian_augment", "hungarian_shortest_path_augmentation_loop", "high",
            "minv.*\\[.*j.*\\].*=.*0x7FFFFFFF|minv.*INT_MAX|hungarian.*relax",
            "cur.*=.*cost.*i0.*j.*-.*u.*i0.*-.*v.*j|reduced.*cost.*hungarian",
            "do.*\\{.*used.*j1.*=.*1|hungarian.*augment.*do.*while|p.*j1.*!=.*0"
        ),
        new PatternDef("hungarian_path_update", "hungarian_path_reversal_and_potential_update", "medium",
            "u.*p.*j.*\\+=.*delta|v.*j.*-=.*delta|potential.*update.*delta",
            "j1.*=.*way.*j1|path.*reversal.*way|p.*j1.*=.*p.*j2",
            "do.*\\{.*j2.*=.*way.*j1.*p.*j1.*=.*p.*j2|hungarian.*path.*reverse"
        ),
    };

    // ── main ──────────────────────────────────────────────────────────────────

    @Override
    public void run() throws Exception {
        // Resolve output file.
        File outFile;
        String[] args = getScriptArgs();
        if (args != null && args.length > 0 && !args[0].isEmpty()) {
            outFile = new File(args[0]);
        } else {
            outFile = new File(System.getProperty("user.home"),
                    currentProgram.getName().replaceAll("[^\\w.-]", "_")
                    + "_semantic_hints.json");
        }

        // Decompile all functions.
        DecompInterface decompiler = new DecompInterface();
        decompiler.setOptions(new DecompileOptions());
        decompiler.toggleCCode(true);
        if (!decompiler.openProgram(currentProgram)) {
            printerr("Decompiler failed: " + decompiler.getLastMessage());
            return;
        }

        List<FunctionResult> results = new ArrayList<>();
        int matched   = 0;
        int unmatched = 0;

        try {
            FunctionIterator it = currentProgram.getListing().getFunctions(true);
            while (it.hasNext()) {
                monitor.checkCancelled();
                Function fn = it.next();

                // Skip ROM / external (no body to analyze).
                if (fn.isExternal()) continue;

                DecompileResults res =
                        decompiler.decompileFunction(fn, DECOMPILE_TIMEOUT_SECS, monitor);
                if (res == null || !res.decompileCompleted()) { unmatched++; continue; }
                DecompiledFunction df = res.getDecompiledFunction();
                if (df == null) { unmatched++; continue; }

                String body = df.getC();
                PatternMatch pm = applyPatterns(body, fn.getName());
                if (pm != null) {
                    results.add(new FunctionResult(fn, pm));
                    matched++;
                } else {
                    results.add(new FunctionResult(fn, null));
                    unmatched++;
                }
            }
        } finally {
            decompiler.dispose();
        }

        // Sort results by address.
        results.sort(Comparator.comparing(r -> r.fn.getEntryPoint()));

        // Emit JSON.
        writeJson(outFile, results);

        println(String.format(
            "Pattern scan: %d matched, %d unmatched → %s",
            matched, unmatched, outFile.getAbsolutePath()));

        // Print a quick summary of the most interesting finds.
        println("── Top pattern matches ──────────────────────────────────");
        results.stream()
               .filter(r -> r.match != null && !r.match.patternId.startsWith("?"))
               .sorted(Comparator.comparing((FunctionResult r) -> r.match.confidence)
                                 .reversed())
               .limit(20)
               .forEach(r -> println(String.format(
                   "  %-40s  %s → %s  [%s]",
                   r.fn.getName(),
                   r.fn.getEntryPoint(),
                   r.match.suggestedName,
                   r.match.patternId)));
    }

    // ── pattern matching ──────────────────────────────────────────────────────

    private PatternMatch applyPatterns(String body, String fnName) {
        for (PatternDef pd : PATTERNS) {
            List<String> evidence = new ArrayList<>();
            boolean allMatch = true;

            for (String patStr : pd.evidencePatterns) {
                if (patStr.isEmpty()) continue; // skip intentionally-empty slots
                try {
                    Pattern p = Pattern.compile(patStr,
                            Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
                    Matcher m = p.matcher(body);
                    if (m.find()) {
                        evidence.add(m.group(0).trim().substring(0,
                                Math.min(40, m.group(0).trim().length())));
                    } else {
                        allMatch = false;
                        break;
                    }
                } catch (PatternSyntaxException ex) {
                    allMatch = false;
                    break;
                }
            }

            if (allMatch && !evidence.isEmpty()) {
                // Build a unique suggested name: prefix + stripped address from fnName.
                String addr = fnName.replaceAll("^.*?([0-9a-fA-F]{8}).*$", "$1");
                String sug  = pd.suggestedPrefix + "_" + addr;
                return new PatternMatch(pd.id, sug, pd.confidence, evidence);
            }
        }
        return null; // no pattern matched
    }

    // ── JSON writer ───────────────────────────────────────────────────────────

    private void writeJson(File outFile, List<FunctionResult> results) throws IOException {
        try (PrintWriter pw = new PrintWriter(new FileWriter(outFile))) {
            pw.println("{");
            pw.println("  \"program\": " + jsonStr(currentProgram.getName()) + ",");
            pw.println("  \"language\": " + jsonStr(currentProgram.getLanguageID().toString()) + ",");
            pw.println("  \"functions\": [");
            for (int i = 0; i < results.size(); i++) {
                FunctionResult r = results.get(i);
                pw.println("    {");
                pw.println("      \"address\": " + jsonStr("0x" + r.fn.getEntryPoint()) + ",");
                pw.println("      \"ghidra_name\": " + jsonStr(r.fn.getName()) + ",");
                if (r.match != null) {
                    pw.println("      \"pattern\": " + jsonStr(r.match.patternId) + ",");
                    pw.println("      \"suggested_name\": " + jsonStr(r.match.suggestedName) + ",");
                    pw.println("      \"confidence\": " + jsonStr(r.match.confidence) + ",");
                    pw.print  ("      \"evidence\": [");
                    pw.print(r.match.evidence.stream()
                            .map(DetectSemanticPatterns::jsonStr)
                            .collect(Collectors.joining(", ")));
                    pw.println("]");
                } else {
                    pw.println("      \"pattern\": null,");
                    pw.println("      \"suggested_name\": null,");
                    pw.println("      \"confidence\": null,");
                    pw.println("      \"evidence\": []");
                }
                pw.println("    }" + (i < results.size() - 1 ? "," : ""));
            }
            pw.println("  ]");
            pw.println("}");
        }
    }

    private static String jsonStr(String s) {
        if (s == null) return "null";
        return "\"" + s.replace("\\", "\\\\")
                       .replace("\"", "\\\"")
                       .replace("\n", "\\n")
                       .replace("\r", "\\r") + "\"";
    }

    // ── data classes ──────────────────────────────────────────────────────────

    private static class PatternDef {
        final String   id;
        final String   suggestedPrefix;
        final String   confidence;
        final String[] evidencePatterns;

        PatternDef(String id, String prefix, String conf, String... patterns) {
            this.id               = id;
            this.suggestedPrefix  = prefix;
            this.confidence       = conf;
            this.evidencePatterns = patterns;
        }
    }

    private static class PatternMatch {
        final String       patternId;
        final String       suggestedName;
        final String       confidence;
        final List<String> evidence;

        PatternMatch(String id, String name, String conf, List<String> ev) {
            this.patternId     = id;
            this.suggestedName = name;
            this.confidence    = conf;
            this.evidence      = ev;
        }
    }

    private static class FunctionResult {
        final Function     fn;
        final PatternMatch match;

        FunctionResult(Function fn, PatternMatch match) {
            this.fn    = fn;
            this.match = match;
        }
    }
}
