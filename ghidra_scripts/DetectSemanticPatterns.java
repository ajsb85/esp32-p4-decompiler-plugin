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
