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
