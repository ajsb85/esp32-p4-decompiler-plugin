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
        new PatternDef("dinic_bfs_level_v2", "dinic_bfs_level_graph_sink_reachable", "high",
            "level.*\\[.*\\].*=.*-1|bfs.*level.*init|dinic.*level.*graph",
            "level.*u.*=.*level.*v.*\\+.*1|bfs.*level.*assign|level.*sink.*>=.*0",
            "cap.*>.*0.*&&.*level.*<.*0|dinic.*bfs.*reachable|augmenting.*path.*bfs"
        ),
        new PatternDef("dinic_dfs_blocking_v2", "dinic_dfs_blocking_flow_current_edge_opt", "high",
            "iter.*\\[.*\\].*=.*head|current.*edge.*optimisation|dinic.*iter.*ptr",
            "dfs.*blocking.*flow|d.*=.*dfs.*u.*t.*f.*cap|dinic.*blocking.*augment",
            "cap.*-=.*d|rev.*cap.*\\+=.*d|dinic.*flow.*update.*reverse"
        ),
        new PatternDef("dinic_phase_loop", "dinic_max_flow_bfs_dfs_phase_accumulate", "medium",
            "while.*bfs.*s.*t|dinic.*phase.*loop|max_flow.*bfs.*dfs",
            "flow.*\\+=.*f|dinic.*total.*flow.*accumulate|f.*=.*dfs.*s.*t.*INF",
            "dinic.*max.*flow.*return|flow.*network.*augment.*repeat|dinic.*while.*bfs"
        ),
        new PatternDef("splay_rotate", "splay_tree_single_rotation_parent_fix", "high",
            "ch.*opp.*=.*inner|splay.*rotate.*inner.*child|splay.*rotate.*dir.*opp",
            "parent.*=.*g|splay.*link.*grandparent|splay.*rotate.*grandparent.*fix",
            "ch.*0.*==.*p|ch.*1.*==.*p|splay.*rotate.*direction.*detect"
        ),
        new PatternDef("splay_splay", "splay_tree_zig_zig_zag_to_root", "high",
            "while.*parent.*!=.*-1|splay.*to.*root.*loop|splay.*zig.*zig.*zag",
            "xdir.*==.*pdir.*rotate.*p|zig.*zig.*rotate.*parent.*first|splay.*double.*rotation",
            "rotate.*x.*splay.*root|splay.*root.*=.*x|splay.*single.*zig.*rotation"
        ),
        new PatternDef("splay_find", "splay_tree_find_and_splay_to_root", "medium",
            "key.*==.*pool.*cur.*key.*splay.*cur|splay.*find.*splay.*on.*hit|splay.*search.*and.*splay",
            "cur.*=.*ch.*0.*key.*<|cur.*=.*ch.*1.*key.*>|splay.*bst.*traverse.*find",
            "return.*1.*splay.*find.*success|splay.*find.*return.*found|splay.*find.*miss"
        ),
        new PatternDef("sam_extend", "suffix_automaton_extend_state_clone", "high",
            "cur.*=.*sam_sz\\+\\+|sam.*new.*state.*extend|sam.*extend.*len.*last.*\\+.*1",
            "while.*p.*!=.*-1.*next.*c.*==.*-1|sam.*suffix.*link.*walk|sam.*extend.*suffix.*link",
            "clone.*=.*sam_sz\\+\\+|sam.*clone.*state.*split|sam.*link.*q.*=.*clone"
        ),
        new PatternDef("sam_suffix_link", "suffix_automaton_suffix_link_update", "high",
            "sam_st.*link.*=.*0|sam.*link.*initial.*state|sam.*suffix.*link.*root",
            "sam_st.*q.*len.*\\+.*1.*==.*sam_st.*q.*len|sam.*no.*clone.*needed|sam.*link.*q.*direct",
            "sam_st.*p.*next.*c.*=.*clone|sam.*redirect.*transitions.*clone|sam.*clone.*next.*copy"
        ),
        new PatternDef("sam_contains", "suffix_automaton_substring_membership_query", "medium",
            "cur.*=.*0.*sam.*contains|sam.*traverse.*pattern|sam.*query.*substring",
            "next.*c.*==.*-1.*return.*0|sam.*missing.*transition.*reject|sam.*contains.*walk",
            "cur.*=.*next.*c|sam.*follow.*transition|sam.*accept.*substring.*return.*1"
        ),
        // ── Sprint 122: link_cut_tree ─────────────────────────────────────────
        new PatternDef("lct_access", "link_cut_tree_access_preferred_path", "high",
            "lct_access|lct.*preferred.*path|access.*splay.*path.*root",
            "lct_is_root|lct.*path.*parent.*pointer|while.*par.*!=.*-1.*splay",
            "lct.*ch.*1.*=.*last|lct.*cut.*preferred.*child|lct.*attach.*last.*node"
        ),
        new PatternDef("lct_splay_rotate", "link_cut_tree_splay_rotate_operation", "high",
            "lct_splay|lct_rotate|lct.*zig.*zig.*zig.*zag",
            "lct_push_all|lct.*push.*lazy.*flags.*root.*down|lct.*push_rev.*ancestor",
            "lct.*ch.*k.*1.*=.*w|lct.*rotate.*y.*z|lct.*splay.*amortise"
        ),
        new PatternDef("lct_link_cut", "link_cut_tree_link_cut_connectivity", "high",
            "lct_link|lct_cut|lct.*make_root.*link.*cut",
            "lct_make_root|lct.*re.*root.*represented.*tree|lct.*rev.*=.*1",
            "lct_connected|lct_find_root|lct.*find.*root.*same.*tree"
        ),
        // ── Sprint 122: palindrome_tree ───────────────────────────────────────
        new PatternDef("pt_init_roots", "palindrome_tree_imaginary_root_init", "high",
            "pt.*len.*=.*-1|eertree.*odd.*root|palindrome_tree.*root.*minus.*one",
            "pt.*len.*=.*0|eertree.*even.*root|palindrome_tree.*even.*empty.*palindrome",
            "pt.*link.*=.*0|eertree.*suffix.*link.*root.*self|pt.*imaginary.*root"
        ),
        new PatternDef("pt_get_link", "palindrome_tree_suffix_link_walk", "high",
            "pt_get_link|eertree.*get.*link|palindrome.*walk.*suffix.*link",
            "pt_str.*left.*==.*pt_str.*pos|eertree.*palindrome.*extend.*check|left.*=.*pos.*pt.*len.*-.*1",
            "v.*=.*pt.*link|eertree.*suffix.*link.*follow|palindrome_tree.*walk.*to.*root"
        ),
        new PatternDef("pt_add_char", "palindrome_tree_add_character_extend", "medium",
            "pt_add|eertree.*add.*character|palindrome_tree.*extend.*char",
            "pt.*sz\\+\\+|eertree.*new.*node.*palindrome|pt.*nw.*=.*pt_sz",
            "pt.*len.*=.*pt.*cur.*len.*\\+.*2|eertree.*new.*palindrome.*length|pt.*link.*=.*1.*single.*char"
        ),
        // ── Sprint 122: convex_hull_trick ─────────────────────────────────────
        new PatternDef("cht_add_line", "convex_hull_trick_add_line_to_hull", "high",
            "cht_add|cht.*add.*line.*hull|convex_hull_trick.*insert.*line",
            "cht_bad|cht.*remove.*middle.*line|hull.*bad.*line.*prune",
            "hull.*sz--|hull.*pop.*dominated.*line|cht.*maintain.*lower.*envelope"
        ),
        new PatternDef("cht_query_min", "convex_hull_trick_query_minimum", "high",
            "cht_query|cht.*query.*minimum|convex_hull.*minimum.*at.*x",
            "ptr_idx.*\\+.*1.*<.*hull_sz|cht.*monotone.*pointer.*walk|cht.*amortised.*query",
            "hull.*ptr_idx.*m.*\\*.*x.*\\+.*hull.*ptr_idx.*q|cht.*evaluate.*line.*at.*x|cht.*return.*min.*y"
        ),
        new PatternDef("cht_dp_slope", "convex_hull_trick_dp_slope_optimisation", "medium",
            "cht_add.*-2.*prefix|cht.*slope.*dp.*transition|convex_hull.*dp.*optimise",
            "dp.*i.*=.*cht_query.*prefix.*i.*\\+.*prefix.*i.*prefix.*i|cht.*dp.*recurrence|slope_trick.*dp",
            "prefix.*i.*\\*.*prefix.*i|cht.*intercept.*dp.*j.*prefix.*j.*squared|cht.*line.*per.*dp.*state"
        ),
        // ── Sprint 123: euler_tour_tree ───────────────────────────────────────
        new PatternDef("ett_dfs_timestamps", "euler_tour_tree_dfs_timestamps", "high",
            "ett_tin|euler_tour.*entry.*time|dfs.*tin.*tout.*timestamp",
            "ett_timer\\+\\+|euler_tour.*timer.*increment|dfs.*timestamp.*assign",
            "tin\\[v\\].*=.*timer|tout\\[v\\].*=.*timer|euler_tour.*record.*entry.*exit"
        ),
        new PatternDef("ett_subtree_range", "euler_tour_tree_subtree_range_query", "high",
            "tin.*>=.*tin.*&&.*tin.*<=.*tout|euler_tour.*subtree.*range.*check",
            "ett_subtree_sum|euler_tour.*sum.*within.*tin.*tout|subtree.*query.*euler.*timestamps",
            "tin\\[i\\].*>=.*tin\\[v\\].*tin\\[i\\].*<=.*tout\\[v\\]|euler_tour.*range.*membership"
        ),
        new PatternDef("ett_iterative_dfs", "euler_tour_tree_iterative_dfs", "medium",
            "ett_stack|euler_tour.*iterative.*stack|dfs.*stack.*phase.*enter.*exit",
            "ph.*==.*0.*tin|euler_tour.*phase.*zero.*entry|iterative_dfs.*push.*exit.*marker",
            "ett_phase|euler_tour.*phase.*array|dfs.*two_phase.*stack.*enter.*exit"
        ),
        // ── Sprint 123: aliens_trick ──────────────────────────────────────────
        new PatternDef("aliens_lambda_search", "aliens_trick_lambda_binary_search", "high",
            "aln_solve.*lam|aliens.*lambda.*binary.*search|wqs.*binary.*search.*penalty",
            "cnt.*>=.*ALN_K|aliens.*group.*count.*check.*k|lambda.*optimisation.*segment.*count",
            "lo.*=.*mid.*\\+.*1|hi.*=.*mid.*-.*1|aliens.*binary.*search.*convergence"
        ),
        new PatternDef("aliens_dp_penalty", "aliens_trick_dp_with_penalty", "high",
            "aln_seg_cost.*lam|aliens.*dp.*penalty.*per.*group|wqs.*cost.*plus.*lambda",
            "dp\\[j\\].*\\+.*aln_seg_cost.*\\+.*lam|aliens.*recurrence.*penalty|dp.*group.*penalty.*transition",
            "final_cost.*-=.*final_lam.*\\*.*final_cnt|aliens.*remove.*lambda.*adjustment|wqs.*depenalise"
        ),
        new PatternDef("aliens_rmq_build", "aliens_trick_rmq_precompute", "medium",
            "aln_mn|aln_mx|aliens.*precompute.*min.*max",
            "aln_build_rmq|aliens.*build.*rmq.*table|wqs.*range.*min.*max.*precompute",
            "aln_seg_cost.*=.*aln_mx.*-.*aln_mn|aliens.*segment.*cost.*max.*minus.*min"
        ),
        // ── Sprint 123: segment_tree_beats ────────────────────────────────────
        new PatternDef("stb_chmin_update", "segment_tree_beats_chmin_update", "high",
            "stb_update|segment_tree_beats.*chmin|ji_driver.*range.*chmin",
            "stb_max2\\[nd\\].*<.*val|segment_tree_beats.*break.*condition|beats.*second.*max.*guard",
            "stb_push_chmin|beats.*apply.*chmin.*lazy|ji_driver.*propagate.*max.*cap"
        ),
        new PatternDef("stb_pushup_max", "segment_tree_beats_pushup_max_tracking", "high",
            "stb_max1|stb_max2|stb_maxcnt|segment_tree_beats.*max.*second.*count",
            "stb_pushup|beats.*merge.*max1.*max2.*maxcnt|ji_driver.*pushup.*merge",
            "maxcnt\\[nd\\].*=.*maxcnt.*nd.*2|beats.*count.*maximum.*merge|stb.*max.*count.*combine"
        ),
        new PatternDef("stb_lazy_propagate", "segment_tree_beats_lazy_propagation", "medium",
            "stb_pushdown|segment_tree_beats.*pushdown|beats.*lazy.*propagate",
            "stb_lazy\\[nd\\].*=.*0x7FFFFFFF|beats.*clear.*lazy.*sentinel|ji_driver.*reset.*lazy",
            "push_chmin.*nd.*2.*lazy|beats.*push.*children.*chmin.*lazy|stb.*lazy.*inherit"
        ),
        // ── Sprint 124: extended_gcd ──────────────────────────────────────────
        new PatternDef("egcd_recursive", "extended_gcd_recursive_bezout", "high",
            "egcd|extended_gcd|extended_euclidean",
            "px.*=.*y1|egcd.*back.*subst|bezout.*coefficient.*unwind",
            "py.*=.*x1.*-.*a.*b.*\\*.*y1|egcd.*recursive.*coefficient|euclid.*extended.*return.*xy"
        ),
        new PatternDef("egcd_mod_inv", "extended_gcd_modular_inverse", "high",
            "mod_inv|modular_inverse.*egcd|modinv.*extended",
            "x.*%.*m.*\\+.*m.*%.*m|mod_inv.*normalise.*negative|inverse.*adjust.*mod.*positive",
            "egcd.*a.*m.*&.*x|extended.*gcd.*inverse.*from.*bezout|mod_inv.*return.*x.*percent.*m"
        ),
        new PatternDef("egcd_base_case", "extended_gcd_base_case_identity", "medium",
            "if.*b.*==.*0.*px.*=.*1|egcd.*base.*case.*identity|euclid.*stop.*b.*zero",
            "px.*=.*1.*py.*=.*0|egcd.*base.*x.*one.*y.*zero|extended_euclidean.*trivial.*solution",
            "return.*a.*if.*b.*zero|egcd.*terminal.*coefficient|euclid.*extended.*leaf.*xy"
        ),
        // ── Sprint 124: cuckoo_hashing ────────────────────────────────────────
        new PatternDef("cuck_insert_evict", "cuckoo_hashing_eviction_loop", "high",
            "cuck_insert|cuckoo.*insert.*evict|cuckoo.*hash.*kick",
            "ev.*<.*MAX_EVICT|cuckoo.*eviction.*limit|cuckoo.*cycle.*sentinel.*return.*0",
            "T1.*h1.*k.*=.*k|cuckoo.*place.*table1|cuckoo.*kick.*occupant.*alternate"
        ),
        new PatternDef("cuck_lookup_dual", "cuckoo_hashing_dual_table_lookup", "high",
            "cuck_lookup|cuckoo.*lookup.*T1.*T2|cuckoo.*two.*table.*probe",
            "T1\\[h1\\(k\\)\\].*==.*k.*\\|\\|.*T2\\[h2\\(k\\)\\].*==.*k|cuckoo.*check.*both.*tables",
            "h1.*k.*%.*CAP|h2.*k.*CAP.*%.*CAP|cuckoo.*dual.*hash.*function"
        ),
        new PatternDef("cuck_init_tables", "cuckoo_hashing_table_initialisation", "medium",
            "cuck_init|cuckoo.*init.*T1.*T2|cuckoo.*clear.*both.*tables",
            "T1.*i.*=.*CUCK_EMPTY|T2.*i.*=.*CUCK_EMPTY|cuckoo.*sentinel.*zero.*fill",
            "cuckoo.*capacity.*prime|cuckoo.*EMPTY.*sentinel.*zero|cuckoo.*reset.*sub_tables"
        ),
        // ── Sprint 124: dominator_tree ────────────────────────────────────────
        new PatternDef("dom_intersect", "dominator_tree_intersect_rpo", "high",
            "dom_intersect|dominator.*intersect.*rpo|idom.*finger.*walk",
            "rpo_idx.*b1.*>.*rpo_idx.*b2.*b1.*=.*idom.*b1|dominator.*walk.*up.*rpo.*order",
            "while.*b1.*!=.*b2|dominator.*converge.*fingers|idom.*intersection.*rpo.*indices"
        ),
        new PatternDef("dom_compute_iter", "dominator_tree_iterative_dataflow", "high",
            "dom_compute|dominator.*iterative.*dataflow|cooper.*harvey.*kennedy.*idom",
            "new_idom.*=.*dom_intersect|dominator.*new_idom.*predecessor|idom.*changed.*repeat",
            "idom.*DOM_UNDEF|dominator.*undefined.*initialise|dom.*changed.*=.*1.*while"
        ),
        new PatternDef("dom_depth_walk", "dominator_tree_depth_computation", "medium",
            "dom_depth|dominator.*tree.*depth|idom.*depth.*walk.*root",
            "while.*v.*!=.*DOM_ROOT.*v.*=.*idom.*v|dominator.*depth.*walk.*up",
            "d\\+\\+.*idom|dominator.*count.*steps.*root|dom_depth.*return.*d"
        ),
        // ── treap_implicit ──────────────────────────────────────────────────────
        new PatternDef("treap_split_implicit", "treap_implicit_split_by_rank", "high",
            "treap.*split|split.*implicit|split.*rank.*left.*right",
            "lsz.*=.*left.*sz|implicit.*key.*subtree.*size|left_size.*>=.*k",
            "treap_split.*pool.*rev|lazy.*rev.*push_down.*split|push_down.*before.*split"
        ),
        new PatternDef("treap_merge_prio", "treap_implicit_merge_heap_priority", "high",
            "treap.*merge|merge.*prio.*heap|treap.*left.*right.*priority",
            "prio.*>.*prio|heap.*property.*merge.*treap|if.*prio.*greater.*merge",
            "pool.*left.*=.*treap_merge|pool.*right.*=.*treap_merge|merge.*push_up"
        ),
        new PatternDef("treap_lazy_rev", "treap_implicit_lazy_reverse", "medium",
            "lazy.*rev|rev.*flag.*treap|push_down.*rev.*swap",
            "rev.*\\^=.*1|flip.*rev.*children|swap.*left.*right.*rev",
            "push_down.*in_stk.*rev|treap.*reverse.*range|rev.*propagate.*children"
        ),
        // ── matrix_exponentiation ───────────────────────────────────────────────
        new PatternDef("matexp_multiply", "matrix_exponentiation_2x2_multiply", "high",
            "mat.*mul|matrix.*multiply|mat_mul.*result.*mod",
            "for.*i.*2.*j.*2.*k.*2|2x2.*matrix.*dot.*product|mat.*a.*i.*k.*b.*k.*j",
            "s.*+=.*A.*i.*k.*B.*k.*j|matrix.*accumulate.*product|C.*a.*i.*j.*=.*s.*mod"
        ),
        new PatternDef("matexp_fast_pow", "matrix_exponentiation_repeated_squaring", "high",
            "mat_pow|matrix.*fast.*pow|mat.*exp.*repeated.*squaring",
            "exp.*>>=.*1|while.*exp.*>.*0.*exp.*>>=|if.*exp.*&.*1.*result.*=.*mat_mul",
            "base.*=.*mat_mul.*base.*base|matrix.*square.*each.*step|repeated.*squaring.*matrix"
        ),
        new PatternDef("matexp_identity", "matrix_exponentiation_identity_init", "medium",
            "identity.*matrix|mat.*identity.*init|result.*diagonal.*one",
            "a.*0.*0.*=.*1.*a.*1.*1.*=.*1.*a.*0.*1.*=.*0|init.*result.*identity",
            "mat.*eye|matexp.*identity.*before.*loop|result.*start.*identity.*matrix"
        ),
        // ── lyndon_factorization ────────────────────────────────────────────────
        new PatternDef("lyndon_duval_scan", "lyndon_factorization_duval_scan", "high",
            "duval|lyndon.*factor|lyndon.*word.*decompose",
            "j.*=.*i.*k.*=.*i.*\\+.*1.*while.*k.*<.*n|duval.*j.*k.*advance",
            "s.*j.*<=.*s.*k.*j.*=.*i.*j\\+\\+.*k\\+\\+|lyndon.*scan.*j.*reset.*i"
        ),
        new PatternDef("lyndon_emit_words", "lyndon_factorization_emit_words", "high",
            "emit.*lyndon|lyndon.*word.*len.*=.*k.*-.*j|while.*i.*<=.*j.*i.*\\+=.*word_len",
            "word_len.*k.*-.*j|lyndon.*stride.*i.*+=.*word_len|factor.*length.*emit.*loop",
            "lyn_starts|lyn_lens|lyndon.*record.*start.*length"
        ),
        new PatternDef("lyndon_compare", "lyndon_factorization_char_compare", "medium",
            "s.*j.*<.*s.*k|lyndon.*char.*compare|lyn_s.*j.*<=.*lyn_s.*k",
            "if.*s.*j.*<.*s.*k.*j.*=.*i|lyndon.*reset.*j.*on.*less|duval.*strict.*less.*reset",
            "lyndon.*string.*suffix.*rotation|lyn_s.*compare.*duval.*progress"
        ),

        // ── DSU with rollback (no path compression) ──────────────────────────
        new PatternDef("dsu_find_no_compress", "dsu_rollback_find_without_path_compression", "high",
            "while.*dr_p.*x.*!=.*x.*x.*=.*dr_p.*x|while.*p.*x.*!=.*x.*x.*=.*p.*x",
            "find.*no.*compress|dsu_rollback_find",
            "dsu_no_compress|rollback_find|dsu_path_free"
        ),
        new PatternDef("dsu_rollback_push", "dsu_rollback_push_undo_record_before_union", "high",
            "dr_snode.*dr_top.*=.*b.*dr_soldp.*dr_top.*=.*dr_p.*b|snode.*top.*=.*b.*soldp.*top",
            "push.*undo.*stack.*before.*union|dsu_undo_push.*union_by_rank",
            "dsu_undo_push|rollback_stack|dsu_pre_save"
        ),
        new PatternDef("dsu_rollback_restore", "dsu_rollback_pop_undo_records_to_checkpoint", "high",
            "while.*dr_top.*>.*cp.*dr_top--|while.*top.*>.*checkpoint.*top--",
            "dr_p.*b.*=.*dr_soldp.*dr_top.*dr_r.*a.*=.*dr_soldr|undo.*restore.*pop",
            "dsu_rollback|dsu_undo_pop|checkpoint_restore"
        ),

        // ── Sweep-line interval depth ─────────────────────────────────────────
        new PatternDef("sweep_open_close_ev", "sweep_line_open_close_event_creation", "high",
            "sw_ev.*sw_ne.*=.*SwEv.*ls.*i.*\\+.*1.*sw_ev.*sw_ne.*=.*SwEv.*rs.*i.*\\+.*1.*-.*1",
            "create.*open.*close.*events.*interval|ev.*open.*delta.*\\+1.*close.*-1",
            "sweep_events|open_close|interval_events"
        ),
        new PatternDef("sweep_depth_max", "sweep_line_running_depth_maximum", "high",
            "cur.*\\+=.*sw_ev.*i.*d.*if.*cur.*>.*mx.*mx.*=.*cur|running_sum.*update.*max",
            "current.*\\+=.*event.*delta.*max.*sweep|depth.*sweep.*increment.*max",
            "sweep_depth|interval_depth|sweep_max"
        ),

        // ── Parallel binary search ────────────────────────────────────────────
        new PatternDef("pbs_outer_log_loop", "parallel_bsearch_log_n_outer_iterations", "high",
            "for.*iter.*=.*0.*iter.*<.*PBS_LOG.*iter\\+\\+.*psum.*=.*0|log_n_passes_parallel_bsearch",
            "outer_log_loop.*parallel.*binary.*search|pbs_iter_count",
            "pbs_outer|parallel_bsearch|pbs_log_iter"
        ),
        new PatternDef("pbs_mid_per_query", "parallel_bsearch_per_query_midpoint_check", "high",
            "if.*pbs_lo.*q.*>.*pbs_hi.*q.*continue.*mid.*=.*pbs_lo.*\\+.*pbs_hi.*\\/.*2.*if.*mid.*==.*i",
            "mid.*lo.*q.*hi.*q.*2.*if.*mid.*==.*i.*check|per_query_mid_check_parallel",
            "pbs_mid|parallel_mid_check|pbs_query_mid"
        ),
        new PatternDef("pbs_narrow_lo_hi", "parallel_bsearch_narrow_lo_hi_per_query", "high",
            "if.*psum.*>=.*pbs_thr.*q.*pbs_hi.*q.*=.*mid.*-.*1.*else.*pbs_lo.*q.*=.*mid.*\\+.*1",
            "check.*pass.*hi.*q.*=.*mid.*-.*1.*else.*lo.*q.*=.*mid.*\\+.*1|narrow_parallel_range",
            "pbs_narrow|pbs_lo_hi|parallel_binary_narrow"
        ),

        // ── O(n log n) LIS via patience sorting ─────────────────────────────
        new PatternDef("lis_patience_lb", "lis_patience_sort_lower_bound_tails", "high",
            "pos.*=.*la_lb.*la_tails.*len.*la_a.*i|pos.*=.*lower_bound.*tails.*len.*a.*i",
            "lower_bound.*tails.*len.*v.*patience.*sort|lis_patience.*lb.*tails",
            "lis_patience|patience_lb|lis_tails_lb"
        ),
        new PatternDef("lis_tails_extend", "lis_patience_tails_array_extend_or_replace", "high",
            "la_tails.*pos.*=.*la_a.*i.*if.*pos.*==.*len.*len\\+\\+|tails.*pos.*=.*a.*i.*pos.*==.*len",
            "tails\\[pos\\].*=.*a\\[i\\].*if.*pos.*==.*len.*len\\+\\+|patience_extend_replace",
            "lis_extend|tails_replace|patience_len"
        ),

        // ── Min-cost max-flow (SPFA) ─────────────────────────────────────────
        new PatternDef("mcmf_reverse_edge", "mcmf_xor_based_reverse_edge_indexing", "high",
            "mc_e.*mc_ec.*=.*McEdge.*u.*0.*-cost.*mc_hd.*v|reverse_edge.*cost.*neg.*xor",
            "mc_e\\[mc_ec\\].*\\{.*u.*0.*-.*cost|backward_edge.*zero_cap.*neg_cost",
            "mcmf_reverse|xor_reverse_edge|mcmf_backward"
        ),
        new PatternDef("mcmf_spfa_relax", "mcmf_spfa_capacity_gated_edge_relaxation", "high",
            "if.*mc_e.*i.*cap.*>.*0.*&&.*mc_d.*u.*\\+.*mc_e.*i.*cost.*<.*mc_d.*v",
            "cap.*>.*0.*dist.*u.*cost.*<.*dist.*v.*relax|spfa_residual_relax",
            "mcmf_relax|spfa_cap_relax|mcmf_spfa"
        ),
        new PatternDef("mcmf_augment_xor", "mcmf_augment_path_via_xor_reverse_edge", "high",
            "mc_e.*e.*cap.*-=.*flow.*mc_e.*e.*\\^.*1.*cap.*\\+=.*flow|e\\^1.*cap.*\\+",
            "e.*\\^.*1.*to.*path.*reconstruction|mc_aug.*xor.*reverse|augment_xor",
            "mcmf_aug_xor|mcmf_augment|xor_aug_path"
        ),
        new PatternDef("mcmf_cost_accumulate", "mcmf_cost_accumulate_per_augmentation", "high",
            "flow.*\\+=.*pcap.*cost.*\\+=.*c.*\\*.*pcap|total_cost.*\\+=.*path_cost.*\\*.*flow",
            "cost.*\\+=.*dist.*t.*\\*.*bottleneck|mcmf_cumulative_cost",
            "mcmf_cost|mcmf_accumulate|mcmf_total_cost"
        ),

        // ── Randomized Quickselect ───────────────────────────────────────────
        new PatternDef("rqs_partition_lomuto", "quickselect_lomuto_partition_store_index", "high",
            "store.*=.*lo.*for.*i.*=.*lo.*i.*<.*hi.*if.*arr.*i.*<=.*pivot.*swap.*store.*store\\+\\+",
            "pivot.*swap.*store.*lo.*arr.*store.*hi.*lomuto.*partition|rqs_store.*pivot",
            "rqs_partition|quickselect_partition|lomuto_store"
        ),
        new PatternDef("rqs_median_of_three", "quickselect_median_of_three_pivot", "high",
            "mid.*=.*lo.*\\+.*hi.*-.*lo.*\\/.*2.*if.*arr.*lo.*>.*arr.*mid.*swap.*lo.*mid",
            "if.*arr.*lo.*>.*arr.*hi.*swap.*lo.*hi.*if.*arr.*mid.*>.*arr.*hi.*swap.*mid.*hi|median_of_three",
            "rqs_pivot|med3_pivot|quickselect_median3"
        ),
        new PatternDef("rqs_tail_recurse", "quickselect_tail_narrow_range_loop", "high",
            "while.*lo.*<.*hi.*p.*=.*partition.*if.*p.*==.*k.*return.*arr.*p.*else.*if.*p.*<.*k.*lo.*=.*p.*\\+.*1",
            "p.*==.*k.*return.*p.*<.*k.*lo.*=.*p.*\\+.*1.*hi.*=.*p.*-.*1|quickselect_narrow",
            "rqs_select|quickselect_loop|rqs_lo_hi_narrow"
        ),

        // ── Manacher Palindrome ──────────────────────────────────────────────
        new PatternDef("manacher_transform", "manacher_hash_sentinel_transform", "high",
            "man_t.*=.*#.*for.*i.*<.*n.*man_t.*=.*man_s.*i.*man_t.*=.*#|transform.*#.*palindrome.*sentinel",
            "tlen.*=.*0.*t.*tlen\\+\\+.*=.*#.*for.*i.*=.*0.*i.*<.*n.*t.*=.*s.*i.*t.*=.*#|manacher_build_t",
            "manacher_transform|man_tlen|palindrome_sentinel_insert"
        ),
        new PatternDef("manacher_mirror_expand", "manacher_mirror_right_boundary_expand", "high",
            "if.*i.*<.*r.*p.*i.*=.*min.*p.*mirror.*r.*-.*i.*while.*t.*i.*-.*p.*i.*-.*1.*==.*t.*i.*\\+.*p.*i.*\\+.*1",
            "mirror.*=.*2.*c.*-.*i.*if.*i.*<.*r.*p.*i.*=.*p.*mirror.*<.*r.*-.*i|manacher_expand_center",
            "manacher_mirror|man_expand|palindrome_expand_right"
        ),
        new PatternDef("manacher_right_update", "manacher_update_rightmost_palindrome_center", "high",
            "if.*i.*\\+.*p.*i.*>.*r.*c.*=.*i.*r.*=.*i.*\\+.*p.*i|update.*c.*r.*rightmost.*manacher",
            "c.*=.*i.*r.*=.*i.*\\+.*p.*i.*if.*i.*\\+.*p.*i.*>.*r|manacher_center_right_update",
            "manacher_right|man_c_r|manacher_boundary_update"
        ),

        // ── Sqrt Decomposition ───────────────────────────────────────────────
        new PatternDef("sqd_build_blocks", "sqrt_decomp_build_block_sums", "high",
            "for.*i.*=.*0.*i.*<.*sqd_n.*bsum.*i.*\\/.*sqd_b.*\\+=.*arr.*i|block_sum.*\\+=.*arr.*i.*block.*=.*i.*\\/.*B",
            "sqd_bsum.*idx.*\\/.*SQD_B.*\\+=.*delta|sqrt_decomp_block_build",
            "sqd_build|block_sum_build|sqrt_decomp_preprocess"
        ),
        new PatternDef("sqd_point_update", "sqrt_decomp_point_update_and_block_sum", "high",
            "arr.*idx.*\\+=.*delta.*bsum.*idx.*\\/.*b.*\\+=.*delta|sqd_update.*sqd_bsum.*\\+=.*delta",
            "sqd_arr.*idx.*\\+=.*delta.*sqd_bsum.*idx.*\\/.*SQD_B.*\\+=.*delta|point_update_block",
            "sqd_update|sqrt_point_update|block_sum_update"
        ),
        new PatternDef("sqd_range_query", "sqrt_decomp_range_query_partial_full_blocks", "high",
            "bl.*=.*l.*\\/.*sqd_b.*br.*=.*r.*\\/.*sqd_b.*if.*bl.*==.*br.*for.*i.*=.*l.*i.*<=.*r",
            "for.*b.*=.*bl.*\\+.*1.*b.*<.*br.*sum.*\\+=.*bsum.*b.*for.*i.*=.*right_start.*i.*<=.*r|sqd_query",
            "sqd_query|sqrt_range_sum|block_partial_full_query"
        ),

        // ── Lucas theorem (C(n,k) mod prime) ────────────────────────────────
        new PatternDef("lucas_digit_recurse", "lucas_theorem_base_p_digit_recursion", "high",
            "comb_mod_p.*n.*%.*p.*k.*%.*p.*p.*\\*.*lucas.*n.*\\/.*p.*k.*\\/.*p.*p.*%.*p",
            "return.*lt_comb.*n.*p.*k.*p.*p.*\\*.*lt_lucas.*n.*p.*k.*p.*p|lucas_recursive",
            "lucas_recurse|lucas_digits|lucas_mod_p"
        ),
        new PatternDef("lucas_base_case", "lucas_theorem_base_case_k_zero", "medium",
            "if.*k.*==.*0.*return.*1|lucas_base.*k.*zero.*return.*one",
            "k.*==.*0.*\\{.*return.*1.*\\}.*lucas.*theorem|base.*case.*lucas",
            "lucas_base|lucas_k_zero|lucas_trivial"
        ),
        new PatternDef("lucas_fact_table", "lucas_theorem_factorial_table_mod_p", "high",
            "lt_fact.*0.*=.*1.*for.*i.*=.*1.*i.*<.*p.*i\\+\\+.*lt_fact.*i.*=.*lt_fact.*i.*-.*1.*\\*.*i.*%.*p",
            "fact\\[0\\].*=.*1.*fact\\[i\\].*=.*fact\\[i.*-.*1\\].*\\*.*i.*%.*p|factorial_mod_p_table",
            "lucas_fact|fact_mod_p|factorial_table_p"
        ),

        // ── Bitset-accelerated subset sum DP ────────────────────────────────
        new PatternDef("bitset_shift_or", "bitset_dp_shift_or_update", "high",
            "dp.*=.*dp.*|.*dp.*<<.*bs_a.*i.*&.*mask|dp.*\\|=.*dp.*<<.*a.*i.*&.*mask",
            "dp.*\\|.*dp.*<<.*weight.*bitset.*dp.*update|shift_or_bitmask_dp",
            "bitset_shift_or|bs_dp_update|dp_shift_or"
        ),
        new PatternDef("bitset_popcount", "bitset_dp_popcount_achievable_sums", "medium",
            "for.*x.*=.*dp.*x.*x.*>>=.*1.*cnt.*\\+=.*x.*&.*1|popcount.*dp.*achievable.*sums",
            "cnt.*\\+=.*x.*&.*1.*x.*>>=.*1|__builtin_popcount.*dp.*bitset",
            "bitset_popcount|bs_count|bitset_bit_count"
        ),
        new PatternDef("bitset_mask_clamp", "bitset_dp_target_width_clamp_mask", "medium",
            "mask.*=.*1u.*<<.*BS_W.*\\+.*1.*-.*1|mask.*=.*1.*<<.*W.*\\+.*1.*-.*1.*clamp",
            "& mask.*where.*mask.*W.*bits|bitset_clamp.*target.*width",
            "bitset_mask|bs_width_mask|dp_clamp"
        ),

        // ── Shift-And pattern matching ────────────────────────────────────────
        new PatternDef("shift_and_mask_build", "shift_and_character_bitmask_build", "high",
            "sa_mask.*sa_p.*j.*|=.*1u.*<<.*j|mask.*P.*j.*\\|=.*1.*<<.*j",
            "for.*j.*=.*0.*j.*<.*SA_M.*j\\+\\+.*mask.*p.*j.*\\|=.*1.*<<.*j|char_bitmask_build",
            "shift_and_mask|sa_mask|char_bitmask"
        ),
        new PatternDef("shift_and_state_update", "shift_and_state_vector_shift_or_mask", "high",
            "D.*=.*D.*<<.*1.*|.*1u.*&.*sa_mask.*sa_t.*i|D.*=.*D.*<<.*1.*\\|.*1.*&.*mask.*T.*i",
            "state.*=.*shift_left.*or_one.*and_char_mask|shift_and_core_update",
            "shift_and_update|sa_state|shift_or_one"
        ),
        new PatternDef("shift_and_match_check", "shift_and_match_top_bit_detection", "high",
            "if.*D.*&.*1u.*<<.*SA_M.*-.*1.*matches\\+\\+|if.*D.*&.*1.*<<.*m.*-.*1.*count",
            "top_bit.*set.*pattern.*match|shift_and.*bit.*m.*-.*1.*match",
            "shift_and_match|sa_match|shift_and_top_bit"
        ),

        // ── Maximum clique (bitmask brute force) ─────────────────────────────
        new PatternDef("clique_subset_enumerate", "max_clique_2n_subset_enumeration", "high",
            "for.*S.*=.*0.*S.*<.*1.*<<.*CL_N.*S\\+\\+.*cl_pop.*S.*<=.*mc.*continue",
            "for.*S.*<.*1.*<<.*n.*S.*popcount.*S.*<=.*mc.*continue|bitmask_clique_enum",
            "clique_enum|max_clique_2n|clique_bitmask"
        ),
        new PatternDef("clique_pair_check", "max_clique_pairwise_adjacency_clique_test", "high",
            "for.*u.*<.*CL_N.*S.*>>.*u.*&.*1.*for.*v.*=.*u.*\\+.*1.*S.*>>.*v.*&.*1.*!cl_adj.*u.*v",
            "if.*!adj.*u.*v.*ok.*=.*0|check.*all.*pairs.*in.*subset.*clique",
            "clique_pair|adjacency_check|clique_test"
        ),

        // ── Rope string (split/concat binary tree of substrings) ─────────────
        new PatternDef("rope_weight_index", "rope_string_weight_based_char_index", "high",
            "while.*type.*==.*ROPE_INTERNAL.*if.*k.*<.*weight.*node.*=.*left.*else.*k.*-=.*weight.*node.*=.*right",
            "rp_index|rope_index.*weight.*left.*right|rope_char_access_via_weight",
            "rp_index|rope_index|rope_string_access"
        ),
        new PatternDef("rope_split_recursive", "rope_string_recursive_split_at_position", "high",
            "rp_split.*type.*==.*ROPE_LEAF.*out_left.*=.*rp_new_leaf.*out_right.*=.*rp_new_leaf",
            "if.*k.*<=.*w.*rp_split.*left.*k.*sl.*sr.*out_left.*=.*sl.*out_right.*=.*rp_new_internal.*sr|rope_split",
            "rp_split|rope_split|rope_string_split"
        ),
        new PatternDef("rope_concat_weight", "rope_string_concat_internal_node_weight", "high",
            "rp_new_internal.*rrope.*lrope.*weight.*=.*rp_len.*rrope|rope_concat.*weight.*=.*len.*left",
            "rp_pool.*weight.*=.*rp_len.*rp_pool.*left|rope_internal_weight_update",
            "rp_new_internal|rope_concat|rope_weight_update"
        ),

        // ── Virtual tree (auxiliary tree on query-node set) ──────────────────
        new PatternDef("vt_tin_sort_stack", "virtual_tree_tin_sorted_monotone_stack", "high",
            "vt_sort_by_tin.*S.*stk.*stk_top.*=.*0.*stk.*stk_top\\+\\+.*=.*1.*for.*i.*=.*0.*i.*<.*3",
            "sort.*S.*by.*tin.*push.*root.*for.*each.*v.*in.*S.*l.*=.*vt_lca.*stk.*top.*v|virtual_tree_build",
            "vt_sort_by_tin|virtual_tree_build|tin_sorted_query"
        ),
        new PatternDef("vt_lca_binary_lift", "virtual_tree_lca_via_binary_lifting", "high",
            "vt_up.*k.*v.*=.*vt_up.*k-1.*vt_up.*k-1.*v|for.*k.*VT_LOG.*1.*vt_up.*k.*u.*!=.*vt_up.*k.*v",
            "for.*k.*=.*VT_LOG.*-.*1.*k.*>=.*0.*k--.*if.*vt_up.*k.*u.*!=.*vt_up.*k.*v.*u.*=.*vt_up.*k.*u|vt_lca",
            "vt_lca|virtual_tree_lca|binary_lift_lca"
        ),
        new PatternDef("vt_edge_drain_stack", "virtual_tree_drain_stack_emit_edges", "high",
            "while.*stk_top.*>.*1.*edge_from.*edge_cnt.*=.*stk.*stk_top.*-.*2.*edge_to.*edge_cnt.*=.*stk.*stk_top.*-.*1",
            "while.*stk_top.*>.*1.*edge_from.*=.*stk.*stk_top.*-.*2.*edge_to.*=.*stk.*stk_top.*-.*1.*edge_cnt\\+\\+.*stk_top--",
            "vt_drain_stack|virtual_tree_edges|drain_stk_edges"
        ),

        // ── Min-cost max-flow (SPFA augmentation, reverse-edge XOR trick) ────
        new PatternDef("mcf_reverse_edge_xor", "min_cost_flow_reverse_edge_index_xor", "high",
            "mcf_cap.*e.*\\^.*1.*\\+=.*f|cap.*e\\^1.*\\+=.*flow.*reverse.*edge.*xor.*index",
            "mcf_cap.*e.*-=.*f.*mcf_cap.*e.*\\^.*1.*\\+=.*f|augment.*cap.*xor.*reverse",
            "mcf_cap.*e.*\\^.*1|min_cost_flow_xor_reverse|mcf_reverse_xor"
        ),
        new PatternDef("mcf_spfa_relax", "min_cost_flow_spfa_bellman_ford_relaxation", "high",
            "mcf_dist.*u.*\\+.*mcf_cost.*e.*<.*mcf_dist.*v.*mcf_dist.*v.*=.*mcf_dist.*u.*\\+.*mcf_cost.*e",
            "dist.*u.*\\+.*cost.*e.*<.*dist.*v.*dist.*v.*=.*dist.*u.*\\+.*cost.*e.*prevv.*v.*=.*u|spfa_relax",
            "mcf_spfa|spfa_relax|min_cost_flow_dist_relax"
        ),
        new PatternDef("mcf_augment_loop", "min_cost_flow_path_augmentation_loop", "high",
            "while.*mcf_spfa.*s.*t.*f.*=.*MCF_INF.*for.*v.*=.*t.*v.*!=.*s.*v.*=.*mcf_prevv.*v",
            "total_flow.*\\+=.*f.*total_cost.*\\+=.*f.*\\*.*mcf_dist.*t|mcf_run.*augment.*path",
            "mcf_run|mcf_augment|min_cost_flow_main_loop"
        ),

        // ── Euler circuit (Hierholzer's algorithm) ───────────────────────────
        new PatternDef("hierholzer_stack_push", "euler_circuit_hierholzer_stack_based_dfs", "high",
            "eu_stk.*eu_sp\\+\\+.*=.*start.*while.*eu_sp.*>.*0.*u.*=.*eu_stk.*eu_sp.*-.*1",
            "euler_stk.*push.*start.*while.*stack.*not.*empty.*peek.*top|hierholzer_main_loop",
            "hierholzer|euler_stk|euler_circuit_hierholzer"
        ),
        new PatternDef("hierholzer_edge_mark", "euler_circuit_xor_mark_both_edge_directions", "high",
            "eu_used.*e.*=.*eu_used.*e.*\\^.*1.*=.*1|used.*edge.*xor.*reverse.*both.*marked",
            "eu_used.*e.*=.*eu_used.*e\\^1.*=.*1|mark.*both_directed_halves.*used",
            "hierholzer_edge_xor|eu_mark|euler_edge_both"
        ),
        new PatternDef("hierholzer_circuit_pop", "euler_circuit_pop_exhausted_vertex_to_circuit", "high",
            "eu_circuit.*eu_clen\\+\\+.*=.*eu_stk.*--eu_sp|circuit.*\\[clen\\+\\+\\].*=.*stk.*\\[--sp\\]",
            "pop.*exhausted.*vertex.*push.*to.*circuit|if.*done.*circuit.*append.*pop",
            "hierholzer_pop|euler_circuit_pop|euler_clen"
        ),

        // ── Bipartite matching (Kuhn's DFS augmenting path) ──────────────────
        new PatternDef("kuhn_match_update", "kuhn_bipartite_match_assign_on_augment", "high",
            "bm_match_r.*v.*=.*u.*return.*1|match_r.*v.*=.*u.*return.*true.*augment.*success",
            "if.*match_r.*v.*==-1.*||.*dfs.*match_r.*v.*match_r.*v.*=.*u|kuhn_augment",
            "kuhn_match|bm_match_r|kuhn_augment_assign"
        ),
        new PatternDef("kuhn_visit_dfs", "kuhn_bipartite_visited_right_skip", "high",
            "if.*!bm_adj.*u.*v.*||.*bm_vis.*v.*continue.*bm_vis.*v.*=.*1",
            "skip_non_edge_or_visited.*mark_visited.*right_node|kuhn_dfs_visit",
            "kuhn_dfs|bm_vis|kuhn_skip_visited"
        ),
        new PatternDef("kuhn_vis_reset", "kuhn_bipartite_visited_reset_per_left_node", "medium",
            "for.*v.*=.*0.*v.*<.*BM_R.*v\\+\\+.*bm_vis.*v.*=.*0.*if.*bm_dfs.*u.*match\\+\\+",
            "for.*j.*=.*0.*j.*<.*R.*bm_vis.*j.*=.*0.*before.*each.*augmentation|kuhn_outer",
            "kuhn_reset_vis|bm_vis_reset|kuhn_outer_loop"
        ),

        // ── Andrew's monotone chain convex hull ────────────────────────────
        new PatternDef("hull_cross_product", "convex_hull_2d_cross_product", "high",
            "A\\.x.*-.*O\\.x.*\\*.*B\\.y.*-.*O\\.y.*-.*A\\.y.*-.*O\\.y.*\\*.*B\\.x.*-.*O\\.x",
            "long.*long.*cross.*O.*A.*B.*=.*A\\.x.*-.*O\\.x.*B\\.y.*-.*O\\.y.*-.*A\\.y.*O\\.y|cross_2d",
            "ch_cross|hull_cross|convex_hull_2d"
        ),
        new PatternDef("hull_right_turn_pop", "convex_hull_right_turn_pop_lower_hull", "high",
            "while.*k.*>=.*2.*&&.*ch_cross.*ch_hull.*k.*-.*2.*ch_hull.*k.*-.*1.*ch_pts.*i.*<=.*0.*k--",
            "while.*k.*>=.*2.*cross.*hull.*k-2.*hull.*k-1.*pt.*<=.*0.*pop|monotone_chain_pop",
            "hull_pop|ch_pop|hull_right_turn"
        ),
        new PatternDef("hull_upper_sentinel", "convex_hull_upper_hull_sentinel_t_variable", "medium",
            "for.*i.*=.*CH_N.*-.*2.*t.*=.*k.*\\+.*1.*i.*>=.*0.*i--.*while.*k.*>=.*t.*cross",
            "upper_hull.*t.*=.*k.*\\+.*1.*i.*from.*n-2.*downto.*0|sentinel_upper_hull",
            "hull_upper|ch_upper|hull_sentinel"
        ),

        // ── Rabin-Karp rolling hash string matching ──────────────────────────
        new PatternDef("rk_rolling_remove", "rabin_karp_rolling_hash_remove_leftmost", "high",
            "th.*=.*th.*\\+.*RK_MOD.*-.*rk_t.*i.*\\*.*pw.*%.*RK_MOD.*\\*.*RK_BASE.*%.*RK_MOD",
            "th.*=.*th.*-.*T.*i.*\\*.*pw.*%.*mod.*\\*.*base.*%.*mod|rolling_hash_remove",
            "rk_rolling|rk_remove|rabin_karp_roll"
        ),
        new PatternDef("rk_hash_add", "rabin_karp_rolling_hash_add_rightmost", "high",
            "th.*=.*th.*\\+.*rk_t.*i.*\\+.*RK_M.*%.*RK_MOD|th.*=.*th.*\\+.*T.*i.*\\+.*m.*%.*mod",
            "rolling_hash_add.*new_rightmost_char|rk_extend.*new_char",
            "rk_add|rk_extend|rabin_karp_add"
        ),
        new PatternDef("rk_collision_verify", "rabin_karp_hash_collision_char_verify", "medium",
            "if.*ph.*==.*th.*int.*ok.*=.*1.*for.*j.*=.*0.*j.*<.*RK_M.*j\\+\\+.*if.*rk_p.*j.*!=.*rk_t",
            "if.*pattern_hash.*==.*text_hash.*verify.*char.*by.*char|spurious_hit_check",
            "rk_verify|rk_collision|rabin_karp_verify"
        ),

        // ── Linear (Euler's) Sieve ───────────────────────────────────────────
        new PatternDef("ls_spf_mark", "linear_sieve_smallest_prime_factor_mark", "high",
            "ls_spf.*i.*\\*.*p.*=.*p|spf.*i.*\\*.*primes.*j.*=.*primes.*j",
            "if.*ls_spf.*i.*==.*p.*break|if.*spf.*i.*==.*primes.*j.*break",
            "ls_spf|spf_linear|linear_sieve_spf"
        ),
        new PatternDef("ls_prime_collect", "linear_sieve_prime_collection", "high",
            "if.*ls_spf.*i.*==.*0.*ls_spf.*i.*=.*i.*ls_primes.*ls_pcnt\\+\\+.*=.*i",
            "if.*spf.*i.*==.*0.*primes.*pcnt\\+\\+.*=.*i|sieve_prime_collect",
            "ls_primes|ls_pcnt|linear_sieve_primes"
        ),
        new PatternDef("ls_factorize", "linear_sieve_factorize_via_spf", "high",
            "while.*n.*>.*1.*factor.*=.*ls_spf.*n.*n.*\\/=.*factor|factorize.*spf",
            "spf.*n.*!=.*n|smallest_prime_factor.*divide",
            "ls_factorize|spf_factorize|linear_sieve_factor"
        ),

        // ── Sprague-Grundy (combinatorial game theory) ───────────────────────
        new PatternDef("sg_mex_compute", "sprague_grundy_mex_calculation", "high",
            "while.*seen.*&.*1.*<<.*mex.*mex\\+\\+|mex.*=.*0.*while.*seen.*>>.*mex.*&.*1",
            "seen.*\\|=.*1.*<<.*sg_grundy|seen.*\\|=.*1.*<<.*grundy.*n.*sub",
            "sg_grundy|grundy_mex|sprague_grundy_mex"
        ),
        new PatternDef("sg_subtraction_game", "sprague_grundy_subtraction_game_dp", "high",
            "sg_grundy.*0.*=.*0.*for.*n.*=.*1.*sg_grundy.*n.*=.*mex|grundy.*n.*sub.*1.*sub.*<=.*3",
            "for.*sub.*=.*1.*sub.*<=.*3.*sub.*<=.*n.*seen.*\\|=.*1.*<<.*sg_grundy.*n.*sub",
            "sg_compute|grundy_compute|sprague_grundy_dp"
        ),
        new PatternDef("sg_pile_xor", "sprague_grundy_multi_pile_nim_xor", "high",
            "g_xor.*\\^=.*sg_grundy.*piles.*i|g_xor.*\\^=.*grundy.*pile",
            "total_g.*\\+=.*sg_grundy.*piles|total_grundy.*\\+=.*grundy.*pile",
            "sg_pile_xor|grundy_xor|sprague_grundy_game_value"
        ),

        // ── Bitmask DP — Travelling Salesman (Held-Karp) ─────────────────────
        new PatternDef("tsp_bitmask_init", "bitmask_dp_tsp_held_karp_init", "high",
            "tsp_dp.*1.*\\[0\\].*=.*0|dp.*1.*0.*=.*0.*start.*city.*0.*mask.*1",
            "for.*m.*=.*0.*m.*<.*full.*for.*v.*=.*0.*tsp_dp.*m.*v.*=.*TSP_INF",
            "tsp_dp|held_karp_init|bitmask_dp_tsp_init"
        ),
        new PatternDef("tsp_transition", "bitmask_dp_tsp_state_transition", "high",
            "nmask.*=.*mask.*\\|.*1.*<<.*v.*ncost.*=.*tsp_dp.*mask.*u.*\\+.*tsp_dist.*u.*v",
            "if.*ncost.*<.*tsp_dp.*nmask.*v.*tsp_dp.*nmask.*v.*=.*ncost|tsp_relax",
            "tsp_transition|held_karp_relax|bitmask_dp_tsp_expand"
        ),
        new PatternDef("tsp_final_tour", "bitmask_dp_tsp_return_to_origin", "high",
            "for.*v.*=.*1.*v.*<.*TSP_N.*c.*=.*tsp_dp.*full_mask.*v.*\\+.*tsp_dist.*v.*0",
            "if.*c.*<.*min_cost.*min_cost.*=.*c|tsp_final.*full_mask.*return.*origin",
            "tsp_final|held_karp_return|bitmask_dp_tsp_result"
        ),

        // ── Compressed Trie (Patricia Trie) ──────────────────────────────────
        new PatternDef("trie_compressed_insert", "trie_compressed_insert_key", "high",
            "ct_goto\\[cur\\]\\[c\\].*==.*-1|ac_goto\\[cur\\]\\[c\\].*=.*-1.*ct_new_node|patricia_insert.*bit_diff",
            "b_diff.*=.*CT_BITS.*-.*1.*while.*b_diff.*>=.*0.*ct_bit.*key.*b_diff.*==.*ct_bit|bit_index_find_differ",
            "ct_insert|patricia_insert|trie_compressed_insert|radix_tree_insert"
        ),
        new PatternDef("trie_compressed_split", "trie_compressed_split_edge", "high",
            "ct_nodes\\[nid\\]\\.right.*=.*nid.*ct_nodes\\[nid\\]\\.left.*=.*cur|patricia_split.*back_edge",
            "if.*side.*ct_nodes\\[prev\\]\\.right.*=.*nid.*else.*ct_nodes\\[prev\\]\\.left.*=.*nid",
            "ct_split|patricia_split|trie_compressed_split_edge|radix_split"
        ),
        new PatternDef("trie_compressed_search", "trie_compressed_lookup", "high",
            "next.*=.*ct_bit.*key.*n->bit.*\\?.*n->right.*:.*n->left|patricia_search.*back_edge_test",
            "if.*next.*==.*-1.*||.*ct_nodes\\[next\\]\\.bit.*>=.*n->bit.*return.*ct_nodes\\[cur\\]\\.key.*==.*key",
            "ct_search|patricia_search|trie_compressed_lookup|radix_tree_search"
        ),

        // ── Fibonacci Heap ────────────────────────────────────────────────────
        new PatternDef("fib_heap_link", "fibonacci_heap_link_tree", "high",
            "fh_list_remove\\(y\\).*fh_nodes\\[y\\]\\.parent.*=.*x|fibonacci_link.*degree.*mark.*0",
            "fh_nodes\\[x\\]\\.degree\\+\\+.*fh_nodes\\[y\\]\\.mark.*=.*0|fh_link.*consolidate",
            "fh_link|fibonacci_heap_link|fib_tree_link|heap_link_same_degree"
        ),
        new PatternDef("fib_heap_consolidate", "fibonacci_heap_consolidate", "high",
            "fh_deg\\[d\\].*!=.*-1.*y.*=.*fh_deg\\[d\\].*fh_nodes\\[x\\]\\.key.*>.*fh_nodes\\[y\\]\\.key|fib_consolidate",
            "fh_link\\(y.*x\\).*fh_deg\\[d\\].*=.*-1.*d\\+\\+|fibonacci_consolidate_degree_table",
            "fh_consolidate|fibonacci_heap_consolidate|fib_heap_rebuild_roots|consolidate_degrees"
        ),
        new PatternDef("fib_heap_decrease_key", "fibonacci_heap_decrease_key", "high",
            "fh_nodes\\[x\\]\\.key.*=.*new_key.*p.*=.*fh_nodes\\[x\\]\\.parent|fib_decrease.*cascading_cut",
            "fh_cut\\(x.*p\\).*fh_cascading_cut\\(p\\)|fibonacci_decrease_key_cut_cascade",
            "fh_decrease_key|fibonacci_heap_decrease_key|fib_heap_relax_key|decrease_key_cascade"
        ),

        // ── Persistent Treap ──────────────────────────────────────────────────
        new PatternDef("treap_persistent_clone", "treap_persistent_copy_on_write", "high",
            "pt_pool\\[id\\].*=.*pt_pool\\[t\\]|persistent_treap_clone.*copy_on_write.*cow",
            "pt_clone.*pt_pool_sz\\+\\+.*pt_pool\\[id\\].*=.*pt_pool\\[t\\]|treap_cow_node",
            "pt_clone|treap_persistent_clone|persistent_treap_copy|cow_treap_node"
        ),
        new PatternDef("treap_persistent_split", "treap_persistent_split_by_key", "high",
            "pt_clone\\(t\\).*pt_pool\\[nc\\]\\.right.*=.*pt_split_l.*pt_upd\\(nc\\)|persistent_treap_split",
            "pt_split_l.*=.*nc.*pt_pool\\[nc\\]\\.left.*=.*pt_split_r.*pt_upd\\(nc\\)|treap_split_cow",
            "pt_split|treap_persistent_split|persistent_treap_split_key|functional_treap_split"
        ),
        new PatternDef("treap_persistent_merge", "treap_persistent_merge_trees", "high",
            "pt_pool\\[l\\]\\.prio.*>.*pt_pool\\[r\\]\\.prio.*nl.*=.*pt_clone\\(l\\)|persistent_treap_merge",
            "pt_pool\\[nl\\]\\.right.*=.*pt_merge.*pt_pool\\[l\\]\\.right.*r.*pt_upd\\(nl\\)|treap_merge_cow",
            "pt_merge|treap_persistent_merge|persistent_treap_combine|functional_treap_merge"
        ),

        // ── Suffix Array SA-IS ────────────────────────────────────────────────
        new PatternDef("sais_classify", "sais_classify_suffix_types", "high",
            "sais_type\\[n-1\\].*=.*1.*sentinel.*S-type|suffix_type_classify.*lms",
            "sais_type\\[i\\].*=.*1.*s\\[i\\].*<.*s\\[i\\+1\\]|classify_sl_suffix_array",
            "sais_classify|suffix_type_sl|sa_is_classify|sais_type_array"
        ),
        new PatternDef("sais_is_lms", "sais_is_leftmost_s_suffix", "high",
            "sais_type\\[i\\].*==.*1.*&&.*sais_type\\[i-1\\].*==.*0|leftmost_s_type_suffix",
            "is_lms.*i.*>.*0.*type.*S.*prev.*L|lms_suffix_check_boundary",
            "sais_is_lms|is_lms_suffix|leftmost_s_type|sa_is_lms_detect"
        ),
        new PatternDef("sais_sort", "sais_suffix_array_build", "high",
            "sais_sa\\[i\\].*=.*i.*insertion_sort.*suffix|suffix_array_sa_is_build",
            "sais_cmp.*sais_sa\\[j\\].*key.*>.*0.*sais_sa\\[j\\+1\\]|sa_is_induced_sort",
            "sais_sort|suffix_array_induced_sort|sa_is_construct|sais_build_sa"
        ),

        // ── Hopcroft-Karp Bipartite Matching ──────────────────────────────────
        new PatternDef("hk_bfs", "hopcroft_karp_bfs_layered", "high",
            "hk_dist\\[u\\].*=.*0.*queue.*match_l.*==.*-1|hopcroft_karp_bfs_layer",
            "hk_match_r\\[v\\].*==.*-1.*found.*=.*1.*dist.*HK_INF|bipartite_bfs_augment",
            "hk_bfs|hopcroft_karp_bfs|bipartite_layered_graph|hk_layer_build"
        ),
        new PatternDef("hk_dfs", "hopcroft_karp_dfs_augment", "high",
            "hk_match_r\\[v\\].*==.*-1.*hk_dist\\[w\\].*==.*hk_dist\\[u\\].*\\+.*1|hopcroft_dfs_path",
            "hk_match_l\\[u\\].*=.*v.*hk_match_r\\[v\\].*=.*u.*return.*1|bipartite_dfs_augment",
            "hk_dfs|hopcroft_karp_dfs|bipartite_augmenting_path|hk_augment"
        ),
        new PatternDef("hk_max_matching", "hopcroft_karp_maximum_matching", "high",
            "hk_match_l\\[u\\].*=.*-1.*hk_match_r\\[v\\].*=.*-1.*matching.*=.*0|hopcroft_karp_init",
            "hk_bfs.*hk_dfs.*matching\\+\\+|bipartite_max_matching_hopcroft",
            "hk_max_matching|hopcroft_karp_matching|bipartite_matching_hk|max_bipartite_match"
        ),

        // ── Count Inversions Merge Sort ───────────────────────────────────────
        new PatternDef("inv_merge_sort", "count_inversions_merge_sort", "high",
            "inv_count.*\\+=.*mid.*-.*i.*a\\[i\\].*>.*a\\[j\\]|merge_sort_inversion_count",
            "inv_merge_sort.*mid.*=.*n.*\\/.*2.*inv_merge_sort.*a.*mid|merge_inversion_recurse",
            "inv_merge_sort|count_inversions_merge|merge_sort_inversions|inversion_count_merge"
        ),
        new PatternDef("inv_merge_step", "inversion_merge_combine", "high",
            "inv_tmp\\[k\\+\\+\\].*=.*a\\[j\\+\\+\\].*inv_count.*\\+=.*mid.*-.*i|inversion_count_merge_step",
            "while.*i.*<.*mid.*j.*<.*n.*a\\[i\\].*<=.*a\\[j\\].*inv_tmp|merge_inversion_combine",
            "inv_merge_step|inversion_merge_combine|merge_count_step|inv_count_merge"
        ),
        new PatternDef("inv_count_result", "inversion_count_total", "high",
            "inv_orig_first.*=.*inv_arr\\[0\\].*inv_orig_last.*inv_arr\\[INV_N.*-.*1\\]|inversion_bookend",
            "inv_count.*=.*0.*inv_merge_sort.*INV_N.*checksum.*inv_orig_first|inversion_tally",
            "inv_count_result|inversion_count_total|count_inversions_result|inv_total_count"
        ),
        // ── sqrt_tree (O(1) RMQ via sqrt decomposition + sparse table) ─────
        new PatternDef("sqt_build", "sqrt_tree_build", "high",
            "sqt_pmin\\[lo\\].*=.*sqt_arr\\[lo\\].*for.*i.*=.*lo.*\\+.*1.*i.*<.*hi|sqrt_tree_prefix_build",
            "sqt_smin\\[hi.*-.*1\\].*=.*sqt_arr\\[hi.*-.*1\\].*sqt_bmin\\[b\\]|sqrt_tree_suffix_build",
            "sqt_build|sqrt_tree_build|sqt_sparse|sqrt_rmq_construct"
        ),
        new PatternDef("sqt_query", "sqrt_tree_query", "high",
            "bl.*=.*l.*\\/.*SQTREE_B.*br.*=.*r.*\\/.*SQTREE_B.*bl.*==.*br|sqrt_tree_same_block",
            "sqt_min.*sqt_smin\\[l\\].*sqt_pmin\\[r\\].*lb.*=.*bl.*\\+.*1|sqrt_tree_cross_block",
            "sqt_query|sqrt_tree_query|sqrt_rmq_query|sqt_min_range"
        ),
        new PatternDef("sqt_sparse_table", "sqrt_tree_sparse", "high",
            "sqt_sparse\\[0\\]\\[b\\].*=.*sqt_bmin\\[b\\].*for.*k.*=.*1.*k.*<.*SQTREE_LOG|sqrt_sparse_init",
            "sqt_sparse\\[k\\]\\[b\\].*=.*sqt_min.*sqt_sparse\\[k.*-.*1\\]\\[b\\].*sqt_sparse\\[k.*-.*1\\]|sqrt_sparse_fill",
            "sqt_sparse_table|sqrt_tree_sparse|sqt_block_sparse|sqrt_rmq_sparse"
        ),
        // ── dancing_links (DLX exact-cover solver) ──────────────────────────
        new PatternDef("dlx_cover", "dancing_links_cover", "high",
            "dlx_pool\\[dlx_pool\\[c\\]\\.R\\]\\.L.*=.*dlx_pool\\[c\\]\\.L.*dlx_pool\\[dlx_pool\\[c\\]\\.L\\]\\.R|dlx_column_cover",
            "dlx_col_size\\[jc\\]--.*dlx_pool\\[dlx_pool\\[j\\]\\.D\\]\\.U.*=.*dlx_pool\\[j\\]\\.U|dlx_node_remove",
            "dlx_cover|dancing_links_cover|dlx_hide_column|exact_cover_cover"
        ),
        new PatternDef("dlx_uncover", "dancing_links_uncover", "high",
            "dlx_col_size\\[jc\\]\\+\\+.*dlx_pool\\[dlx_pool\\[j\\]\\.D\\]\\.U.*=.*j.*dlx_pool\\[dlx_pool\\[j\\]\\.U\\]\\.D|dlx_restore",
            "dlx_pool\\[dlx_pool\\[c\\]\\.R\\]\\.L.*=.*c.*dlx_pool\\[dlx_pool\\[c\\]\\.L\\]\\.R.*=.*c|dlx_column_restore",
            "dlx_uncover|dancing_links_uncover|dlx_restore_column|exact_cover_uncover"
        ),
        new PatternDef("dlx_search", "dancing_links_search", "high",
            "dlx_pool\\[0\\]\\.R.*==.*0.*dlx_solutions\\+\\+.*dlx_sol_hash.*\\^=.*h|dlx_solution_found",
            "dlx_col_size\\[c\\].*<.*dlx_col_size\\[best\\].*best.*=.*c.*dlx_cover\\(best\\)|dlx_mrv_heuristic",
            "dlx_search|dancing_links_search|dlx_backtrack|exact_cover_search"
        ),
        // ── flow_push_relabel (highest-label push-relabel max-flow) ─────────
        new PatternDef("pr_push", "push_relabel_push", "high",
            "pr_excess\\[u\\].*<.*res.*\\?.*pr_excess\\[u\\].*:.*res.*pr_edges\\[e\\]\\.flow.*\\+=|push_relabel_saturate",
            "pr_edges\\[pr_edges\\[e\\]\\.rev\\]\\.flow.*-=.*send.*pr_excess\\[u\\].*-=.*send.*pr_excess\\[v\\]|push_relabel_adjust",
            "pr_push|push_relabel_push|pr_saturate_edge|max_flow_push"
        ),
        new PatternDef("pr_relabel", "push_relabel_relabel", "high",
            "min_h.*=.*2.*\\*.*pr_n.*for.*e.*=.*pr_head\\[u\\].*e.*>=.*0.*pr_edges\\[e\\]\\.cap.*-.*pr_edges\\[e\\]\\.flow|pr_admissible_scan",
            "pr_height\\[v\\].*<.*min_h.*min_h.*=.*pr_height\\[v\\].*pr_height\\[u\\].*=.*min_h.*\\+.*1|pr_height_update",
            "pr_relabel|push_relabel_relabel|pr_lift_node|max_flow_relabel"
        ),
        new PatternDef("pr_max_flow", "push_relabel_max_flow", "high",
            "pr_bfs_height.*pr_height\\[pr_S\\].*=.*pr_n.*for.*i.*=.*0.*i.*<.*pr_n.*pr_cur\\[i\\]|pr_init_preflow",
            "pr_excess\\[pr_S\\].*-=.*res.*pr_excess\\[v\\].*\\+=.*res.*pr_cur\\[i\\].*=.*pr_head\\[i\\]|pr_discharge_source",
            "pr_max_flow|push_relabel_max_flow|pr_highest_label|max_flow_push_relabel"
        ),

        // ── 2D Binary Indexed Tree (2D Fenwick) ──────────────────────────────
        new PatternDef("bit2_update_nested", "2d_fenwick_nested_loop_update", "high",
            "for.*i.*=.*x.*i.*<=.*BIT2_N.*i.*\\+=.*i.*&.*-i.*for.*j.*=.*y.*j.*<=.*BIT2_M.*j.*\\+=.*j.*&.*-j",
            "bit2_arr.*i.*j.*\\+=.*v|2d_bit_update.*outer.*inner.*fenwick",
            "bit2_update|2d_fenwick_update|bit2d_update|fenwick2d"
        ),
        new PatternDef("bit2_query_nested", "2d_fenwick_nested_loop_prefix_query", "high",
            "for.*i.*=.*x.*i.*>.*0.*i.*-=.*i.*&.*-i.*for.*j.*=.*y.*j.*>.*0.*j.*-=.*j.*&.*-j",
            "s.*\\+=.*bit2_arr.*i.*j|2d_bit_query.*sum.*prefix",
            "bit2_query|2d_fenwick_query|bit2d_prefix|fenwick2d_query"
        ),

        // ── Matrix rank over GF(2) (XOR Gaussian elimination) ────────────────
        new PatternDef("gf2_bit_pivot", "gf2_rank_bit_column_pivot_test", "high",
            "if.*gf2_m.*row.*>>.*col.*&.*1u.*pivot.*=.*row.*break",
            "\\(m\\[row\\].*>>.*col\\).*&.*1.*|.*gf2_col_pivot_bit",
            "gf2_bit_pivot|gf2_pivot|matrix_rank_gf2_bit"
        ),
        new PatternDef("gf2_xor_eliminate", "gf2_rank_xor_row_elimination", "high",
            "gf2_m.*row.*\\^=.*gf2_m.*rank|row.*\\^=.*m.*rank.*xor.*elimination.*gf2",
            "if.*row.*!=.*rank.*&&.*gf2_m.*row.*>>.*col.*&.*1u.*gf2_m.*row.*\\^=",
            "gf2_xor|gf2_eliminate|matrix_rank_xor|gf2_row_elim"
        ),

        // ── Tree Isomorphism (AHU canonical label hashing) ───────────────────
        new PatternDef("tree_iso_canonical_label", "tree_iso_ahu_canonical_label_dict", "high",
            "ti_label_of.*code|canonical.*label.*dict.*tree_iso|label_of.*key.*ti_dict",
            "ti_dict.*==.*key|ti_dict_sz|canonical_label_lookup|ahu_label_dict",
            "tree_iso_label|ahu_canonical|ti_label_of|tree_isomorphism_dict"
        ),
        new PatternDef("tree_iso_children_sort", "tree_iso_children_label_insertion_sort", "high",
            "ch_labels.*ch_cnt|insertion.*sort.*ch_labels|children.*label.*sort.*tree_iso",
            "ch_labels.*b\\+1.*=.*ch_labels.*b|sort.*children.*canonical.*label",
            "tree_iso_sort|ch_labels_sort|children_label_sort|ahu_children_sort"
        ),
        new PatternDef("tree_iso_postorder_dfs", "tree_iso_postorder_dfs_label", "high",
            "ti_par.*v.*==.*u.*ch_labels|postorder.*label.*tree_iso|order.*ord_sz.*label",
            "for.*i.*=.*ord_sz.*-.*1.*i.*>=.*0|reverse_dfs_order.*label.*children",
            "tree_iso_postorder|ti_par|tree_iso_dfs|ahu_postorder"
        ),

        // ── Hall's Theorem / Bipartite Matching via Hall condition ───────────
        new PatternDef("hall_nbr_union", "hall_theorem_neighbourhood_union_bitmask", "high",
            "nbr.*\\|=.*hm_adj.*u|neighbourhood.*union.*bitmask.*hall|nbr.*OR.*adj.*subset",
            "for.*u.*<.*HM_N.*if.*s.*&.*1u.*<<.*u.*nbr.*\\|=|hall_nbr_union",
            "hall_nbr|hm_adj|hall_neighbourhood|hall_theorem_nbr_union"
        ),
        new PatternDef("hall_subset_check", "hall_theorem_subset_violation_check", "high",
            "nbr_size.*<.*s_size.*violations|hall.*violation.*subset.*check|hall_condition_fail",
            "for.*s.*=.*1.*s.*<.*1.*<<.*HM_N|subset_enum.*hall_check|hall_violations",
            "hall_violations|hall_subset|hall_condition|hall_marriage_check"
        ),
        new PatternDef("hall_augment_dfs", "hall_bipartite_augmenting_path_dfs", "high",
            "hm_match_r.*r.*<.*0.*\\|\\|.*hm_dfs.*hm_match_r.*r|augmenting_path.*hall_match",
            "hm_visited.*r.*=.*1|hm_match_r.*r.*=.*u|bipartite_augment_dfs.*hall",
            "hm_dfs|hm_match_r|hall_augment|bipartite_hall_dfs"
        ),

        // ── Topological-order DP (longest path in DAG / Kahn's relaxation) ──
        new PatternDef("topo_dp_kahn_sort", "topo_dp_kahn_bfs_topological_sort", "high",
            "if.*--td_indeg.*v.*==.*0.*td_queue.*tail|kahn.*topo.*indeg.*enqueue|indeg.*decrement.*zero.*enqueue",
            "td_indeg.*td_edges.*i.*v|kahn_topological_sort.*dag|topo_sort_kahn_bfs",
            "topo_dp_kahn|td_indeg|kahn_sort|topological_dp_indeg"
        ),
        new PatternDef("topo_dp_relax", "topo_dp_dag_edge_relaxation", "high",
            "td_dist.*u.*\\+.*w.*>.*td_dist.*v.*td_dist.*v.*=|dag_relax.*topo_order|longest_path_relax.*dag",
            "if.*td_dist.*u.*\\+.*w.*>.*td_dist.*v|edge_relaxation.*topological.*dp",
            "topo_dp_relax|td_dist|dag_relax|topological_dp_edge_relax"
        ),
        new PatternDef("topo_dp_longest", "topo_dp_longest_path_dag_scan", "high",
            "longest.*<.*td_dist.*i.*longest.*=.*td_dist.*i|max_dist.*dag.*topo_dp|longest_path_dag_final",
            "for.*i.*<.*TD_V.*if.*td_dist.*i.*>.*longest|topo_dp_max_scan|dag_longest_path",
            "topo_dp_longest|td_dist_max|dag_longest|topological_dp_longest_path"
        ),

        // ── Count-Min Sketch (probabilistic frequency estimation) ────────────
        new PatternDef("cms_parallel_hash_update", "count_min_sketch_k_hash_update", "high",
            "for.*i.*=.*0.*i.*<.*CMS_K.*i\\+\\+.*cms_table.*i.*cms_hash.*i.*x.*\\+\\+",
            "for.*i.*<.*k.*table\\[i\\]\\[h_i\\(x\\)\\]\\+\\+|count_min_parallel_update",
            "cms_update|count_min_update|cms_parallel_hash|sketch_increment"
        ),
        new PatternDef("cms_min_query", "count_min_sketch_minimum_over_tables", "high",
            "mn.*=.*cms_table.*0.*cms_hash.*0.*x.*for.*i.*=.*1.*i.*<.*CMS_K.*v.*cms_table.*i.*if.*v.*<.*mn",
            "if.*v.*<.*mn.*mn.*=.*v.*count_min_query.*min.*k.*tables|cms_estimate",
            "cms_query|count_min_query|cms_min|sketch_frequency"
        ),

        // ── Viterbi algorithm (HMM most probable state sequence) ─────────────
        new PatternDef("viterbi_dp_recurrence", "viterbi_dp_max_transition_times_emit", "high",
            "vt_dp.*t.*s.*=.*best_p.*\\*.*vt_emit.*s.*vt_obs.*t.*for.*ps.*=.*0.*ps.*<.*VT_S",
            "dp.*t.*s.*=.*argmax.*dp.*t-1.*ps.*trans.*ps.*s.*\\*.*emit.*s.*obs.*t|viterbi_update",
            "viterbi_dp|vt_dp|viterbi_recurrence|hmm_viterbi"
        ),
        new PatternDef("viterbi_backpointer", "viterbi_backpointer_argmax", "high",
            "vt_bt.*t.*s.*=.*best|bt.*t.*s.*=.*argmax_ps.*dp.*t.*-.*1.*trans.*ps.*s",
            "backpointer.*=.*best.*argmax.*prev_state|viterbi_traceback_ptr",
            "viterbi_bt|vt_bt|viterbi_backtrack|hmm_backpointer"
        ),
        new PatternDef("viterbi_traceback", "viterbi_path_traceback", "high",
            "path.*VT_T.*-.*1.*=.*best_s.*for.*t.*=.*VT_T.*-.*2.*t.*>=.*0.*t--.*path.*t.*=.*vt_bt",
            "path.*t.*=.*bt.*t.*\\+.*1.*path.*t.*\\+.*1.*|viterbi_retrace.*path",
            "viterbi_traceback|vt_path|viterbi_decode|hmm_decode"
        ),

        // ── XOR Basis / Linear Basis over GF(2) ──────────────────────────────
        new PatternDef("xor_basis_insert", "xor_basis_gf2_insert_reduce", "high",
            "for.*i.*=.*XB_BITS.*-.*1.*i.*>=.*0.*i--.*if.*x.*>>.*i.*&.*1.*xb_basis.*i|linear_basis_insert.*gf2",
            "x.*\\^=.*xb_basis.*i.*xb_basis.*i.*=.*x.*xb_sz\\+\\+|gf2_basis_reduction.*pivot",
            "xb_insert|xb_basis|linear_basis_gf2|xor_basis_reduce"
        ),
        new PatternDef("xor_basis_max_xor", "xor_basis_max_xor_greedy", "high",
            "for.*i.*=.*XB_BITS.*-.*1.*i.*>=.*0.*i--.*if.*res.*\\^.*xb_basis.*i.*>.*res.*res.*\\^=.*xb_basis.*i",
            "res.*\\^.*xb_basis.*i.*>.*res.*greedy.*xor.*maximize|max_xor_linear_basis",
            "xb_max_xor|xor_basis_maximize|linear_basis_max|gf2_max_xor"
        ),
        new PatternDef("xor_basis_span_count", "xor_basis_span_size_power2", "high",
            "cnt.*<<=.*1.*for.*i.*=.*0.*i.*<.*xb_sz|span_count.*=.*1.*<<.*basis_size|xor_basis_span",
            "return.*1.*<<.*xb_sz.*|return.*cnt.*power_of_2.*basis_rank|gf2_span_cardinality",
            "xb_span_count|xb_sz|xor_basis_rank|linear_basis_span"
        ),

        // ── Subset Sum (SOS) Transform / Walsh-Hadamard ──────────────────────
        new PatternDef("sos_or_transform", "sos_dp_or_zeta_transform", "high",
            "for.*i.*=.*0.*i.*<.*SST_LOG.*for.*mask.*<.*SST_N.*if.*mask.*&.*1.*<<.*i.*sst_f.*mask.*\\+=.*sst_f.*mask.*\\^",
            "sst_f.*mask.*\\+=.*sst_f.*mask.*\\^.*1.*<<.*i.*|zeta_transform.*or_subset_sum",
            "sst_or_transform|sst_f|sos_dp_or|subset_sum_transform_or"
        ),
        new PatternDef("sos_mobius_invert", "sos_dp_mobius_inversion", "high",
            "for.*i.*=.*0.*i.*<.*SST_LOG.*for.*mask.*<.*SST_N.*if.*mask.*&.*1.*<<.*i.*sst_f.*mask.*-=.*sst_f.*mask.*\\^",
            "sst_f.*mask.*-=.*sst_f.*mask.*\\^.*1.*<<.*i.*|mobius_inversion.*subset_sum",
            "sst_mobius_invert|sos_inverse|mobius_subset|zeta_inversion"
        ),
        new PatternDef("sos_wht", "sos_walsh_hadamard_transform", "high",
            "for.*len.*=.*1.*len.*<.*SST_N.*len.*<<=.*1.*u.*=.*sst_f.*i.*\\+.*j.*v.*=.*sst_f.*i.*\\+.*j.*\\+.*len",
            "sst_f.*i.*\\+.*j.*=.*u.*\\+.*v.*sst_f.*i.*\\+.*j.*\\+.*len.*=.*u.*-.*v.*|wht_butterfly",
            "sst_wht|wht_butterfly|walsh_hadamard|xor_convolution_wht"
        ),

        // ── Kirchhoff Matrix-Tree Theorem (Laplacian cofactor determinant) ────
        new PatternDef("kmt_laplacian_build", "kirchhoff_laplacian_matrix_build", "high",
            "kmt_L.*u.*u.*\\+=.*w.*kmt_L.*v.*v.*\\+=.*w.*kmt_L.*u.*v.*-=.*w.*kmt_L.*v.*u.*-=.*w",
            "laplacian.*degree.*on_diagonal.*weight.*off_diagonal.*negative|kmt_add_edge.*laplacian",
            "kmt_add_edge|kmt_L|kirchhoff_laplacian|laplacian_matrix_build"
        ),
        new PatternDef("kmt_bareiss_det", "kirchhoff_bareiss_integer_determinant", "high",
            "kmt_M.*row.*j.*=.*kmt_M.*col.*col.*\\*.*kmt_M.*row.*j.*-.*kmt_M.*row.*col.*\\*.*kmt_M.*col.*j.*\\/.*prev",
            "bareiss.*num.*=.*M.*col.*col.*\\*.*M.*row.*j.*-.*M.*row.*col.*\\*.*M.*col.*j|integer_det_bareiss",
            "kmt_det|kmt_M|bareiss_elimination|integer_gaussian_det"
        ),
        new PatternDef("kmt_spanning_trees", "kirchhoff_spanning_tree_count", "high",
            "kmt_M.*i.*j.*=.*kmt_L.*i.*\\+.*1.*j.*\\+.*1.*|cofactor.*laplacian.*n_minus_1.*submatrix",
            "return.*kmt_det.*m.*|spanning_trees.*=.*laplacian_cofactor.*kirchhoff_theorem",
            "kmt_spanning_trees|kirchhoff_cofactor|matrix_tree_theorem|spanning_tree_count"
        ),

        // ── Johnson's All-Pairs Shortest Paths ───────────────────────────────
        new PatternDef("johnson_bellman_ford_reweight", "johnson_bf_reweight_h_array", "high",
            "for.*iter.*<.*JN.*for.*e.*<.*JE.*jn_h.*u.*\\+.*w.*<.*jn_h.*v.*jn_h.*v.*=.*jn_h.*u.*\\+.*w",
            "if.*h.*u.*\\+.*w.*<.*h.*v.*h.*v.*=.*h.*u.*\\+.*w.*bellman_ford.*reweight|johnson_bf_h",
            "johnson_bellman_ford|jn_h|johnson_reweight|bf_potential_function"
        ),
        new PatternDef("johnson_edge_reweight", "johnson_edge_reweighting_rw", "high",
            "rw.*=.*jn_edges.*e.*\\.w.*\\+.*jn_h.*u.*-.*jn_h.*v.*|rw.*=.*w.*\\+.*h.*u.*-.*h.*v",
            "reweighted.*edge.*w.*\\+.*h_u.*-.*h_v.*non_negative.*dijkstra|johnson_rw",
            "johnson_reweight|rw_edge|johnson_nonneg|johnson_edge_transform"
        ),
        new PatternDef("johnson_deweight", "johnson_distance_correction_deweight", "high",
            "d.*v.*\\+=.*jn_h.*v.*-.*jn_h.*src.*|d.*v.*\\+=.*h.*v.*-.*h.*src.*original_dist",
            "for.*v.*<.*JN.*if.*d.*v.*<.*JN_INF.*d.*v.*\\+=.*h.*v.*-.*h.*src|apsp_deweight",
            "johnson_deweight|jn_apsp|johnson_distance_correct|apsp_correction"
        ),

        // ── CRC-32 (ISO 3309 / Ethernet / ZIP) ──────────────────────────────
        new PatternDef("crc32_table_gen", "crc32_lookup_table_generation_256_entries", "high",
            "for.*i.*=.*0.*i.*<.*256.*crc.*=.*i.*for.*j.*=.*0.*j.*<.*8.*crc.*=.*crc.*&.*1.*crc.*>>.*1.*\\^.*CRC32_POLY.*:.*crc.*>>.*1",
            "crc32_table.*i.*=.*crc.*polynomial.*0xEDB88320.*lookup_table_256|crc32_init",
            "crc32_init|crc32_table|crc32_poly|crc_table_gen"
        ),
        new PatternDef("crc32_update", "crc32_table_driven_byte_update", "high",
            "crc.*=.*crc.*>>.*8.*\\^.*crc32_table.*crc.*\\^.*buf.*i.*&.*0xFF|crc32_per_byte_update",
            "for.*i.*<.*n.*crc.*=.*crc.*>>.*8.*\\^.*table.*crc.*\\^.*byte.*|crc32_roll",
            "crc32_compute|crc32_update|crc32_byte|crc_table_lookup"
        ),

        // ── Gale-Shapley stable matching ─────────────────────────────────────
        new PatternDef("gs_proposal_advance", "gale_shapley_proposal_pointer_advance", "high",
            "w.*=.*gs_man_pref.*m.*gs_next.*m.*\\+\\+|man_pref.*m.*next_proposal.*m.*\\+\\+",
            "proposal_pointer.*advance.*per_man.*gs_next.*\\+\\+|gale_shapley_next_woman",
            "gs_next|gale_shapley_propose|stable_match_proposal|man_optimal_advance"
        ),
        new PatternDef("gs_woman_prefer_check", "gale_shapley_woman_rank_comparison", "high",
            "gs_woman_rank.*w.*m.*<.*gs_woman_rank.*w.*m2|woman_rank.*m.*<.*woman_rank.*current",
            "if.*woman_rank.*new_man.*<.*woman_rank.*current.*accept.*reject|gs_displace",
            "gs_woman_rank|gale_shapley_displace|stable_match_accept|woman_rank_cmp"
        ),
        new PatternDef("gs_free_displaced", "gale_shapley_free_displaced_man", "high",
            "gs_match_m.*m2.*=.*-1.*free_count|match_m.*m2.*=.*-1.*displaced_man_freed",
            "gs_match_m.*m2.*=.*-1|displaced.*man.*m2.*freed.*gale_shapley|stable_match_displace",
            "gs_match_m|gale_shapley_free|stable_match_displace|man_freed"
        ),

        // ── Optimal BST (Knuth-Yao quadrangle-inequality optimization) ───────
        new PatternDef("knuth_bst_root_bound", "optimal_bst_knuth_root_range_optimization", "high",
            "klo.*=.*ob_root.*i.*j.*-.*1.*khi.*=.*ob_root.*i.*\\+.*1.*j.*for.*k.*=.*klo.*k.*<=.*khi",
            "root.*i.*j.*-1.*<=.*root.*i.*j.*<=.*root.*i.*\\+1.*j.*knuth.*quadrangle",
            "ob_root|knuth_root_bound|optimal_bst_bound|knuth_yao_opt"
        ),
        new PatternDef("knuth_bst_weight_sum", "optimal_bst_cumulative_frequency_weight", "high",
            "ob_w.*i.*j.*=.*ob_w.*i.*j.*-.*1.*\\+.*ob_freq.*j.*|w.*i.*j.*=.*w.*i.*j_minus_1.*\\+.*freq.*j",
            "cost.*=.*left.*\\+.*right.*\\+.*ob_w.*i.*j.*|optimal_bst_cost.*subtree.*root_weight",
            "ob_w|knuth_bst_weight|optimal_bst_freq_sum|bst_dp_weight"
        ),

        // ── Ukkonen Suffix Tree ───────────────────────────────────────────────
        new PatternDef("ukkonen_active_point", "ukkonen_suffix_tree_active_point_update", "high",
            "active_len.*>=.*edge_len.*active_edge.*=.*char_idx.*active_len.*-=.*el.*active_node.*=.*nxt",
            "al.*>=.*el.*ae.*=.*char_idx.*s.*i.*-.*al.*\\+.*el.*al.*-=.*el.*an.*=.*nxt|walk_down_active_point",
            "ukon_active|active_point|ukkonen_walk_down|suffix_tree_active_len"
        ),
        new PatternDef("ukkonen_split_edge", "ukkonen_suffix_tree_split_internal_node", "high",
            "spl.*=.*new_node.*start.*start.*\\+.*al.*ch.*ae.*=.*spl.*ch.*char_idx.*s.*i.*=.*new_node.*i.*INF",
            "nd.*nxt.*start.*\\+=.*al.*nd.*spl.*ch.*char_idx.*s.*nd.*nxt.*start.*=.*nxt|ukkonen_split",
            "ukon_split|split_edge|ukkonen_internal|suffix_tree_rule2"
        ),
        new PatternDef("ukkonen_suffix_link", "ukkonen_suffix_tree_suffix_link_chain", "high",
            "last_new.*!=.*-1.*nd.*last_new.*link.*=.*spl|last_new.*link.*=.*active_node.*last_new.*=.*-1",
            "ukon_last_new.*=.*spl.*rem--.*an.*==.*0.*al.*>.*0.*al--.*ae.*=.*char_idx|ukkonen_suffix_link_resolve",
            "ukon_last_new|last_new_link|ukkonen_link|suffix_link_chain"
        ),

        // ── Jacobi Symbol ─────────────────────────────────────────────────────
        new PatternDef("jacobi_strip_twos", "jacobi_symbol_factor_of_two_extraction", "high",
            "while.*a.*&.*1.*==.*0.*a.*>>=.*1.*r.*=.*n.*&.*7.*r.*==.*3.*r.*==.*5.*result.*=.*-result",
            "a.*>>=.*1.*n.*%.*8.*==.*3.*n.*%.*8.*==.*5.*result.*\\*=.*-1|jacobi_strip_factors_2",
            "jacobi_strip|jacobi_factor_two|quadratic_reciprocity_2|legendre_strip_2"
        ),
        new PatternDef("jacobi_reciprocity", "jacobi_symbol_quadratic_reciprocity_swap", "high",
            "tmp.*=.*a.*a.*=.*n.*n.*=.*tmp.*a.*&.*3.*==.*3.*n.*&.*3.*==.*3.*result.*=.*-result",
            "swap.*a.*n.*both_3_mod_4.*result.*flip|jacobi_swap_reciprocity.*n.*%.*4.*==.*3",
            "jacobi_reciprocity|jacobi_swap|quadratic_reciprocity|legendre_swap"
        ),
        new PatternDef("jacobi_reduce", "jacobi_symbol_iterative_reduction_loop", "high",
            "while.*a.*!=.*0.*while.*a.*&.*1.*==.*0.*a.*>>=.*1.*a.*%.*n.*n.*==.*1.*return.*result",
            "a.*=.*a.*%.*n.*n.*==.*1.*result.*0.*otherwise|jacobi_reduce_mod_n",
            "jacobi_sym|jacobi_reduce|legendre_symbol|jacobi_gcd_check"
        ),

        // ── Segmented Prime Sieve ─────────────────────────────────────────────
        new PatternDef("seg_sieve_base_primes", "segmented_sieve_base_prime_generation", "high",
            "for.*i.*=.*2.*i.*<=.*SEG_SQRT.*seg_small.*i.*seg_primes.*seg_np\\+\\+.*=.*i.*seg_small.*j.*=.*0",
            "sieve.*i.*<=.*sqrt.*R.*primes.*n_primes\\+\\+.*=.*i.*small.*j.*=.*false|seg_sieve_phase1",
            "seg_small|seg_primes|sieve_base|segmented_sieve_phase1"
        ),
        new PatternDef("seg_sieve_range_mark", "segmented_sieve_range_composite_marking", "high",
            "start.*=.*SEG_L.*\\+.*p.*-.*1.*\\/.*p.*\\*.*p.*start.*==.*p.*start.*\\+=.*p.*seg_sieve.*j.*-.*SEG_L.*=.*0",
            "start.*=.*ceil.*L.*p.*\\*.*p.*if.*start.*==.*p.*start.*\\+=.*p.*for.*j.*=.*start.*j.*<=.*R.*j.*\\+=.*p",
            "seg_sieve|seg_mark|segmented_composite|sieve_range_mark"
        ),
        new PatternDef("seg_sieve_count_primes", "segmented_sieve_prime_count_first_last", "high",
            "for.*i.*<.*SEG_LEN.*seg_sieve.*i.*n_primes\\+\\+.*first_prime.*=.*SEG_L.*\\+.*i.*last_prime.*=.*SEG_L.*\\+.*i",
            "seg_sieve.*i.*count\\+\\+.*if.*!first_prime.*first_prime.*=.*L.*\\+.*i.*last.*=.*L.*\\+.*i|count_range_primes",
            "seg_count|first_prime|last_prime|segmented_sieve_result"
        ),

        // ── Booth's algorithm (lexicographically smallest rotation) ───────────
        new PatternDef("booth_failure_func", "booth_kmp_style_failure_function_rotated", "high",
            "i.*=.*br_f.*j.*-.*1.*-.*k.*while.*i.*!=.*-1.*s.*j.*%.*n.*!=.*s.*k.*\\+.*i.*\\+.*1.*%.*n",
            "while.*i.*!=.*-1.*s.*j.*%.*n.*!=.*s.*k.*i.*1.*%.*n.*booth_kmp_failure|booth_rotation",
            "booth_rotation|br_f|booth_kmp|smallest_rotation_failure"
        ),
        new PatternDef("booth_shift_k", "booth_candidate_k_shift_on_improvement", "high",
            "if.*s.*j.*%.*n.*<.*s.*k.*\\+.*i.*\\+.*1.*%.*n.*k.*=.*j.*-.*i.*-.*1|if.*s.*j_mod_n.*<.*s.*candidate.*shift_k",
            "k.*=.*j.*-.*i.*-.*1.*booth.*lex_smaller.*rotation.*update|booth_k_update",
            "booth_k|booth_candidate|booth_lex_shift|smallest_rotation_k"
        ),

        // ── Closest pair of points (divide & conquer) ────────────────────────
        new PatternDef("closest_pair_strip_filter", "closest_pair_strip_width_dx_squared_filter", "high",
            "dx.*=.*arr.*i.*\\.x.*-.*mx.*if.*dx.*\\*.*dx.*<.*d.*strip.*m\\+\\+",
            "if.*dx.*\\*.*dx.*<.*d.*strip_candidate.*add.*strip_filter.*x_distance|cp_strip",
            "cp_strip|cp_strip_min|closest_pair_strip|strip_width_filter"
        ),
        new PatternDef("closest_pair_strip_inner", "closest_pair_strip_early_termination_by_dy", "high",
            "for.*j.*=.*i.*\\+.*1.*j.*<.*m.*dy.*=.*strip.*j.*\\.y.*-.*strip.*i.*\\.y.*dy.*\\*.*dy.*>=.*best.*break",
            "strip_inner.*dy.*sq.*>=.*d.*break.*closest_pair.*O7_comparisons|cp_strip_dy",
            "cp_strip_min|strip_inner_loop|closest_pair_dy_break|O7_strip"
        ),

        // ── Longest Increasing Subsequence — patience sort (O(n log n)) ──────
        new PatternDef("lis_patience_tails", "lis_patience_tails_binary_search", "high",
            "tails.*\\[.*pos.*\\].*=.*arr.*\\[.*i.*\\]|tails.*\\[.*pos.*\\].*=.*val",
            "pos.*==.*len.*len\\+\\+|if.*pos.*==.*len.*\\+\\+",
            "lis_patience|patience_sort_lis|lis_tails"
        ),
        new PatternDef("lis_patience_lower_bound", "lis_patience_lower_bound_bisect", "high",
            "lo.*=.*0.*hi.*=.*len|lo.*hi.*=.*len.*while.*lo.*<.*hi.*mid.*=.*lo.*\\+.*hi.*>>.*1",
            "tails.*\\[.*mid.*\\].*<.*val.*lo.*=.*mid.*\\+.*1|if.*tails.*mid.*<.*val.*lo",
            "lis_lower_bound|patience_bisect|lis_binary_search"
        ),
        new PatternDef("lis_patience_result", "lis_patience_length_accumulator", "medium",
            "for.*i.*=.*0.*i.*<.*n.*i\\+\\+.*pos.*=.*lis_lower_bound|for.*n.*patience.*pos.*lower",
            "len.*=.*0.*tails.*\\[.*MAXN.*\\]|int.*len.*=.*0.*tails.*int",
            "lis_patience|lis_length|patience_sort_length|lis_nlogn"
        ),

        // ── Persistent Trie (XOR / versioned binary trie) ────────────────────
        new PatternDef("persistent_trie_clone", "persistent_trie_spine_clone_on_insert", "high",
            "clone_node.*src.*pool.*\\[.*id.*\\].*=.*pool.*\\[.*src.*\\]|clone.*pool.*id.*=.*pool.*src",
            "pool_sz\\+\\+.*pool.*\\[.*id.*\\]\\.ch|new_node.*pool_sz.*ch.*\\[.*0.*\\].*=.*-1",
            "ptrie_insert|persistent_trie.*insert|clone_node.*spine"
        ),
        new PatternDef("persistent_trie_insert", "persistent_trie_versioned_root_insert", "high",
            "prev_root.*==.*-1.*new_node\\(\\).*clone_node.*prev_root|ptrie_insert.*prev_root.*clone",
            "for.*b.*=.*BITS.*-.*1.*b.*>=.*0.*b--.*bit.*=.*val.*>>.*b.*&.*1",
            "ptrie_insert|persistent_trie_insert|versioned_root.*spine"
        ),
        new PatternDef("persistent_trie_max_xor", "persistent_trie_max_xor_greedy_descent", "high",
            "want.*=.*val.*>>.*b.*&.*1.*\\^.*1.*prefer.*opposite|want.*xor.*1.*bit.*prefer",
            "res.*\\|=.*1u.*<<.*b.*cur.*=.*pool.*\\[.*cur.*\\]\\.ch.*\\[.*want.*\\]|res.*bit.*cur.*ch.*want",
            "ptrie_max_xor|persistent_trie.*xor|max_xor_trie"
        ),

        // ── Half-plane intersection — feasibility and depth query ─────────────
        new PatternDef("hpi_contains", "halfplane_intersection_feasibility_check", "high",
            "hp.*\\[.*i.*\\]\\.a.*\\*.*px.*\\+.*hp.*\\[.*i.*\\]\\.b.*\\*.*py|a.*px.*b.*py.*<=.*c.*halfplane",
            "val.*>.*hp.*\\[.*i.*\\]\\.c.*return.*0|if.*val.*>.*c.*return.*0.*hpi",
            "hpi_contains|halfplane_contains|hp_feasible"
        ),
        new PatternDef("hpi_depth", "halfplane_intersection_depth_counter", "high",
            "for.*i.*=.*0.*i.*<.*n.*i\\+\\+.*if.*hp.*\\[.*i.*\\]\\.a.*\\*.*px.*\\+.*hp.*\\[.*i.*\\]\\.b.*\\*.*py.*<=.*hp.*\\[.*i.*\\]\\.c.*cnt\\+\\+",
            "int.*cnt.*=.*0.*for.*n.*hpi.*depth|cnt.*\\+\\+.*half.*plane.*satisfy",
            "hpi_depth|halfplane_depth|hp_constraint_count"
        ),
        new PatternDef("hpi_grid_scan", "halfplane_intersection_grid_point_scan", "medium",
            "for.*x.*=.*x0.*x.*<=.*x1.*x.*\\+=.*dx.*for.*y.*=.*y0.*y.*<=.*y1.*y.*\\+=.*dy",
            "hpi_contains.*hp.*n.*x.*y.*cnt\\+\\+|if.*hpi_contains.*cnt\\+\\+.*grid",
            "hpi_grid_count|halfplane_grid_scan|hp_grid_intersect"
        ),
        new PatternDef("eb_trie_insert", "aho_corasick_trie_insert_goto_update", "high",
            "ac_goto\\[cur\\]\\[c\\].*==.*-1.*ac_new_node|ac_goto\\[cur\\]\\[.*-.*'a'\\].*=.*ac_sz\\+\\+",
            "cur.*=.*ac_goto\\[cur\\]\\[.*\\].*ac_output.*\\|=.*1.*<<.*pat_id",
            "ac_insert|aho_corasick_insert|trie_insert_pattern"
        ),
        new PatternDef("eb_fail_link_bfs", "aho_corasick_bfs_failure_link_build", "high",
            "ac_fail\\[v\\].*=.*ac_goto\\[ac_fail\\[u\\]\\]\\[c\\]|fail.*=.*ac_goto.*fail.*c",
            "ac_output\\[v\\].*\\|=.*ac_output\\[ac_fail\\[v\\]\\]|output.*\\|=.*output.*fail",
            "ac_build|aho_corasick_build|failure_link_bfs"
        ),
        new PatternDef("eb_search_popcount", "aho_corasick_search_output_popcount", "high",
            "cur.*=.*ac_goto\\[cur\\]\\[.*-.*'a'\\].*mask.*=.*ac_output\\[cur\\]",
            "mask.*&.*mask.*-.*1.*count\\+\\+|popcount.*output.*cur.*count",
            "ac_search|aho_corasick_search|multi_pattern_scan"
        ),
        new PatternDef("zm_zeta_subset", "zeta_transform_subset_sum_over_bits", "high",
            "for.*i.*=.*0.*i.*<.*n.*for.*mask.*1.*<<.*n.*mask.*&.*1.*<<.*i.*a\\[mask\\].*\\+=.*a\\[mask.*\\^.*1.*<<.*i\\]",
            "a\\[mask\\].*\\+=.*a\\[mask.*\\^.*1.*<<.*i\\]|zeta.*transform.*subset.*sum",
            "zeta_transform|sos_dp_zeta|subset_sum_transform"
        ),
        new PatternDef("zm_mobius_inv", "mobius_inversion_subset_difference", "high",
            "a\\[mask\\].*-=.*a\\[mask.*\\^.*1.*<<.*i\\]|mobius.*a\\[mask\\].*-=",
            "for.*i.*<.*n.*mask.*&.*1.*<<.*i.*a\\[mask\\].*-=.*a\\[mask.*\\^",
            "mobius_transform|mobius_inversion|zeta_inverse"
        ),
        new PatternDef("zm_superset_zeta", "zeta_superset_sum_over_bits", "medium",
            "for.*mask.*>=.*0.*!.*mask.*&.*1.*<<.*i.*a\\[mask\\].*\\+=.*a\\[mask.*\\|.*1.*<<.*i\\]",
            "zeta_superset|superset_sum|and_convolution_zeta",
            "a\\[mask\\].*\\+=.*a\\[mask.*\\|.*1.*<<.*i\\].*superset"
        ),
        new PatternDef("cp_floyd_warshall", "chinese_postman_floyd_shortest_paths", "high",
            "cp_sp\\[i\\]\\[k\\].*!=.*CP_INF.*cp_sp\\[k\\]\\[j\\].*!=.*CP_INF.*cp_sp\\[i\\]\\[j\\]",
            "cp_sp\\[i\\]\\[k\\].*\\+.*cp_sp\\[k\\]\\[j\\].*<.*cp_sp\\[i\\]\\[j\\]",
            "cp_floyd|chinese_postman_floyd|route_inspection_apsp"
        ),
        new PatternDef("cp_odd_match", "chinese_postman_odd_degree_bitmask_matching", "high",
            "deg\\[i\\].*&.*1.*cp_odd\\[cp_odd_n\\+\\+\\]|odd.*degree.*vertex.*collect",
            "cp_dp\\[mask.*1.*<<.*i.*1.*<<.*j\\].*=.*cp_dp\\[mask\\].*\\+.*cp_sp\\[cp_odd\\[i\\]\\]",
            "cp_min_matching|chinese_postman_match|odd_vertex_matching_dp"
        ),
        new PatternDef("cp_solve_total", "chinese_postman_total_cost_edge_sum_plus_extra", "medium",
            "total.*\\+=.*cp_dist\\[i\\]\\[j\\].*i.*<.*j|edge.*sum.*total.*route_inspection",
            "cp_find_odd.*cp_min_matching.*total.*\\+.*extra|cp_solve.*total.*extra",
            "cp_solve|chinese_postman_solve|route_inspection_cost"
        ),

        // ── bidirectional_bfs ─────────────────────────────────────────────────
        new PatternDef("bb_frontier_expand", "bidirectional_bfs_frontier_alternating_expand", "high",
            "bb_dist_fwd\\[v\\].*==.*BB_INF.*bb_dist_fwd\\[v\\].*=.*bb_dist_fwd\\[u\\].*\\+.*1|dist_fwd.*=.*dist_fwd.*\\+.*1",
            "bb_dist_bwd\\[v\\].*==.*BB_INF.*bb_dist_bwd\\[v\\].*=.*bb_dist_bwd\\[u\\].*\\+.*1|dist_bwd.*=.*dist_bwd.*\\+.*1",
            "bb_bfs|bidirectional_bfs_search|bidir_bfs_path_length"
        ),
        new PatternDef("bb_meet_check", "bidirectional_bfs_meet_in_middle_check", "high",
            "bb_dist_bwd\\[v\\].*!=.*BB_INF.*bb_dist_fwd\\[v\\].*\\+.*bb_dist_bwd\\[v\\]|dist_fwd.*\\+.*dist_bwd.*<.*best",
            "bb_dist_fwd\\[v\\].*!=.*BB_INF.*d.*=.*dist_fwd.*\\+.*dist_bwd|meet.*middle.*best.*update",
            "bb_meet|bidir_bfs_meet_node|bidirectional_frontier_intersection"
        ),
        new PatternDef("bb_two_queues", "bidirectional_bfs_dual_queue_interleave", "medium",
            "fq_head.*<.*fq_tail.*bq_head.*<.*bq_tail|forward_queue.*backward_queue.*interleave",
            "bb_queue\\[fq_tail\\+\\+\\].*=.*src.*bb_queue\\[bq_tail\\+\\+\\].*=.*dst|fwd_q.*src.*bwd_q.*dst",
            "run_bidirectional_bfs_tests|bb_bfs.*src.*dst|bidir_shortest_path"
        ),

        // ── a_star_search ─────────────────────────────────────────────────────
        new PatternDef("as_heuristic_manhattan", "a_star_manhattan_heuristic_grid", "high",
            "as_heuristic.*node.*goal.*nr.*nc.*gr.*gc|manhattan.*dr.*\\+.*dc.*heuristic",
            "as_f\\[nb\\].*=.*ng.*\\+.*as_heuristic\\(nb.*goal\\)|f_score.*g_score.*heuristic_cost",
            "as_heuristic|astar_heuristic|manhattan_distance_heuristic"
        ),
        new PatternDef("as_heap_priority", "a_star_min_heap_open_set_priority", "high",
            "as_f\\[as_heap\\[p\\]\\].*<=.*as_f\\[as_heap\\[i\\]\\]|heap_push.*sift_up.*f_score_order",
            "as_heap_pop.*as_heap\\[0\\].*as_heap_sz--|open_set_pop.*best_f_score",
            "as_heap_push|as_heap_pop|astar_open_set_heap"
        ),
        new PatternDef("as_grid_expand", "a_star_grid_neighbor_expand_with_wall_check", "medium",
            "as_grid\\[nr\\]\\[nc\\].*continue.*as_closed\\[nb\\].*continue|wall_check.*closed_check.*skip",
            "ng.*<.*as_g\\[nb\\].*as_g\\[nb\\].*=.*ng.*as_f\\[nb\\].*=.*ng.*\\+|g_score_improve.*update_f",
            "as_astar|run_a_star_tests|astar_grid_search"
        ),

        // ── ford_fulkerson_dfs ────────────────────────────────────────────────
        new PatternDef("ff_residual_edges", "ford_fulkerson_residual_graph_edge_pair", "high",
            "ff_cap\\[e\\].*-=.*f.*ff_cap\\[e.*\\^.*1\\].*\\+=.*f|residual.*cap.*back_edge.*augment",
            "ff_to\\[ff_ecnt\\].*=.*v.*ff_cap\\[ff_ecnt\\].*=.*c.*ff_nxt|forward_back_edge_pair_add",
            "ff_add_edge|ford_fulkerson_add_edge|residual_graph_build"
        ),
        new PatternDef("ff_dfs_augment", "ford_fulkerson_dfs_augmenting_path", "high",
            "ff_vis\\[u\\].*=.*1.*ff_cap\\[e\\].*<=.*0.*continue|dfs_augment.*visited.*capacity_check",
            "ff_dfs.*u.*t.*pushed.*ff_cap\\[e\\].*<.*pushed|bottleneck_dfs_path_find",
            "ff_dfs|ford_fulkerson_dfs_find_path|augmenting_path_dfs"
        ),
        new PatternDef("ff_maxflow_loop", "ford_fulkerson_maxflow_outer_loop", "high",
            "ff_vis\\[i\\].*=.*0.*ff_dfs.*s.*t.*FF_INF.*f.*<=.*0.*break|reset_visited_augment_loop",
            "flow.*\\+=.*f.*while.*ff_dfs.*s.*t|total_flow_accumulate_augment",
            "ff_maxflow|ford_fulkerson_max_flow|run_ford_fulkerson_tests"
        ),

        // ── segtree_fractional_cascading ──────────────────────────────────────
        new PatternDef("fc_build_merge_sorted", "segtree_fractional_cascading_build_merge", "high",
            "fc_off\\[node\\].*=.*fc_alloc.*fc_val\\[fc_alloc\\+\\+\\]|seg_tree_node_sorted_array_alloc",
            "fc_val\\[k\\+\\+\\].*=.*lv\\[i\\+\\+\\].*fc_val\\[k\\+\\+\\].*=.*rv\\[j\\+\\+\\]|merge_sorted_children_into_parent",
            "fc_build|segtree_fractional_cascading_build|merge_sort_tree_node"
        ),
        new PatternDef("fc_cross_links", "segtree_fractional_cascading_lpos_rpos_crosslinks", "high",
            "fc_lpos\\[base.*\\+.*p\\].*=.*fc_count_le.*lv.*nl.*fc_val|left_child_cross_link_fractional_cascade",
            "fc_rpos\\[base.*\\+.*p\\].*=.*fc_count_le.*rv.*nr.*fc_val|right_child_cross_link_fractional_cascade",
            "fc_lpos|fc_rpos|fractional_cascading_cross_link_build"
        ),
        new PatternDef("fc_kth_query", "segtree_fractional_cascading_kth_range_query", "medium",
            "fc_len\\[2\\*node\\].*left_in_range.*right_in_range.*k.*<=.*left_in_range|cascading_kth_descent",
            "fc_val\\[fc_off\\[node\\]\\].*root_v\\[.*\\].*fc_count_le|sorted_node_kth_extract",
            "fc_kth|fc_query|run_fc_tests|segtree_fractional_cascading_query"
        ),

        // ── edge_coloring ─────────────────────────────────────────────────────
        new PatternDef("ec_free_color_assign", "edge_coloring_free_color_vertex_assign", "high",
            "ec_vertex_color_edge\\[v\\]\\[c\\].*==.*EC_NONE.*return.*c|find_free_color_at_vertex",
            "ec_color\\[e\\].*=.*c.*ec_vertex_color_edge\\[u\\]\\[c\\].*=.*e|edge_color_assign_update_table",
            "ec_free_color|ec_assign|edge_coloring_assign_color"
        ),
        new PatternDef("ec_augment_path", "edge_coloring_augmenting_alternating_path_swap", "high",
            "ec_vertex_color_edge\\[v\\]\\[c2\\].*ec_color\\[e2\\].*=.*c1.*ec_vertex_color_edge|alternating_path_color_swap",
            "int.*tmp.*=.*c1.*c1.*=.*c2.*c2.*=.*tmp.*ec_augment_path|swap_c1_c2_augment_continue",
            "ec_augment_path|edge_coloring_alternating_path|vizing_fan_rotation"
        ),
        new PatternDef("ec_verify_coloring", "edge_coloring_validity_check", "medium",
            "ec_color\\[e1\\].*==.*ec_color\\[e2\\].*u1.*==.*u2.*u1.*==.*v2.*v1.*==.*u2|same_color_shared_vertex_check",
            "ec_count_colors|used\\[ec_color\\[e\\]\\].*=.*1|distinct_colors_used_count",
            "ec_verify|ec_count_colors|run_ec_tests|edge_coloring_verify"
        ),

        // ── max_independent_set ───────────────────────────────────────────────
        new PatternDef("mis_bitmask_adj", "max_independent_set_bitmask_adjacency", "high",
            "mis_adj\\[u\\].*\\|=.*1u.*<<.*v.*mis_adj\\[v\\].*\\|=.*1u.*<<.*u|bitmask_adjacency_bidirectional_add",
            "mis_adj\\[v\\].*&.*candidates.*mis_popcount|neighbor_mask_within_candidates_degree",
            "mis_adj|mis_add_edge|max_independent_set_graph_build"
        ),
        new PatternDef("mis_branch_bound", "max_independent_set_branch_and_bound_search", "high",
            "candidates.*==.*0u.*cur_size.*>.*mis_best.*mis_best.*=.*cur_size|leaf_update_best_independent_set",
            "cur_size.*\\+.*mis_popcount.*candidates.*<=.*mis_best.*return|upper_bound_prune_branch",
            "mis_search|mis_solve|max_independent_set_branch_bound"
        ),
        new PatternDef("mis_popcount", "max_independent_set_popcount_bitmask", "medium",
            "x.*=.*x.*-.*x.*>>.*1.*&.*0x55555555u.*0x33333333u.*0x0f0f0f0fu|parallel_popcount_32bit",
            "x.*\\*.*0x01010101u.*>>.*24|popcount_multiply_shift_extract",
            "mis_popcount|bitmask_popcount|run_mis_tests"
        ),

        // ── Articulation Points and Bridges ───────────────────────────────────
        new PatternDef("apb_disc_low_update", "articulation_points_bridges_disc_low_tarjan", "high",
            "disc.*low.*apb_disc.*apb_low.*apb_timer|tarjan_disc_low_init",
            "apb_disc|apb_low|disc.*low.*timer|low.*disc.*back_edge",
            "apb_find_all|run_apb_tests|articulation.*bridge.*dfs"
        ),
        new PatternDef("apb_ap_check", "articulation_points_bridges_cut_vertex_condition", "high",
            "low.*v.*>=.*disc.*u.*apb_is_ap.*par|cut_vertex_ap_flag",
            "apb_is_ap|is_ap.*low.*disc|apb_count_ap|low.*>=.*disc.*parent",
            "apb_stk_child|root_children_ap_check|apb_dfs"
        ),
        new PatternDef("apb_bridge_check", "articulation_points_bridges_edge_bridge_condition", "high",
            "low.*v.*>.*disc.*u.*apb_is_bridge|bridge.*edge.*low.*gt.*disc",
            "apb_is_bridge|apb_eid|is_bridge.*low.*disc|apb_count_bridges",
            "apb_add_edge|apb_head.*apb_to.*apb_nxt|apb_ecnt.*edge_id"
        ),

        // ── Treap with Order Statistics ───────────────────────────────────────
        new PatternDef("tos_split_merge", "treap_order_stats_split_by_key_merge", "high",
            "tos_split.*tos_pool.*key.*<=.*k|treap_split_key_left_right",
            "tos_merge.*tos_pool.*pri.*>=|treap_merge_heap_priority",
            "tos_split|tos_merge|run_tos_tests|treap.*order.*stat"
        ),
        new PatternDef("tos_size_update", "treap_order_stats_subtree_size_maintain", "high",
            "tos_pool.*sz.*=.*1.*\\+.*tos_sz.*left.*tos_sz.*right|treap_size_upd",
            "tos_upd|tos_sz|subtree.*size.*left.*right.*plus_one",
            "tos_pool.*sz|tos_root|treap_order_stats_size"
        ),
        new PatternDef("tos_kth_rank", "treap_order_stats_kth_smallest_rank_query", "high",
            "ls.*tos_sz.*left.*k.*<=.*ls.*k.*==.*ls.*\\+.*1.*k.*-=.*ls|kth_order_stat",
            "tos_kth|tos_rank|kth_smallest.*left_size|order_of_rank",
            "tos_insert|tos_erase|tos_split.*tos_merge.*tos_rand"
        ),

        // ── Maximum Weight Closure ────────────────────────────────────────────
        new PatternDef("mc_closure_source_sink", "maximum_closure_source_sink_construction", "high",
            "mc_add_edge.*s.*i.*weights.*i|mc_add_edge.*i.*t.*-weights|closure_pos_neg_edges",
            "pos_sum.*weights.*>.*0|mc_solve.*pos_sum.*mc_maxflow|max_closure_reduction",
            "mc_solve|run_mc_tests|maximum_closure.*min_cut"
        ),
        new PatternDef("mc_dinic_bfs_level", "maximum_closure_dinic_bfs_level_graph", "high",
            "mc_level.*=.*-1.*mc_level.*s.*=.*0.*mc_bfs_queue|dinic_bfs_level_init",
            "mc_bfs|mc_level.*mc_cap.*>.*0.*mc_level.*v.*==.*-1|bfs_level_graph",
            "mc_head|mc_to|mc_cap|mc_nxt|mc_iter|dinic_flow_network"
        ),
        new PatternDef("mc_dinic_blocking_flow", "maximum_closure_dinic_blocking_flow_dfs", "high",
            "mc_dfs.*mc_level.*v.*!=.*mc_level.*u.*\\+.*1.*mc_cap.*<=.*0|dinic_dfs_block",
            "mc_cap.*e.*-=.*d.*mc_cap.*e.*\\^.*1.*\\+=.*d|residual_cap_update",
            "mc_maxflow|mc_dfs|mc_iter|pos_sum.*-.*mc_maxflow.*s.*t"
        ),
        new PatternDef("eph_hierholzer_stack", "euler_path_hierholzer_stack_dfs", "high",
            "eph_stk.*eph_stk_top.*eph_hierholzer|hierholzer_iterative_stack",
            "eph_used.*e.*=.*1.*eph_used.*e.*\\^.*1.*=.*1|euler_edge_used_reverse",
            "eph_path.*eph_path_len.*eph_stk.*--eph_stk_top|euler_path_append"
        ),
        new PatternDef("eph_adj_list_init", "euler_path_adjacency_list_init", "high",
            "eph_head.*=.*-1.*eph_enum.*=.*0|euler_adj_list_reset",
            "eph_to.*eph_used.*eph_next.*eph_head|euler_edge_struct_fields",
            "eph_add_edge.*eph_to.*eph_enum.*=.*v.*eph_used.*eph_enum.*=.*0|euler_add_half_edge"
        ),
        new PatternDef("eph_circuit_verify", "euler_path_circuit_all_edges_used", "medium",
            "eph_all_used|euler_path_completeness_check",
            "eph_used.*i.*!eph_used|euler_unused_edge_check",
            "eph_path_len.*eph_hierholzer.*eph_all_used|euler_path_length_verify"
        ),
        new PatternDef("nfs_scaling_phase", "network_flow_scaling_delta_phase", "high",
            "delta.*=.*1.*while.*delta.*<=.*max_cap.*delta.*<<=.*1.*delta.*>>=.*1|capacity_scaling_delta_init",
            "nfs_max_flow.*delta.*>>=.*1.*while.*delta.*>=.*1|scaling_phase_halve_delta",
            "nfs_dfs.*s.*t.*NFS_INF.*delta.*nfs_iter.*nfs_visited|scaling_augment_dfs"
        ),
        new PatternDef("nfs_residual_update", "network_flow_scaling_residual_cap_update", "high",
            "nfs_cap.*e.*-=.*d.*nfs_cap.*e.*\\^.*1.*\\+=.*d|scaling_residual_cap_pair",
            "nfs_to.*nfs_cap.*nfs_nxt.*nfs_head.*nfs_iter|scaling_flow_edge_fields",
            "nfs_add_edge.*nfs_cap.*=.*cap.*nfs_cap.*=.*0|scaling_forward_reverse_edge"
        ),
        new PatternDef("nfs_dfs_threshold", "network_flow_scaling_dfs_delta_threshold", "medium",
            "nfs_cap.*e.*<.*delta.*continue|scaling_dfs_skip_below_delta",
            "nfs_visited.*nfs_dfs.*u.*t.*pushed.*<.*nfs_cap|scaling_dfs_pushed_min",
            "nfs_iter.*v.*!=.*-1.*nfs_iter.*v.*=.*nfs_nxt.*nfs_iter.*v|scaling_current_arc"
        ),
        new PatternDef("mvc_augment_dfs", "min_vertex_cover_augmenting_path_dfs", "high",
            "mvc_dfs.*mvc_ml.*u.*=.*v.*mvc_mr.*v.*=.*u|konig_matching_augment",
            "mvc_visited.*v.*=.*1.*mvc_mr.*v.*==.*-1.*mvc_dfs.*mvc_mr.*v|mvc_alternating_path",
            "mvc_max_matching.*mvc_dfs|konig_bipartite_max_matching"
        ),
        new PatternDef("mvc_konig_reachability", "min_vertex_cover_konig_alternating_reach", "high",
            "mvc_reach_l.*mvc_reach_r.*mvc_ml.*u.*==.*-1|konig_unmatched_left_seed",
            "mvc_reach_r.*v.*=.*1.*qr.*qr_t.*mvc_reach_l.*u.*=.*1.*ql.*ql_t|konig_alternating_bfs",
            "mvc_ml.*u.*!=.*v.*mvc_reach_r.*v.*=.*1|konig_unmatched_edge_reachable"
        ),
        new PatternDef("mvc_cover_construct", "min_vertex_cover_konig_cover_set", "medium",
            "!mvc_reach_l.*u.*mvc_ml.*u.*!=.*-1.*cover\\+\\+|konig_left_not_reachable_in_cover",
            "mvc_reach_r.*v.*cover\\+\\+|konig_right_reachable_in_cover",
            "mvc_vertex_cover.*mvc_max_matching.*mvc_reach_l.*mvc_reach_r|konig_theorem_cover"
        ),
        new PatternDef("ffm_ntt_butterfly", "fast_fourier_mod_ntt_butterfly_unit", "high",
            "ffm_mulmod.*wn.*w|ntt_twiddle_factor_advance",
            "ffm_bit_rev.*n.*>>.*1|ntt_bit_reversal_permutation",
            "ffm_ntt.*invert.*ffm_inv.*FFM_G|ntt_inverse_primitive_root"
        ),
        new PatternDef("ffm_poly_multiply", "fast_fourier_mod_polynomial_convolution", "high",
            "ffm_ntt.*ffm_fa.*0.*ffm_ntt.*ffm_fb.*0|ntt_forward_transform_pair",
            "ffm_fc.*ffm_mulmod.*ffm_fa.*ffm_fb|ntt_pointwise_product",
            "ffm_ntt.*ffm_fc.*1|ntt_inverse_transform_result"
        ),
        new PatternDef("ffm_modpow_inv", "fast_fourier_mod_modular_exponentiation", "medium",
            "ffm_pow.*base.*FFM_MOD.*-.*2|ntt_fermat_inverse",
            "ffm_mulmod.*result.*base|ntt_modular_square_accumulate",
            "FFM_MOD.*-.*1.*len|ntt_order_divisor_twiddle"
        ),
        new PatternDef("hpq_heavy_child", "heavy_path_queries_heavy_child_select", "high",
            "hpq_sz.*hpq_heavy.*hpq_sz.*hpq_heavy|hld_heavy_child_max_subtree",
            "hpq_heavy.*u.*-1|hld_leaf_no_heavy_child",
            "hpq_depth.*hpq_head_chain|hld_chain_head_depth_track"
        ),
        new PatternDef("hpq_path_climb", "heavy_path_queries_path_climb_chains", "high",
            "hpq_head_chain.*u.*!=.*hpq_head_chain.*v|hld_different_chains_climb",
            "hpq_par.*hpq_head_chain.*u|hld_jump_to_parent_of_chain_head",
            "hpq_depth.*hpq_head_chain.*u.*<.*hpq_depth.*hpq_head_chain.*v|hld_swap_deeper_chain"
        ),
        new PatternDef("hpq_seg_query", "heavy_path_queries_segment_tree_range_sum", "medium",
            "hpq_seg_query.*node.*2.*l.*mid|hld_segtree_left_child_query",
            "hpq_pos.*hpq_head_chain.*hpq_pos.*u|hld_flat_position_range",
            "hpq_seg.*node.*=.*hpq_seg.*node.*2.*\\+.*hpq_seg.*node.*2.*\\+.*1|hld_segtree_merge"
        ),
        new PatternDef("ort_merge_sort_tree", "offline_range_tree_merge_sort_build", "high",
            "ort_merge.*ort_buf.*ort_off.*ort_len|range_tree_merge_children_ylists",
            "ort_build.*node.*2.*l.*mid.*ort_build.*node.*2.*\\+.*1|range_tree_recursive_build",
            "ort_bufpos.*ort_off.*node|range_tree_buffer_allocation"
        ),
        new PatternDef("ort_count_range", "offline_range_tree_binary_search_count", "high",
            "ort_count_range.*a.*n.*lo.*hi|range_tree_sorted_ylist_count",
            "lb.*ub.*m.*a.*m.*<.*lo.*lb.*=.*m.*\\+.*1|range_tree_lower_bound_bisect",
            "lb.*-.*left|range_tree_count_in_interval"
        ),
        new PatternDef("ort_2d_query", "offline_range_tree_2d_range_query", "medium",
            "ort_query.*xl.*xr.*yl.*yr|range_tree_2d_decomposition",
            "xl.*>.*r.*xr.*<.*l.*return.*0|range_tree_x_range_prune",
            "xl.*<=.*l.*r.*<=.*xr.*ort_count_range|range_tree_x_covered_y_search"
        ),
        new PatternDef("johnson_reweight", "johnson_allpairs_edge_reweight", "high",
            "w.*\\+.*h\\[u\\].*-.*h\\[v\\]|johnson_potential_reweight",
            "bellman_ford.*src.*n.*\\+.*1|johnson_virtual_node_bf",
            "dij_dist.*-.*h\\[s\\].*\\+.*h\\[v\\]|johnson_distance_correction"
        ),
        new PatternDef("johnson_dijkstra", "johnson_allpairs_dijkstra_phase", "high",
            "dijkstra_reweighted.*src.*h.*n|johnson_per_source_dijkstra",
            "dij_done.*dij_dist.*INF|johnson_dijkstra_init",
            "dist_out\\[s\\]\\[v\\].*dij_dist|johnson_apsp_output_matrix"
        ),
        new PatternDef("johnson_apsp", "johnson_allpairs_shortest_paths", "medium",
            "add_edge.*q.*0|johnson_virtual_source_zero_edges",
            "finite_count.*path_sum|johnson_apsp_finite_path_accumulate",
            "johnson.*n_nodes|johnson_algorithm_entry"
        ),
        new PatternDef("dsu_rollback_union", "dsu_rollback_union_by_rank", "high",
            "parent\\[b\\].*=.*a.*rank\\[a\\].*\\+\\+|dsu_rollback_union_rank_merge",
            "stk_node.*stk_old_parent.*stk_old_rank|dsu_rollback_stack_push",
            "dsu_find.*while.*parent.*!=.*x|dsu_rollback_no_path_compression"
        ),
        new PatternDef("dsu_rollback_restore", "dsu_rollback_undo_union", "high",
            "parent\\[b\\].*=.*stk_old_parent|dsu_rollback_restore_parent",
            "rank\\[a\\].*=.*stk_old_rank|dsu_rollback_restore_rank",
            "dsu_restore.*while.*top.*>.*checkpoint|dsu_rollback_to_checkpoint"
        ),
        new PatternDef("dsu_rollback_save", "dsu_rollback_checkpoint_save", "medium",
            "dsu_save.*return.*dsu.*top|dsu_rollback_save_stack_depth",
            "comp_full.*comp_after.*dsu_find|dsu_rollback_component_count",
            "offline.*dsu.*rollback|dsu_rollback_offline_connectivity"
        ),
        new PatternDef("catalan_dp_recur", "catalan_number_dp_recurrence", "high",
            "catalan\\[n\\].*\\+=.*catalan\\[i\\].*catalan\\[n.*-.*1.*-.*i\\]|catalan_convolution_recurrence",
            "catalan\\[0\\].*=.*1.*catalan\\[1\\].*=.*1|catalan_base_cases",
            "for.*n.*=.*2.*MAX_N.*catalan\\[n\\]|catalan_tabulation_loop"
        ),
        new PatternDef("catalan_bracket_dp", "catalan_bracket_sequence_dp", "high",
            "bracket_dp.*i.*\\+.*1.*j.*\\+.*1|catalan_open_bracket_transition",
            "bracket_dp.*i.*\\+.*1.*j.*-.*1|catalan_close_bracket_transition",
            "bracket_dp.*len.*\\[0\\]|catalan_bracket_final_count"
        ),
        new PatternDef("catalan_verify", "catalan_number_multi_interpretation", "medium",
            "count_bst.*count_bracket_sequences.*count_mountain|catalan_three_combinatorial_views",
            "expected.*1.*1.*2.*5.*14.*42.*132|catalan_known_sequence_check",
            "catalan\\[5\\].*\\+.*catalan\\[6\\].*\\+.*catalan\\[7\\]|catalan_sum_verification"
        ),
        new PatternDef("prim_root_factor", "primitive_root_factorize_pm1", "high",
            "while.*rem.*%.*f.*==.*0.*rem.*\\/=.*f|primitive_root_trial_division_pm1",
            "factors\\[nf\\+\\+\\].*=.*f|primitive_root_prime_factor_collect",
            "for.*f.*\\*.*f.*<=.*rem.*f\\+\\+|primitive_root_factor_loop_bound"
        ),
        new PatternDef("prim_root_check", "primitive_root_order_check", "high",
            "pr_pow.*g.*pm1.*\\/.*factors.*i.*p.*==.*1|primitive_root_order_test_fermat",
            "for.*g.*=.*2.*g.*<.*p.*g\\+\\+|primitive_root_candidate_scan",
            "ok.*=.*0.*break|primitive_root_refutation_break"
        ),
        new PatternDef("prim_root_verify", "primitive_root_result_xor", "medium",
            "xor_roots.*\\^=.*r|primitive_root_xor_accumulate",
            "primitive_root.*pr_primes.*i|primitive_root_test_prime_array",
            "sum_roots.*\\+=.*r|primitive_root_sum_accumulate"
        ),
        new PatternDef("poly_interp_num", "polynomial_interpolation_numerator", "high",
            "num.*=.*num.*\\*.*q.*\\+.*p.*-.*xs.*j.*%.*p.*%.*p|lagrange_numerator_product",
            "for.*j.*=.*0.*j.*<.*n.*j\\+\\+.*if.*j.*==.*i.*continue|lagrange_skip_self_index",
            "num.*=.*1.*den.*=.*1|lagrange_init_num_den_per_term"
        ),
        new PatternDef("poly_interp_inv", "polynomial_interpolation_fermat_inverse", "high",
            "interp_pow.*den.*p.*-.*2.*p|lagrange_fermat_inverse_denominator",
            "den.*=.*den.*\\*.*xs.*i.*\\+.*p.*-.*xs.*j.*%.*p.*%.*p|lagrange_denominator_product",
            "result.*=.*result.*\\+.*ys.*i.*\\*.*num.*%.*p.*\\*.*inv_den.*%.*p|lagrange_accumulate_term"
        ),
        new PatternDef("poly_interp_query", "polynomial_interpolation_multiquery", "medium",
            "lagrange_eval.*xs.*ys.*3.*5.*INTERP_MOD|polynomial_interpolation_query_at_5",
            "lagrange_eval.*xs.*ys.*3.*7.*INTERP_MOD|polynomial_interpolation_query_at_7",
            "n_queries.*<<.*16.*r5.*&.*0xFF.*<<.*8.*r7|polynomial_interpolation_result_pack"
        ),
        new PatternDef("stl_swap_merge", "small_to_large_size_swap", "high",
            "if.*stl_sz.*rx.*<.*stl_sz.*ry|small_to_large_size_guard_swap",
            "stl_sz.*rx.*\\+=.*stl_sz.*ry|small_to_large_size_accumulate",
            "stl_par.*ry.*=.*rx|small_to_large_parent_redirect"
        ),
        new PatternDef("stl_rehash", "small_to_large_element_rehash", "high",
            "for.*i.*=.*0.*i.*<.*stl_nelem.*b.*i\\+\\+|small_to_large_iterate_smaller_set",
            "stl_freq.*a.*elem.*\\+=.*stl_freq.*b.*elem|small_to_large_frequency_merge",
            "stl_elems.*a.*stl_nelem.*a\\+\\+.*=.*elem|small_to_large_elem_list_append"
        ),
        new PatternDef("stl_path_compress", "small_to_large_path_compression", "medium",
            "stl_par.*x.*=.*stl_par.*stl_par.*x|small_to_large_path_halving",
            "while.*stl_par.*x.*!=.*x.*x.*=.*stl_par.*x|small_to_large_find_loop",
            "stl_freq.*rx.*e.*>.*stl_max_freq.*stl_max_freq|small_to_large_max_freq_update"
        ),
        // ── Suffix Array DC3 (Skew Algorithm) ────────────────────────────────
        new PatternDef("dc3_sample_sort", "suffix_array_dc3_sample_sort", "high",
            "dc3_rank.*i.*dc3_rank.*i.*\\+.*1.*dc3_rank.*i.*\\+.*2|suffix_array_dc3_triple_rank",
            "for.*i.*%.*3.*!=.*0|suffix_array_dc3_nonsample_skip",
            "dc3_sa12.*dc3_n12|suffix_array_dc3_sample_index"
        ),
        new PatternDef("dc3_merge", "suffix_array_dc3_merge_step", "high",
            "dc3_merge.*sa12.*sa0|suffix_array_dc3_merge_samples",
            "dc3_rank.*dc3_sa12.*p.*\\+.*dc3_n0|suffix_array_dc3_rank_lookup",
            "while.*p0.*<.*dc3_n0.*&&.*p12.*<.*dc3_n12|suffix_array_dc3_merge_loop"
        ),
        new PatternDef("dc3_leq", "suffix_array_dc3_leq_compare", "medium",
            "dc3_leq.*a1.*b1.*a2.*b2|suffix_array_dc3_tuple_compare",
            "dc3_rank.*a.*\\+.*1.*dc3_rank.*b.*\\+.*1|suffix_array_dc3_rank_compare",
            "return.*a1.*<.*b1.*\\|\\|.*a1.*==.*b1|suffix_array_dc3_lex_order"
        ),
        // ── Longest Common Extension (LCE via sparse table) ──────────────────
        new PatternDef("lce_sparse_build", "lce_sparse_table_build", "high",
            "lce_sp.*i.*0.*=.*lce_lcp.*i|longest_common_extension_sparse_init",
            "lce_sp.*i.*j.*=.*lce_min.*lce_sp.*i.*j.*-.*1.*lce_sp.*i.*\\+.*lce_pw.*j.*-.*1|lce_sparse_table_fill",
            "lce_pw.*j.*=.*lce_pw.*j.*-.*1.*\\*.*2|lce_power_of_two_table"
        ),
        new PatternDef("lce_query", "lce_range_min_query", "high",
            "lce_query.*l.*r|longest_common_extension_range_query",
            "k.*=.*lce_log2.*r.*-.*l.*\\+.*1|lce_query_log2_span",
            "lce_min.*lce_sp.*l.*k.*lce_sp.*r.*-.*lce_pw.*k.*\\+.*1|lce_sparse_query_formula"
        ),
        new PatternDef("lce_lcp_pair", "lce_lcp_pair_computation", "medium",
            "lce_lcp.*i.*=.*lce_query.*lce_rank.*i.*lce_rank.*i.*\\+.*1|lce_lcp_via_rank",
            "lce_rank.*lce_sa.*i.*=.*i|lce_rank_from_sa",
            "lce_total.*\\+=.*lce_lcp.*i|lce_total_accumulate"
        ),
        // ── Discrete Log Pohlig-Hellman ────────────────────────────────────────
        new PatternDef("pohlig_baby_step", "pohlig_hellman_baby_step", "high",
            "ph_baby.*j.*=.*ph_mod_pow.*ph_g.*j.*ph_pe.*ph_p|pohlig_hellman_baby_giant_table",
            "ph_tab.*ph_baby.*j.*=.*j|pohlig_hellman_table_store",
            "for.*j.*=.*0.*j.*<.*ph_pe.*j\\+\\+|pohlig_hellman_baby_loop"
        ),
        new PatternDef("pohlig_giant_step", "pohlig_hellman_giant_step", "high",
            "ph_giant.*=.*ph_mod_pow.*ph_g.*ph_pe.*ph_p|pohlig_hellman_giant_base",
            "ph_gamma.*=.*ph_h.*ph_mod_pow.*ph_giant.*k.*ph_p|pohlig_hellman_gamma_update",
            "ph_tab.*ph_gamma|pohlig_hellman_lookup_gamma"
        ),
        new PatternDef("pohlig_crt", "pohlig_hellman_crt_combine", "medium",
            "ph_crt.*x.*ph_crt.*mod|pohlig_hellman_crt_accumulate",
            "ph_x.*\\+=.*ph_dk.*ph_mod_crt|pohlig_hellman_crt_partial_log",
            "g_result.*<<.*16.*ph_x.*&.*0xFF.*<<.*8|pohlig_hellman_result_pack"
        ),

        // ── Weighted Interval Scheduling DP (Sprint 145) ──────────────────────
        new PatternDef("wis_sort_finish", "wis_sort_by_finish_time", "high",
            "wis_ivs.*j.*\\.finish.*>.*key\\.finish|ivs.*j.*finish.*>.*key.*finish",
            "wis_ivs.*j.*\\+.*1.*=.*wis_ivs.*j|wis_sort.*finish.*insertion",
            "wis_sort|weighted_interval.*sort|sort_by_finish"
        ),
        new PatternDef("wis_pred_bsearch", "wis_predecessor_binary_search", "high",
            "wis_ivs.*mid.*\\.finish.*<=.*t|wis_ivs.*finish.*<=.*start",
            "lo.*=.*mid.*\\+.*1.*ans.*=.*mid|hi.*=.*mid.*-.*1.*ans.*bsearch",
            "wis_pred|wis_predecessor|pred_binary_search"
        ),
        new PatternDef("wis_dp_recurrence", "wis_dp_take_or_skip", "high",
            "wis_dp.*i.*\\+.*1.*=.*take.*>.*skip.*?.*take.*:.*skip|wis_dp.*max.*take.*skip",
            "wis_ivs.*i.*\\.weight.*\\+.*dp_p|wis_take.*weight.*dp_predecessor",
            "wis_solve|wis_dp|weighted_interval_dp"
        ),

        // ── Longest Palindromic Subsequence DP (Sprint 145) ───────────────────
        new PatternDef("lpq_diag_fill", "lpq_dp_diagonal_length_fill", "high",
            "for.*len.*=.*2.*len.*<=.*LPQ_N|for.*length.*=.*2.*length.*<=.*n",
            "j.*=.*i.*\\+.*len.*-.*1|j\\s*=\\s*i\\s*\\+\\s*length\\s*-\\s*1",
            "lpq_solve|lpq_dp|lps_diagonal|palindromic_subseq"
        ),
        new PatternDef("lpq_char_match", "lpq_character_equality_branch", "high",
            "lpq_s.*i.*==.*lpq_s.*j|lps_s.*i.*==.*lps_s.*j",
            "len.*==.*2.*?.*2.*:.*lpq_dp.*i.*\\+.*1.*j.*-.*1.*\\+.*2|dp.*i\\+1.*j-1.*2",
            "lpq_match|palindromic_extend|char_equal_lps"
        ),
        new PatternDef("lpq_max_subprob", "lpq_max_of_subproblems", "high",
            "lpq_dp.*i.*\\+.*1.*j.*>.*lpq_dp.*i.*j.*-.*1|dp.*i\\+1.*j.*dp.*i.*j-1",
            "lpq_dp.*i.*j.*=.*a.*>.*b.*?.*a.*:.*b|lps_max_sub.*mismatch",
            "lpq_mismatch|lps_max|lpq_dp_mismatch"
        ),

        // ── Maximum Sum Subrectangle (Sprint 145) ─────────────────────────────
        new PatternDef("msr_col_compress", "msr_column_range_compress_to_1d", "high",
            "msr_col_sum.*row.*\\+=.*msr_mat.*row.*r|col_sum.*row.*\\+=.*mat.*row.*r",
            "for.*r.*=.*l.*r.*<.*MSR_COLS|for.*right.*=.*left.*right.*<.*cols",
            "msr_max_rect|msr_col_compress|column_range_sum"
        ),
        new PatternDef("msr_kadane", "msr_kadane_max_subarray", "high",
            "cur.*=.*cur.*\\+.*v.*>.*v.*?.*cur.*\\+.*v.*:.*v|cur.*=.*max.*cur.*\\+.*v.*v",
            "if.*cur.*>.*max_so_far.*max_so_far.*=.*cur|msr_max_so_far.*update",
            "msr_kadane|kadane_1d|max_subarray_kadane"
        ),
        new PatternDef("msr_left_right_scan", "msr_left_right_boundary_scan", "high",
            "for.*l.*=.*0.*l.*<.*MSR_COLS|for.*left.*=.*0.*left.*<.*cols",
            "for.*row.*=.*0.*row.*<.*MSR_ROWS.*msr_col_sum.*row.*=.*0|reset_col_sum",
            "msr_max_rect|left_right_scan|msr_boundary_loop"
        ),
        new PatternDef("knuth_opt_quadrangle", "knuth_opt_quadrangle_inequality", "high",
            "opt.*i.*j.*-.*1.*<=.*opt.*i.*j.*<=.*opt.*i.*\\+.*1.*j|kn_opt.*monotone",
            "for.*k.*=.*kn_opt.*i.*j.*-.*1.*k.*<=.*kn_opt.*i.*\\+.*1.*j|knuth_range_k",
            "kn_dp|knuth_opt_dp|quadrangle_inequality_dp"
        ),
        new PatternDef("knuth_opt_interval", "knuth_opt_interval_fill", "high",
            "for.*len.*=.*2.*len.*<=.*KN_N|for.*length.*=.*2.*length.*<=.*n",
            "for.*i.*\\+.*len.*-.*1.*<.*KN_N|for.*i.*\\+.*length.*-.*1.*<.*n.*j.*=.*i.*\\+.*len",
            "kn_dp.*i.*j|interval_dp_knuth|stone_merge_knuth"
        ),
        new PatternDef("knuth_opt_range_cost", "knuth_opt_prefix_range_weight", "high",
            "kn_w.*r.*\\+.*1.*-.*kn_w.*l|prefix_sum.*range.*weight",
            "kn_w.*i.*\\+.*1.*=.*kn_w.*i.*\\+.*i.*\\+.*1|prefix_sum_init_weights",
            "kn_range_w|range_weight_sum|knuth_cost_function"
        ),
        new PatternDef("mdm_gauss_elim_mod", "mdm_gauss_elimination_modular", "high",
            "for.*col.*=.*0.*col.*<.*MDM_N|pivot_row.*=.*MDM_N|gauss_mod_pivot",
            "inv_pivot.*=.*mdm_inv.*mat.*col.*col.*MDM_MOD|modular_inverse_pivot",
            "mdm_det|gauss_elim_mod|matrix_det_mod"
        ),
        new PatternDef("mdm_fermat_inverse", "mdm_fermat_little_theorem_inverse", "high",
            "mdm_powmod.*a.*m.*-.*2.*m|pow.*m.*-.*2.*mod.*prime|fermat_inv",
            "result.*=.*result.*\\*.*base.*%.*m|base.*=.*base.*\\*.*base.*%.*m",
            "mdm_inv|mdm_powmod|modular_inverse_prime"
        ),
        new PatternDef("mdm_row_reduce", "mdm_row_reduction_modular", "high",
            "factor.*=.*mat.*row.*col.*\\*.*inv_pivot.*%.*MDM_MOD|row_reduce_factor",
            "mat.*row.*k.*=.*mat.*row.*k.*\\+.*MDM_MOD.*-.*sub.*%.*MDM_MOD|subtract_mod",
            "mdm_det.*row.*reduce|modular_row_sub|gauss_mod_eliminate"
        ),
        new PatternDef("mono_min_dc", "monotone_minima_divide_conquer", "high",
            "mm_dc.*rs.*re.*cs.*ce|monotone_minima_dc.*row_range.*col_range",
            "mid_r.*=.*rs.*\\+.*re.*-.*rs.*\\/.*2|mid_row.*=.*lo.*\\+.*hi.*-.*lo.*>>.*1",
            "mm_argmin|monotone_minima|mono_min_dc"
        ),
        new PatternDef("mono_min_pivot", "monotone_minima_pivot_search", "high",
            "for.*c.*=.*cs.*\\+.*1.*c.*<.*ce.*v.*=.*mm_cost.*mid_r.*c|scan_pivot_col",
            "best_col.*=.*cs.*best_val.*=.*mm_cost.*mid_r.*cs|init_best_col_val",
            "mm_argmin.*mid_r.*=.*best_col|set_row_argmin|mono_min_argmin"
        ),
        new PatternDef("mono_min_monotone_check", "monotone_minima_property_verify", "high",
            "mm_argmin.*i.*<.*mm_argmin.*i.*-.*1|argmin.*not.*non_decreasing",
            "monotone_ok.*=.*0|monotone_property_violated|mono_check_fail",
            "mm_argmin|monotone_ok|monotone_minima_verify"
        ),
        new PatternDef("smawk_cost_fn", "smawk_totally_monotone_cost", "high",
            "sm_cost.*r.*c.*d.*r.*-.*c.*d.*d.*2.*c|totally_monotone_cost_fn",
            "sm_col_buf|sm_reduce|smawk_brute|smawk_row_minima",
            "argmin_brute|sm_argmin|monotone_matrix_min"
        ),
        new PatternDef("smawk_reduce_step", "smawk_column_reduction", "high",
            "survivor_row.*=.*out.*-.*1|sm_cost.*survivor_row.*cols.*out|dominated_col_remove",
            "if.*out.*<.*n_rows.*cols.*out.*=.*cols.*j|smawk_reduce_output",
            "sm_reduce|n_rows.*n_cols.*out|smawk_column_elim"
        ),
        new PatternDef("smawk_nondec_verify", "smawk_argmin_nondecreasing_check", "high",
            "argmin_brute.*i.*<.*argmin_brute.*i.*-.*1|nondec.*=.*0|smawk_monotone_fail",
            "smawk_brute.*SM_ROWS.*SM_COLS|run_smawk_tests|smawk_verify_property",
            "nondec.*nondec.*\\+.*3|smawk_result_pack|totally_monotone_verify"
        ),
        new PatternDef("lc_cht_bad_line", "line_container_cht_redundancy_check", "high",
            "lc_bad.*a.*b.*c.*c\\.b.*-.*a\\.b.*a\\.m.*-.*b\\.m|cht_line_redundant",
            "c\\.b.*-.*a\\.b.*a\\.m.*-.*b\\.m.*<=.*b\\.b.*-.*a\\.b.*a\\.m.*-.*c\\.m|lower_envelope_bad",
            "lc_bad|lc_hull|lc_sz|convex_hull_trick_check"
        ),
        new PatternDef("lc_cht_add_line", "line_container_cht_insert", "high",
            "while.*lc_sz.*>=.*2.*lc_bad.*lc_hull.*lc_sz.*-.*2|cht_remove_dominated",
            "lc_hull.*lc_sz\\+\\+|lc_add.*m.*b|line_container_push",
            "lc_add|lc_sz--|lc_hull|cht_insert_line"
        ),
        new PatternDef("lc_cht_query_min", "line_container_cht_binary_search", "high",
            "lc_hull.*mid.*\\.m.*x.*\\+.*lc_hull.*mid.*\\.b.*>.*lc_hull.*mid.*1.*\\.m|cht_bsearch",
            "lo.*=.*mid.*\\+.*1|hi.*=.*mid|lc_query_min|cht_lower_envelope_query",
            "lc_hull.*lo.*\\.m.*x.*\\+.*lc_hull.*lo.*\\.b|lc_query_result"
        ),
        new PatternDef("bw_modular_arith", "berlekamp_welch_field_arithmetic", "high",
            "bw_mod|bw_inv.*a.*p.*-.*2|bw_mul.*bw_add.*bw_sub|field_arith_fp",
            "a.*%.*BW_P.*if.*a.*<.*0.*a.*\\+.*BW_P|mod_reduce_prime",
            "bw_inv|bw_eval|bw_mod|fermat_little_theorem_inverse"
        ),
        new PatternDef("bw_system_build", "berlekamp_welch_linear_system", "high",
            "bw_mat.*i.*j.*=.*xpow.*xpow.*=.*bw_mul.*xpow.*xi|rs_equation_coeffs",
            "bw_mat.*i.*BW_K.*BW_E.*=.*bw_mod.*-.*yi|error_locator_coeff",
            "bw_mat.*i.*BW_UNK.*=.*bw_mul.*yi.*xi|berlekamp_welch_rhs"
        ),
        new PatternDef("bw_recovery", "berlekamp_welch_polynomial_recovery", "high",
            "bw_eval.*Q.*3.*.*bw_inv.*bw_eval.*E.*1|rs_polynomial_division",
            "E_at_err.*=.*bw_eval.*E.*1.*2|error_locator_root_check",
            "bw_gauss|bw_mat.*j.*BW_UNK|berlekamp_welch_decode"
        ),
        // ── eulerian_number ───────────────────────────────────────────────────────
        new PatternDef("eulerian_recurrence", "eulerian_number_dp_recurrence", "high",
            "en_dp.*n.*k.*=.*k.*\\+.*1.*en_dp.*n.*-.*1.*k.*\\+.*n.*-.*k.*en_dp.*n.*-.*1.*k.*-.*1|eulerian_ascent_recurrence",
            "eulerian_build|eulerian_number_table|ascent_count_dp",
            "en_dp|A_n_k_eulerian|permutation_ascent_count"
        ),
        new PatternDef("eulerian2_recurrence", "second_order_eulerian_dp_recurrence", "high",
            "en2_dp.*n.*k.*=.*k.*\\+.*1.*en2_dp.*n.*-.*1.*k.*\\+.*2.*\\*.*n.*-.*1.*-.*k.*\\+.*1.*en2_dp|eulerian2_recurrence",
            "eulerian2_build|second_order_eulerian|bspline_combinatorics",
            "en2_dp|<<n,k>>|multiset_permutation_ascent"
        ),
        new PatternDef("eulerian_rowsum", "eulerian_number_row_sum_factorial", "medium",
            "row_sum.*=.*0.*en_dp.*i.*\\+=|eulerian_row_sum_check",
            "row_sum.*n.*==.*factorial|sum_row_equals_n_factorial",
            "row_sum|eulerian_total_perms|factorial_verify_dp"
        ),
        // ── number_of_divisors_sieve ──────────────────────────────────────────────
        new PatternDef("ndiv_additive_sieve", "divisor_count_additive_sieve", "high",
            "nd_div.*m.*\\+\\+.*m.*\\+=.*d|divisor_count_increment_multiples",
            "for.*d.*=.*1.*d.*<=.*ND_LIMIT.*for.*m.*=.*d.*m.*<=.*ND_LIMIT.*m.*\\+=.*d|additive_divisor_sieve",
            "nd_div|ndiv_additive|divisor_sieve_inner_loop"
        ),
        new PatternDef("ndiv_spf_sieve", "divisor_count_spf_factorization", "high",
            "spf.*m.*==.*spf.*p.*is.*prime.*spf.*m.*=.*p|smallest_prime_factor_sieve",
            "nd_div2.*n.*=.*e.*\\+.*1.*\\*.*nd_div2.*m.*spf_factor_exponent|multiplicative_divisor_count",
            "spf|nd_div2|smallest_prime_factor|multiplicative_ndiv"
        ),
        new PatternDef("ndiv_sum_formula", "divisor_count_sum_over_range", "medium",
            "ndiv_sum.*=.*0.*arr.*i.*\\+=|sum_of_divisor_counts",
            "sum_d_n_floor_L_d|divisor_function_sum|ndiv_sum_verify",
            "ndiv_sum|divisor_count_total|sum_tau_function"
        ),
        // ── count_distinct_substrings ─────────────────────────────────────────────
        new PatternDef("cds_suffix_array", "count_distinct_substrings_suffix_array", "high",
            "build_sa.*prefix_doubling|cds_sort.*cds_cmp.*cds_gap|suffix_array_prefix_double",
            "rk.*sa.*i.*=.*tmp.*sa.*i.*-.*1.*\\+.*cds_cmp|suffix_array_rank_update",
            "cds_gap|build_sa|suffix_array_distinct_substrings"
        ),
        new PatternDef("cds_lcp_kasai", "count_distinct_substrings_kasai_lcp", "high",
            "inv_sa.*sa.*i.*=.*i.*kasai|build_lcp.*h.*\\+\\+.*h--|kasai_lcp_algorithm",
            "lcp.*inv_sa.*i.*-.*1.*=.*h.*if.*h.*>.*0.*h--|kasai_decrement_h",
            "build_lcp|inv_sa|kasai|lcp_from_suffix_array"
        ),
        new PatternDef("cds_formula", "count_distinct_substrings_formula", "high",
            "total.*=.*n.*\\*.*n.*\\+.*1.*\\/.*2.*-.*lcp.*i|distinct_substrings_formula",
            "count_distinct.*total.*-=.*lcp.*i|subtract_lcp_array_sum",
            "count_distinct|distinct_substrings_lcp|n_n1_div2_minus_sum_lcp"
        ),
        /* Sprint 149: stirling_numbers, partition_function, coin_change_unbounded */
        new PatternDef("stirling1_build", "stirling_first_kind_table", "high",
            "str1.*n.*k.*=.*n.*-.*1.*\\*.*str1.*n-1.*k.*\\+.*str1.*n-1.*k-1|stirling1_recurrence",
            "str1.*0.*0.*=.*1.*for.*n.*=.*1.*k.*=.*1.*k.*<=.*n|stirling1_base_init",
            "stirling1|stirling_first_kind|unsigned_stirling|cycle_permutation_count"
        ),
        new PatternDef("stirling1_query", "stirling_first_kind_lookup", "high",
            "c52.*=.*str1.*5.*2.*c43.*=.*str1.*4.*3|stirling1_lookup_indices",
            "str1.*n.*k.*stirling.*first.*kind|stirling1_table_access",
            "str1|c52|c43|stirling1_query|stirling_cycles"
        ),
        new PatternDef("stirling1_verify", "stirling_first_kind_check", "medium",
            "c55.*=.*str1.*5.*5.*c55.*==.*1|stirling1_diagonal_one",
            "metric_a.*=.*c52.*&.*0xFF.*metric_b.*=.*c43.*&.*0xFF|stirling1_pack_result",
            "stirling1_verify|stirling_diagonal|stirling_identity"
        ),
        new PatternDef("partition_build", "integer_partition_pentagonal", "high",
            "part.*0.*=.*1.*gpos.*=.*k.*\\*.*3.*k.*-.*1.*\\/.*2|pentagonal_number_gen",
            "val.*\\+=.*part.*n.*-.*gpos.*val.*-=.*part.*n.*-.*gpos|pentagonal_inclusion_exclusion",
            "partition_build|part.*pentagonal|integer_partition_dp|euler_pentagonal"
        ),
        new PatternDef("partition_query", "integer_partition_lookup", "high",
            "p7.*=.*part.*7.*p10.*=.*part.*10.*p12.*=.*part.*12|partition_result_indices",
            "part.*n.*partition.*function.*pentagonal.*recurrence|partition_table_lookup",
            "p7|p10|p12|partition_query|partition_function_result"
        ),
        new PatternDef("partition_verify", "integer_partition_check", "medium",
            "metric_a.*=.*p10.*&.*0xFF.*metric_b.*=.*p7.*&.*0xFF|partition_pack_result",
            "run_partition_tests.*partition_build.*p7.*p10|partition_test_driver",
            "partition_verify|partition_pack|pentagonal_check"
        ),
        new PatternDef("cc_unbounded_dp", "coin_change_unbounded_ways", "high",
            "cc_dp.*0.*=.*1.*for.*ci.*=.*0.*c.*=.*coins.*ci|unbounded_knapsack_coin",
            "cc_dp.*j.*\\+=.*cc_dp.*j.*-.*int.*c.*j.*=.*int.*c.*j.*<=.*target|coin_unbounded_inner",
            "cc_count_ways|cc_dp|unbounded_knapsack|coin_change_combinations"
        ),
        new PatternDef("cc_unbounded_test", "coin_change_unbounded_cases", "high",
            "coins1.*1.*2.*5.*cc_count_ways.*coins1.*3.*10|unbounded_coins_test1",
            "coins2.*1.*5.*6.*9.*cc_count_ways.*coins2.*4.*11|unbounded_coins_test2",
            "w1.*cc_count_ways|w2.*cc_count_ways|coin_change_test_cases"
        ),
        new PatternDef("cc_unbounded_pack", "coin_change_unbounded_result", "medium",
            "metric_a.*=.*w1.*&.*0xFF.*metric_b.*=.*w2.*&.*0xFF|coin_change_pack_result",
            "run_coin_change_tests.*cc_count_ways.*w1.*w2|coin_change_test_driver",
            "cc_unbounded_pack|coin_change_result|unbounded_ways_pack"
        ),

        // ── Sprint 150: fractional_knapsack_heap ──────────────────────────────
        new PatternDef("fkh_heap_push", "fractional_knapsack_heap_push", "high",
            "fkh_heap.*ratio.*>=.*fkh_heap.*ratio.*break|heap_push_ratio_cmp",
            "fkh_heap.*fkh_size.*=.*it.*fkh_size.*\\+\\+.*i.*=.*fkh_size|fkh_push_insert",
            "fkh_push|fractional_knapsack_push|heap_push_item_ratio"
        ),
        new PatternDef("fkh_heap_pop", "fractional_knapsack_heap_pop", "high",
            "fkh_heap.*0.*=.*fkh_heap.*--fkh_size|heap_pop_replace_last",
            "largest.*=.*l.*fkh_heap.*l.*ratio.*>.*fkh_heap.*largest.*ratio|heap_sift_down_ratio",
            "fkh_pop|fractional_knapsack_pop|heap_extract_max_ratio"
        ),
        new PatternDef("fkh_solve_greedy", "fractional_knapsack_greedy_fill", "high",
            "best.*weight.*<=.*remaining.*total_value.*\\+=.*best.*value|fkh_full_item_take",
            "total_value.*\\+=.*best.*value.*\\*.*remaining.*\\/.*best.*weight|fkh_partial_item_fraction",
            "fkh_solve|fractional_knapsack_solve|greedy_ratio_fill"
        ),

        // ── Sprint 150: segment_add_chmin ─────────────────────────────────────
        new PatternDef("sac_push_lazy", "segment_beats_push_lazy_add_chmin", "high",
            "sac_push_add.*lazy_add.*\\+=.*v|sac_push_chmin.*lazy_chmin.*=.*v|segtree_beats_lazy",
            "lazy_chmin.*!=.*SAC_INF.*lazy_chmin.*\\+=.*v|segtree_beats_chmin_adjust_add",
            "sac_push_add|sac_push_chmin|segment_beats_lazy_propagation"
        ),
        new PatternDef("sac_pullup_max2", "segment_beats_pullup_second_max", "high",
            "cnt_max.*=.*cnt_max.*\\+.*cnt_max|sac_pullup_equal_max_count",
            "max2.*>.*max1.*max2.*max1|sac_pullup_second_max_candidate",
            "sac_pullup|segment_beats_merge|second_max_cnt_max"
        ),
        new PatternDef("sac_range_chmin", "segment_beats_range_chmin_break", "high",
            "v.*>=.*st.*nd.*max1.*return|segtree_beats_chmin_prune",
            "v.*>.*st.*nd.*max2.*sac_push_chmin|segtree_beats_chmin_apply_leaf",
            "sac_range_chmin|segment_beats_chmin|ji_driver_segtree_chmin"
        ),

        // ── Sprint 150: moebius_function_sieve ───────────────────────────────
        new PatternDef("mfs_linear_sieve", "moebius_linear_sieve_build", "high",
            "mfs_mu.*i.*=.*-1.*is_prime|moebius_prime_assignment_neg1",
            "i.*%.*p.*==.*0.*mfs_mu.*i.*\\*.*p.*=.*0.*break|moebius_squared_factor_zero",
            "mfs_sieve|moebius_sieve|linear_sieve_mu"
        ),
        new PatternDef("mfs_mu_multiplicative", "moebius_multiplicative_propagation", "high",
            "mfs_mu.*i.*\\*.*p.*=.*-mfs_mu.*i|moebius_multiplicative_step",
            "i.*%.*p.*!=.*0.*mfs_mu.*i.*\\*.*p.*=.*-mfs_mu|moebius_coprime_factor",
            "mfs_mu|moebius_function|mu_multiplicative_sieve"
        ),
        new PatternDef("mfs_squarefree", "moebius_squarefree_count_sum", "medium",
            "mfs_mu.*k.*\\*.*n.*\\/.*k.*\\*.*k|moebius_squarefree_formula",
            "k.*\\*.*k.*<=.*n.*cnt.*\\+=.*mfs_mu.*k|moebius_squarefree_loop",
            "mfs_squarefree_count|moebius_inclusion_exclusion|squarefree_count_mu"
        ),

        // ── Sprint 151: cycle_detection_floyd ────────────────────────────────
        new PatternDef("cdf_phase1_meet", "floyd_tortoise_hare_meet", "high",
            "slow.*=.*fn.*slow.*fast.*=.*fn.*fn.*fast|floyd_phase1_advance",
            "slow.*!=.*fast.*slow.*=.*fn.*slow.*fast.*=.*fn.*fn|tortoise_hare_loop",
            "floyd_cycle_detect|tortoise_hare|cycle_detection_floyd"
        ),
        new PatternDef("cdf_phase2_mu", "floyd_cycle_start_mu", "high",
            "slow.*=.*x0.*slow.*!=.*fast.*mu\\+\\+|floyd_mu_phase2",
            "mu.*=.*0.*slow.*=.*x0.*while.*slow.*!=.*fast|floyd_find_cycle_start",
            "cycle_start_mu|floyd_phase2|mu_cycle_start"
        ),
        new PatternDef("cdf_phase3_lambda", "floyd_cycle_length_lambda", "medium",
            "lam.*=.*1.*fast.*=.*fn.*slow.*slow.*!=.*fast.*lam\\+\\+|floyd_lambda_phase3",
            "cycle_length.*lam|lambda_cycle_length|floyd_phase3_length",
            "out_lambda|cycle_len_floyd|floyd_lambda"
        ),

        // ── Sprint 151: cycle_detection_brent ────────────────────────────────
        new PatternDef("bcdf_power_teleport", "brent_power_teleport", "high",
            "power.*==.*lam.*tortoise.*=.*hare.*power.*\\*=.*2|brent_teleport_step",
            "if.*power.*==.*lam.*tortoise.*hare.*power.*\\*.*2.*lam.*=.*0|brent_power_doubling",
            "brent_cycle_detect|power_teleport|brent_phase1"
        ),
        new PatternDef("bcdf_lambda_find", "brent_cycle_length_direct", "high",
            "hare.*=.*fn.*hare.*lam\\+\\+.*while.*tortoise.*!=.*hare|brent_lambda_count",
            "out_lambda.*=.*lam.*lam.*=.*1.*power.*=.*1|brent_find_lambda",
            "brent_lambda|cycle_len_brent|lam_brent"
        ),
        new PatternDef("bcdf_mu_find", "brent_cycle_start_mu", "medium",
            "for.*i.*<.*lam.*hare.*=.*fn.*hare.*mu.*=.*0|brent_advance_lambda_steps",
            "tortoise.*!=.*hare.*tortoise.*=.*fn.*hare.*=.*fn.*mu\\+\\+|brent_mu_phase2",
            "brent_mu|brent_phase2|mu_brent_start"
        ),

        // ── Sprint 151: derangement_dp ───────────────────────────────────────
        new PatternDef("dera_recurrence", "derangement_dp_recurrence", "high",
            "dera_D.*n.*=.*n.*-.*1.*\\*.*dera_D.*n.*-.*1.*\\+.*dera_D.*n.*-.*2|derangement_recurrence",
            "D.*n.*=.*n-1.*D.*n-1.*\\+.*D.*n-2|derangement_dp_formula",
            "derangement_dp|dera_build|derangement_recurrence_dp"
        ),
        new PatternDef("dera_inclusion_excl", "derangement_inclusion_exclusion", "high",
            "binom.*\\*.*fact.*n.*-.*k.*k.*%.*2.*==.*0.*result.*\\+=|derangement_ie_even",
            "k.*%.*2.*!=.*0.*result.*-=.*binom.*\\*.*fact|derangement_ie_odd",
            "dera_inclusion_exclusion|derangement_ie|inclusion_exclusion_derangement"
        ),
        new PatternDef("dera_count", "derangement_count_lookup", "medium",
            "dera_count|dera_D.*k|derangement_count_table",
            "return.*dera_D.*k|derangement_table_lookup|dera_count_fn",
            "dera_MAXN|derangement_maxn|dera_count_limit"
        ),

        // ── Nim game (Sprague-Grundy, multi-pile XOR) ────────────────────────
        new PatternDef("nim_pile_xor_sum", "nim_game_xor_sum_piles", "high",
            "xv.*\\^=.*piles.*i|nim_xor_sum.*piles.*n|xor.*pile.*for.*loop",
            "nim_xor_sum|nim_pile_xor|xor_sum_piles",
            "return.*xv|nim_sum_return|pile_xor_accumulate"
        ),
        new PatternDef("nim_p_position", "nim_game_p_position_check", "high",
            "nim_xor_sum.*==.*0u.*?.*1u.*:.*0u|nim_is_losing|p_position_nim",
            "nim_is_losing|losing_position_nim|nim_sum_zero_check",
            "return.*nim_xor_sum.*==.*0|nim_pposition_return|nim_lose_detect"
        ),
        new PatternDef("nim_winning_move", "nim_game_find_winning_move", "high",
            "target.*=.*piles.*i.*\\^.*xv|nim_find_winning_move|winning_pile_reduce",
            "target.*<.*piles.*i.*new_size_out|nim_move_target|pile_reduce_winning",
            "return.*-1.*losing.*no.*winning.*move|nim_no_winning_move|nim_move_idx"
        ),

        // ── Necklace counting (Burnside + Euler totient + Mobius) ─────────────
        new PatternDef("nck_burnside_sum", "necklace_burnside_phi_sum", "high",
            "n.*%.*d.*==.*0.*nck_phi.*d.*\\*.*nck_pow2.*n.*d|necklace_burnside_divisor",
            "total.*\\+=.*nck_phi.*d.*nck_pow2|burnside_phi_pow2_sum",
            "necklace_count_burnside|nck_burnside|burnside_necklace_count"
        ),
        new PatternDef("nck_lyndon_mobius", "necklace_lyndon_mobius_count", "high",
            "nck_mu.*n.*d.*mu.*>.*0.*total.*\\+=.*nck_pow2|lyndon_mu_positive",
            "mu.*<.*0.*total.*-=.*nck_pow2|lyndon_mu_negative|mobius_lyndon_sub",
            "lyndon_count|nck_lyndon|lyndon_word_count_mobius"
        ),
        new PatternDef("nck_phi_factor", "necklace_euler_phi_factorization", "high",
            "result.*-=.*result.*p|euler_phi_factor_result|phi_reduce_factor",
            "n.*>.*1.*result.*-=.*result.*n|phi_remaining_prime|nck_phi_fn",
            "nck_phi|euler_totient_necklace|phi_for_necklace"
        ),

        // ── Bracket sequence DP (valid sequences, min removals, parenthesization) ──
        new PatternDef("bsq_count_dp", "bracket_sequence_valid_count_dp", "high",
            "ndp.*j.*\\+.*1.*\\+=.*dp.*j|bracket_seq_add_open_dp",
            "j.*>.*0.*ndp.*j.*-.*1.*\\+=.*dp.*j|bracket_seq_close_dp",
            "bracket_seq_count|bsq_count|valid_bracket_sequences_dp"
        ),
        new PatternDef("bsq_min_removals", "bracket_sequence_min_removals", "high",
            "open.*>.*0.*open--|close\\+\\+|bracket_mismatch_close_count",
            "return.*open.*\\+.*close|bracket_min_removals|unmatched_bracket_sum",
            "bracket_min_removals|bsq_removals|min_bracket_delete"
        ),
        new PatternDef("bsq_parenthesization", "bracket_sequence_parenthesization_dp", "high",
            "p.*i.*\\+=.*p.*k.*\\*.*p.*i.*-.*k|parenthesization_recurrence",
            "parenthesization_count|bsq_paren|catalan_parenthesization_dp",
            "p.*1.*=.*1.*p.*0.*=.*0|parenthesization_init|paren_count_base"
        ),

        // ── Sieve of Atkin (prime sieve via quadratic forms) ──────────────────
        new PatternDef("atk_quadratic_flip", "atkin_quadratic_form_flag_flip", "high",
            "flags.*n.*\\^=.*1|atkin_flip_prime_flag|sieve_atkin_toggle",
            "4.*x2.*\\+.*y2|3.*x2.*\\+.*y2|3.*x2.*-.*y2|atkin_quadratic_forms",
            "n.*%.*12.*==.*1.*||.*n.*%.*12.*==.*5|atkin_mod12_check|quadratic_form_residue"
        ),
        new PatternDef("atk_square_elim", "atkin_square_multiple_elimination", "high",
            "r2.*=.*r.*\\*.*r.*k.*\\+=.*r2|atkin_eliminate_square_multiples",
            "flags.*k.*=.*0.*k.*\\+=.*r2|atkin_clear_square_composites",
            "atkin_sieve|atk_square_elim|sieve_of_atkin_squarefree"
        ),
        new PatternDef("atk_count_primes", "atkin_count_sieve_primes", "medium",
            "atkin_flags.*i|atkin_count_primes|count_primes_atkin_sieve",
            "cnt.*\\+\\+.*atkin_flags|prime_count_atkin|atkin_prime_accumulate",
            "isqrt32|atkin_sqrt_limit|sieve_atkin_sqrt_bound"
        ),

        // ── MEX / Grundy values for combinatorial games ────────────────────────
        new PatternDef("mex_present_mark", "mex_reachable_values_mark", "high",
            "present.*reachable.*i|mex_mark_present|grundy_mex_bitmap_set",
            "compute_mex|mex_grundy|minimum_excludant_compute",
            "for.*m.*<=.*MEX_MAXN.*!present.*m.*return.*m|mex_scan_missing"
        ),
        new PatternDef("mex_subtraction_game", "grundy_subtraction_game_compute", "high",
            "g.*n.*-.*1.*g.*n.*-.*2.*g.*n.*-.*3|subtraction_game_reachable",
            "subtraction_grundy|grundy_subtraction|sub_g.*compute_mex",
            "g.*n.*%.*4|subtraction_period4|subtraction_grundy_period"
        ),
        new PatternDef("mex_multi_xor", "grundy_multi_game_xor_sum", "high",
            "nim_g.*\\[.*\\].*\\^.*nim_g|multi_game_grundy_xor|nimber_xor_combine",
            "multi_xor.*!=.*0.*first_wins|grundy_xor_p_position|nimber_nonzero_wins",
            "nim_pile_grundy|nim_g|single_pile_nim_grundy_value"
        ),

        // ── Goldbach conjecture verification ──────────────────────────────────
        new PatternDef("gold_sieve_build", "goldbach_eratosthenes_sieve_build", "high",
            "gold_is_prime.*j.*=.*0.*j.*\\+=.*i|goldbach_sieve_composite_mark",
            "build_sieve|gold_sieve|eratosthenes_goldbach_prime_table",
            "gold_is_prime.*0.*=.*0.*gold_is_prime.*1.*=.*0|goldbach_sieve_init"
        ),
        new PatternDef("gold_smallest_pair", "goldbach_find_smallest_prime_pair", "high",
            "gold_is_prime.*p.*&&.*gold_is_prime.*n.*-.*p|goldbach_pair_check",
            "goldbach_smallest|gold_smallest|goldbach_min_prime_decompose",
            "p.*<=.*n.*\\/.*2.*gold_is_prime|goldbach_half_bound_scan"
        ),
        new PatternDef("gold_count_pairs", "goldbach_count_prime_pairs", "medium",
            "goldbach_count_pairs|gold_count|goldbach_pair_count_unordered",
            "cnt.*\\+\\+.*gold_is_prime.*p.*&&.*gold_is_prime.*n.*-.*p|goldbach_accumulate_pairs",
            "goldbach_verify_all|gold_verify|goldbach_all_even_check"
        ),

        // ── Sprint 154: Farey Sequence ───────────────────────────────────────
        new PatternDef("farey_mediant_next", "farey_sequence_next_term", "high",
            "k.*=.*q0.*\\+.*n.*\\/.*q1|farey_mediant_step|farey_next_term",
            "p2.*=.*k.*\\*.*p1.*-.*p0|farey_numerator_update|farey_mediant_num",
            "q2.*=.*k.*\\*.*q1.*-.*q0|farey_denominator_update|farey_mediant_den"
        ),
        new PatternDef("farey_count_terms", "farey_sequence_count", "high",
            "farey_count|cnt.*\\+\\+.*p1.*!=.*1u.*||.*q1.*!=.*1u|farey_term_count",
            "cnt.*=.*2u.*p0.*=.*0u.*q0.*=.*1u.*p1.*=.*1u.*q1.*=.*n|farey_init_pair",
            "while.*p1.*!=.*1.*q1.*!=.*1.*farey|farey_iterate_until_one_one"
        ),
        new PatternDef("farey_nth_term", "farey_sequence_index_lookup", "medium",
            "farey_nth_term|farey_term_at_index|farey_idx_lookup",
            "cur.*<.*idx.*p2.*=.*k.*\\*.*p1|farey_advance_to_index",
            "q1.*<<.*16.*|.*p1|farey_pack_fraction|farey_return_pq"
        ),

        // ── Sprint 154: Linear Diophantine Equation ──────────────────────────
        new PatternDef("dioph_ext_gcd", "diophantine_extended_euclidean", "high",
            "ext_gcd|dioph_gcd|g.*=.*ext_gcd.*b.*a.*%.*b.*x1.*y1",
            "px.*=.*y1.*py.*=.*x1.*-.*a.*\\/.*b.*\\*.*y1|dioph_coeff_backsubstitute",
            "diophantine|dioph_solve|linear_diophantine_equation"
        ),
        new PatternDef("dioph_solvable_check", "diophantine_divisibility_check", "high",
            "c.*%.*g.*!=.*0.*return.*0|dioph_no_solution|diophantine_unsat_check",
            "scale.*=.*c.*\\/.*g|dioph_scale_particular|diophantine_particular_soln",
            "rx.*=.*x0.*\\*.*scale.*ry.*=.*y0.*\\*.*scale|dioph_particular_assign"
        ),
        new PatternDef("dioph_verify_soln", "diophantine_verify_solution", "medium",
            "a.*\\*.*x.*\\+.*b.*\\*.*y.*==.*c|dioph_verify|diophantine_check_result",
            "solvable.*&&.*verify|dioph_solution_valid|diophantine_result_ok",
            "dioph_solve.*12.*8.*4|dioph_test_case|diophantine_fixture_run"
        ),

        // ── Sprint 154: Totient Sum (linear sieve) ───────────────────────────
        new PatternDef("totient_linear_sieve", "totient_sum_sieve_build", "high",
            "tot_phi.*i.*\\*.*p.*=.*tot_phi.*i.*\\*.*p|totient_phi_composite_rule",
            "i.*%.*p.*==.*0u.*tot_phi.*i.*\\*.*p.*=.*tot_phi.*i.*\\*.*p|totient_phi_divisible",
            "tot_phi.*i.*\\*.*p.*=.*tot_phi.*i.*\\*.*p.*-.*1u|totient_phi_coprime_rule"
        ),
        new PatternDef("totient_sum_prefix", "totient_sum_accumulate", "high",
            "totient_sum|s.*\\+=.*tot_phi.*k|totient_prefix_accumulate",
            "for.*k.*=.*1u.*k.*<=.*n.*k.*<.*TOT_MAX|totient_sum_loop_bound",
            "s10.*==.*32|totient_sum_10_check|phi_sum_to_10"
        ),
        new PatternDef("totient_sieve_primes", "totient_linear_sieve_primes", "medium",
            "tot_is_composite.*i.*\\*.*p.*=.*1u|totient_mark_composite",
            "tot_primes.*tot_pcnt\\+\\+.*=.*i|totient_prime_list_append",
            "for.*j.*<.*tot_pcnt.*i.*\\*.*tot_primes.*j.*<.*TOT_MAX|totient_inner_sieve_loop"
        ),

        // ── Sprint 155: Josephus Problem ─────────────────────────────────────
        new PatternDef("josephus_iterative", "josephus_survivor_pos", "high",
            "pos.*=.*pos.*\\+.*k.*%.*i|josephus_recurrence_step",
            "for.*i.*=.*2u.*i.*<=.*n.*i\\+\\+.*pos.*=.*pos.*\\+.*k.*%.*i|josephus_loop_n",
            "pos.*=.*0u.*for.*i.*=.*2u|josephus_init_and_loop"
        ),
        new PatternDef("josephus_k2", "josephus_step2_formula", "high",
            "pos.*=.*pos.*\\+.*2u.*%.*i|josephus_k2_recurrence",
            "j10.*=.*josephus.*10u.*2u|josephus_n10_k2_call",
            "j7.*=.*josephus_k.*7u.*3u|josephus_n7_k3_call"
        ),
        new PatternDef("josephus_metric", "josephus_result_encode", "medium",
            "metric_a.*=.*j10.*\\+.*1u|josephus_metric_a_offset",
            "metric_b.*=.*j7.*\\+.*1u|josephus_metric_b_offset",
            "g_result.*=.*n_tests.*<<.*16u.*|.*metric_a.*<<.*8u.*|.*metric_b|josephus_result_pack"
        ),

        // ── Sprint 155: Wilson's Theorem ──────────────────────────────────────
        new PatternDef("wilson_primality", "wilson_is_prime_test", "high",
            "fact.*==.*p.*-.*1u.*\\?.*1u.*:.*0u|wilson_congruence_check",
            "factorial_mod.*p.*-.*1u.*p|wilson_factorial_call",
            "wilson_is_prime.*p.*<.*2u.*return.*0u|wilson_base_case"
        ),
        new PatternDef("wilson_factorial_mod", "wilson_factorial_mod_loop", "high",
            "f.*=.*uint32_t.*f.*\\*.*uint32_t.*i.*%.*m|wilson_mod_multiply",
            "for.*i.*=.*2u.*i.*<=.*n.*i\\+\\+.*f.*=.*f.*\\*.*i.*%.*m|wilson_factorial_loop",
            "f.*=.*1u.*for.*i.*=.*2u|wilson_factorial_init"
        ),
        new PatternDef("wilson_count_primes", "wilson_count_primes_range", "medium",
            "cnt20.*=.*count_wilson_primes.*20u|wilson_count_to_20",
            "for.*p.*=.*2u.*p.*<=.*limit.*p\\+\\+.*wilson_is_prime.*p|wilson_sieve_loop",
            "cnt.*\\+\\+.*wilson_is_prime.*p|wilson_prime_counter"
        ),

        // ── Sprint 155: Grid Path Count ───────────────────────────────────────
        new PatternDef("grid_path_dp", "grid_path_count_fill", "high",
            "dp.*i.*j.*=.*grid_obs.*i.*j.*\\?.*0u.*:.*dp.*i.*-.*1u.*j.*\\+.*dp.*i.*j.*-.*1u|grid_path_recurrence",
            "for.*i.*=.*1u.*i.*<.*rows.*for.*j.*=.*1u.*j.*<.*cols|grid_path_inner_loops",
            "dp.*rows.*-.*1u.*cols.*-.*1u|grid_path_bottom_right"
        ),
        new PatternDef("grid_path_init", "grid_path_boundary_init", "high",
            "dp.*0.*j.*=.*grid_obs.*0.*j.*\\?.*0u.*:.*dp.*0.*j.*-.*1u|grid_path_first_row",
            "dp.*i.*0.*=.*grid_obs.*i.*0.*\\?.*0u.*:.*dp.*i.*-.*1u.*0|grid_path_first_col",
            "dp.*0.*0.*=.*1u|grid_path_start_cell"
        ),
        new PatternDef("grid_path_metric", "grid_path_result_encode", "medium",
            "paths3x3.*=.*count_paths_3x3|grid_path_3x3_call",
            "metric_a.*=.*paths3x3|grid_path_metric_a",
            "metric_b.*=.*paths5x5.*%.*200u.*\\+.*5u|grid_path_metric_b_clamp"
        ),
        new PatternDef("spq_block_assign", "sqrt_path_block_partition", "high",
            "block_id.*=.*depth.*SPQ_BLOCK|i.*\\/.*SPQ_BLOCK|spq_blk.*\\^=.*spq_val",
            "spq_build|sqrt_decomp_build|block_xor_init",
            "spq_blk.*\\[.*i.*\\/.*SPQ_BLOCK.*\\]|sqrt_block_assign"
        ),
        new PatternDef("spq_range_query", "sqrt_path_range_xor_query", "high",
            "lb.*=.*l.*\\/.*SPQ_BLOCK|rb.*=.*r.*\\/.*SPQ_BLOCK|l_block.*==.*r_block",
            "for.*b.*=.*lb.*\\+.*1.*b.*<.*rb.*ans.*\\^=.*spq_blk|whole_block_xor",
            "spq_query|sqrt_path_query|range_xor_sqrt"
        ),
        new PatternDef("spq_metric", "sqrt_path_result_encode", "medium",
            "spq_query.*2.*6|sqrt_query_range_call",
            "spq_query.*0.*8|sqrt_query_full_range",
            "g_result.*2u.*16.*q1.*8.*q2|sqrt_path_metric_encode"
        ),
        new PatternDef("cf_convergent_recurrence", "continued_frac_convergent_step", "high",
            "p.*=.*a.*\\*.*p1.*\\+.*p2|p.*=.*cf_a.*\\*.*p_prev.*\\+.*p_prev2",
            "q.*=.*a.*\\*.*q1.*\\+.*q2|q.*=.*cf_a.*\\*.*q_prev.*\\+.*q_prev2",
            "p2.*=.*p1.*p1.*=.*p|q2.*=.*q1.*q1.*=.*q"
        ),
        new PatternDef("cf_coeff_init", "continued_frac_coeff_init", "high",
            "p2.*=.*1.*p1.*=.*cf_a.*\\[.*0.*\\]|cf_p_prev2_init",
            "q2.*=.*0.*q1.*=.*1|cf_q_prev2_init",
            "cf_a.*\\[.*CF_LEN.*\\]|continued_fraction_coeffs"
        ),
        new PatternDef("cf_metric", "continued_frac_result_encode", "medium",
            "fp.*=.*p1.*&.*0xFFu|cf_p1_low_byte",
            "fq.*=.*q1.*&.*0xFFu|cf_q1_low_byte",
            "CF_LEN.*<<.*16.*fp.*<<.*8.*fq|continued_frac_encode"
        ),
        new PatternDef("pell_cf_step", "pell_equation_cf_iteration", "high",
            "m.*=.*d.*\\*.*a.*-.*m|pell_m_update|pe_cf_m_step",
            "d.*=.*D.*-.*m.*\\*.*m.*\\/.*d|pell_d_update|pe_cf_d_step",
            "a.*=.*a0.*\\+.*m.*\\/.*d|pell_a_update|pe_cf_a_step"
        ),
        new PatternDef("pell_solution_check", "pell_equation_verify_solution", "high",
            "p.*\\*.*p.*-.*D.*\\*.*q.*\\*.*q.*==.*1|pell_verify|pell_check_solution",
            "pe_isqrt|isqrt.*pell|integer_sqrt_pell",
            "a0.*=.*pe_isqrt.*D|pell_a0_init"
        ),
        new PatternDef("pell_metric", "pell_equation_result_encode", "medium",
            "n_iters.*<<.*16.*xl.*<<.*8.*yl|pell_result_pack",
            "xl.*=.*p.*&.*0xFFu|pell_x_low_byte",
            "yl.*=.*q.*&.*0xFFu|pell_y_low_byte"
        ),
        new PatternDef("harshad_digit_sum", "harshad_digit_sum_extract", "high",
            "s.*\\+?=.*n.*%.*10|digit_sum_accumulate",
            "n.*/?=.*10.*s.*\\+=.*n|digit_extraction_loop",
            "digit_sum.*harshad|harshad_sum_compute"
        ),
        new PatternDef("harshad_divisibility", "harshad_divisibility_check", "high",
            "n.*%.*s.*==.*0|divisible_by_digit_sum",
            "is_harshad|harshad_check_remainder",
            "digit_sum.*==.*0.*return.*0|harshad_zero_guard"
        ),
        new PatternDef("harshad_metric", "harshad_result_encode", "medium",
            "count.*<<.*16.*last.*<<.*8.*checksum|harshad_pack_result",
            "last.*=.*i.*is_harshad|harshad_last_update",
            "count.*last.*0xFF|harshad_checksum_encode"
        ),
        new PatternDef("lucky_odd_init", "lucky_sieve_odd_init", "high",
            "i.*\\+?=.*2.*lucky_arr|odd_number_fill",
            "1.*\\+.*2.*\\*.*i.*lucky|lucky_step2_init",
            "lucky_sz.*=.*0.*i.*1.*i.*\\+=.*2|lucky_sieve_init"
        ),
        new PatternDef("lucky_sieve_step", "lucky_sieve_remove_step", "high",
            "step.*=.*arr.*k.*arr.*k.*\\+\\+|lucky_sieve_step_advance",
            "i.*\\+.*1.*%.*step.*!=.*0.*keep|lucky_sieve_filter",
            "new_sz.*lucky_arr.*new_sz.*\\+\\+|lucky_sieve_compact"
        ),
        new PatternDef("lucky_metric", "lucky_sieve_result_encode", "medium",
            "count.*<<.*16.*last.*0xFF.*<<.*8|lucky_pack_result",
            "arr.*i.*<=.*50|lucky_bound_filter",
            "count.*last.*checksum.*0xFF|lucky_checksum_encode"
        ),
        new PatternDef("palindrome_prime_check", "palindrome_prime_dual_test", "high",
            "is_prime.*is_palindrome|palindrome_prime_filter",
            "is_prime.*i.*&&.*is_palindrome.*i|combined_primality_palindrome",
            "palindrome_prime.*count|palindrome_prime_counter"
        ),
        new PatternDef("palindrome_reverse_digits", "palindrome_digit_reversal", "high",
            "reversed.*\\*.*10.*n.*%.*10|digit_reversal_loop",
            "original.*==.*reversed|palindrome_equality_check",
            "n.*/?=.*10.*reversed.*\\*=.*10|palindrome_reverse_extract"
        ),
        new PatternDef("palindrome_prime_metric", "palindrome_prime_result_encode", "medium",
            "count.*<<.*16.*last.*0xFF.*<<.*8|palindrome_prime_pack",
            "last.*=.*i.*is_prime.*is_palindrome|palindrome_prime_last_update",
            "count.*last.*checksum.*0xFFu|palindrome_prime_checksum"
        ),
        new PatternDef("berlekamp_massey_discrepancy", "bm_discrepancy_loop", "high",
            "d.*=.*d.*\\+.*MOD.*-.*C.*j.*\\*.*s.*i.*-.*j.*%.*MOD.*%.*MOD|bm_discrepancy_accum",
            "C.*j.*\\+.*delta.*=.*C.*j.*\\+.*delta.*\\+.*MOD.*-.*coeff.*\\*.*B.*j.*%.*MOD|bm_coeff_update",
            "2.*\\*.*L.*<=.*i|bm_length_double_check"
        ),
        new PatternDef("berlekamp_massey_field_ops", "bm_field_arithmetic", "high",
            "mod_pow.*base.*mod.*-.*2.*mod|bm_fermat_inverse",
            "d.*\\*.*mod_inv.*db.*BM_MOD|bm_discrepancy_normalize",
            "L.*=.*i.*\\+.*1.*-.*L|bm_lfsr_length_update"
        ),
        new PatternDef("berlekamp_massey_polynomial", "bm_recurrence_poly", "medium",
            "B.*j.*=.*T.*j|bm_save_poly_snapshot",
            "delta.*=.*1.*db.*=.*d|bm_reset_delta_after_grow",
            "lfsr_len.*last_s.*checksum|bm_result_encode"
        ),
        new PatternDef("aho_corasick_dp_failure", "acdp_failure_link_build", "high",
            "fail.*child.*=.*goto.*fail.*parent.*c|acdp_failure_link_assign",
            "accept.*s.*|=.*accept.*fail.*s|acdp_accept_propagate",
            "goto.*u.*c.*=.*goto.*fail.*u.*c|acdp_complete_automaton"
        ),
        new PatternDef("aho_corasick_dp_transition", "acdp_dp_step", "high",
            "ndp.*nxt.*\\+=.*dp.*s|acdp_dp_accumulate",
            "if.*accept.*s.*continue|acdp_skip_forbidden_state",
            "nxt.*=.*goto.*s.*c.*if.*!accept.*nxt|acdp_valid_transition"
        ),
        new PatternDef("aho_corasick_dp_count", "acdp_count_valid", "medium",
            "count.*\\+=.*dp.*s.*!accept.*s|acdp_sum_non_accepting",
            "AC_SLEN|acdp_string_length_constant",
            "count.*strlen_u.*checksum|acdp_result_encode"
        ),
        new PatternDef("two_sat_impl_graph", "tsi_implication_add", "high",
            "impl.*u.*\\^.*1.*impl_cnt.*u.*\\^.*1|tsi_negation_edge",
            "add_implication.*a.*\\^.*1.*b.*b.*\\^.*1.*a|tsi_clause_implications",
            "rimpl.*v.*rimpl_cnt.*v|tsi_reverse_graph"
        ),
        new PatternDef("two_sat_kosaraju", "tsi_kosaraju_scc", "high",
            "kos_ord.*kos_top\\+\\+.*=.*u|tsi_forward_order_push",
            "kos_comp.*u.*=.*comp.*dfs_backward|tsi_backward_assign",
            "for.*i.*=.*kos_top.*-.*1.*i.*>=.*0|tsi_reverse_order_iter"
        ),
        new PatternDef("two_sat_assignment", "tsi_truth_extract", "medium",
            "kos_comp.*2.*k.*>.*kos_comp.*2.*k.*\\+.*1|tsi_comp_order_assign",
            "assign_nib.*=.*assign_nib.*<<.*1.*|.*val|tsi_nibble_build",
            "n_vars.*assign_nib.*checksum|tsi_result_encode"
        ),
        new PatternDef("phi_inverse_sieve", "phi_inv_sieve_init", "high",
            "phi_sieve.*\\[i\\].*=.*i|.*for.*i.*<=.*PHI_LIMIT|phi_inv_init_range",
            "phi_sieve.*\\[j\\].*-=.*phi_sieve.*\\[j\\].*\\/.*i|phi_inv_prime_reduce",
            "phi_sieve.*\\[i\\].*==.*i.*phi_sieve.*\\[j\\]|phi_inv_prime_detect"
        ),
        new PatternDef("phi_inverse_collect", "phi_inv_collect_roots", "high",
            "phi_sieve.*\\[n\\].*==.*TARGET_M|phi_inv_match_target",
            "inv_count.*xor_vals.*\\^=.*n|phi_inv_accumulate_xor",
            "inv_count.*<<.*16.*xor_vals.*<<.*8.*checksum|phi_inv_result_encode"
        ),
        new PatternDef("phi_inverse_result", "phi_inv_encode", "medium",
            "phi_sieve.*\\[j\\].*-=.*phi_sieve.*\\[j\\].*\\/|phi_inv_euler_step",
            "for.*n.*1.*PHI_LIMIT.*phi_sieve.*n.*==|phi_inv_scan_range",
            "xor_vals.*n.*inv_count.*xor_vals.*checksum|phi_inv_pack_result"
        ),
        new PatternDef("happy_number_digit_sq", "hn_digit_sum_sq", "high",
            "d.*=.*n.*%.*10.*n.*\\/=.*10.*s.*\\+=.*d.*\\*.*d|hn_extract_digit_sq",
            "while.*n.*>.*0.*d.*=.*n.*%.*10|hn_digit_loop_body",
            "digit_sum_sq.*n.*while.*n.*!=.*1.*n.*!=.*4|hn_cycle_anchor"
        ),
        new PatternDef("happy_number_classify", "hn_is_happy_check", "high",
            "while.*n.*!=.*1.*&&.*n.*!=.*4.*n.*=.*digit_sum_sq|hn_happy_termination",
            "hn_count.*xor_happy.*\\^=.*i|hn_happy_accumulate",
            "is_happy.*i.*hn_count.*xor_happy|hn_range_classify"
        ),
        new PatternDef("happy_number_result", "hn_result_encode", "medium",
            "n.*!=.*1.*n.*!=.*4.*return.*n.*==.*1|hn_happy_return",
            "hn_count.*<<.*16.*xor_happy.*<<.*8.*checksum|hn_pack_result",
            "for.*i.*HN_LO.*HN_HI.*is_happy.*i|hn_iterate_range"
        ),
        new PatternDef("armstrong_digit_count", "arm_count_digits", "high",
            "do.*d\\+\\+.*tmp.*\\/=.*10.*while.*tmp.*>.*0|arm_digit_count_loop",
            "digits.*=.*count_digits.*n.*sum.*0.*tmp.*=.*n|arm_init_power_sum",
            "uint_pow.*d.*digits.*sum.*\\+=|arm_accumulate_power"
        ),
        new PatternDef("armstrong_classify", "arm_is_armstrong_check", "high",
            "sum.*==.*n.*is_armstrong|arm_self_match_test",
            "arm_count.*xor_arm.*\\^=.*i|arm_collect_xor",
            "for.*i.*ARM_LO.*ARM_HI.*is_armstrong.*i|arm_range_scan"
        ),
        new PatternDef("armstrong_result", "arm_result_encode", "medium",
            "result.*\\*=.*base.*for.*i.*0.*i.*<.*exp|arm_int_pow_loop",
            "xor_low.*=.*xor_arm.*&.*0xFF|arm_xor_low_byte",
            "arm_count.*<<.*16.*xor_low.*<<.*8.*checksum|arm_pack_result"
        ),
        new PatternDef("delannoy_dp_fill", "delannoy_table_fill", "high",
            "dp.*i.*0.*=.*1.*dp.*0.*j.*=.*1|delannoy_boundary_init",
            "dp.*i.*j.*=.*dp.*i.*-.*1.*j.*\\+.*dp.*i.*j.*-.*1.*\\+.*dp.*i.*-.*1.*j.*-.*1|delannoy_recurrence",
            "for.*i.*1.*i.*<=.*m.*for.*j.*1.*j.*<=.*n|delannoy_nested_loop"
        ),
        new PatternDef("delannoy_checksum", "delannoy_grid_checksum", "high",
            "for.*m.*1.*m.*<=.*4.*for.*n.*1.*n.*<=.*4|delannoy_grid_iter",
            "s.*\\+=.*delannoy_table.*m.*n.*|delannoy_sum_accum",
            "return.*s.*&.*0xFF|delannoy_checksum_mask"
        ),
        new PatternDef("delannoy_result", "delannoy_result_encode", "medium",
            "d33.*=.*delannoy_table.*3.*3|delannoy_d33_call",
            "metric_a.*=.*d33.*&.*0xFF|delannoy_metric_a",
            "n_tests.*<<.*16.*metric_a.*<<.*8.*metric_b|delannoy_pack_result"
        ),
        new PatternDef("motzkin_conv_sum", "motzkin_convolution_step", "high",
            "for.*k.*0.*k.*<=.*i.*-.*2.*s.*\\+=.*m.*k.*\\*.*m.*i.*-.*2.*-.*k|motzkin_convolution",
            "s.*=.*m.*i.*-.*1.*for.*k.*0|motzkin_step_init",
            "m.*i.*=.*s.*|motzkin_store_result"
        ),
        new PatternDef("motzkin_xor_check", "motzkin_xor_fingerprint", "high",
            "for.*i.*1.*i.*<=.*9.*x.*\\^=.*motzkin.*i|motzkin_xor_loop",
            "return.*x.*&.*0xFF|motzkin_xor_mask",
            "motzkin_xor_check.*void|motzkin_check_fn"
        ),
        new PatternDef("motzkin_result", "motzkin_result_encode", "medium",
            "m6.*=.*motzkin.*6.*m7.*=.*motzkin.*7|motzkin_m6_m7_eval",
            "metric_a.*=.*m6.*&.*0xFF|motzkin_metric_a",
            "n_tests.*<<.*16.*metric_a.*<<.*8.*metric_b|motzkin_pack_result"
        ),
        new PatternDef("digital_root_digit_sum", "digital_root_digit_sum_loop", "high",
            "while.*n.*>.*0.*s.*\\+=.*n.*%.*10.*n.*\\/=.*10|dr_digit_sum_loop",
            "return.*s.*digit_sum|dr_digit_sum_return",
            "uint32_t.*digit_sum.*uint32_t.*n|dr_digit_sum_sig"
        ),
        new PatternDef("digital_root_formula", "digital_root_formula_apply", "high",
            "if.*n.*==.*0.*return.*0|dr_zero_base_case",
            "return.*1.*\\+.*n.*-.*1.*%.*9|dr_mod9_formula",
            "uint32_t.*digital_root.*uint32_t.*n|dr_formula_sig"
        ),
        new PatternDef("digital_root_result", "digital_root_result_encode", "medium",
            "for.*i.*0.*i.*<.*n_tests.*dr_xor.*\\^=.*digital_root|dr_xor_loop",
            "persist_sum.*\\+=.*additive_persistence|dr_persist_accum",
            "n_tests.*<<.*16.*metric_a.*<<.*8.*metric_b|dr_pack_result"
        ),
        new PatternDef("schroeder_recurrence", "schroeder_recur_verify", "high",
            "6.*\\*.*n.*-.*3.*\\*.*s.*n.*-.*1|sch_coeff_a",
            "n.*-.*2.*\\*.*s.*n.*-.*2|sch_coeff_b",
            "lhs.*==.*rhs.*verify_count|sch_verify_loop"
        ),
        new PatternDef("schroeder_xor_checksum", "schroeder_xor_accum", "medium",
            "xor_acc.*\\^=.*s.*\\[.*n.*\\]|sch_xor_step",
            "metric_a.*verify_count.*0xFF|sch_metric_a",
            "g_result.*n_tests.*<<.*16.*metric_a.*<<.*8|sch_pack"
        ),
        new PatternDef("schroeder_boundary", "schroeder_boundary_check", "medium",
            "if.*metric_a.*==.*0.*metric_a.*=|sch_guard_a",
            "if.*metric_b.*==.*0.*metric_b.*=|sch_guard_b",
            "if.*metric_a.*==.*metric_b.*metric_b.*\\^=|sch_guard_neq"
        ),
        new PatternDef("narayana_pascal", "narayana_pascal_build", "high",
            "C.*n.*0.*=.*1.*C.*n.*k.*=.*C.*n.*-.*1.*k.*-.*1.*\\+.*C.*n.*-.*1.*k|nar_pascal_row",
            "for.*n.*0.*n.*<=.*10.*C.*n.*0.*=.*1|nar_pascal_outer",
            "C.*n.*k.*C.*n.*k.*-.*1.*\\/.*n|nar_narayana_formula"
        ),
        new PatternDef("narayana_peak_verify", "narayana_peak_check", "high",
            "if.*k.*==.*1.*v.*==.*1.*edge_ok|nar_left_edge",
            "if.*k.*==.*n.*v.*==.*1.*edge_ok|nar_right_edge",
            "row_sum.*==.*catalan.*n.*catalan_ok|nar_catalan_check"
        ),
        new PatternDef("narayana_result", "narayana_result_encode", "medium",
            "metric_a.*edge_ok.*&.*0xFF|nar_metric_edge",
            "metric_b.*catalan_ok.*&.*0xFF|nar_metric_catalan",
            "g_result.*n_tests.*<<.*16.*metric_a.*<<.*8.*metric_b|nar_pack"
        ),
        new PatternDef("bell_triangle", "bell_triangle_build", "high",
            "bell_prev.*0.*=.*bell_row.*r.*-.*1|bell_triangle_seed",
            "bell_prev.*c.*=.*bell_prev.*c.*-.*1.*\\+.*bell_row.*c.*-.*1|bell_triangle_step",
            "bell_row.*c.*=.*bell_prev.*c|bell_triangle_copy"
        ),
        new PatternDef("bell_verify", "bell_verify_known", "high",
            "uint32_t.*known.*10.*=.*1.*1.*2.*5.*15.*52|bell_known_table",
            "b.*==.*known.*i.*match_count\\+\\+|bell_match_check",
            "xor_acc.*\\^=.*b|bell_xor_accum"
        ),
        new PatternDef("bell_result", "bell_result_encode", "medium",
            "metric_a.*match_count.*&.*0xFF|bell_metric_match",
            "metric_b.*xor_acc.*\\^.*xor_acc.*>>.*16.*&.*0xFF|bell_metric_xor",
            "g_result.*n_tests.*<<.*16.*metric_a.*<<.*8.*metric_b|bell_pack"
        ),
        new PatternDef("burnside_polya_gcd_pow", "burnside_polya_gcd_pow", "high",
            "pow32.*k.*gcd32.*r.*n|burnside_fix_count",
            "total.*\\+=.*pow32.*k.*gcd32.*r.*n|burnside_orbit_sum",
            "total.*\\/.*n|burnside_necklace_divide"
        ),
        new PatternDef("burnside_polya_cases", "burnside_polya_verify", "high",
            "ns.*\\[5\\].*=.*4.*6.*5.*3.*8|burnside_n_table",
            "ks.*\\[5\\].*=.*3.*2.*3.*4.*2|burnside_k_table",
            "expected.*\\[5\\].*=.*24.*14.*51.*24.*36|burnside_expected_table"
        ),
        new PatternDef("burnside_polya_result", "burnside_polya_result_encode", "medium",
            "got.*==.*expected.*i.*match_count\\+\\+|burnside_match_check",
            "xor_acc.*\\^=.*got|burnside_xor_accum",
            "g_result.*n_tests.*<<.*16.*metric_a.*<<.*8.*metric_b|burnside_pack"
        ),
        new PatternDef("padovan_recurrence", "padovan_recurrence_build", "high",
            "pad_table.*i.*=.*pad_table.*i.*-.*2.*\\+.*pad_table.*i.*-.*3|padovan_step",
            "pad_table.*0.*=.*1.*pad_table.*1.*=.*1.*pad_table.*2.*=.*1|padovan_seed",
            "compute_padovan|padovan_compute_call"
        ),
        new PatternDef("padovan_verify", "padovan_verify_known", "high",
            "known.*PAD_N.*=.*1.*1.*1.*2.*2.*3.*4.*5.*7.*9|padovan_known_table",
            "pad_table.*i.*==.*known.*i.*match_count\\+\\+|padovan_match_check",
            "xor_acc.*\\^=.*pad_table.*i|padovan_xor_accum"
        ),
        new PatternDef("padovan_result", "padovan_result_encode", "medium",
            "metric_a.*match_count.*&.*0xFF|padovan_metric_match",
            "metric_b.*xor_acc.*\\^.*xor_acc.*>>.*16.*&.*0xFF|padovan_metric_xor",
            "g_result.*n_tests.*<<.*16.*metric_a.*<<.*8.*metric_b|padovan_pack"
        ),
        new PatternDef("colatz_iteration", "colatz_iteration_step", "high",
            "n.*&.*1.*n.*=.*3.*\\*.*n.*\\+.*1|colatz_odd_step",
            "n.*>>=.*1|colatz_even_step",
            "while.*n.*!=.*1.*steps\\+\\+|colatz_loop_count"
        ),
        new PatternDef("colatz_verify", "colatz_verify_known", "high",
            "known.*COLATZ_COUNT.*=.*0.*1.*7.*2.*5.*8.*16.*3.*19.*6|colatz_known_table",
            "s.*==.*known.*i.*match_count\\+\\+|colatz_match_check",
            "xor_acc.*\\^=.*s|colatz_xor_accum"
        ),
        new PatternDef("colatz_result", "colatz_result_encode", "medium",
            "metric_a.*match_count.*&.*0xFF|colatz_metric_match",
            "metric_b.*xor_acc.*\\^.*xor_acc.*>>.*16.*&.*0xFF|colatz_metric_xor",
            "g_result.*n_tests.*<<.*16.*metric_a.*<<.*8.*metric_b|colatz_pack"
        ),
        new PatternDef("pratt_mulmod", "pratt_mulmod32", "high",
            "result.*\\+=.*a.*if.*result.*>=.*m.*result.*-=.*m|pratt_mulmod_addshift",
            "a.*<<=.*1.*if.*a.*>=.*m.*a.*-=.*m|pratt_mulmod_doublemod",
            "b.*>>=.*1|pratt_mulmod_halfb"
        ),
        new PatternDef("pratt_powmod", "pratt_powmod32", "high",
            "result.*=.*mulmod.*result.*base.*m|pratt_powmod_square_accum",
            "base.*=.*mulmod.*base.*base.*m|pratt_powmod_base_square",
            "exp.*>>=.*1|pratt_powmod_expshift"
        ),
        new PatternDef("pratt_check", "pratt_certificate_verify", "high",
            "powmod.*a.*pm1.*p.*!=.*1.*return.*0|pratt_fermat_condition",
            "pm1.*\\/.*q.*powmod.*a.*pm1.*\\/.*q.*p.*==.*1.*return.*0|pratt_order_condition",
            "ok_count.*\\+=.*pratt_check|pratt_verify_accumulate"
        ),
        new PatternDef("powerful_spf", "powerful_smallest_prime_factor", "high",
            "d.*\\*.*d.*<=.*n.*n.*%.*d.*==.*0|powerful_trial_divide",
            "n.*\\/.*d.*%.*d.*!=.*0.*return.*0|powerful_exponent_check",
            "while.*n.*%.*d.*==.*0.*n.*\\/=.*d|powerful_consume_factor"
        ),
        new PatternDef("powerful_collect", "powerful_collect_upto", "medium",
            "is_powerful.*n.*out.*cnt\\+\\+|powerful_collect_loop",
            "r.*\\*.*r.*<.*v.*r\\+\\+|powerful_sqrt_iter",
            "r.*\\*.*r.*==.*v.*sq_count\\+\\+|powerful_square_count"
        ),
        new PatternDef("powerful_result", "powerful_result_encode", "medium",
            "metric_a.*sq_count.*&.*0xFF|powerful_metric_sq",
            "small_sum.*%.*251|powerful_metric_modprime",
            "g_result.*n_tests.*<<.*16.*metric_a.*<<.*8.*metric_b|powerful_pack"
        ),
        new PatternDef("semiprime_spf", "semiprime_smallest_prime_factor", "high",
            "n.*&.*1.*==.*0.*return.*2|semiprime_even_check",
            "d.*\\*.*d.*<=.*n.*n.*%.*d.*==.*0.*return.*d|semiprime_spf_loop",
            "return.*n.*prime_self|semiprime_spf_prime_return"
        ),
        new PatternDef("semiprime_detect", "semiprime_is_semiprime", "high",
            "f.*=.*spf.*n.*q.*=.*n.*\\/.*f|semiprime_factor_split",
            "is_prime.*q.*p1.*=.*f.*p2.*=.*q.*return.*1|semiprime_factor_assign",
            "sp_cnt\\+\\+.*factor_sum.*\\+=.*p1|semiprime_accumulate"
        ),
        new PatternDef("semiprime_result", "semiprime_result_encode", "medium",
            "sq_count.*p1.*==.*p2|semiprime_square_detect",
            "metric_b.*factor_sum.*&.*0xFF|semiprime_metric_factorsum",
            "g_result.*n_tests.*<<.*16.*metric_a.*<<.*8.*metric_b|semiprime_pack"
        ),
        new PatternDef("jacobsthal_recur", "jacobsthal_recurrence", "high",
            "j_cur.*j_prev1.*\\+.*2.*\\*.*j_prev2|jacobsthal_double_prev",
            "j_prev2.*=.*j_prev1.*j_prev1.*=.*j_cur|jacobsthal_shift",
            "term_sum.*\\+=.*j_cur.*xor_acc.*\\^=.*j_cur.*&.*0xFF|jacobsthal_accumulate"
        ),
        new PatternDef("jacobsthal_init", "jacobsthal_seed_values", "medium",
            "j_prev2.*=.*0.*j_prev1.*=.*1|jacobsthal_seed_01",
            "term_sum.*=.*j_prev1.*xor_acc.*=.*j_prev1.*&.*0xFF|jacobsthal_init_accum",
            "i.*=.*2.*i.*<=.*12|jacobsthal_loop_range"
        ),
        new PatternDef("jacobsthal_result", "jacobsthal_result_encode", "medium",
            "metric_a.*term_sum.*%.*251|jacobsthal_metric_modprime",
            "metric_b.*xor_acc.*&.*0xFF|jacobsthal_metric_xor",
            "g_result.*n_tests.*<<.*16.*metric_a.*<<.*8.*metric_b|jacobsthal_pack"
        ),
        new PatternDef("pell_lucas_recur", "pell_lucas_recurrence", "high",
            "q_cur.*=.*2.*\\*.*q_prev1.*\\+.*q_prev2|pell_lucas_double_plus",
            "q_prev2.*=.*q_prev1.*q_prev1.*=.*q_cur|pell_lucas_shift",
            "term_sum.*\\+=.*q_cur.*xor_acc.*\\^=.*q_cur.*&.*0xFF|pell_lucas_accumulate"
        ),
        new PatternDef("pell_lucas_init", "pell_lucas_seed_values", "medium",
            "q_prev2.*=.*2.*q_prev1.*=.*2|pell_lucas_seed_22",
            "term_sum.*=.*q_prev2.*\\+.*q_prev1|pell_lucas_init_sum",
            "i.*=.*2.*i.*<=.*10|pell_lucas_loop_range"
        ),
        new PatternDef("pell_lucas_result", "pell_lucas_result_encode", "medium",
            "metric_a.*term_sum.*%.*251|pell_lucas_metric_modprime",
            "metric_b.*xor_acc.*&.*0xFF|pell_lucas_metric_xor",
            "g_result.*n_tests.*<<.*16.*metric_a.*<<.*8.*metric_b|pell_lucas_pack"
        ),
        new PatternDef("perrin_recur", "perrin_recurrence", "high",
            "p\\[i\\].*=.*p\\[i.*-.*2\\].*\\+.*p\\[i.*-.*3\\]|perrin_three_term",
            "p\\[0\\].*=.*3.*p\\[1\\].*=.*0.*p\\[2\\].*=.*2|perrin_seed_302",
            "i.*=.*3.*i.*<.*13|perrin_loop_from3"
        ),
        new PatternDef("perrin_property", "perrin_prime_property", "medium",
            "term_sum.*\\+=.*p\\[i\\].*xor_acc.*\\^=.*p\\[i\\].*&.*0xFF|perrin_accumulate",
            "p\\[1\\].*=.*0|perrin_zero_term",
            "xor_acc.*\\^=.*p.*&.*0xFF|perrin_xor_loop"
        ),
        new PatternDef("perrin_result", "perrin_result_encode", "medium",
            "metric_a.*term_sum.*%.*251|perrin_metric_modprime",
            "metric_b.*xor_acc.*&.*0xFF|perrin_metric_xor",
            "g_result.*n_tests.*<<.*16.*metric_a.*<<.*8.*metric_b|perrin_pack"
        ),
        new PatternDef("kaprekar_digit_sort", "kaprekar_extract_digits", "high",
            "extract_digits|d\\[3\\].*1000.*d\\[2\\].*100.*d\\[1\\].*10.*d\\[0\\]|kaprekar_sort_desc",
            "big.*small.*d\\[3\\].*1000|d\\[0\\].*1000.*d\\[1\\].*100|kaprekar_bigsmall",
            "bubble.*sort.*ascending|d\\[j\\].*>.*d\\[j.*1\\].*tmp|kaprekar_bubblesort"
        ),
        new PatternDef("kaprekar_iteration", "kaprekar_routine_step", "high",
            "n.*!=.*6174.*steps.*<.*7|kaprekar_convergence_loop",
            "big.*-.*small|next.*big.*small|kaprekar_subtract",
            "kaprekar_steps|steps\\+\\+.*n.*==.*0.*steps.*=.*7|kaprekar_step_count"
        ),
        new PatternDef("kaprekar_result", "kaprekar_result_encode", "medium",
            "step_sum.*xor_acc|kaprekar_accumulate_steps",
            "metric_a.*step_sum.*&.*0xFF|kaprekar_metric_sum",
            "g_result.*n_tests.*<<.*16.*metric_a.*<<.*8.*metric_b|kaprekar_pack"
        ),
        new PatternDef("stern_diatomic_even", "stern_diatomic_even_rule", "high",
            "s\\[2.*i\\].*=.*s\\[i\\]|fusc_even_rule|stern_even_index",
            "s\\[2.*i.*1\\].*=.*s\\[i\\].*s\\[i.*1\\]|stern_odd_rule|fusc_odd_index",
            "for.*i.*1.*i.*<=.*10|stern_fill_loop"
        ),
        new PatternDef("stern_diatomic_sequence", "stern_diatomic_compute", "high",
            "s\\[0\\].*=.*0.*s\\[1\\].*=.*1|stern_seed_init",
            "2.*\\*.*i.*<=.*20|stern_even_bound_check",
            "2.*\\*.*i.*1.*<=.*20|stern_odd_bound_check"
        ),
        new PatternDef("stern_diatomic_result", "stern_diatomic_result_encode", "medium",
            "term_sum.*%.*251|stern_metric_modprime",
            "xor_acc.*\\^=.*s\\[i\\].*&.*0xFF|stern_xor_loop",
            "g_result.*n_tests.*<<.*16.*metric_a.*<<.*8.*metric_b|stern_pack"
        ),
        new PatternDef("recaman_subtract_rule", "recaman_step_rule", "high",
            "a\\[i\\].*=.*sub|a\\[i.*1\\].*>.*i.*sub.*<.*SEEN_SIZE.*!seen|recaman_go_back",
            "a\\[i\\].*=.*a\\[i.*1\\].*\\+.*i|recaman_go_forward",
            "seen\\[a\\[i\\]\\].*=.*1|recaman_mark_seen"
        ),
        new PatternDef("recaman_seen_array", "recaman_seen_tracking", "high",
            "seen\\[SEEN_SIZE\\]|uint8_t.*seen|recaman_visited_array",
            "seen\\[0\\].*=.*0|for.*i.*<.*SEEN_SIZE.*seen\\[i\\].*=.*0|recaman_seen_init",
            "sub.*<.*SEEN_SIZE.*!seen\\[sub\\]|recaman_check_visited"
        ),
        new PatternDef("recaman_result", "recaman_result_encode", "medium",
            "term_sum.*%.*251|recaman_metric_modprime",
            "xor_acc.*\\^=.*a\\[i\\].*&.*0xFF|recaman_xor_acc",
            "g_result.*n_tests.*<<.*16.*metric_a.*<<.*8.*metric_b|recaman_pack"
        ),

        // ── automorphic_numbers ───────────────────────────────────────────────
        new PatternDef("automorphic_check", "automorphic_squaremod", "high",
            "sq.*=.*n.*\\*.*n|automorphic_square_compute",
            "mod.*\\*=.*10|while.*tmp.*>.*0.*mod.*\\*=.*10|automorphic_power10",
            "sq.*%.*mod.*==.*n|return.*sq.*%.*mod.*==.*n|automorphic_endswith_check"
        ),
        new PatternDef("automorphic_digit_count", "automorphic_digitlen", "medium",
            "while.*tmp.*>.*0.*tmp.*\\/=.*10|automorphic_digit_loop",
            "d\\+\\+|digit_sum.*\\+=.*d|automorphic_count_digits",
            "is_automorphic.*i|for.*i.*<=.*limit.*is_automorphic|automorphic_scan_range"
        ),
        new PatternDef("automorphic_result", "automorphic_result_encode", "medium",
            "count.*&.*0xFF|out_count.*out_digit_sum|automorphic_metric_pack",
            "automorphic_compute.*limit|automorphic_compute.*10000|automorphic_driver",
            "g_result.*n_tests.*<<.*16.*metric_a.*<<.*8.*metric_b|automorphic_pack"
        ),

        // ── catalan_ballot_problem ────────────────────────────────────────────
        new PatternDef("ballot_comb", "ballot_comb_compute", "high",
            "result.*=.*result.*\\*.*\\(n.*-.*i\\).*\\/.*\\(i.*\\+.*1\\)|ballot_comb_iter",
            "if.*k.*>.*n.*-.*k.*k.*=.*n.*-.*k|ballot_comb_symmetry",
            "comb.*n.*b.*-.*comb.*n.*b.*-.*1|ballot_reflection_formula"
        ),
        new PatternDef("ballot_number", "ballot_number_compute", "high",
            "if.*a.*<=.*b.*return.*0|ballot_invalid_check",
            "total.*=.*a.*\\+.*b|ballot_total_votes",
            "comb.*total.*b.*-.*comb.*total.*b.*-.*1|ballot_path_count"
        ),
        new PatternDef("ballot_result", "ballot_result_encode", "medium",
            "pairs\\[8\\]\\[2\\]|ballot_test_pairs",
            "xor_acc.*\\^=.*bn|sum.*\\+=.*bn|ballot_accumulate",
            "g_result.*n_tests.*<<.*16.*metric_a.*<<.*8.*metric_b|ballot_pack"
        ),

        // ── fuss_catalan ──────────────────────────────────────────────────────
        new PatternDef("fuss_catalan_compute", "fuss_catalan_formula", "high",
            "n.*=.*\\(p.*\\+.*1\\).*\\*.*m|fuss_catalan_nn_compute",
            "denom.*=.*p.*\\*.*m.*\\+.*1|fuss_catalan_denominator",
            "comb.*n.*m.*\\/.*denom|fuss_catalan_divide"
        ),
        new PatternDef("fuss_catalan_enum", "fuss_catalan_loop", "high",
            "for.*p.*=.*1.*p.*<=.*3|fuss_catalan_p_range",
            "for.*m.*=.*0.*m.*<=.*4|fuss_catalan_m_range",
            "fc.*=.*fuss_catalan.*p.*m|fuss_catalan_call"
        ),
        new PatternDef("fuss_catalan_result", "fuss_catalan_result_encode", "medium",
            "xor_acc.*\\^=.*fc|sum.*\\+=.*fc|fuss_catalan_accumulate",
            "n_tests.*=.*15|fuss_catalan_test_count",
            "g_result.*n_tests.*<<.*16.*metric_a.*<<.*8.*metric_b|fuss_catalan_pack"
        ),
        new PatternDef("sylvester_recurrence", "sylvester_step_formula", "high",
            "prev.*\\*.*prev.*-.*1.*\\+.*1|a_n.*=.*a_prev.*sq_minus|sylvester_recurrence",
            "out\\[i\\].*=.*prev.*\\*.*prev.*-.*1.*%.*MOD|sylvester_mod_step",
            "out\\[0\\].*=.*2|sylvester_seed"
        ),
        new PatternDef("sylvester_odd_count", "sylvester_parity_check", "medium",
            "seq\\[i\\].*&.*1U|sylvester_odd_test",
            "count\\+\\+.*odd|odd_count.*sylvester",
            "sum.*odd_count.*&.*0xFF|sylvester_metric_a"
        ),
        new PatternDef("sylvester_result", "sylvester_result_encode", "medium",
            "xor_acc.*\\^=.*seq\\[i\\]|sum.*\\+=.*seq\\[i\\]|sylvester_accumulate",
            "n_tests.*=.*12|sylvester_test_count",
            "g_result.*n_tests.*<<.*16.*metric_a.*<<.*8.*metric_b|sylvester_pack"
        ),
        new PatternDef("golomb_recurrence", "golomb_self_describe_step", "high",
            "1.*\\+.*golomb_seq\\[idx\\]|golomb_step_formula",
            "inner.*=.*golomb_seq\\[i.*-.*1\\]|golomb_inner_lookup",
            "outer.*=.*golomb_seq\\[inner\\]|golomb_outer_lookup"
        ),
        new PatternDef("golomb_self_check", "golomb_self_describe_verify", "high",
            "golomb_count_value.*v.*GOLOMB_N.*==.*golomb_seq\\[v\\]|golomb_verify",
            "count.*golomb_seq\\[i\\].*times|golomb_occurrence_count",
            "correct\\+\\+|golomb_correct_count"
        ),
        new PatternDef("golomb_result", "golomb_result_encode", "medium",
            "xor_acc.*\\^=.*golomb_seq\\[i\\]|sum.*\\+=.*golomb_seq|golomb_accumulate",
            "n_tests.*=.*32|golomb_test_count",
            "g_result.*n_tests.*<<.*16.*metric_a.*<<.*8.*metric_b|golomb_pack"
        ),
        new PatternDef("vdc_digit_reflect", "vdc_base_digit_reverse", "high",
            "digit.*=.*n.*%.*base|n.*\\/=.*base|vdc_digit_extract",
            "num.*=.*num.*\\*.*base.*\\+.*digit|vdc_reflect_accumulate",
            "denom.*\\*=.*base|vdc_denom_shift"
        ),
        new PatternDef("vdc_fixed_point", "vdc_fixed_point_scale", "high",
            "num.*\\*.*SCALE.*\\/.*denom|vdc_fixed_divide",
            "vdc_fixed.*i.*\\+.*1.*2|vdc_base2_call",
            "vdc_fixed.*i.*\\+.*1.*3|vdc_base3_call"
        ),
        new PatternDef("vdc_result", "vdc_result_encode", "medium",
            "sum2.*\\+=.*vdc2|sum3.*\\+=.*vdc3|vdc_sum_accumulate",
            "xor_acc.*\\^=.*vdc2.*\\^.*vdc3|vdc_xor_combine",
            "g_result.*n_tests.*<<.*16.*metric_a.*<<.*8.*metric_b|vdc_pack"
        ),
        new PatternDef("leonardo_recurrence", "leo_recurrence_step", "high",
            "leo.*\\[.*i.*\\].*=.*leo.*\\[.*i.*-.*1.*\\].*\\+.*leo.*\\[.*i.*-.*2.*\\].*\\+.*1|leo_next_val",
            "leo_table.*\\[0\\].*=.*1|leo_init_zero",
            "leo_table.*%.*3.*==.*0|leo_div3_check"
        ),
        new PatternDef("leonardo_smoothsort", "leo_smoothsort_shape", "medium",
            "leo.*\\[.*i.*-.*1u\\].*\\+.*leo.*\\[.*i.*-.*2u\\].*\\+.*1u|leo_offset_recur",
            "leonardo_build|leo_build_table",
            "leonardo_sum_below|leo_partial_sum"
        ),
        new PatternDef("leonardo_result", "leo_result_pack", "medium",
            "count_div3.*\\+\\+|leo_div3_count",
            "xor_div3.*\\^=.*leo_table|leo_xor_accum",
            "LEO_N.*<<.*16.*count_div3.*<<.*8.*xor_div3|leo_pack"
        ),
        new PatternDef("hofstadter_g", "hofstadter_g_lookup", "high",
            "hof_G.*\\[.*i.*\\].*=.*i.*-.*hof_G.*\\[.*hof_G.*\\[.*i.*-.*1.*\\].*\\]|hofg_double_index",
            "hof_G.*\\[0\\].*=.*0|hofg_base_case",
            "hof_G.*\\[.*hof_G.*\\[.*i.*-.*1u.*\\].*\\]|hofg_nested_lookup"
        ),
        new PatternDef("hofstadter_h", "hofstadter_h_lookup", "high",
            "hof_H.*\\[.*i.*\\].*=.*i.*-.*hof_H.*\\[.*tmp2.*\\]|hofh_triple_index",
            "tmp1.*=.*hof_H.*\\[.*i.*-.*1u.*\\]|hofh_tmp_chain",
            "tmp2.*=.*hof_H.*\\[.*tmp1.*\\]|hofh_second_deref"
        ),
        new PatternDef("hofstadter_result", "hofstadter_result_pack", "medium",
            "g_fixed.*\\+\\+|hofstadter_fixed_count",
            "g_sum.*\\+=.*hof_G|hofstadter_sum_accum",
            "HOF_N.*<<.*16.*g_fixed.*<<.*8.*g_sum|hofstadter_pack"
        ),
        new PatternDef("rudin_shapiro_pairs", "rs_pair_count", "high",
            "\\(.*n.*&.*3u.*\\).*==.*3u.*pairs\\+\\+|rs_consec_pair_check",
            "rs_pair_count.*n.*>.*1u|rs_pair_loop",
            "pairs.*&.*1u.*==.*0u|rs_parity_check"
        ),
        new PatternDef("rudin_shapiro_prefix", "rs_prefix_sum", "medium",
            "rudin_shapiro.*i.*s.*\\+=|rs_prefix_accum",
            "rs_prefix_sum.*limit|rs_prefix_call",
            "pos_count.*\\+\\+.*sum_pos.*\\+=.*i|rs_positive_index_sum"
        ),
        new PatternDef("rudin_shapiro_result", "rs_result_pack", "medium",
            "sum_pos.*\\+=.*i|rs_sum_pos_accum",
            "RS_N.*<<.*16.*pos_count.*<<.*8.*sum_pos|rs_pack",
            "rudin_shapiro.*pair_count.*&.*1u|rs_sign_map"
        ),
        // ── Thue-Morse sequence ──────────────────────────────────────────────
        new PatternDef("thue_morse_bittrick", "tm_parity_bittrick", "high",
            "x\\s*\\^=\\s*\\(x\\s*>>\\s*16\\)|tm_xor_fold16",
            "x\\s*\\^=\\s*\\(x\\s*>>\\s*[48]\\)|tm_xor_fold_byte",
            "x\\s*&\\s*1u|tm_parity_extract"
        ),
        new PatternDef("thue_morse_recurrence", "tm_recurrence", "high",
            "t\\s*\\^=\\s*\\(n\\s*&\\s*1u\\)|tm_bit_xor_accum",
            "while.*n\\s*>\\s*0u.*n\\s*>>=\\s*1|tm_shift_loop",
            "thue_morse_rec|tm_rec_call"
        ),
        new PatternDef("thue_morse_count", "tm_count_pack", "medium",
            "thue_morse.*count\\+\\+|tm_count_ones",
            "sum\\s*\\+=\\s*i.*thue_morse|tm_sum_indices",
            "TM_N\\s*<<\\s*16.*count\\s*<<\\s*8|tm_pack_result"
        ),
        // ── Baum-Sweet sequence ───────────────────────────────────────────────
        new PatternDef("baum_sweet_scanner", "bs_zero_run_scan", "high",
            "in_zero.*run_len|bs_zero_run_state",
            "run_len\\s*&\\s*1u.*return\\s*0u|bs_odd_run_reject",
            "bit\\s*==\\s*0u.*in_zero|bs_zero_bit_accum"
        ),
        new PatternDef("baum_sweet_check", "bs_check", "high",
            "baum_sweet.*if.*in_zero.*run_len|bs_run_exit_check",
            "tmp\\s*>>=\\s*1.*bit\\s*=.*tmp\\s*&\\s*1u|bs_bit_shift_scan",
            "if.*n\\s*==\\s*0u.*return\\s*1u|bs_zero_base_case"
        ),
        new PatternDef("baum_sweet_count", "bs_count_pack", "medium",
            "baum_sweet.*count\\+\\+.*xor_idx|bs_count_xor",
            "xor_idx\\s*\\^=\\s*i.*baum_sweet|bs_xor_accum",
            "BS_N\\s*<<\\s*16.*count\\s*<<\\s*8.*xor_idx|bs_pack_result"
        ),
        // ── Regular Paper Folding sequence ────────────────────────────────────
        new PatternDef("paperfolding_adic", "pf_2adic_strip", "high",
            "while.*m\\s*&\\s*1u.*==\\s*0u.*m\\s*>>=\\s*1|pf_strip_twos",
            "m\\s*&\\s*3u.*==\\s*1u|pf_mod4_check",
            "paperfolding.*odd.*part|pf_odd_factor"
        ),
        new PatternDef("paperfolding_classify", "pf_valley_mountain", "high",
            "return.*m\\s*&\\s*3u.*==\\s*1u.*1u.*0u|pf_classify",
            "PF_N.*count.*xor_idx|pf_accum_loop",
            "paperfolding.*count\\+\\+.*xor_idx\\s*\\^=\\s*i|pf_count_xor"
        ),
        new PatternDef("paperfolding_result", "pf_result_pack", "medium",
            "PF_N\\s*<<\\s*16.*count\\s*<<\\s*8.*xor_idx|pf_pack",
            "xor_idx\\s*\\^=\\s*i.*paperfolding|pf_xor_accum",
            "count.*17.*xor.*40|pf_expected_vals"
        ),
        // ── Kolakoski sequence ────────────────────────────────────────────────
        new PatternDef("kolakoski_self_ref_fill", "kol_self_ref_run", "high",
            "buf\\[len\\+\\+\\]\\s*=\\s*sym.*buf\\[i\\]|kol_self_ref_emit",
            "for.*j.*<.*buf\\[i\\].*buf\\[len\\+\\+\\]\\s*=\\s*sym|kol_run_fill_loop",
            "kolakoski.*run.*buf\\[i\\]|kol_run_len_read"
        ),
        new PatternDef("kolakoski_sym_toggle", "kol_sym_toggle", "high",
            "sym\\s*=\\s*3u?\\s*-\\s*sym|kol_toggle_1_2",
            "sym\\s*==\\s*1u?.*sym\\s*==\\s*2u?|kol_sym_alt",
            "kolakoski.*3\\s*-\\s*sym|kol_toggle_expr"
        ),
        new PatternDef("kolakoski_count_pack", "kol_count_pack", "medium",
            "count_ones\\+\\+.*xor_ones\\s*\\^=.*i.*1u?|kol_accum",
            "KOL_N\\s*<<\\s*16.*count_ones\\s*<<\\s*8.*xor_ones|kol_pack_result",
            "kolakoski.*count.*20.*xor.*18|kol_expected_vals"
        ),
        // ── Gijswijt's sequence ───────────────────────────────────────────────
        new PatternDef("gijswijt_tail_rep", "gij_tail_rep_scan", "high",
            "tail_rep.*seq.*m.*L|gij_rep_count_fn",
            "base\\s*=\\s*m\\s*-\\s*needed.*ref\\s*=\\s*m\\s*-\\s*L|gij_block_ptrs",
            "gijswijt.*rep\\+\\+.*match|gij_rep_loop"
        ),
        new PatternDef("gijswijt_next_term", "gij_next_term", "high",
            "gijswijt_next.*seq.*m|gij_next_fn",
            "for.*L\\s*=\\s*m.*L\\s*>=\\s*1u?.*L--|gij_outer_scan",
            "best\\s*<\\s*r.*best\\s*=\\s*r|gij_best_update"
        ),
        new PatternDef("gijswijt_count_pack", "gij_count_pack", "medium",
            "count_ones\\+\\+.*xor_ones\\s*\\^=.*i.*1u?.*gij|gij_accum",
            "GIJ_N\\s*<<\\s*16.*count_ones\\s*<<\\s*8.*xor_ones|gij_pack_result",
            "gijswijt.*count.*14.*xor.*13|gij_expected_vals"
        ),
        // ── Sierpinski triangle (Pascal mod 2) ────────────────────────────────
        new PatternDef("sierpinski_lucas_test", "sier_lucas_bitmask", "high",
            "k\\s*&\\s*n\\s*\\)\\s*==\\s*k|sier_submask_check",
            "for.*n.*<=.*SIER_N.*for.*k.*<=.*n.*k\\s*&\\s*n|sier_nested_loop",
            "sierpinski.*lucas.*mod.*2|sier_lucas_theorem"
        ),
        new PatternDef("sierpinski_odd_accum", "sier_odd_count_xor", "high",
            "total_odd\\+\\+.*xor_k\\s*\\^=\\s*k|sier_odd_accum",
            "if.*k.*&.*n.*==.*k.*total_odd|sier_accum_branch",
            "sierpinski.*total_odd.*xor_k|sier_dual_accum"
        ),
        new PatternDef("sierpinski_result_pack", "sier_result_pack", "medium",
            "SIER_N\\s*<<\\s*16.*total_odd\\s*<<\\s*8.*xor_k|sier_pack_result",
            "total_odd.*65.*xor_k.*15|sier_expected_vals",
            "sierpinski.*0x41.*0x0f|sier_byte_check"
        ),
        // ── Rabbit/Fibonacci sequence ─────────────────────────────────────────
        new PatternDef("rabbit_fib_recurrence", "rabbit_fib_two_var_recurrence", "high",
            "seq\\[i\\]\\s*=\\s*seq\\[i\\s*-\\s*1u?\\]\\s*\\+\\s*seq\\[i\\s*-\\s*2u?\\]|rf_array_fill",
            "seq\\[0\\]\\s*=\\s*1u?.*seq\\[1\\]\\s*=\\s*1u?|rf_seed_vals",
            "rabbit_fibonacci.*RF_N|rf_init_loop"
        ),
        new PatternDef("rabbit_fib_even_count", "rabbit_fib_even_detector", "high",
            "seq\\[i\\]\\s*&\\s*1u?\\s*\\)\\s*==\\s*0u?.*count_even|rf_even_detect",
            "count_even\\+\\+.*xor_even_idx\\s*\\^=|rf_dual_accum",
            "rabbit_fibonacci.*count_even.*xor_even_idx|rf_accum_loop"
        ),
        new PatternDef("rabbit_fib_result_pack", "rabbit_fib_result_pack", "medium",
            "RF_N\\s*<<\\s*16.*count_even\\s*<<\\s*8.*xor_even_idx|rf_pack_result",
            "count_even.*10.*xor_even_idx.*70|rf_expected_vals",
            "rabbit_fibonacci.*0x1e.*0x0a.*0x46|rf_byte_check"
        ),
        // ── Dragon curve (paper folding sequence) ─────────────────────────────
        new PatternDef("dragon_strip_zeros", "dragon_curve_v2_valuation", "high",
            "while\\s*\\(\\s*\\(\\s*n\\s*&\\s*1u?\\s*\\)\\s*==\\s*0u?\\s*\\).*n\\s*>>=\\s*1|dc_strip_zeros",
            "n\\s*>>=\\s*1.*\\(\\s*n\\s*&\\s*1u?\\s*\\)\\s*==\\s*0u?.*1u?.*0u?|dc_advance_check",
            "dragon_term.*dragon_curve.*DC_N|dc_term_fn"
        ),
        new PatternDef("dragon_ones_xor", "dragon_curve_position_xor", "high",
            "count_ones\\+\\+.*xor_pos\\s*\\^=.*i.*0xFFu?|dc_pos_xor_accum",
            "for.*i\\s*=\\s*1u?.*i\\s*<=\\s*DC_N.*dragon_term|dc_main_loop",
            "dragon_curve.*count_ones.*xor_pos|dc_accum_vars"
        ),
        new PatternDef("dragon_result_pack", "dragon_curve_result_pack", "medium",
            "DC_N\\s*<<\\s*16.*count_ones\\s*<<\\s*8.*xor_pos|dc_pack_result",
            "count_ones.*17.*xor_pos.*40|dc_expected_vals",
            "dragon_curve.*0x20.*0x11.*0x28|dc_byte_check"
        ),
        // ── Pascal's triangle mod p (Lucas's theorem) ─────────────────────────
        new PatternDef("pascal_mod_lucas_check", "pascal_mod_lucas_digit_check", "high",
            "k\\s*%\\s*PT_P\\s*\\)\\s*>\\s*\\(\\s*n\\s*%\\s*PT_P|ptm_lucas_digit",
            "while\\s*\\(\\s*k\\s*>\\s*0u?\\s*\\).*k\\s*%.*PT_P.*n\\s*%.*PT_P|ptm_lucas_loop",
            "lucas_nonzero.*pascal_triangle_mod|ptm_lucas_fn"
        ),
        new PatternDef("pascal_mod_triangle_scan", "pascal_mod_double_loop_scan", "high",
            "for.*n.*<.*PT_N.*for.*k.*<=.*n.*lucas_nonzero|ptm_triangle_loop",
            "count_nonzero\\+\\+.*xor_nk\\s*\\^=.*n.*k.*0xFFu?|ptm_xor_accum",
            "pascal_triangle_mod.*count_nonzero.*xor_nk|ptm_accum_vars"
        ),
        new PatternDef("pascal_mod_result_pack", "pascal_mod_result_pack", "medium",
            "PT_N\\s*<<\\s*16.*count_nonzero\\s*<<\\s*8.*xor_nk|ptm_pack_result",
            "count_nonzero.*117.*xor_nk.*26|ptm_expected_vals",
            "pascal_triangle_mod.*0x14.*0x75.*0x1a|ptm_byte_check"
        ),
        new PatternDef("isqrt_newton_iterate", "isqrt_newton_heron_step", "high",
            "isqrt_newton|heron.*iter|newton.*sqrt.*convergence",
            "x\\s*=\\s*y.*y\\s*=.*x\\s*\\+.*n\\s*/\\s*x.*>>\\s*1|newton_sqrt_loop",
            "while.*y\\s*<\\s*x.*x\\s*=\\s*y|isqrt_converge_check"
        ),
        new PatternDef("isqrt_perfect_square_check", "isqrt_perfect_square_detector", "high",
            "r\\s*\\*\\s*r\\s*==\\s*i|count_perfect.*isqrt|perfect_square_count",
            "isqrt_newton.*count_perfect|sum_roots.*count_perfect",
            "isqrt.*for.*i.*n_tests.*r.*r.*==.*i|isqrt_scan_loop"
        ),
        new PatternDef("isqrt_result_pack", "isqrt_result_pack", "medium",
            "n_tests\\s*<<\\s*16.*count_perfect\\s*<<\\s*8.*sum_roots|isqrt_pack_result",
            "count_perfect.*4.*sum_roots.*54|isqrt_expected_vals",
            "0x140436|isqrt_newton.*0x14.*0x04.*0x36|isqrt_byte_check"
        ),
        new PatternDef("champernowne_digit_extract", "champernowne_digit_extractor", "high",
            "champernowne_fill|champ_buf|tmp.*%\\s*10.*v\\s*/=\\s*10",
            "do.*tmp.*len.*v\\s*%\\s*10.*v\\s*/=\\s*10.*while.*v.*>.*0|champ_digit_loop",
            "champernowne.*reverse.*tmp.*most_significant|champ_reverse_step"
        ),
        new PatternDef("champernowne_count_ones", "champernowne_ones_counter", "high",
            "count_ones|champ_buf.*==\\s*1.*count_ones|champernowne.*digit.*one",
            "sum_digits.*count_ones.*champ_buf|champernowne_accum",
            "for.*CHAMP_N.*champ_buf.*==\\s*1|champ_scan_loop"
        ),
        new PatternDef("champernowne_result_pack", "champernowne_result_pack", "medium",
            "CHAMP_N\\s*<<\\s*16.*count_ones\\s*<<\\s*8.*sum_digits|champ_pack_result",
            "count_ones.*8.*sum_digits.*61|champ_expected_vals",
            "0x14083D|champernowne.*0x14.*0x08.*0x3D|champ_byte_check"
        ),
        new PatternDef("zeckendorf_greedy_subtract", "zeckendorf_greedy_step", "high",
            "zeckendorf_count|zeck_fibs|zeckendorf.*greedy.*fibonacci",
            "while.*n.*>.*0.*i.*>=.*0.*zeck_fibs.*i.*>.*n.*i--|zeck_greedy_loop",
            "n\\s*-=\\s*zeck_fibs.*count\\+\\+.*i--|zeckendorf_term_subtract"
        ),
        new PatternDef("zeckendorf_bits_scan", "zeckendorf_bits_scanner", "high",
            "sum_bits.*max_bits.*zeckendorf|zeckendorf_count.*sum_bits",
            "for.*n_tests.*b.*=.*zeckendorf_count.*sum_bits.*\\+=.*b|zeck_scan_loop",
            "b.*>.*max_bits.*max_bits.*=.*b|zeck_max_update"
        ),
        new PatternDef("zeckendorf_result_pack", "zeckendorf_result_pack", "medium",
            "n_tests\\s*<<\\s*16.*sum_bits\\s*<<\\s*8.*max_bits|zeck_pack_result",
            "sum_bits.*25.*max_bits.*3|zeck_expected_vals",
            "0x0F1903|zeckendorf.*0x0F.*0x19.*0x03|zeck_byte_check"
        ),
        new PatternDef("copeland_erdos_digit_scan", "copeland_erdos_digit_scanner", "high",
            "digit_count.*prime|ce_primes.*digit|get_digit.*nd",
            "for.*di.*<.*nd.*get_digit|copeland_digit_loop",
            "even.*digit|d.*&.*1.*even_count|ce_even_digit_check"
        ),
        new PatternDef("copeland_erdos_prime_concat", "copeland_erdos_prime_concat", "high",
            "ce_primes|copeland.*prime.*concat|prime_digit_sequence",
            "total_digits.*\\+.*nd|total_digits.*digit_count|ce_total_accumulate",
            "even_count.*\\+\\+|copeland.*even.*inc|ce_even_increment"
        ),
        new PatternDef("copeland_erdos_result_pack", "copeland_erdos_result_pack", "medium",
            "n_primes\\s*<<\\s*16.*total_digits\\s*<<\\s*8.*even_count|ce_pack_result",
            "total_digits.*16.*even_count.*3|ce_expected_vals",
            "0x0A1003|copeland.*0x0A.*0x10.*0x03|ce_byte_check"
        ),
        new PatternDef("moser_de_bruijn_base4_check", "moser_de_bruijn_base4_check", "high",
            "n\\s*&\\s*3.*>\\s*1|base4_digit.*>.*1|mdb_base4_test",
            "while.*n.*>.*0.*n.*>>=.*2|mdb_base4_scan",
            "is_mdb|moser.*de.*bruijn.*check|mdb_membership"
        ),
        new PatternDef("moser_de_bruijn_generate", "moser_de_bruijn_generator", "high",
            "found.*<.*n_terms.*is_mdb|mdb_collect_terms",
            "sum_terms.*\\+.*i.*xor_terms.*\\^.*i|mdb_accumulate",
            "xor_terms|moser.*xor.*terms|mdb_xor_track"
        ),
        new PatternDef("moser_de_bruijn_result_pack", "moser_de_bruijn_result_pack", "medium",
            "n_terms\\s*<<\\s*16.*sum_terms.*0xFF.*<<\\s*8.*xor_terms|mdb_pack_result",
            "sum_terms.*430.*xor_terms.*80|mdb_expected_vals",
            "0x0CAE50|moser.*0x0C.*0xAE.*0x50|mdb_byte_check"
        ),
        new PatternDef("sum_of_squares_legendre", "sum_of_squares_legendre_check", "high",
            "n.*%.*8.*==.*7|needs_four_squares|legendre.*8b.*7",
            "while.*n.*%.*4.*==.*0.*n.*>>=.*2|four_square_strip",
            "n.*%.*8.*7.*return.*4|sum_sq_four_path"
        ),
        new PatternDef("sum_of_squares_min_classify", "sum_of_squares_classifier", "high",
            "is_perfect_square|min_squares|sum_of_two_squares",
            "if.*ms.*==.*1.*c1|if.*ms.*==.*4.*c4|sum_sq_count",
            "is_sum_of_two_squares|sum_sq_two_check|a.*\\*.*a.*<=.*n"
        ),
        new PatternDef("sum_of_squares_result_pack", "sum_of_squares_result_pack", "medium",
            "n_tests\\s*<<\\s*16.*c1\\s*<<\\s*8.*c4|sum_sq_pack_result",
            "c1.*4.*c4.*2|sum_sq_expected_vals",
            "0x140402|sum_of_squares.*0x14.*0x04.*0x02|sum_sq_byte_check"
        ),
        new PatternDef("digit_dp_count_zeros_state", "digit_dp_count_zeros", "high",
            "extract_digits|dp_count|dp_sum|has_zero|tight",
            "digit_dp_solve|count_zeros_in_range|zero_digit_dp",
            "num_so_far.*10.*d|pos.*tight.*has_zero|digit_dp_leaf"
        ),
        new PatternDef("digit_dp_count_zeros_accumulate", "digit_dp_count_zeros_acc", "high",
            "total_count.*dp_count|total_sum.*dp_sum|accumulate_dp_states",
            "sum_mod.*0xFF|sq.*64.*count.*10|zero_digit_accumulate",
            "n_tests.*100|upper.*100|digit_dp_count_upper"
        ),
        new PatternDef("digit_dp_count_zeros_pack", "digit_dp_count_zeros_pack", "medium",
            "n_tests\\s*<<\\s*16.*total_count\\s*<<\\s*8.*sum_mod|digit_dp_pack",
            "0x640A26|count.*10.*sum_mod.*38|digit_dp_zero_result",
            "upper.*100.*count.*10|digit_dp.*0x64.*0x0A.*0x26"
        ),
        new PatternDef("catalan_triangle_build", "catalan_triangle", "high",
            "cat_tri|catalan_triangle|ballot_triangle",
            "T\\[n\\]\\[0\\].*1|cat_tri.*k-1.*n-1|catalan_recurrence",
            "T.*n.*k.*T.*n.*k.*minus.*1.*T.*n.*minus.*1.*k|catalan_tri_fill"
        ),
        new PatternDef("catalan_triangle_sum", "catalan_triangle_sum", "high",
            "grand_total.*cat_tri|sum_catalan_rows|catalan_grand_sum",
            "max_row5.*cat_tri.*5.*5|catalan_max_entry",
            "grand_total.*625|grand_total_mod.*113|catalan_row_sum_check"
        ),
        new PatternDef("catalan_triangle_pack", "catalan_triangle_pack", "medium",
            "n_tests\\s*<<\\s*16.*grand_total_mod\\s*<<\\s*8.*max_row5|catalan_tri_pack",
            "0x07712A|0x7712a|grand_total_mod.*113.*max_row5.*42",
            "n_tests.*7.*grand_total.*625|catalan_result_check"
        ),
        new PatternDef("squares_of_fibonacci_check", "squares_of_fibonacci", "high",
            "is_fibonacci|fib_table|sq.*f.*f|fibonacci_square",
            "f.*fibs.*k.*sq.*f.*f|fib_squared_check",
            "sq_sum.*sq|count.*is_fibonacci.*sq|fib_sq_accumulate"
        ),
        new PatternDef("squares_of_fibonacci_identity", "squares_of_fibonacci_id", "high",
            "fib_table.*20|FIB_TABLE_SIZE|fibonacci_square_table",
            "fibs.*1.*1.*2.*3.*5.*8|fib_first10|fibonacci_sq_input",
            "sq_sum.*4895|sum_mod.*31|fib_sq_sum_check"
        ),
        new PatternDef("squares_of_fibonacci_pack", "squares_of_fibonacci_pack", "medium",
            "n_tests\\s*<<\\s*16.*count\\s*<<\\s*8.*sum_mod|fib_sq_pack",
            "0x0A021F|count.*2.*sum_mod.*31|fib_sq_result",
            "n_tests.*10.*count.*2|squares_fibonacci.*0x0A.*0x02.*0x1F"
        ),
        new PatternDef("binary_carry_sequence_core", "binary_carry_seq", "high",
            "trailing_ones|trailing.*1.*bits|carries.*add.*1.*binary",
            "while.*v.*&.*1.*cnt\\+\\+.*v.*>>=|trailing_1_count",
            "bcs_sum|bcs_xor|binary_carry.*accumulate"
        ),
        new PatternDef("binary_carry_sequence_range", "binary_carry_range", "high",
            "BCS_N.*12|n.*1.*BCS_N|carry_seq_loop",
            "bcs_sum.*10|bcs_xor.*2|binary_carry.*0x0C0A02",
            "i.*1.*BCS_N.*trailing_ones|carry_seq_sum_xor"
        ),
        new PatternDef("binary_carry_sequence_pack", "binary_carry_pack", "medium",
            "BCS_N\\s*<<\\s*16.*bcs_sum.*<<.*8.*bcs_xor|carry_pack",
            "0x0C0A02|BCS_N.*12.*sum.*10.*xor.*2|binary_carry_result",
            "g_result.*0x0C.*0x0A.*0x02|bcs_g_result"
        ),
        new PatternDef("primes_arith_prog_core", "primes_arith_prog", "high",
            "AP_FIRST.*AP_STEP|ap_first.*ap_step|arithmetic_progression_prime",
            "val.*AP_FIRST.*i.*AP_STEP|val.*5.*i.*6|ap_generate",
            "is_prime_trial|trial_div.*ap|prime_ap_filter"
        ),
        new PatternDef("primes_arith_prog_dirichlet", "primes_ap_dirichlet", "high",
            "count_p.*xor_p|prime_count.*xor_accumulate|ap_prime_accum",
            "xor_p\\s*\\^=.*val|count_p\\+\\+.*xor_p.*val|ap_prime_xor",
            "count_p.*7|xor_p.*27|xor_p.*0x1B|prime_ap_result"
        ),
        new PatternDef("primes_arith_prog_pack", "primes_ap_pack", "medium",
            "AP_N\\s*<<\\s*16.*count_p.*<<.*8.*xor_p|ap_prime_pack",
            "0x08071B|AP_N.*8.*count_p.*7.*xor_p.*27|ap_pack_result",
            "g_result.*0x08.*0x07.*0x1B|ap_g_result"
        ),
        new PatternDef("waring_problem_dp", "waring_squares_dp", "high",
            "wp_dp|waring_dp|min_squares_dp|lagrange_four_square",
            "wp_dp\\[n\\].*=.*n|dp\\[n\\].*n.*worst.*case|waring_init_sentinel",
            "k.*k.*<=.*n.*wp_dp.*n.*k.*k|inner.*loop.*squares.*dp"
        ),
        new PatternDef("waring_problem_sum_max", "waring_sum_max", "high",
            "dp_sum|dp_max|waring_sum.*max|min_sq_sum",
            "dp_sum.*\\+=.*wp_dp|dp_max.*wp_dp|waring_accumulate",
            "dp_sum.*21|dp_max.*4|waring.*0x0A1504"
        ),
        new PatternDef("waring_problem_pack", "waring_pack", "medium",
            "WP_N\\s*<<\\s*16.*dp_sum.*<<.*8.*dp_max|waring_pack",
            "0x0A1504|WP_N.*10.*dp_sum.*21.*dp_max.*4|waring_result",
            "g_result.*0x0A.*0x15.*0x04|wp_g_result"
        ),
        new PatternDef("euler_zigzag_entringer", "euler_zigzag_triangle", "high",
            "ez_T\\[n\\]\\[k\\]\\s*=\\s*ez_T\\[n\\]\\[k.*1\\].*ez_T\\[n.*1\\]\\[n.*k\\]|entringer_recurrence",
            "ez_T|ez_zigzag|entringer.*triangle|zigzag.*diagonal",
            "zigzag\\[n\\]\\s*=\\s*T\\[n\\]\\[n\\]|ez_T.*n.*n.*ez_zigzag"
        ),
        new PatternDef("euler_zigzag_odd_sum", "euler_zigzag_odd_acc", "high",
            "odd_sum.*ez_zigzag|zigzag.*i.*1.*odd_sum|EZ_N.*7.*odd.*E1.*E3.*E5",
            "i\\s*&\\s*1.*odd_sum|odd_indexed.*zigzag|alternate.*sum.*zigzag",
            "odd_sum.*19|ez_zigzag.*1.*2.*16|alternating_perm_sum"
        ),
        new PatternDef("euler_zigzag_pack", "euler_zigzag_pack", "medium",
            "EZ_N\\s*<<\\s*16.*odd_sum.*<<.*8.*max_val|euler_zigzag_pack",
            "0x07133D|EZ_N.*7.*odd_sum.*19.*max_val.*61|zigzag_result",
            "g_result.*0x07.*0x13.*0x3D|ez_g_result"
        ),
        new PatternDef("tangent_numbers_entringer", "tangent_numbers_triangle", "high",
            "tan_E\\[n\\]\\[k\\]\\s*=\\s*tan_E\\[n\\]\\[k.*1\\].*tan_E\\[n.*1\\]\\[n.*k\\]|tangent_entringer",
            "tan_E|tan_vals|tangent.*odd.*diagonal|entringer.*tangent",
            "tan_E\\[row\\]\\[row\\]|2.*k.*1.*tangent.*odd_row"
        ),
        new PatternDef("tangent_numbers_extract", "tangent_numbers_extract", "high",
            "row\\s*=\\s*2.*k.*1.*tan_E\\[row\\]\\[row\\]|tangent_extract",
            "T1.*1.*T3.*2.*T5.*16.*T7.*272|tangent_vals.*1_2_16_272",
            "2.*k.*1.*TAN_N.*4|odd_row_diagonal.*tangent"
        ),
        new PatternDef("tangent_numbers_pack", "tangent_numbers_pack", "medium",
            "TAN_N\\s*<<\\s*16.*sum_t.*<<.*8.*xor_t|tangent_pack",
            "0x042303|TAN_N.*4.*sum.*291.*xor.*259|tangent_result",
            "g_result.*0x04.*0x23.*0x03|tan_g_result"
        ),
        new PatternDef("smooth_numbers_trial_div", "smooth_numbers_trial_div", "high",
            "rem\\s*%\\s*p\\s*==\\s*0.*rem\\s*/=\\s*p|smooth_trial_div",
            "sn_primes|while.*rem.*%.*p.*0.*rem.*p|trial_divide.*smooth",
            "rem.*1.*count_smooth|smooth_remainder_check"
        ),
        new PatternDef("smooth_numbers_classify", "smooth_numbers_classify", "high",
            "SN_UPPER.*SN_B.*smooth|for.*n.*SN_UPPER.*trial.*smooth",
            "count_smooth|sum_smooth|5.smooth.*range|B_smooth.*20",
            "1.*2.*3.*4.*5.*6.*8.*9.*10.*12.*15.*16.*18.*20|smooth_list_20"
        ),
        new PatternDef("smooth_numbers_pack", "smooth_numbers_pack", "medium",
            "SN_UPPER\\s*<<\\s*16.*count_smooth.*<<.*8.*sum_smooth|smooth_pack",
            "0x140E81|SN_UPPER.*20.*count.*14.*sum.*129|smooth_result",
            "g_result.*0x14.*0x0E.*0x81|sn_g_result"
        ),
        new PatternDef("perfect_numbers_sigma", "perfect_numbers_sigma", "high",
            "for.*d.*2.*d.*n.*2.*n.*%.*d.*0.*s.*d|proper_divisor_sum",
            "sigma.*==.*n.*pf_count|perfect_divisor_equal",
            "PF_UPPER.*100.*pf_count.*pf_sum|perfect_sweep_100"
        ),
        new PatternDef("perfect_numbers_check", "perfect_numbers_check", "high",
            "proper_divisor_sum.*n.*==.*n|pf_count.*pf_sum.*perfect",
            "6.*28.*perfect.*count.*2.*sum.*34|perfect_pair_6_28",
            "pf_count.*pf_sum.*PF_UPPER|perfect_numbers_accumulate"
        ),
        new PatternDef("perfect_numbers_pack", "perfect_numbers_pack", "medium",
            "PF_UPPER\\s*<<\\s*16.*pf_count.*<<.*8.*pf_sum|perfect_pack",
            "0x640222|PF_UPPER.*100.*count.*2.*sum.*34|perfect_result",
            "g_result.*0x64.*0x02.*0x22|pf_g_result"
        ),
        new PatternDef("amicable_numbers_sigma", "amicable_numbers_sigma", "high",
            "for.*d.*1.*d.*n.*n.*%.*d.*0.*s.*d|am_sigma",
            "am_sigma.*n.*s.*s.*!=.*n.*am_sigma.*s.*==.*n|amicable_mutual_check",
            "AM_LO.*200.*AM_HI.*300.*amicable|amicable_range_200_300"
        ),
        new PatternDef("amicable_numbers_check", "amicable_numbers_check", "high",
            "sigma.*s.*!=.*n.*sigma.*sigma.*n.*==.*n|amicable_pair_test",
            "220.*284.*amicable.*count.*2.*sum.*504|amicable_pair_220_284",
            "am_count.*am_sum.*amicable|amicable_accumulate"
        ),
        new PatternDef("amicable_numbers_pack", "amicable_numbers_pack", "medium",
            "101.*<<.*16.*am_count.*<<.*8.*am_sum|amicable_pack",
            "0x6502F8|n_tests.*101.*count.*2.*sum.*248|amicable_result",
            "g_result.*0x65.*0x02.*0xF8|am_g_result"
        ),
        new PatternDef("abundant_numbers_sigma", "abundant_numbers_sigma", "high",
            "for.*d.*1.*d.*n.*n.*%.*d.*0.*s.*d|ab_sigma",
            "ab_sigma.*n.*>.*n.*ab_count|abundant_excess_test",
            "AB_UPPER.*50.*abundant.*sigma|abundant_range_50"
        ),
        new PatternDef("abundant_numbers_check", "abundant_numbers_check", "high",
            "sigma.*>.*n.*ab_count.*ab_sum|abundant_count_sum",
            "12.*18.*20.*24.*30.*36.*40.*42.*48.*abundant.*9|abundant_list_9",
            "ab_count.*ab_sum.*AB_UPPER|abundant_accumulate"
        ),
        new PatternDef("abundant_numbers_pack", "abundant_numbers_pack", "medium",
            "AB_UPPER\\s*<<\\s*16.*ab_count.*<<.*8.*ab_sum|abundant_pack",
            "0x32090E|AB_UPPER.*50.*count.*9.*sum.*14|abundant_result",
            "g_result.*0x32.*0x09.*0x0E|ab_g_result"
        ),
        new PatternDef("mersenne_exponents_shift", "mersenne_exponents_shift", "high",
            "1u\\s*<<\\s*p.*-\\s*1u|mersenne_construct_shift",
            "me_is_prime.*1u\\s*<<.*-\\s*1|mersenne_primality_check",
            "ME_UPPER.*20.*me_count.*exp_sum|mersenne_exponent_loop"
        ),
        new PatternDef("mersenne_exponents_count", "mersenne_exponents_count", "high",
            "me_count.*exp_sum.*p.*ME_UPPER|mersenne_count_sum",
            "me_is_prime.*d.*d.*<=.*n.*d\\s*\\+=\\s*2|mersenne_trial_div",
            "7.*66.*0x140742|mersenne_result_pack"
        ),
        new PatternDef("mersenne_exponents_pack", "mersenne_exponents_pack", "medium",
            "ME_UPPER\\s*<<\\s*16.*me_count.*<<.*8.*exp_sum|mersenne_pack",
            "0x140742|ME_UPPER.*20.*count.*7.*sum.*66|mersenne_metrics",
            "g_result.*0x14.*0x07.*0x42|me_g_result"
        ),
        new PatternDef("highly_composite_divisor", "highly_composite_divisor", "high",
            "hc_divisor_count.*d.*<=.*n.*n\\s*%\\s*d.*cnt|highly_composite_div_loop",
            "max_div.*cnt.*>.*max_div.*hc_count|highly_composite_max_track",
            "HC_UPPER.*100.*hc_count.*hc_sum.*max_div|highly_composite_scan"
        ),
        new PatternDef("highly_composite_count", "highly_composite_count", "high",
            "hc_count.*hc_sum.*max_div.*HC_UPPER|hc_accumulate",
            "cnt.*>.*max_div.*max_div.*=.*cnt.*hc_sum|hc_update_max",
            "9.*193.*0x6409C1|highly_composite_result"
        ),
        new PatternDef("highly_composite_pack", "highly_composite_pack", "medium",
            "HC_UPPER\\s*<<\\s*16.*hc_count.*<<.*8.*hc_sum|hc_pack",
            "0x6409C1|HC_UPPER.*100.*count.*9.*sum.*193|hc_metrics",
            "g_result.*0x64.*0x09.*0xC1|hc_g_result"
        ),
        new PatternDef("aliquot_sequence_proper_sum", "aliquot_sequence_proper_sum", "high",
            "aq_proper_sum.*d.*<.*n.*n\\s*%\\s*d.*s\\s*\\+=|aliquot_proper_div",
            "aq_chain_length.*nxt.*aq_proper_sum.*cur|aliquot_chain_follow",
            "AQ_UPPER.*40.*max_steps.*sum_steps|aliquot_outer_loop"
        ),
        new PatternDef("aliquot_sequence_chain", "aliquot_sequence_chain", "high",
            "aq_chain_length.*AQ_STEP_LIMIT.*nxt.*==.*0|aliquot_termination",
            "max_steps.*sum_steps.*len.*>.*max_steps|aliquot_max_track",
            "15.*153.*0x280F99|aliquot_result_values"
        ),
        new PatternDef("aliquot_sequence_pack", "aliquot_sequence_pack", "medium",
            "AQ_UPPER\\s*<<\\s*16.*max_steps.*<<.*8.*sum_steps|aliquot_pack",
            "0x280F99|AQ_UPPER.*40.*max.*15.*sum.*153|aliquot_metrics",
            "g_result.*0x28.*0x0F.*0x99|aq_g_result"
        ),
        new PatternDef("sociable_numbers_proper_sum", "sociable_numbers_proper_sum", "high",
            "soc_proper_sum.*d.*\\*.*d.*<=.*n.*n\\s*%\\s*d.*s\\s*\\+=.*n\\s*/\\s*d|sociable_sqrt_div",
            "soc_proper_sum.*b.*soc_proper_sum.*a.*b\\s*!=\\s*a.*b\\s*>.*1|sociable_pair_check",
            "SOC_UPPER.*300.*count.*sum_acc|sociable_amicable_scan"
        ),
        new PatternDef("sociable_numbers_pair_test", "sociable_numbers_pair_test", "high",
            "b\\s*!=\\s*a.*b\\s*>\\s*1.*soc_proper_sum.*b.*==.*a|amicable_double_check",
            "count\\s*\\+\\+.*sum_acc\\s*\\+=.*a|sociable_count_accum",
            "220.*284.*504|SOC_UPPER.*300.*count.*2.*sum.*248|amicable_pair_values"
        ),
        new PatternDef("sociable_numbers_pack", "sociable_numbers_pack", "medium",
            "SOC_UPPER\\s*<<\\s*16.*count.*<<.*8.*sum_acc|sociable_pack",
            "0x012C02F8|SOC_UPPER.*300.*count.*2.*sum.*248|sociable_metrics",
            "g_result.*0x01.*0x2C.*0x02.*0xF8|soc_g_result"
        ),
        new PatternDef("arithmetic_derivative_factorize", "arithmetic_derivative_factorize", "high",
            "arith_deriv.*result\\s*\\+=\\s*n\\s*/\\s*d.*temp\\s*/=\\s*d|arith_deriv_quotient_accum",
            "ad_is_prime.*arith_deriv.*temp.*d.*d.*<=.*temp|arith_deriv_trial_div",
            "result\\s*\\+=\\s*n\\s*/\\s*temp.*temp\\s*>\\s*1|arith_deriv_residual_prime"
        ),
        new PatternDef("arithmetic_derivative_exceed", "arithmetic_derivative_exceed", "high",
            "count_exceed.*d\\s*>\\s*i.*total_sum\\s*\\+=.*d|arith_deriv_exceed_count",
            "AD_UPPER.*60.*count_exceed.*17.*total_sum.*87|arith_deriv_values",
            "arith_deriv.*i.*>=.*2.*d.*>.*i|arith_deriv_exceed_guard"
        ),
        new PatternDef("arithmetic_derivative_pack", "arithmetic_derivative_pack", "medium",
            "AD_UPPER\\s*<<\\s*16.*count_exceed.*<<.*8.*total_sum|arith_deriv_pack",
            "0x3C1157|AD_UPPER.*60.*count.*17.*sum.*87|arith_deriv_metrics",
            "g_result.*0x3C.*0x11.*0x57|ad_g_result"
        ),
        new PatternDef("liouville_function_omega", "liouville_function_omega", "high",
            "big_omega.*count.*d.*\\*.*d.*<=.*n.*n\\s*%\\s*d.*count\\s*\\+\\+|liouville_big_omega",
            "omega\\s*&\\s*1.*count_neg\\s*\\+\\+.*count_pos\\s*\\+\\+|liouville_parity_branch",
            "LV_UPPER.*56.*count_pos.*count_neg|liouville_dual_counter"
        ),
        new PatternDef("liouville_function_parity", "liouville_function_parity", "high",
            "big_omega.*omega.*omega\\s*&\\s*1u.*count_neg.*count_pos|liouville_odd_even",
            "count_pos.*26.*count_neg.*30|LV_UPPER.*56.*liouville_values",
            "Omega.*even.*lambda.*1.*Omega.*odd.*lambda.*-1|liouville_sign_comment"
        ),
        new PatternDef("liouville_function_pack", "liouville_function_pack", "medium",
            "LV_UPPER\\s*<<\\s*16.*count_pos.*<<.*8.*count_neg|liouville_pack",
            "0x381A1E|LV_UPPER.*56.*pos.*26.*neg.*30|liouville_metrics",
            "g_result.*0x38.*0x1A.*0x1E|lv_g_result"
        ),
        new PatternDef("deficient_numbers_sigma", "deficient_numbers_sigma", "high",
            "for.*d.*1.*d.*<=.*n.*d\\+\\+.*n\\s*%\\s*d.*==.*0.*s.*\\+=.*d|dn_sigma_divisor_loop",
            "sigma.*<.*2.*\\*.*n|dn_deficiency_test",
            "dn_sigma.*dn_count.*dn_sum|deficient_sigma_call"
        ),
        new PatternDef("deficient_numbers_sweep", "deficient_numbers_sweep", "high",
            "dn_count.*\\+\\+.*dn_sum.*\\+=.*n|deficient_accumulate",
            "for.*n.*1.*n.*<=.*DN_UPPER.*dn_sigma|deficient_outer_loop",
            "dn_count.*dn_sum.*DN_UPPER.*50|deficient_sweep_bounds"
        ),
        new PatternDef("deficient_numbers_pack", "deficient_numbers_pack", "medium",
            "DN_UPPER\\s*<<\\s*16.*dn_count.*<<.*8.*dn_sum|deficient_pack",
            "0x3227CB|DN_UPPER.*50.*dn_count.*39.*dn_sum.*203|deficient_metrics",
            "g_result.*0x32.*0x27.*0xCB|dn_g_result"
        ),
        new PatternDef("twin_primes_isprime", "twin_primes_isprime", "high",
            "d.*\\*.*d.*<=.*n.*n\\s*%\\s*d.*==.*0.*return.*0|tp_is_prime_trial",
            "n.*<.*2.*return.*0.*n.*==.*2.*return.*1|tp_is_prime_base",
            "tp_is_prime.*n.*\\+.*2.*tp_is_prime|twin_pair_check"
        ),
        new PatternDef("twin_primes_sweep", "twin_primes_sweep", "high",
            "pair_count.*\\+\\+.*first_sum.*\\+=.*p|twin_prime_accumulate",
            "for.*p.*2.*p.*\\+.*2.*<=.*TP_UPPER|twin_prime_outer_loop",
            "pair_count.*first_sum.*TP_UPPER.*100|twin_prime_sweep_bounds"
        ),
        new PatternDef("twin_primes_pack", "twin_primes_pack", "medium",
            "TP_UPPER\\s*<<\\s*16.*pair_count.*<<.*8.*first_sum|twin_prime_pack",
            "0x6408EC|TP_UPPER.*100.*pair_count.*8.*first_sum.*236|twin_prime_metrics",
            "g_result.*0x64.*0x08.*0xEC|tp_g_result"
        ),
        new PatternDef("prime_gaps_collect", "prime_gaps_collect", "high",
            "pg_is_prime.*primes.*np.*\\+\\+|prime_gaps_sieve_collect",
            "for.*n.*2.*n.*<=.*PG_UPPER.*pg_is_prime|prime_gaps_outer_loop",
            "np.*<.*PG_MAXPRIMES.*primes.*np.*=.*n|prime_gaps_array_fill"
        ),
        new PatternDef("prime_gaps_maxgap", "prime_gaps_maxgap", "high",
            "gap.*=.*primes.*i.*\\+.*1.*-.*primes.*i|prime_gaps_diff",
            "gap_count.*\\+\\+.*gap.*>.*max_gap.*max_gap.*=.*gap|prime_gaps_running_max",
            "for.*i.*0.*i.*\\+.*1.*<.*np.*gap|prime_gaps_sweep"
        ),
        new PatternDef("prime_gaps_pack", "prime_gaps_pack", "medium",
            "PG_UPPER\\s*<<\\s*16.*max_gap.*<<.*8.*gap_count|prime_gaps_pack",
            "0x640818|PG_UPPER.*100.*max_gap.*8.*gap_count.*24|prime_gaps_metrics",
            "g_result.*0x64.*0x08.*0x18|pg_g_result"
        ),
        new PatternDef("weird_numbers_abundant", "weird_numbers_abundant", "high",
            "dsum\\s*[+]=\\s*d|div_sum.*proper.*divisor|wn_divisors.*dsum",
            "dsum\\s*>\\s*n|sum.*proper.*divisors.*greater|abundant.*check",
            "for.*d.*1.*d.*<.*n.*n.*%.*d.*==.*0|proper_divisors_loop"
        ),
        new PatternDef("weird_numbers_knapsack", "weird_numbers_knapsack", "high",
            "wn_reach\\[s\\s*-\\s*d\\]|reachable.*subset.*sum.*backward",
            "for.*s.*=.*n.*s.*>=.*d.*s--|knapsack.*backward.*sweep.*weird",
            "wn_reach\\[n\\]|pseudoperfect.*reachable.*check"
        ),
        new PatternDef("weird_numbers_pack", "weird_numbers_pack", "medium",
            "WN_UPPER\\s*<<\\s*16.*first_weird.*<<.*8.*wn_count|weird_numbers_pack",
            "0x644601|WN_UPPER.*100.*first_weird.*70.*wn_count.*1|weird_numbers_metrics",
            "g_result.*0x64.*0x46.*0x01|wn_g_result"
        ),
        new PatternDef("practical_numbers_divisors", "practical_numbers_divisors", "high",
            "pn_divisors.*d.*<=.*n|for.*d.*1.*d.*<=.*n.*n.*%.*d.*==.*0",
            "all.*divisors.*including.*n|pn_divisors.*nd.*<.*PN_MAXDIV",
            "for.*d.*=.*1.*d.*<=.*n.*d[+][+]|full_divisors_loop_practical"
        ),
        new PatternDef("practical_numbers_coverage", "practical_numbers_coverage", "high",
            "pn_reach\\[s\\s*-\\s*d\\]|reachable.*knapsack.*practical",
            "for.*k.*=.*1.*k.*<=.*n.*!pn_reach|coverage.*check.*every.*1.*n",
            "pn_reach\\[0\\].*=.*1|practical_sum_init"
        ),
        new PatternDef("practical_numbers_pack", "practical_numbers_pack", "medium",
            "PN_UPPER\\s*<<\\s*16.*pn_count.*<<.*8.*second_practical|practical_numbers_pack",
            "0x3C1402|PN_UPPER.*60.*pn_count.*20.*second.*2|practical_numbers_metrics",
            "g_result.*0x3C.*0x14.*0x02|pn_g_result"
        ),
        new PatternDef("cousin_primes_isprime", "cousin_primes_isprime", "high",
            "cp_is_prime.*n|d.*\\*.*d.*<=.*n.*d.*%.*d.*==.*0.*cousin",
            "for.*d.*=.*3.*d.*\\*.*d.*<=.*n.*d.*[+]=.*2|trial_division_cousin",
            "cp_is_prime.*p.*&&.*cp_is_prime.*p.*[+].*4|cousin_pair_test"
        ),
        new PatternDef("cousin_primes_sweep", "cousin_primes_sweep", "high",
            "p.*[+].*4.*<=.*CP_UPPER|for.*p.*=.*2.*p.*[+].*4.*<=.*100",
            "cp_count[+][+].*last_p.*=.*p|cousin_pair_count_track",
            "for.*p.*2.*p.*\\+.*4u.*<=.*CP_UPPER.*p[+][+]|cousin_primes_loop"
        ),
        new PatternDef("cousin_primes_pack", "cousin_primes_pack", "medium",
            "CP_UPPER\\s*<<\\s*16.*cp_count.*<<.*8.*last_p|cousin_primes_pack",
            "0x64084F|CP_UPPER.*100.*cp_count.*8.*last_p.*79|cousin_primes_metrics",
            "g_result.*0x64.*0x08.*0x4F|cp_g_result"
        ),

        // ── sexy_primes ───────────────────────────────────────────────────────
        new PatternDef("sexy_primes_is_prime", "sexy_primes_is_prime", "high",
            "is_prime_sp|sexy.*prime.*check|p\\s*[+]\\s*6.*prime",
            "for.*d\\s*=\\s*3.*d\\s*[*]\\s*d\\s*<=.*n.*d\\s*[+]=\\s*2|trial_div_odd_sp",
            "n\\s*%\\s*d\\s*==\\s*0.*return\\s*0|is_prime_sp_reject"
        ),
        new PatternDef("sexy_primes_loop", "sexy_primes_loop", "high",
            "for.*p.*2.*p\\s*[+]\\s*6.*<=.*SP_UPPER|sexy_pair_scan",
            "is_prime_sp.*p.*&&.*is_prime_sp.*p\\s*[+]\\s*6|sexy_pair_test",
            "sp_count[+][+].*last_p\\s*=\\s*p|sexy_primes_accumulate"
        ),
        new PatternDef("sexy_primes_pack", "sexy_primes_pack", "medium",
            "SP_UPPER\\s*<<\\s*16.*sp_count.*<<.*8.*last_p|sexy_primes_pack",
            "0x031AC1|SP_UPPER.*200.*sp_count.*26.*last_p.*193|sexy_primes_metrics",
            "g_result.*sp_count.*metric_a.*metric_b|sp_g_result"
        ),

        // ── safe_primes ───────────────────────────────────────────────────────
        new PatternDef("safe_primes_is_prime", "safe_primes_is_prime", "high",
            "is_prime_safe|safe.*prime.*check|p\\s*-\\s*1.*>>\\s*1.*prime",
            "for.*d\\s*=\\s*3.*d\\s*[*]\\s*d\\s*<=.*n.*d\\s*[+]=\\s*2|trial_div_odd_safe",
            "n\\s*%\\s*d\\s*==\\s*0.*return\\s*0|is_prime_safe_reject"
        ),
        new PatternDef("safe_primes_loop", "safe_primes_loop", "high",
            "for.*p.*5.*p\\s*<=.*SAFE_UPPER.*p\\s*[+]=\\s*2|safe_prime_scan",
            "is_prime_safe.*p.*&&.*is_prime_safe.*p\\s*-\\s*1.*>>\\s*1|safe_test_pair",
            "safe_count[+][+].*last_safe\\s*=\\s*p|safe_primes_accumulate"
        ),
        new PatternDef("safe_primes_pack", "safe_primes_pack", "medium",
            "SAFE_UPPER\\s*<<\\s*16.*safe_count.*<<.*8.*last_safe|safe_primes_pack",
            "0x03000C07|SAFE_UPPER.*300.*safe_count.*12.*last_safe.*263|safe_primes_metrics",
            "g_result.*safe_count.*metric_a.*metric_b|safe_g_result"
        ),

        // ── chen_primes ───────────────────────────────────────────────────────
        new PatternDef("chen_primes_omega", "chen_primes_omega", "high",
            "omega_cp|prime_factor_count_cp|cnt[+][+].*n\\s*>>=\\s*1",
            "while.*n\\s*%\\s*d\\s*==\\s*0.*cnt[+][+].*n\\s*/=\\s*d|omega_trial_div",
            "if.*n\\s*>\\s*1.*cnt[+][+]|omega_last_factor"
        ),
        new PatternDef("chen_primes_loop", "chen_primes_loop", "high",
            "for.*p.*2.*p\\s*[+]\\s*2.*<=.*CP_UPPER|chen_prime_scan",
            "is_prime_cp.*q.*||.*omega_cp.*q.*==\\s*2|chen_test_condition",
            "chen_count[+][+].*last_chen\\s*=\\s*p|chen_primes_accumulate"
        ),
        new PatternDef("chen_primes_pack", "chen_primes_pack", "medium",
            "CP_UPPER\\s*<<\\s*16.*chen_count.*<<.*8.*last_chen|chen_primes_pack",
            "0x031561|CP_UPPER.*100.*chen_count.*21.*last_chen.*97|chen_primes_metrics",
            "g_result.*chen_count.*metric_a.*metric_b|cp_g_result_chen"
        ),
        new PatternDef("sophie_germain_is_prime", "sophie_germain_is_prime", "high",
            "is_prime_sgp.*n.*<.*2.*return.*0|sophie_germain_primality",
            "for.*d.*3.*d.*d.*<=.*n.*d.*2.*n.*%.*d.*==.*0|sgp_trial_div_loop",
            "return.*1.*is_prime_sgp|sgp_prime_return"
        ),
        new PatternDef("sophie_germain_scan", "sophie_germain_scan", "high",
            "for.*p.*2.*p.*<=.*SGP_UPPER.*p[+][+]|sophie_germain_scan_loop",
            "is_prime_sgp.*p.*&&.*is_prime_sgp.*2.*p.*1|sgp_sophie_test",
            "sg_count[+][+].*last_sg\\s*=\\s*p|sgp_accumulate"
        ),
        new PatternDef("sophie_germain_pack", "sophie_germain_pack", "medium",
            "n_tests\\s*<<\\s*16.*metric_a.*<<.*8.*metric_b|sophie_germain_pack",
            "sg_count.*0xFF.*last_sg.*0xFF|sgp_mask_metrics",
            "g_result.*n_tests.*metric_a.*metric_b|sgp_g_result"
        ),
        new PatternDef("ramanujan_sieve", "ramanujan_sieve", "high",
            "is_p\\[0\\]\\s*=\\s*0.*is_p\\[1\\]\\s*=\\s*0|ramanujan_sieve_init",
            "for.*i.*i.*i.*<=.*RAM_LIMIT.*is_p\\[i\\].*j.*i.*i.*j.*<=.*RAM_LIMIT.*j.*i|ramanujan_sieve_inner",
            "sieve_ram|ramanujan_sieve_fn"
        ),
        new PatternDef("ramanujan_pi_scan", "ramanujan_pi_scan", "high",
            "pi_ram.*x.*cnt.*i.*2.*i.*<=.*x.*is_p\\[i\\].*cnt[+][+]|ramanujan_pi_fn",
            "for.*x.*2.*x.*<=.*RAM_LIMIT.*found.*<.*RAM_N|ramanujan_scan_loop",
            "pi_ram.*x.*-.*pi_ram.*x.*>>.*1.*>=.*found.*1|ramanujan_diff_cond"
        ),
        new PatternDef("ramanujan_pack", "ramanujan_pack", "medium",
            "found[+][+].*last_rp\\s*=\\s*x|ramanujan_accumulate",
            "found.*0xFF.*last_rp.*0xFF|ramanujan_mask_metrics",
            "g_result.*n_tests.*metric_a.*metric_b|ramanujan_g_result"
        ),
        new PatternDef("super_primes_build", "super_primes_build", "high",
            "for.*n.*2.*n.*<=.*SP_LIMIT.*prime_cnt.*<.*SP_MAX|super_primes_build_loop",
            "is_prime_sp.*n.*primes\\[prime_cnt[+][+]\\].*n|super_primes_store",
            "build_primes|prime_cnt.*0|super_primes_init"
        ),
        new PatternDef("super_primes_scan", "super_primes_scan", "high",
            "for.*i.*0.*i.*<.*prime_cnt.*i[+][+].*idx.*i.*1|super_primes_scan_loop",
            "is_prime_sp.*idx.*sp_count[+][+].*last_sp.*primes\\[i\\]|super_prime_test",
            "super_prime.*prime.*indexed|sp_comment_indexed"
        ),
        new PatternDef("super_primes_pack", "super_primes_pack", "medium",
            "n_tests\\s*<<\\s*16.*metric_a.*<<.*8.*metric_b|super_primes_pack",
            "sp_count.*0xFF.*last_sp.*0xFF|super_primes_mask",
            "g_result.*sp_count.*metric_a.*metric_b|super_primes_g_result"
        ),
        // ── Sprint 184: primorial_primes, fortunate_numbers, pierpont_primes ──
        new PatternDef("primorial_primes_build", "primorial_primes_build", "high",
            "primorial\\s*[*]=\\s*prim_bases|primorial_primes_multiply",
            "cand_plus.*primorial.*[+].*1u|cand_minus.*primorial.*-.*1u|primorial_cands",
            "is_prime_pp.*cand_plus.*count[+][+]|is_prime_pp.*cand_minus.*count[+][+]|primorial_prime_check"
        ),
        new PatternDef("primorial_primes_collect", "primorial_primes_collect", "high",
            "count[+][+].*last_pp.*cand|primorial_prime_collect_last",
            "PRIM_BASE_COUNT.*4|prim_bases.*2.*3.*5.*7|primorial_prime_bases",
            "last_pp.*>.*last_pp.*cand|primorial_prime_max_update"
        ),
        new PatternDef("primorial_primes_pack", "primorial_primes_pack", "medium",
            "n_tests\\s*<<\\s*16.*metric_a.*<<.*8.*metric_b|primorial_primes_pack",
            "count.*0xFF.*last_pp.*0xFF|primorial_primes_mask",
            "g_result.*n_tests.*metric_a.*metric_b|primorial_primes_g_result"
        ),
        new PatternDef("fortunate_numbers_find", "fortunate_numbers_find", "high",
            "fortunate_find.*primorial|for.*m.*2.*is_prime_fn.*primorial.*[+].*m|fortunate_search_m",
            "primorial.*[*]=.*fn_primes|fn_primes.*2.*3.*5.*7.*11|fortunate_primorial_build",
            "fn_sum.*[+]=.*fn.*last_fn.*=.*fn|fortunate_accumulate"
        ),
        new PatternDef("fortunate_numbers_loop", "fortunate_numbers_loop", "high",
            "for.*i.*FN_COUNT.*fortunate_find|fortunate_outer_loop",
            "fn.*fortunate_find.*primorial|fortunate_call_find",
            "FN_COUNT.*5|fn_primes\\[FN_COUNT\\]|fortunate_fn_count"
        ),
        new PatternDef("fortunate_numbers_pack", "fortunate_numbers_pack", "medium",
            "n_tests\\s*<<\\s*16.*metric_a.*<<.*8.*metric_b|fortunate_numbers_pack",
            "fn_sum.*0xFF.*last_fn.*0xFF|fortunate_numbers_mask",
            "g_result.*fn_sum.*last_fn|fortunate_numbers_g_result"
        ),
        new PatternDef("pierpont_primes_smooth", "pierpont_primes_smooth", "high",
            "for.*pw2.*PP_LIMIT.*pw2\\s*<<=\\s*1|for.*pw3.*pw3.*[*]=.*3|pierpont_smooth_enumerate",
            "smooth\\[scnt[+][+]\\]\\s*=\\s*pw3|pierpont_smooth_store",
            "sort_u32.*smooth.*scnt|pierpont_sort_smooth"
        ),
        new PatternDef("pierpont_primes_check", "pierpont_primes_check", "high",
            "cand.*smooth\\[i\\].*[+].*1|is_prime_pp1.*cand.*pp_count[+][+]|pierpont_check_cand",
            "pp_count[+][+].*last_pp.*=.*cand|pierpont_collect_prime",
            "PP_LIMIT.*512|PP_SLOTS.*32|pierpont_limits"
        ),
        new PatternDef("pierpont_primes_pack", "pierpont_primes_pack", "medium",
            "n_tests\\s*<<\\s*16.*metric_a.*<<.*8.*metric_b|pierpont_primes_pack",
            "pp_count.*0xFF.*last_pp.*0xFF|pierpont_primes_mask",
            "g_result.*n_tests.*metric_a.*metric_b|pierpont_primes_g_result"
        ),
        new PatternDef("wagstaff_primes_exp", "wagstaff_primes_exp", "high",
            "pow2\\s*=\\s*1u\\s*<<\\s*p|wagstaff_shift_p",
            "num\\s*=\\s*pow2\\s*[+]\\s*1u|wagstaff_num_plus1",
            "cand\\s*=\\s*num\\s*/\\s*3u|wagstaff_div3"
        ),
        new PatternDef("wagstaff_primes_loop", "wagstaff_primes_loop", "high",
            "for.*p\\s*=\\s*3u.*p\\s*<=\\s*WP_PMAX|wagstaff_outer_loop",
            "is_prime_wp.*p.*is_prime_wp.*cand|wagstaff_double_prime",
            "wp_count[+][+].*last_wp\\s*=\\s*cand|wagstaff_collect"
        ),
        new PatternDef("wagstaff_primes_pack", "wagstaff_primes_pack", "medium",
            "n_tests\\s*<<\\s*16.*metric_a.*<<.*8.*metric_b|wagstaff_primes_pack",
            "wp_count.*0xFF.*last_wp.*0xFF|wagstaff_primes_mask",
            "g_result.*n_tests.*metric_a.*metric_b|wagstaff_primes_g_result"
        ),
        new PatternDef("carol_numbers_compute", "carol_numbers_compute", "high",
            "m\\s*=\\s*[(]1u\\s*<<\\s*n[)]\\s*-\\s*1u|carol_m_shift",
            "cand\\s*=\\s*m\\s*[*]\\s*m\\s*-\\s*2u|carol_square_minus2",
            "is_prime_cn.*cand|carol_primality_check"
        ),
        new PatternDef("carol_numbers_loop", "carol_numbers_loop", "high",
            "for.*n\\s*=\\s*2u.*n\\s*<=\\s*CN_NMAX|carol_outer_loop",
            "cn_count[+][+].*last_cn\\s*=\\s*cand|carol_collect",
            "CN_NMAX.*15u|CN_SLOTS.*16u|carol_limits"
        ),
        new PatternDef("carol_numbers_pack", "carol_numbers_pack", "medium",
            "n_tests\\s*<<\\s*16.*metric_a.*<<.*8.*metric_b|carol_numbers_pack",
            "cn_count.*0xFF.*last_cn.*0xFF|carol_numbers_mask",
            "g_result.*n_tests.*metric_a.*metric_b|carol_numbers_g_result"
        ),
        new PatternDef("thabit_numbers_compute", "thabit_numbers_compute", "high",
            "cand\\s*=\\s*3u\\s*[*]\\s*[(]1u\\s*<<\\s*n[)]\\s*-\\s*1u|thabit_formula",
            "is_prime_tn.*cand|thabit_primality_check",
            "TN_NMAX.*28u|TN_SLOTS.*16u|thabit_limits"
        ),
        new PatternDef("thabit_numbers_loop", "thabit_numbers_loop", "high",
            "for.*n\\s*=\\s*0u.*n\\s*<=\\s*TN_NMAX|thabit_outer_loop",
            "tn_count[+][+].*last_tn\\s*=\\s*cand|thabit_collect",
            "tn_count.*TN_SLOTS|thabit_slot_guard"
        ),
        new PatternDef("thabit_numbers_pack", "thabit_numbers_pack", "medium",
            "n_tests\\s*<<\\s*16.*metric_a.*<<.*8.*metric_b|thabit_numbers_pack",
            "tn_count.*0xFF.*last_tn.*0xFF|thabit_numbers_mask",
            "g_result.*n_tests.*metric_a.*metric_b|thabit_numbers_g_result"
        ),
        new PatternDef("cullen_numbers_formula", "cullen_numbers_formula", "high",
            "n\\s*[*]\\s*[(]1u\\s*<<\\s*n[)]\\s*[+]\\s*1u|cullen_formula",
            "is_prime_cn.*cand|cullen_primality_check",
            "CN_MAX.*20u|cullen_limit"
        ),
        new PatternDef("cullen_numbers_loop", "cullen_numbers_loop", "high",
            "for.*n\\s*=\\s*1u.*n\\s*<=\\s*CN_MAX|cullen_outer_loop",
            "count_comp[+][+].*cullen_sum\\s*[+]=\\s*cand|cullen_collect",
            "count_comp.*CN_MAX|cullen_composite_guard"
        ),
        new PatternDef("cullen_numbers_pack", "cullen_numbers_pack", "medium",
            "n_tests\\s*<<\\s*16.*metric_a.*<<.*8.*metric_b|cullen_numbers_pack",
            "count_comp.*0xFF.*cullen_sum.*0xFF|cullen_numbers_mask",
            "g_result.*n_tests.*metric_a.*metric_b|cullen_numbers_g_result"
        ),
        new PatternDef("woodall_numbers_formula", "woodall_numbers_formula", "high",
            "n\\s*[*]\\s*[(]1u\\s*<<\\s*n[)]\\s*-\\s*1u|woodall_formula",
            "is_prime_wn.*cand|woodall_primality_check",
            "WN_MAX.*20u|woodall_limit"
        ),
        new PatternDef("woodall_numbers_loop", "woodall_numbers_loop", "high",
            "for.*n\\s*=\\s*1u.*n\\s*<=\\s*WN_MAX|woodall_outer_loop",
            "count_prime[+][+].*last_prime_w\\s*=\\s*cand|woodall_collect",
            "count_prime.*WN_MAX|woodall_prime_guard"
        ),
        new PatternDef("woodall_numbers_pack", "woodall_numbers_pack", "medium",
            "n_tests\\s*<<\\s*16.*metric_a.*<<.*8.*metric_b|woodall_numbers_pack",
            "count_prime.*0xFF.*last_prime_w.*0xFF|woodall_numbers_mask",
            "g_result.*n_tests.*metric_a.*metric_b|woodall_numbers_g_result"
        ),
        new PatternDef("fermat_numbers_formula", "fermat_numbers_formula", "high",
            "exp\\s*=\\s*1u\\s*<<\\s*n.*cand\\s*=\\s*[(]1u\\s*<<\\s*exp[)]\\s*[+]\\s*1u|fermat_formula",
            "is_prime_fn.*cand|fermat_primality_check",
            "FN_MAX.*4u|fermat_limit"
        ),
        new PatternDef("fermat_numbers_loop", "fermat_numbers_loop", "high",
            "for.*n\\s*=\\s*0u.*n\\s*<=\\s*FN_MAX|fermat_outer_loop",
            "count_prime[+][+].*fermat_sum\\s*[+]=\\s*cand|fermat_collect",
            "fermat_sum.*FN_MAX|fermat_sum_guard"
        ),
        new PatternDef("fermat_numbers_pack", "fermat_numbers_pack", "medium",
            "n_tests\\s*<<\\s*16.*metric_a.*<<.*8.*metric_b|fermat_numbers_pack",
            "count_prime.*0xFF.*fermat_sum.*0xFF|fermat_numbers_mask",
            "g_result.*n_tests.*metric_a.*metric_b|fermat_numbers_g_result"
        ),
        new PatternDef("fibonacci_primes_recurrence", "fibonacci_primes_recurrence", "high",
            "fib\\[i\\]\\s*=\\s*fib\\[i.*1\\]\\s*\\+\\s*fib\\[i.*2\\]|fibonacci_primes_recurrence",
            "is_prime_fp.*fib\\[i\\]|fibonacci_primes_test",
            "count_fp\\+\\+.*prime_sum.*fib|fibonacci_primes_accumulate"
        ),
        new PatternDef("fibonacci_primes_sieve", "fibonacci_primes_sieve", "high",
            "FIB_N.*20|fibonacci_primes_size",
            "fib\\[0\\].*0.*fib\\[1\\].*1|fibonacci_primes_seeds",
            "count_fp.*0xFF.*checksum.*0xFF|fibonacci_primes_mask"
        ),
        new PatternDef("fibonacci_primes_pack", "fibonacci_primes_pack", "medium",
            "n_tests\\s*<<\\s*16.*metric_a.*<<.*8.*metric_b|fibonacci_primes_pack",
            "prime_sum.*251|fibonacci_primes_mod",
            "g_result.*n_tests.*metric_a.*metric_b|fibonacci_primes_g_result"
        ),
        new PatternDef("lucas_primes_recurrence", "lucas_primes_recurrence", "high",
            "luc\\[i\\]\\s*=\\s*luc\\[i.*1\\]\\s*\\+\\s*luc\\[i.*2\\]|lucas_primes_recurrence",
            "luc\\[0\\].*2.*luc\\[1\\].*1|lucas_primes_seeds",
            "is_prime_lp.*luc\\[i\\]|lucas_primes_test"
        ),
        new PatternDef("lucas_primes_count", "lucas_primes_count", "high",
            "count_lp\\+\\+.*prime_sum.*luc|lucas_primes_accumulate",
            "LUC_N.*20|lucas_primes_size",
            "prime_sum.*251|lucas_primes_mod"
        ),
        new PatternDef("lucas_primes_pack", "lucas_primes_pack", "medium",
            "n_tests\\s*<<\\s*16.*metric_a.*<<.*8.*metric_b|lucas_primes_pack",
            "count_lp.*0xFF.*checksum.*0xFF|lucas_primes_mask",
            "g_result.*n_tests.*metric_a.*metric_b|lucas_primes_g_result"
        ),
        new PatternDef("sierpinski_numbers_loop", "sierpinski_numbers_loop", "high",
            "k.*K_MAX.*k.*2|sierpinski_numbers_odd_loop",
            "k.*1u.*1u\\s*<<\\s*n.*1|sierpinski_numbers_candidate",
            "all_composite.*0.*break|sierpinski_numbers_short_circuit"
        ),
        new PatternDef("sierpinski_numbers_check", "sierpinski_numbers_check", "high",
            "is_prime_sn.*val|sierpinski_numbers_primality",
            "count_s\\+\\+.*cand_sum.*k|sierpinski_numbers_accumulate",
            "K_MAX.*99.*N_EXP.*6|sierpinski_numbers_bounds"
        ),
        new PatternDef("sierpinski_numbers_pack", "sierpinski_numbers_pack", "medium",
            "n_tests\\s*<<\\s*16.*metric_a.*<<.*8.*metric_b|sierpinski_numbers_pack",
            "count_s.*0xFF.*cand_sum.*0xFF|sierpinski_numbers_mask",
            "g_result.*n_tests.*metric_a.*metric_b|sierpinski_numbers_g_result"
        ),
        new PatternDef("riesel_numbers_table", "riesel_numbers_table", "high",
            "riesel_k\\s*\\[|riesel_numbers_table",
            "2293.*9221.*23669|riesel_numbers_constants",
            "dig_sum.*riesel_digit_sum|riesel_numbers_digit_sum"
        ),
        new PatternDef("riesel_numbers_threshold", "riesel_numbers_threshold", "high",
            "riesel_k.*>>.*8.*>.*100|riesel_numbers_threshold",
            "cnt_large\\+\\+|riesel_numbers_count_large",
            "dig_sum.*%.*251|riesel_numbers_mod251"
        ),
        new PatternDef("riesel_numbers_pack", "riesel_numbers_pack", "medium",
            "RIESEL_N\\s*<<\\s*16.*cnt_large.*<<.*8|riesel_numbers_pack",
            "cnt_large.*0xFF.*dig_sum|riesel_numbers_mask",
            "g_result.*RIESEL_N.*cnt_large.*dig_sum|riesel_numbers_g_result"
        ),
        new PatternDef("kynea_numbers_formula", "kynea_numbers_formula", "high",
            "pow2\\s*\\+\\s*1.*\\*.*pow2\\s*\\+\\s*1.*-\\s*2|kynea_numbers_formula",
            "pow2\\s*<<=\\s*1|kynea_numbers_doubling",
            "kynea_is_prime.*kval|kynea_numbers_primality"
        ),
        new PatternDef("kynea_numbers_count", "kynea_numbers_count", "high",
            "prime_cnt\\+\\+.*composite_cnt\\+\\+|kynea_numbers_count",
            "KYNEA_N.*<<.*16.*prime_cnt.*<<.*8|kynea_numbers_result_pack",
            "composite_cnt.*0xFF.*prime_cnt.*0xFF|kynea_numbers_mask"
        ),
        new PatternDef("kynea_numbers_pack", "kynea_numbers_pack", "medium",
            "g_result.*KYNEA_N.*prime_cnt.*composite_cnt|kynea_numbers_g_result",
            "kynea_numbers_composite|composite_cnt",
            "kynea_numbers_prime|prime_cnt.*KYNEA_N"
        ),
        new PatternDef("leyland_numbers_nested", "leyland_numbers_nested", "high",
            "pow_u32.*x.*y.*pow_u32.*y.*x|leyland_numbers_formula",
            "for.*x.*<=.*5.*for.*y.*<=.*x|leyland_numbers_nested_loop",
            "leyland_is_prime.*ley|leyland_numbers_primality"
        ),
        new PatternDef("leyland_numbers_count", "leyland_numbers_count", "high",
            "prime_cnt.*total_sum.*count|leyland_numbers_accum",
            "total_sum.*%.*251|leyland_numbers_mod251",
            "10u\\s*<<\\s*16.*prime_cnt.*total_sum|leyland_numbers_pack"
        ),
        new PatternDef("leyland_numbers_pack", "leyland_numbers_pack", "medium",
            "g_result.*10u.*prime_cnt.*total_sum|leyland_numbers_g_result",
            "prime_cnt.*0xFF.*total_sum|leyland_numbers_mask",
            "leyland_numbers_prime.*leyland_numbers_sum|leyland_numbers_metrics"
        ),
        new PatternDef("emirp_primes_reverse", "emirp_primes_reverse", "high",
            "reverse_digits.*n.*10u.*rev.*10u|emirp_digit_reversal",
            "rev.*rev.*10u.*n.*10u.*n|emirp_reversal_loop",
            "while.*n.*0u.*rev.*10u.*n.*10u|emirp_reverse_digits"
        ),
        new PatternDef("emirp_primes_test", "emirp_primes_test", "high",
            "is_emirp.*is_prime.*rev.*==.*n|emirp_palindrome_check",
            "is_prime.*n.*reverse_digits.*n.*rev.*!=.*n|emirp_nonpalindrome",
            "is_prime.*rev.*return.*0u.*is_prime|emirp_double_prime_check"
        ),
        new PatternDef("emirp_primes_collect", "emirp_primes_collect", "medium",
            "total_sum.*251u.*cnt_le100|emirp_metrics_pack",
            "count.*15u.*is_emirp|emirp_count_loop",
            "15u.*<<.*16.*total_sum.*251u.*cnt_le100|emirp_g_result"
        ),
        new PatternDef("mills_primes_array", "mills_primes_array", "high",
            "mills.*2u.*11u.*1361u|mills_known_primes",
            "static.*const.*uint32_t.*mills.*3.*2u.*11u|mills_prime_array",
            "mills\\[2\\].*251u|mills_largest_mod"
        ),
        new PatternDef("mills_primes_verify", "mills_primes_verify", "high",
            "total_sum.*mills.*i.*is_prime.*mills|mills_sum_primality",
            "cnt_prime.*is_prime.*mills.*i|mills_count_primes",
            "total_sum.*1374u|mills_known_sum"
        ),
        new PatternDef("mills_primes_pack", "mills_primes_pack", "medium",
            "3u.*<<.*16.*total_sum.*251u.*mills.*2.*251u|mills_g_result",
            "total_sum.*251u.*<<.*8.*mills.*251u|mills_pack_metrics",
            "mills_primes_sum.*mills_primes_largest|mills_primes_metrics"
        ),
        new PatternDef("strong_primes_sieve", "strong_primes_sieve", "high",
            "build_sieve.*sieve.*0u.*sieve.*1u|strong_sieve_init",
            "sieve.*i.*==.*0u.*j.*=.*i.*\\*.*i.*j.*<.*SIEVE_LIMIT|strong_sieve_inner",
            "sieve.*0.*1.*SIEVE_LIMIT.*primes.*np|strong_sieve_collect"
        ),
        new PatternDef("strong_primes_test", "strong_primes_test", "high",
            "2u.*\\*.*p_mid.*>.*p_prev.*\\+.*p_next|strong_prime_condition",
            "p_prev.*primes.*i.*p_mid.*primes.*i.*p_next.*primes.*i|strong_triple_walk",
            "strong_prime.*2.*p.*>.*prev.*next|strong_arithmetic_mean"
        ),
        new PatternDef("strong_primes_collect", "strong_primes_collect", "medium",
            "total_sum.*1129u|strong_primes_known_sum",
            "15u.*<<.*16.*total_sum.*251u.*cnt_le50|strong_primes_g_result",
            "cnt_le50.*p_mid.*50u.*count.*15u|strong_primes_count_pack"
        ),
        new PatternDef("prime_triplets_sieve", "prime_triplets_sieve", "high",
            "sieve.*p.*2u.*==.*0u.*sieve.*p.*6u.*==.*0u|triplet_type1_test",
            "p.*\\+.*2u.*\\+.*6u.*SIEVE_LIMIT|triplet_bound_check",
            "build_sieve.*SIEVE_LIMIT.*408u|prime_triplets_sieve_init"
        ),
        new PatternDef("prime_triplets_count", "prime_triplets_count", "high",
            "sum_p.*\\+.*p.*cnt_lt200.*\\+\\+|triplet_accumulate",
            "p.*<.*200u.*cnt_lt200|triplet_lt200_gate",
            "10u.*<<.*16.*sum_p.*251u.*cnt_lt200|prime_triplets_g_result"
        ),
        new PatternDef("prime_triplets_pattern", "prime_triplets_pattern", "medium",
            "sieve.*p.*0u.*&&.*sieve.*p.*2.*0u.*&&.*sieve.*p.*6.*0u|three_sieve_tests",
            "sum_p.*%.*251u|prime_triplets_sum_mod",
            "count_prime_triplets.*type1.*p.*p.*2.*p.*6|triplet_type1_collect"
        ),
        new PatternDef("balanced_primes_sieve", "balanced_primes_sieve", "high",
            "build_sieve.*SIEVE_LIMIT.*600u|balanced_primes_sieve_600",
            "primes.*np.*<.*120u.*np.*\\+\\+|balanced_prime_array_fill",
            "sieve.*0u.*primes.*np|balanced_collect_prime_array"
        ),
        new PatternDef("balanced_primes_test", "balanced_primes_test", "high",
            "2u.*\\*.*p_mid.*==.*p_prev.*\\+.*p_next|balanced_prime_equality",
            "p_prev.*primes.*i.*p_mid.*primes.*i.*p_next.*primes.*i|balanced_triple_walk",
            "bal_sum.*\\+.*p_mid.*cnt_le200.*\\+\\+|balanced_sum_accumulate"
        ),
        new PatternDef("balanced_primes_collect", "balanced_primes_collect", "medium",
            "bal_sum.*%.*251u|balanced_sum_mod251",
            "10u.*<<.*16.*bal_sum.*251u.*cnt_le200|balanced_primes_g_result",
            "cnt_le200.*p_mid.*200u.*count.*10u|balanced_primes_count_pack"
        ),
        new PatternDef("good_primes_sieve", "good_primes_sieve", "high",
            "p_mid.*\\*.*p_mid.*>.*p_prev.*\\*.*p_next|good_prime_geometric_test",
            "p_prev.*primes.*i.*p_mid.*primes.*i.*p_next.*primes.*i|good_triple_walk",
            "build_sieve.*good_primes|good_primes_sieve_init"
        ),
        new PatternDef("good_primes_test", "good_primes_test", "high",
            "p_mid.*p_mid.*p_prev.*p_next.*geometric_mean|good_prime_sq_product",
            "good_sum.*\\+.*p_mid.*cnt_le50.*\\+\\+|good_prime_accumulate",
            "count.*<.*15u.*good_prime|good_prime_limit15"
        ),
        new PatternDef("good_primes_collect", "good_primes_collect", "medium",
            "good_sum.*%.*251u|good_primes_sum_mod251",
            "15u.*<<.*16.*good_sum.*251u.*cnt_le50|good_primes_g_result",
            "cnt_le50.*p_mid.*50u.*count.*15u.*good_sum.*901|good_primes_count_pack"
        ),
        new PatternDef("palindromic_primes_reverse", "palindromic_primes_reverse", "high",
            "reversed.*\\*.*10u.*n.*%.*10u.*n.*\\/.*10u|palindrome_digit_extract",
            "reversed.*==.*original.*is_palindrome|palindrome_equality_test",
            "is_palindrome.*sieve.*palindromic_prime|palindrome_prime_filter"
        ),
        new PatternDef("palindromic_primes_collect", "palindromic_primes_collect", "high",
            "pal_sum.*\\+=.*i.*cnt_lt200.*\\+\\+|palindromic_prime_accumulate",
            "pal_sum.*%.*251u|palindromic_sum_mod251",
            "12u.*<<.*16.*pal_sum.*251u.*cnt_lt200|palindromic_primes_g_result"
        ),
        new PatternDef("palindromic_primes_sieve", "palindromic_primes_sieve", "medium",
            "sieve.*i.*==.*0u.*is_palindrome.*i.*count.*12u|palindromic_prime_sieve_loop",
            "count.*<.*12u.*palindromic|palindromic_prime_limit12",
            "cnt_lt200.*i.*200u.*pal_sum.*1449u|palindromic_primes_count_pack"
        ),
        new PatternDef("isolated_primes_twin_test", "isolated_primes_twin_test", "high",
            "prev_twin.*is_prime_small.*i.*-.*2u.*next_twin.*is_prime_small.*i.*\\+.*2u|isolated_neighbour_check",
            "prev_twin.*==.*0u.*next_twin.*==.*0u|isolated_both_zero",
            "is_prime_small.*sieve.*SIEVE_LIMIT.*isolated|isolated_prime_sieve_lookup"
        ),
        new PatternDef("isolated_primes_collect", "isolated_primes_collect", "high",
            "iso_sum.*\\+=.*i.*cnt_mod4.*\\+\\+|isolated_prime_accumulate",
            "iso_sum.*%.*251u|isolated_sum_mod251",
            "10u.*<<.*16.*iso_sum.*251u.*cnt_mod4|isolated_primes_g_result"
        ),
        new PatternDef("isolated_primes_mod4", "isolated_primes_mod4", "medium",
            "i.*%.*4u.*==.*1u.*cnt_mod4|isolated_prime_mod4_test",
            "count.*<.*10u.*isolated|isolated_prime_limit10",
            "cnt_mod4.*4u.*iso_sum.*577u.*count.*10u|isolated_primes_count_pack"
        ),
        new PatternDef("weak_primes_mean_test", "weak_primes_mean_test", "high",
            "p_prev.*p_next.*>.*2u.*p_mid|weak_prime_arithmetic_mean",
            "p_prev.*primes.*i.*p_mid.*primes.*i.*p_next.*primes.*i|weak_prime_triple_walk",
            "build_sieve.*weak_primes|weak_primes_sieve_init"
        ),
        new PatternDef("weak_primes_collect", "weak_primes_collect", "high",
            "weak_sum.*\\+=.*p_mid.*cnt_mod6.*\\+\\+|weak_prime_accumulate",
            "weak_sum.*%.*251u|weak_sum_mod251",
            "15u.*<<.*16.*weak_sum.*251u.*cnt_mod6|weak_primes_g_result"
        ),
        new PatternDef("weak_primes_mod6", "weak_primes_mod6", "medium",
            "p_mid.*%.*6u.*==.*1u.*cnt_mod6|weak_prime_mod6_test",
            "count.*<.*15u.*weak.*prime|weak_prime_limit15",
            "cnt_mod6.*9u.*weak_sum.*817u.*count.*15u|weak_primes_count_pack"
        ),
        new PatternDef("circular_primes_rotate", "circular_primes_rotate", "high",
            "rot.*pow10.*lead.*rest.*rotate_left|circular_prime_digit_rotate",
            "is_prime.*rot.*rotate_left.*digits|circular_prime_rotation_check",
            "circ_sum.*\\+=.*n.*is_circular_prime|circular_prime_accumulate"
        ),
        new PatternDef("circular_primes_count", "circular_primes_count", "high",
            "count.*\\+\\+.*circ_sum.*n.*200u|circular_prime_count200",
            "n_tests.*count.*0xFFu.*metric_a.*circ_sum.*251u|circular_prime_pack",
            "circ_sum.*>>.*3u.*251u.*metric_b|circular_prime_shift_mod"
        ),
        new PatternDef("circular_primes_detect", "circular_primes_detect", "medium",
            "digits.*num_digits.*rot.*n.*i.*digits.*1u|circular_prime_digit_loop",
            "rotate_left.*rot.*digits|circular_prime_rotate_call",
            "run_circular_primes.*g_result|circular_primes_entry"
        ),
        new PatternDef("truncatable_right", "truncatable_right", "high",
            "t.*n.*t.*10u.*is_prime.*t|right_truncatable_loop",
            "right_count.*\\+\\+.*right_sum.*\\+=.*n.*is_right_truncatable|right_trunc_accumulate",
            "is_right_truncatable.*is_left_truncatable|trunc_prime_both_check"
        ),
        new PatternDef("truncatable_left", "truncatable_left", "high",
            "pow10_table.*num_digits.*truncated.*n.*%.*pow10_table|left_truncatable_mod",
            "tmp.*10u.*==.*0u.*return.*0u|left_trunc_no_zero_digit",
            "left_count.*\\+\\+.*is_left_truncatable|left_trunc_count"
        ),
        new PatternDef("truncatable_pack", "truncatable_pack", "medium",
            "n_tests.*right_count.*0xFFu.*metric_a.*right_sum.*251u|trunc_prime_pack",
            "metric_b.*left_count.*251u.*metric_b.*==.*0u|trunc_prime_metric_b",
            "run_truncatable_primes.*g_result|truncatable_primes_entry"
        ),
        new PatternDef("lucky_primes_sieve", "lucky_primes_sieve", "high",
            "lucky.*lucky_sz.*i.*2u.*MAX_N|lucky_sieve_odd_init",
            "sieve_val.*lucky.*step.*i.*1u.*%.*sieve_val|lucky_sieve_remove_step",
            "build_lucky.*lucky_sz.*step|lucky_sieve_build"
        ),
        new PatternDef("lucky_primes_search", "lucky_primes_search", "high",
            "is_prime.*n.*is_lucky.*n.*count.*\\+\\+.*lp_sum|lucky_prime_find",
            "lo.*hi.*lucky_sz.*mid.*lo.*hi.*1u|lucky_binary_search",
            "lp_sum.*\\+=.*n.*count.*250u|lucky_prime_accumulate250"
        ),
        new PatternDef("lucky_primes_pack", "lucky_primes_pack", "medium",
            "n_tests.*count.*0xFFu.*metric_a.*lp_sum.*251u|lucky_prime_pack",
            "metric_b.*lucky_sz.*251u.*metric_a.*==.*0u|lucky_prime_metric_guard",
            "run_lucky_primes.*g_result|lucky_primes_entry"
        ),
        // ── Sprint 193 ────────────────────────────────────────────────────────
        new PatternDef("happy_primes_happy_check", "happy_primes_happy", "high",
            "digit_sq_sum.*n.*%.*10u.*d.*\\*.*d.*s.*\\+=|happy_digit_sq_loop",
            "n.*==.*1u.*return.*1u.*n.*==.*4u.*return.*0u|happy_cycle_detect",
            "is_happy.*MAX_ITER.*digit_sq_sum|happy_iteration_bound"
        ),
        new PatternDef("happy_primes_search", "happy_primes_search", "high",
            "is_prime.*n.*is_happy.*n.*count.*\\+\\+.*hp_sum|happy_prime_find",
            "hp_sum.*\\+=.*n.*count.*MAX_N|happy_prime_accumulate",
            "run_happy_primes.*g_result|happy_primes_entry"
        ),
        new PatternDef("happy_primes_pack", "happy_primes_pack", "medium",
            "n_tests.*count.*0xFFu.*metric_a.*hp_sum.*251u|happy_prime_pack",
            "metric_b.*hp_sum.*251u.*1u.*251u|happy_prime_metric_b",
            "hp_sum.*MAX_N.*g_result|happy_primes_result"
        ),
        new PatternDef("catalan_primes_check", "catalan_primes_check", "high",
            "catalan_vals.*1u.*1u.*2u.*5u.*14u.*42u|catalan_table_init",
            "is_prime.*catalan_vals.*i.*prime_count.*\\+\\+|catalan_prime_test",
            "cat_sum.*\\+=.*catalan_vals.*idx_sum.*\\+=.*i|catalan_prime_accum"
        ),
        new PatternDef("catalan_primes_search", "catalan_primes_search", "high",
            "prime_count.*cat_sum.*idx_sum.*MAX_CAT.*catalan_vals|catalan_prime_find",
            "catalan_vals.*i.*is_prime.*prime_count.*cat_sum|catalan_prime_loop",
            "run_catalan_primes.*g_result|catalan_primes_entry"
        ),
        new PatternDef("catalan_primes_pack", "catalan_primes_pack", "medium",
            "n_tests.*prime_count.*0xFFu.*metric_a.*cat_sum.*251u|catalan_prime_pack",
            "metric_b.*idx_sum.*MAX_CAT.*251u|catalan_prime_metric_b",
            "catalan_primes.*g_result|catalan_primes_result"
        ),
        new PatternDef("strobogrammatic_primes_rot", "strobogrammatic_digit_rot", "high",
            "rot_digit.*d.*==.*6u.*return.*9u.*d.*==.*9u.*return.*6u|strob_6_9_swap",
            "get_digits.*len.*n.*%.*10u.*buf.*len|strob_digit_extract",
            "is_strobogrammatic.*rot_digit.*digits.*lo.*hi|strob_palindrome_check"
        ),
        new PatternDef("strobogrammatic_primes_search", "strobogrammatic_primes_search", "high",
            "is_prime.*n.*is_strobogrammatic.*n.*count.*\\+\\+.*sp_sum|strob_prime_find",
            "sp_sum.*\\+=.*n.*count.*MAX_N|strob_prime_accumulate",
            "run_strobogrammatic_primes.*g_result|strobogrammatic_primes_entry"
        ),
        new PatternDef("strobogrammatic_primes_pack", "strobogrammatic_primes_pack", "medium",
            "n_tests.*count.*0xFFu.*metric_a.*sp_sum.*251u|strob_prime_pack",
            "metric_b.*sp_sum.*251u.*3u.*251u|strob_prime_metric_b",
            "sp_sum.*MAX_N.*g_result|strob_primes_result"
        ),
        new PatternDef("undulating_primes_digit", "undulating_digit_extract", "high",
            "get_digits_msf.*tmp.*len.*n.*%.*10u.*buf.*i.*tmp.*len.*1u.*i|undulating_msf_extract",
            "digits_msf.*msf.*len.*3u|undulating_min_len",
            "is_undulating.*get_digits_msf.*len.*3u|undulating_check_entry"
        ),
        new PatternDef("undulating_primes_alternation", "undulating_alternation_check", "high",
            "prev_up.*digits.*i.*>.*digits.*i.*1u.*next_up.*digits.*i.*1u.*>.*digits.*i|undulating_direction",
            "prev_up.*==.*next_up.*return.*0u|undulating_flip_fail",
            "is_undulating.*is_prime.*count.*up_sum|undulating_prime_scan"
        ),
        new PatternDef("undulating_primes_pack", "undulating_primes_pack", "medium",
            "n_tests.*count.*0xFFu.*metric_a.*up_sum.*251u|undulating_prime_pack",
            "metric_b.*up_sum.*251u.*3u.*251u|undulating_prime_metric_b",
            "up_sum.*MAX_N.*g_result|undulating_primes_result"
        ),
        new PatternDef("repunit_primes_build", "repunit_build", "high",
            "build_repunit.*r.*0u.*i.*0u.*i.*<.*len.*r.*r.*10u.*1u|repunit_construct",
            "build_repunit.*len.*<.*=.*9u.*32.*bit|repunit_bound",
            "is_prime.*build_repunit.*len.*rp_sum|repunit_prime_test"
        ),
        new PatternDef("repunit_primes_scan", "repunit_scan", "high",
            "for.*len.*2u.*len.*<.*=.*MAX_REPUNIT_LEN.*build_repunit.*len|repunit_loop",
            "is_prime.*r.*count.*rp_sum.*\\+=.*r|repunit_prime_collect",
            "run_repunit_primes.*rp_sum.*count|repunit_run_entry"
        ),
        new PatternDef("repunit_primes_pack", "repunit_primes_pack", "medium",
            "n_tests.*count.*0xFFu.*metric_a.*rp_sum.*251u|repunit_prime_pack",
            "metric_b.*rp_sum.*251u.*5u.*251u|repunit_prime_metric_b",
            "rp_sum.*MAX_REPUNIT_LEN.*g_result|repunit_primes_result"
        ),
        new PatternDef("additive_primes_digit_sum", "additive_digit_sum", "high",
            "digit_sum.*s.*0u.*n.*>.*0u.*s.*\\+=.*n.*%.*10u.*n.*\\/=.*10u|additive_digit_sum_loop",
            "digit_sum.*return.*s|additive_digit_sum_return",
            "is_prime.*digit_sum.*n.*additive|additive_digitsum_prime_check"
        ),
        new PatternDef("additive_primes_scan", "additive_scan", "high",
            "is_prime.*n.*&&.*is_prime.*digit_sum.*n.*count.*ap_sum|additive_prime_scan",
            "ap_sum.*\\+=.*n.*count.*MAX_N|additive_prime_accumulate",
            "run_additive_primes.*g_result|additive_primes_entry"
        ),
        new PatternDef("additive_primes_pack", "additive_primes_pack", "medium",
            "n_tests.*count.*0xFFu.*metric_a.*ap_sum.*251u|additive_prime_pack",
            "metric_b.*ap_sum.*251u.*4u.*251u|additive_prime_metric_b",
            "ap_sum.*MAX_N.*g_result|additive_primes_result"
        ),
        new PatternDef("sphenic_numbers_squarefree", "sphenic_squarefree_check", "high",
            "n.*%.*4u.*==.*0u.*return.*0u|sphenic_squarefree_even",
            "d.*\\*.*d.*<=.*n.*n.*%.*d.*\\*.*d.*==.*0u.*return.*0u|sphenic_squarefree_odd",
            "is_squarefree.*n.*count_distinct_prime_factors.*n.*==.*3u|sphenic_three_factor_check"
        ),
        new PatternDef("sphenic_numbers_factor_count", "sphenic_factor_count", "high",
            "count_distinct_prime_factors.*n.*while.*n.*%.*2u.*==.*0u.*n.*\\/=.*2u|sphenic_factor_2",
            "count.*n.*%.*d.*==.*0u.*count\\+\\+.*while.*n.*%.*d.*==.*0u.*n.*\\/=.*d|sphenic_factor_odd",
            "n.*>.*1u.*count\\+\\+.*return.*count|sphenic_factor_residual"
        ),
        new PatternDef("sphenic_numbers_pack", "sphenic_numbers_pack", "medium",
            "sp_sum.*%.*251u.*sp_sum.*\\/.*251u.*5u.*%.*251u|sphenic_metric_pack",
            "run_sphenic_numbers.*g_result|sphenic_result_store",
            "n_tests.*<<.*16u.*metric_a.*<<.*8u.*metric_b|sphenic_result_combine"
        ),
        new PatternDef("ore_numbers_divisor_stats", "ore_divisor_stats", "high",
            "divisor_stats.*n.*d_count.*d_sum.*i.*\\*.*i.*<=.*n|ore_divisor_loop",
            "n.*%.*i.*==.*0u.*cnt\\+\\+.*sum.*\\+=.*i.*i.*!=.*n.*\\/.*i|ore_divisor_pair",
            "cnt\\+\\+.*sum.*\\+=.*n.*\\/.*i.*d_count.*d_sum|ore_divisor_output"
        ),
        new PatternDef("ore_numbers_harmonic_check", "ore_harmonic_check", "high",
            "ds.*>.*0u.*n.*\\*.*dc.*%.*ds.*==.*0u|ore_harmonic_divisible",
            "divisor_stats.*n.*dc.*ds.*n.*\\*.*dc.*%.*ds|ore_harmonic_test",
            "count\\+\\+.*ore_sum.*\\+=.*n|ore_harmonic_accumulate"
        ),
        new PatternDef("ore_numbers_pack", "ore_numbers_pack", "medium",
            "ore_sum.*%.*251u.*ore_sum.*\\/.*251u.*3u.*%.*251u|ore_metric_pack",
            "run_ore_numbers.*g_result|ore_result_store",
            "n_tests.*<<.*16u.*metric_a.*<<.*8u.*metric_b|ore_result_combine"
        ),
        new PatternDef("hoax_numbers_digit_sum", "hoax_digit_sum", "high",
            "digit_sum.*n.*s.*\\+=.*n.*%.*10u.*n.*\\/=.*10u|hoax_digit_accumulate",
            "prime_factor_digit_sum.*n.*digit_sum.*2u.*while.*n.*%.*2u.*==.*0u|hoax_pf_digit_2",
            "digit_sum.*d.*while.*n.*%.*d.*==.*0u.*n.*\\/=.*d|hoax_pf_digit_odd"
        ),
        new PatternDef("hoax_numbers_composite_check", "hoax_composite_check", "high",
            "is_prime.*n.*continue.*digit_sum.*n.*==.*prime_factor_digit_sum.*n|hoax_composite_filter",
            "count\\+\\+.*hoax_sum.*\\+=.*n|hoax_accumulate",
            "run_hoax_numbers.*g_result|hoax_result_store"
        ),
        new PatternDef("hoax_numbers_pack", "hoax_numbers_pack", "medium",
            "hoax_sum.*%.*251u.*hoax_sum.*\\/.*251u.*6u.*%.*251u|hoax_metric_pack",
            "n_tests.*count.*0xFFu.*metric_a.*hoax_sum.*251u|hoax_pack_n_tests",
            "n_tests.*<<.*16u.*metric_a.*<<.*8u.*metric_b|hoax_result_combine"
        ),
        new PatternDef("prime_quadruplets_sieve", "prime_quadruplets_sieve", "high",
            "is_prime.*p.*is_prime.*p.*2u.*is_prime.*p.*6u.*is_prime.*p.*8u|quadruplet_test",
            "count\\+\\+.*quad_sum.*\\+=.*p.*%.*251u|quadruplet_accumulate",
            "p.*5u.*p.*8u.*<=.*MAX_N|quadruplet_range_loop"
        ),
        new PatternDef("prime_quadruplets_check", "prime_quadruplets_check", "high",
            "is_prime.*p.*&&.*is_prime.*p.*2.*&&.*is_prime.*p.*6.*&&.*is_prime.*p.*8|quadruplet_all_prime",
            "quad_sum.*\\+=.*p.*%.*251u|quadruplet_sum_mod",
            "run_prime_quadruplets.*g_result|quadruplet_result_store"
        ),
        new PatternDef("prime_quadruplets_pack", "prime_quadruplets_pack", "medium",
            "quad_sum.*%.*251u.*quad_sum.*\\/.*251u.*7u.*%.*251u|quadruplet_metric_pack",
            "n_tests.*count.*0xFFu.*metric_a.*quad_sum.*251u|quadruplet_pack_n_tests",
            "n_tests.*<<.*16u.*metric_a.*<<.*8u.*metric_b|quadruplet_result_combine"
        ),
        new PatternDef("interprime_numbers_find", "interprime_numbers_find", "high",
            "next_prime.*n.*p.*n.*1u.*while.*p.*2u.*is_prime.*p|interprime_bracket_search",
            "p.*q.*==.*2u.*n|interprime_average_check",
            "p.*n.*1u.*while.*p.*>=.*2u.*is_prime.*p|interprime_prev_prime"
        ),
        new PatternDef("interprime_numbers_accum", "interprime_numbers_accum", "high",
            "count\\+\\+.*ip_sum.*\\+=.*n.*%.*251u|interprime_accumulate",
            "is_prime.*n.*continue.*next_prime.*n|interprime_composite_filter",
            "run_interprime_numbers.*g_result|interprime_result_store"
        ),
        new PatternDef("interprime_numbers_pack", "interprime_numbers_pack", "medium",
            "ip_sum.*%.*251u.*ip_sum.*\\/.*251u.*8u.*%.*251u|interprime_metric_pack",
            "n_tests.*count.*0xFFu.*metric_a.*ip_sum.*251u|interprime_pack_n_tests",
            "n_tests.*<<.*16u.*metric_a.*<<.*8u.*metric_b|interprime_result_combine"
        ),
        new PatternDef("achilles_numbers_powerful", "achilles_numbers_powerful", "high",
            "prime_exp.*m.*2u.*<.*2u.*return.*0u|achilles_powerful_check",
            "is_powerful.*n.*&&.*is_perfect_power.*n|achilles_filter",
            "prime_exp.*n.*p.*while.*n.*%.*p.*==.*0u|achilles_exp_count"
        ),
        new PatternDef("achilles_numbers_perfect_power", "achilles_numbers_perfect_power", "high",
            "is_perfect_power.*n.*1u.*<<.*k.*<=.*n|achilles_power_kth_root",
            "pw.*>.*n.*\\/.*r.*1u.*overflow.*1u|achilles_overflow_guard",
            "count\\+\\+.*ach_sum.*\\+=.*n.*%.*251u|achilles_accumulate"
        ),
        new PatternDef("achilles_numbers_pack", "achilles_numbers_pack", "medium",
            "ach_sum.*%.*251u.*ach_sum.*\\/.*251u.*6u.*%.*251u|achilles_metric_pack",
            "n_tests.*count.*0xFFu.*metric_a.*ach_sum.*251u|achilles_pack_n_tests",
            "n_tests.*<<.*16u.*metric_a.*<<.*8u.*metric_b|achilles_result_combine"
        ),
        new PatternDef("zeisel_numbers_factorize", "zeisel_numbers_factorize", "high",
            "spf.*n.*n.*%.*2u.*==.*0u.*return.*2u|zeisel_smallest_prime",
            "distinct_primes.*n.*pf.*maxpf.*cnt.*last.*spf|zeisel_extract_primes",
            "d1.*d0.*pf.*1.*pf.*0.*d1.*%.*d0.*!=.*0u|zeisel_recurrence_check"
        ),
        new PatternDef("zeisel_numbers_linear_rec", "zeisel_numbers_linear_rec", "high",
            "a.*d1.*\\/.*d0.*pf.*1.*a.*pf.*0.*b.*pf.*1.*apf0|zeisel_ab_compute",
            "pf.*i.*!=.*a.*pf.*i.*1u.*\\+.*b.*return.*0u|zeisel_verify_factors",
            "is_zeisel.*n.*count\\+\\+.*zsum.*\\+=.*n|zeisel_accumulate"
        ),
        new PatternDef("zeisel_numbers_pack", "zeisel_numbers_pack", "medium",
            "count.*0xFFu.*zsum.*%.*251u|zeisel_metric_pack",
            "n_tests.*499u.*count.*8u.*zsum.*2135u|zeisel_expected_values",
            "n_tests.*<<.*16u.*metric_a.*<<.*8u.*metric_b|zeisel_result_combine"
        ),
        new PatternDef("hyperperfect_numbers_sigma", "hyperperfect_numbers_sigma", "high",
            "sigma_s.*n.*s.*0u.*d.*2u.*d.*<.*n.*n.*%.*d.*==.*0u|hyperperfect_div_sum",
            "is_hyperperfect.*n.*s.*sigma_s.*n.*s.*==.*0u|hyperperfect_zero_guard",
            "n.*1u.*%.*s.*!=.*0u.*k.*n.*1u.*\\/.*s.*k.*>=.*1u|hyperperfect_k_check"
        ),
        new PatternDef("hyperperfect_numbers_classify", "hyperperfect_numbers_classify", "high",
            "is_hyperperfect.*n.*count\\+\\+.*hsum.*\\+=.*n|hyperperfect_accumulate",
            "n_tests.*299u.*count.*3u.*hsum.*55u|hyperperfect_expected_values",
            "k.*1.*perfect.*k.*2.*2_hyperperfect|hyperperfect_k_family"
        ),
        new PatternDef("hyperperfect_numbers_pack", "hyperperfect_numbers_pack", "medium",
            "count.*0xFFu.*hsum.*%.*251u|hyperperfect_metric_pack",
            "n_tests.*<<.*16u.*metric_a.*<<.*8u.*metric_b|hyperperfect_result_combine",
            "hsum.*%.*251u.*55u.*metric_b|hyperperfect_metric_b"
        ),
        new PatternDef("vampire_numbers_digits", "vampire_numbers_digits", "high",
            "sort4.*dn.*dn.*0.*n.*1000u.*dn.*1.*n.*100u.*%.*10u|vampire_digit_extract",
            "a.*10u.*a.*<=.*99u.*n.*%.*a.*!=.*0u.*b.*n.*\\/.*a|vampire_fang_loop",
            "a.*%.*10u.*==.*0u.*b.*%.*10u.*==.*0u.*continue|vampire_double_zero_reject"
        ),
        new PatternDef("vampire_numbers_multiset", "vampire_numbers_multiset", "high",
            "df.*0.*a.*10u.*df.*1.*a.*%.*10u.*df.*2.*b.*10u|vampire_fang_digits",
            "sort4.*df.*df.*k.*!=.*dn.*k.*match.*0u|vampire_digit_multiset_cmp",
            "is_vampire4.*n.*count\\+\\+.*vsum.*\\+=.*n|vampire_accumulate"
        ),
        new PatternDef("vampire_numbers_pack", "vampire_numbers_pack", "medium",
            "count_lo.*n.*<.*5000u.*vsum.*%.*251u|vampire_metric_pack",
            "n_tests.*7u.*count_lo.*6u.*vsum.*16514u|vampire_expected_values",
            "n_tests.*<<.*16u.*metric_a.*<<.*8u.*metric_b|vampire_result_combine"
        ),
        new PatternDef("frugal_numbers_digit_count", "frugal_numbers_digit_count", "high",
            "digit_count.*n.*0u.*return.*1u.*d.*0u.*n.*0u.*n.*\\/.*10u.*d\\+\\+|frugal_digit_count",
            "factorization_digits.*fd.*0u.*d.*2u.*d.*d.*<=.*n.*n.*%.*d.*==.*0u|frugal_factor_loop",
            "exp.*1u.*fd.*digit_count.*exp|frugal_exp_digits"
        ),
        new PatternDef("frugal_numbers_classify", "frugal_numbers_classify", "high",
            "is_frugal.*factorization_digits.*n.*<.*digit_count.*n|frugal_strict_less",
            "is_frugal.*n.*<.*2u.*return.*0u|frugal_trivial_reject",
            "count\\+\\+.*fsum.*\\+=.*n.*is_frugal|frugal_accumulate"
        ),
        new PatternDef("frugal_numbers_pack", "frugal_numbers_pack", "medium",
            "metric_a.*count.*0xFFu.*metric_b.*fsum.*%.*251u|frugal_metric_pack",
            "n_tests.*<<.*16u.*metric_a.*<<.*8u.*metric_b|frugal_result_combine",
            "n_tests.*499u.*fsum.*%.*251u|frugal_expected_values"
        ),
        new PatternDef("equidigital_numbers_digit_count", "equidigital_numbers_digit_count", "high",
            "factorization_digits.*n.*==.*digit_count.*n|equidigital_equal_test",
            "is_equidigital.*n.*<.*2u.*return.*0u|equidigital_trivial_reject",
            "exp.*1u.*fd.*digit_count.*exp|equidigital_exp_digits"
        ),
        new PatternDef("equidigital_numbers_classify", "equidigital_numbers_classify", "high",
            "is_equidigital.*factorization_digits.*==.*digit_count|equidigital_equal_classify",
            "count\\+\\+.*esum.*\\+=.*n.*is_equidigital|equidigital_accumulate",
            "d.*2u.*d.*d.*<=.*n.*n.*%.*d.*0u.*exp.*0u|equidigital_factor_trial"
        ),
        new PatternDef("equidigital_numbers_pack", "equidigital_numbers_pack", "medium",
            "metric_a.*count.*0xFFu.*metric_b.*esum.*%.*251u|equidigital_metric_pack",
            "n_tests.*<<.*16u.*metric_a.*<<.*8u.*metric_b|equidigital_result_combine",
            "n_tests.*499u.*esum.*%.*251u|equidigital_expected_values"
        ),
        new PatternDef("multiply_perfect_sigma", "multiply_perfect_sigma", "high",
            "sigma.*n.*s.*0u.*d.*1u.*d.*d.*<=.*n.*n.*%.*d.*==.*0u.*s.*\\+=.*d|multiply_perfect_sigma_loop",
            "d.*!=.*n.*\\/.*d.*s.*\\+=.*n.*\\/.*d|multiply_perfect_sigma_pair",
            "is_multiply_perfect.*sigma.*n.*%.*n.*==.*0u.*s.*\\/.*n.*>=.*2u|multiply_perfect_ktest"
        ),
        new PatternDef("multiply_perfect_classify", "multiply_perfect_classify", "high",
            "is_multiply_perfect.*n.*<.*2u.*return.*0u|multiply_perfect_trivial_reject",
            "count\\+\\+.*msum.*\\+=.*n.*is_multiply_perfect|multiply_perfect_accumulate",
            "s.*\\/.*n.*>=.*2u.*sigma.*k.*perfect|multiply_perfect_k_ge2"
        ),
        new PatternDef("multiply_perfect_pack", "multiply_perfect_pack", "medium",
            "metric_a.*count.*0xFFu.*metric_b.*msum.*%.*251u|multiply_perfect_metric_pack",
            "n_tests.*<<.*16u.*metric_a.*<<.*8u.*metric_b|multiply_perfect_result_combine",
            "n_tests.*199u.*msum.*%.*251u|multiply_perfect_expected_values"
        ),
        new PatternDef("permutable_primes_check", "permutable_primes_check", "high",
            "all_perms_prime.*digits.*len.*is_prime.*num|permutable_prime_all_perms",
            "next_permutation.*pivot.*swap_idx.*digits.*reverse_suffix|permutable_next_perm",
            "is_permutable_prime.*is_prime.*num_digits.*all_perms_prime|permutable_top_level"
        ),
        new PatternDef("permutable_primes_count", "permutable_primes_count", "medium",
            "count\\+\\+.*psum.*\\+=.*n.*is_permutable_prime|permutable_accumulate",
            "n_tests.*199u.*psum.*%.*251u|permutable_expected_values",
            "metric_a.*count.*0xFFu.*metric_b.*psum.*%.*251u|permutable_metric_pack"
        ),
        new PatternDef("permutable_primes_pack", "permutable_primes_pack", "medium",
            "n_tests.*<<.*16u.*metric_a.*<<.*8u.*metric_b|permutable_result_combine",
            "g_result.*0x00C71088|permutable_result_constant",
            "metric_b.*136u.*metric_a.*16u|permutable_known_counts"
        ),
        new PatternDef("untouchable_numbers_sieve", "untouchable_numbers_sieve", "high",
            "proper_div_sum.*m.*sv.*reachable.*sv|untouchable_sieve_mark",
            "m.*<=.*50000u.*reachable.*sv.*1u|untouchable_sieve_bound",
            "for.*m.*2u.*m.*50000u.*sv.*proper_div_sum|untouchable_outer_sieve"
        ),
        new PatternDef("untouchable_numbers_count", "untouchable_numbers_count", "medium",
            "reachable.*n.*count\\+\\+.*usum.*\\+=.*n|untouchable_accumulate",
            "n_tests.*199u.*usum.*%.*251u|untouchable_expected_values",
            "metric_a.*count.*0xFFu.*metric_b.*usum.*%.*251u|untouchable_metric_pack"
        ),
        new PatternDef("untouchable_numbers_pack", "untouchable_numbers_pack", "medium",
            "n_tests.*<<.*16u.*metric_a.*<<.*8u.*metric_b|untouchable_result_combine",
            "g_result.*0x00C70AE6|untouchable_result_constant",
            "metric_b.*230u.*metric_a.*10u|untouchable_known_counts"
        ),
        new PatternDef("colossally_abundant_check", "colossally_abundant_check", "high",
            "sigma.*n.*sn.*is_superabundant.*sn.*m.*sm.*n|colossally_abundant_super_check",
            "sig_cache.*sn.*is_colossally_abundant|colossally_abundant_cache",
            "for.*m.*1u.*m.*n.*sm.*sig_cache.*sigma.*m|colossally_abundant_dominance"
        ),
        new PatternDef("colossally_abundant_count", "colossally_abundant_count", "medium",
            "count\\+\\+.*casum.*\\+=.*n.*is_colossally_abundant|colossally_abundant_accumulate",
            "n_tests.*199u.*casum.*%.*251u|colossally_abundant_expected_values",
            "metric_a.*count.*0xFFu.*metric_b.*casum.*%.*251u|colossally_abundant_metric_pack"
        ),
        new PatternDef("colossally_abundant_pack", "colossally_abundant_pack", "medium",
            "n_tests.*<<.*16u.*metric_a.*<<.*8u.*metric_b|colossally_abundant_result_combine",
            "g_result.*0x00C706C9|colossally_abundant_result_constant",
            "metric_b.*201u.*metric_a.*6u|colossally_abundant_known_counts"
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
