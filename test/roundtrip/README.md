# Round-Trip Validation

Validates the full decompiler pipeline: **compile → decompile → recompile → verify**.

The suite ships 76 bare-metal RISC-V fixtures covering a broad range of algorithm
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
| `test_trie.c` | Prefix trie: 26-child array, insert 6 words, 8 searches (5 found), XOR of lengths | `0x00060507` | |
| `test_quicksort.c` | Lomuto quicksort: sort {5,3,8,1,7,2,9,4,6} in-place; verify XOR+sum of output | `0x00092D01` | |
| `test_dp.c` | LCS DP: 2D table for "ABCBDAB" vs "BDCAB", length=4 | `0x00070504` | |
| `test_mergesort.c` | Top-down stable merge sort: {9,2,7,1,5,3,8,4,6,0} → {0..9}, two-pointer merge | `0x000A2D01` | |
| `test_union_find.c` | Union-Find with path compression + union by rank; 8 nodes, 7 unions | `0x00080700` | |
| `test_bfs.c` | BFS on 7-node tree graph; shortest-path distances from source 0 | `0x00070B01` | |
| `test_knapsack.c` | 0/1 Knapsack 1D DP with reverse iteration; 4 items, W=8, optimal=10 | `0x0004080A` | |
| `test_dfs.c` | Recursive DFS on 6-node DAG; finish times: {6,4,5,3,2,1}, sum=21, xor=7 | `0x00061507` | |
| `test_kmp.c` | KMP pattern matching: "ABABABABC" / "ABABC", match at pos 4 | `0x00090504` | |
| `test_dijkstra.c` | Dijkstra SSSP on 5-node weighted DAG; dist={0,2,5,7,8}, sum=22, xor=8 | `0x00051608` | |
| `test_binary_search.c` | Range binary search on {2,4,4,4,4,8…}; target=4, first=1, count=4 | `0x000A0104` | |
| `test_toposort.c` | Kahn's topological sort on 6-node DAG; order=[4,5,0,2,3,1], sum=15, xor=1 | `0x00060F01` | |
| `test_fib_memo.c` | Top-down memoized Fibonacci fib(0..9); fib(9)=34, xor_all=54 | `0x000A2236` | |
| `test_sieve.c` | Sieve of Eratosthenes ≤50; 15 primes, last=47, xor=26 | `0x000F2F1A` | |
| `test_edit_dist.c` | Levenshtein edit distance "KITTEN"→"SITTING" via 2D DP; dist=3 | `0x00060703` | |
| `test_bellman_ford.c` | Bellman-Ford SSSP on 5-node graph with neg weights; dist={0,6,7,2,4}, sum=19, xor=7 | `0x00051307` | |
| `test_counting_sort.c` | Stable counting sort {4,2,2,8,3,3,1,4,1,8}→{1…8,8}; sum=36, xor=0 | `0x000A2400` | |
| `test_floyd_warshall.c` | Floyd-Warshall all-pairs SP on 4-node graph; sum_off_diag=46, xor=2 | `0x00042E02` | |
| `test_bitset.c` | Word bitset union/intersect: A={1,3,5,7,9,11}, B={3,5,7,11,13,17}; pop_u=8, pop_i=4 | `0x0008041E` | |
| `test_pow_mod.c` | Fast modular exponentiation (square-and-multiply); 4 calls, sum=141, xor=83 | `0x00048D53` | |
| `test_segment_tree.c` | Segment tree range sum n=8; queries [0..7]=72,[2..5]=36,[1..4]=28; xor=112 | `0x00084870` | |
| `test_fenwick.c` | Fenwick/BIT prefix sums n=6 {1,3,5,7,9,11}; prefix(1)=1,prefix(3)=9,prefix(6)=36, xor=44 | `0x0006242C` | |
| `test_lis.c` | LIS patience sort {3,1,4,1,5,9,2,6,5,3,5}; length=4, pile-tops={1,2,3,5}, xor=5 | `0x000B0405` | |
| `test_zfunc.c` | Z-function on "AABAAB" n=6; z={0,1,0,3,1,0}, sum=5, xor=3 | `0x00060503` | |
| `test_radix_sort.c` | LSD radix sort base-16 2-pass; {45,12,78,23,56,89,34,67}→sorted; last=89, xor=120 | `0x00085978` | |
| `test_manacher.c` | Manacher palindrome on "ABACABA"; P max=7 (full string), sum=17 | `0x00070711` | |
| `test_coin_change.c` | Coin change min-coins DP {1,5,12,25}; dp[11]=3,dp[14]=3,dp[30]=2 | `0x00040802` | |
| `test_kadane.c` | Kadane max subarray {-2,1,-3,4,-1,2,1,-5,4}; max=6 at [3..6] | `0x00090636` | |
| `test_ext_gcd.c` | Extended GCD Bezout coefficients on 3 pairs; gcd={5,6,25} sum=36 xor=26 | `0x0003241A` | |
| `test_sparse_table.c` | Sparse table RMQ n=8 {3,7,1,9,2,8,5,4}; RMQ(0,1)=3,RMQ(1,4)=1,RMQ(5,7)=4 | `0x00080806` | |
| `test_activity_sel.c` | Activity selection greedy n=6; sorted by end, count=4, sum_end=22 | `0x00060416` | |
| `test_lps.c` | Longest Palindromic Subsequence "BBABCBCAB" n=9; LPS=7, n-LPS=2 | `0x00090702` | |
| `test_dutch_flag.c` | Dutch National Flag 3-way partition {2,0,2,1,1,0} pivot=1; lo=2, mid=4 | `0x00060204` | |
| `test_prim_mst.c` | Prim's MST n=5 dense O(n²); edges 0-1(2),1-2(3),1-4(5),0-3(6); weight=16 | `0x00051004` | |
| `test_subset_sum.c` | Subset sum boolean DP {3,5,2,8,7}; targets {10,12,11} all reachable; xor=13 | `0x0005030D` | |
| `test_next_greater.c` | Next Greater Element monotonic stack {4,5,2,10,8,3,6,1}; count=4, xor=3 | `0x00080403` | |
| `test_josephus.c` | Josephus recurrence pos=(pos+k)%i; (n=10,k=3)→4, (n=7,k=2)→7, (n=12,k=4)→1 | `0x000A0C02` | |
| `test_quick_select.c` | QuickSelect k-th smallest Lomuto; {7,2,1,6,5,3,4,8} k∈{0,3,7}→{1,4,8} | `0x00080D0D` | |
| `test_matrix_chain.c` | Matrix chain mult DP; dims={2,3,4,5} n=3; dp[0][2]=64, dp[0][1]=24 | `0x00034018` | |
| `test_kruskal.c` | Kruskal's MST with path-compressed Union-Find; n=5 graph; weight=12, edges=4 | `0x00050C04` | |
| `test_floyd_cycle.c` | Floyd tortoise-hare; next={1,2,3,4,2,6,2}; cycle_start=2, len=3 | `0x00070203` | |
| `test_sliding_window.c` | Sliding window max monotonic deque; {1,3,-1,-3,5,3,6,7} w=3; sum=29 xor=1 | `0x00081D01` | |
| `test_bitmask_enum.c` | Bitmask enumeration 2^n subsets; {2,3,7,5} div-by-3; count=6 max=15 | `0x0004060F` | |
| `test_two_pointer.c` | Two-pointer pair sum {1..10} target=11; 5 pairs; xor of lo-values=1 | `0x000A0501` | |
| `test_min_stack.c` | Min-stack dual array; push{5,3,7,2}; getMin seq={2,3,3,5}; sum=13 xor=7 | `0x00040D07` | |
| `test_boyer_moore_vote.c` | Boyer-Moore majority vote {3,2,3,1,3,3,2}; candidate=3, freq=4 | `0x00070304` | |
| `test_count_inversions.c` | Count inversions merge sort {6,5,4,3,2,1}; inv=15 xor=7 | `0x00060F07` | |
| `test_jump_search.c` | Jump search O(√n); {1,3..19} block=3; find{7,13,19}; xor_idx=12 | `0x000A030C` | |
| `test_lc_substring.c` | Longest Common Substring DP; "ABABC"/"BABCAB"; lcs=4 ("BABC") | `0x00050604` | |
| `test_catalan.c` | Catalan numbers DP C(0..5)={1,1,2,5,14,42}; sum(C3+C4+C5)=61 xor=33 | `0x00063D21` | |
| `test_shell_sort.c` | Shell sort gap-halving; {8,3,7,1,5,2,9,4} n=8; last=9 xor=7 | `0x00080907` | |
| `test_interpolation_search.c` | Interp search; {1,3,..15} n=8; find{7,13}→{3,6}; count=2 xor=5 | `0x00080205` | |
| `test_n_queens.c` | N-Queens backtrack; N=4:2,N=5:10,N=6:4; sum=16 xor=12 | `0x0006100C` | |
| `test_rabin_karp.c` | Rabin-Karp rolling hash; "aaabaabaab" pat="aab" BASE=26 MOD=101; matches 1,4,7; count=3 xor=2 | `0x000A0302` | |
| `test_pancake_sort.c` | Pancake sort; {3,6,1,5,2,4} n=6; sorted last=6 xor=7 | `0x00060607` | |
| `test_comb_sort.c` | Comb sort gap*10/13; {5,2,8,1,9,3,6} n=7; sorted last=9 xor=2 | `0x00070902` | |
| `test_cycle_sort.c` | Cycle sort min-writes; {3,1,5,4,2} n=5; writes=4 xor=1 | `0x00050401` | |

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
158 algorithm patterns using multi-regex heuristics. Run it as a Ghidra post-script
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
| Data structures | BST insert / in-order traverse, min-heap insert / extract-min, AVL rotate / balance, trie insert / search |
| Codecs | RLE encode/decode run scanning, Base64 6-bit extraction + table |
| Divide & conquer | Quicksort Lomuto partition + recursive sub-range split, merge sort two-pointer merge + mid-split |
| Dynamic programming | 2D DP table fill, LCS diagonal/max pattern |
| Graph algorithms | Union-Find path compression, union by rank, BFS queue + distance relaxation, DFS visited-mark + finish-time |
| String algorithms | KMP failure function backtrack, KMP full-match detection |
| Graph shortest-path | Dijkstra edge relaxation, linear min-scan for unvisited node |
| Binary search variants | lo/hi/mid bisection frame, leftmost/rightmost range convergence |
| Topological sort | Kahn's in-degree decrement + BFS queue, topo order output |
| Memoization DP | Fibonacci cache-check hit, recursive memoize-before-return |
| Number theory | Sieve outer i*i bound + composite marking, prime scan |
| Edit distance DP | Levenshtein 2D fill with 3-way min, character equality check |
| Bellman-Ford | n-1 relaxation passes + INF guard, negative-cycle final pass |
| Counting sort | Frequency count by value, prefix-sum, stable right-to-left output |
| Floyd-Warshall | Triple k/i/j loop + INF guard + 2D relaxation |
| Bitset | Shift-set / shift-test, Kernighan popcount, word-level OR/AND |
| Modular arithmetic | Square-and-multiply loop (while exp>0 + right-shift + squaring) |
| Segment tree | Bottom-up build (2i/2i+1 formula), l/r odd-boundary query halving |
| Fenwick tree | i+=i&(-i) update / i-=i&(-i) prefix-sum (lowest-set-bit trick) |
| LIS patience sort | Patience sort: binary search in piles + piles[lo]=v + if(lo==np)np++ |
| Z-function | [l,r) window + if(i<r)min(r-i,z[i-l]) init + s[z[i]]==s[i+z[i]] extend loop |
| LSD radix sort | Low/high nibble key (arr&0xF, arr>>4) + stable right-to-left --cnt[key] output |
| Manacher's palindrome | mirror=2*c-i + if(i<r)min(r-i,p[mirror]) init + T[i±p±1] expand |
| Coin change DP | dp[0]=0; dp[i]=inf; for each coin: dp[i]=min(dp[i], dp[i-c]+1) |
| Kadane max-subarray | if(cur+a[i]>a[i])extend else restart + global-max update idiom |
| Extended Euclidean GCD | if(b==0)*x=1,*y=0; recursive: *x=y1, *y=x1-(a/b)*y1 |
| Sparse table RMQ | Build st[j][i]=min(st[j-1][i],st[j-1][i+(1<<(j-1))]); query min(st[k][l],st[k][r-(1<<k)+1]) |
| Activity selection | Sort by .end; greedy: if(start≥last_end){count++;last_end=end} |
| LPS interval DP | for(len=2..n) j=i+len-1; if(s[i]==s[j])dp+2 else max(dp[i+1][j],dp[i][j-1]) |
| Dutch National Flag | while(mid≤hi) 3-branch: <pivot swap+lo++mid++; ==pivot mid++; >pivot swap+hi-- |
| Prim's MST | min-key scan (!in_mst && key<best); relax adj[u][v] < key[v] |
| Subset sum DP | dp[0]=1; for each v: for j=limit..v: dp[j]\|=dp[j-v] (boolean 0/1) |
| Next Greater Element | while(top>=0 && arr[stack[top]]<arr[i]) nge[stack[top--]]=arr[i]; stack[++top]=i |
| Josephus recurrence | pos=0; for i=2..n: pos=(pos+k)%i; survivor=pos+1 |
| QuickSelect | Lomuto partition; if(pivot==k)return; recurse only one side |
| Matrix chain DP | l=2..n diagonal; dp[i][j]=min(dp[i][k]+dp[k+1][j]+dims product) |
| Kruskal's MST | sort edges; if find(u)!=find(v): union+accumulate weight |
| Floyd cycle detection | phase1: do{slow=f; fast=f(f)}while≠; phase2: slow=0,advance; phase3: count |
| Sliding window max | pop-back while arr[back]<=arr[i]; pop-front stale; emit arr[deq[head]] |
| Bitmask enumeration | for mask=0..1<<n: for b=0..n: if(mask&(1<<b)) sum+=items[b] |
| Two-pointer pair sum | lo/hi converge; s==target: lo++,hi--; s<target: lo++; else hi-- |
| Minimum stack | push: min_stk[top]=min(x,min_stk[top-1]); getMin: min_stk[top-1] |
| Boyer-Moore majority vote | if(count==0) reset; else ==candidate count++; else count-- |
| Count inversions (merge sort) | cnt+=mid-i when arr[right]<arr[left] in merge step |
| Jump search | step forward by √n; linear scan back on overshoot |
| Longest common substring DP | dp[i][j]=dp[i-1][j-1]+1 on match; else 0 (reset vs LCS) |
| Catalan numbers DP | cat[n]=sum(cat[i]*cat[n-1-i]); index complement idiom |
| Shell sort | outer gap=n/2;gap/=2; inner: j-=gap strided shift |
| Interpolation search | value-weighted probe: lo+(key-arr[lo])*(hi-lo)/(arr[hi]-arr[lo]) |
| N-Queens backtracking | three-array col/diag1/diag2; anti-diag index row-c+n-1; triple set/unset |
| Rabin-Karp rolling hash | h_pow=BASE^(m-1)%MOD; rolling: remove-leading-and-slide; char verify on collision |
| Pancake sort | find-max in [0..size); double flip; skip-if-in-place guard |
| Comb sort | gap=gap*10/13 shrink; while(gap>1 || !sorted) outer condition |
| Cycle sort | position count loop; nested cycle rotation; explicit writes counter; skip-duplicates guard |
| Dynamic programming (extra) | 0/1 knapsack 1D reverse iteration, capacity-subproblem table access |

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
