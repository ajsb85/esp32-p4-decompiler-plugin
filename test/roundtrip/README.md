# Round-Trip Validation

Validates the full decompiler pipeline: **compile → decompile → recompile → verify**.

The suite ships 201 bare-metal RISC-V fixtures covering a broad range of algorithm
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
| `test_ternary_search.c` | Ternary search min(x-t)^2; 3 queries {3,5,8}→min; sum=16 xor=14 | `0x0003100E` | |
| `test_miller_rabin.c` | Miller-Rabin primality; {2,3,5,9,11,15,17,97}; prime count=6 xor=127 | `0x0008067F` | |
| `test_max_rect_histogram.c` | Max rect in histogram; {2,1,5,6,2,3} n=6; max_area=10 xor=1 | `0x00060A01` | |
| `test_trapping_rain.c` | Trapping rain two-pointer; {4,2,0,3,2,5} n=6; water=9 xor=2 | `0x00060902` | |
| `test_jump_game.c` | Jump game greedy; 5 tests; reachable count=3 xor=1 | `0x00050301` | |
| `test_gas_station.c` | Gas station greedy; 3 tests; valid starts=2 xor=7 | `0x00030207` | |
| `test_bipartite_check.c` | Bipartite BFS 2-coloring; triangle/square/pentagon; bipartite count=1 xor=1 | `0x00030101` | |
| `test_kahn_toposort.c` | Kahn toposort BFS in-degree; 6-node DAG; n_init_zero=2 last=1 | `0x00060201` | |
| `test_word_break.c` | Word break DP; "leetcode"/"applepenapple"/"catsandog"; count_yes=2 xor=12 | `0x0003020C` | |
| `test_count_paths_dag.c` | DAG path count memoized; 6-node DAG; paths(0,5)=4 xor_all=6 | `0x00060406` | |
| `test_euler_totient.c` | Euler's totient φ(n) via prime factorisation; φ{12,13,36,100}={4,12,12,40}; sum=68 xor=44 | `0x0004442C` | |
| `test_difference_array.c` | Difference array O(1) range-update + prefix-sum reconstruct; A={3,5,5,3,3,1}; sum=20 xor=2 | `0x00061402` | |
| `test_crt.c` | Chinese Remainder Theorem (direct construction + mod_inv); 3 instances; sum=71 xor=25 | `0x00034719` | |
| `test_longest_bitonic.c` | Longest Bitonic Subsequence O(n²) DP; {1,5,2,8,3}; max_lbs=4 xor_lbs=7 | `0x00050407` | |
| `test_hamming.c` | Hamming distance pairwise + total array; pairs sum=9; total HD of {4,14,2}=6 | `0x00030906` | |
| `test_palindrome_partition.c` | Min palindrome cuts interval DP; "aab"/"abcba"/"aabbc"; cuts sum=3 xor=3 | `0x00030303` | |
| `test_rotate_array.c` | Array rotation 3-reversal method; {1..7} right by 2→{6,7,1,2,3,4,5}; last=5 | `0x00070205` | |
| `test_matrix_power.c` | Matrix fast exponentiation for Fibonacci; F(10)=55 F(20)=6765; sum=164 xor=90 | `0x0002A45A` | |
| `test_tribonacci.c` | Tribonacci T(0..9)={0,1,1,2,4,7,13,24,44,81}; sum=177 xor=105 | `0x000AB169` | |
| `test_count_bits.c` | Brian Kernighan popcount in 0..15; total=32 xor=4 | `0x00102004` | |
| `test_stock_k_trans.c` | Stock 2-transaction state machine; prices={3,3,5,0,0,3,1,4}; profit=6 | `0x00080603` | |
| `test_coin_ways.c` | Unbounded coin ways (coins={1,2,3}); ways(4)=4 ways(6)=7 ways(10)=14 | `0x0003190D` | |
| `test_lca.c` | LCA depth-leveling on 7-node tree; LCA(4,5)=2 LCA(4,6)=1 LCA(2,7)=1 | `0x00030402` | |
| `test_interval_merge.c` | Merge overlapping intervals; {[1,3],[2,6],[8,10],[15,18]}→3 merged; xor_ends=30 | `0x0004031E` | |
| `test_num_islands.c` | DFS flood-fill island count; 3 grids; islands={1,2,2}; sum=5 xor=1 | `0x00030501` | |
| `test_prefix_xor.c` | Prefix XOR range queries; arr={1..8}; xorRange results={4,4,8}; sum=16 xor=8 | `0x00031008` | |
| `test_tarjan_scc.c` | Tarjan SCC on directed graph; 5 nodes; 3 SCCs; sizes={2,2,1}; xor=1 | `0x00050201` | |
| `test_huffman.c` | Huffman code-length DFS; freqs={5,2,1,3,4}; sum_codelen=33 n_leaf=5 | `0x00052102` | |
| `test_toposort_dfs.c` | Post-order DFS toposort; 5-node DAG; order sum=10 xor=4 | `0x00050A04` | |
| `test_nim.c` | Sprague-Grundy XOR nim; 5 piles; various game states | `0x00050102` | |
| `test_tsp_bitmask.c` | Held-Karp TSP DP; 4 cities; min Hamiltonian cycle=80 | `0x00045004` | |
| `test_euler_circuit.c` | Hierholzer Euler circuit; 5-node multigraph; circuit length | `0x00050601` | |
| `test_convex_hull.c` | Graham scan; 6 points; hull size=5 sum_x=7 sum_y=5 | `0x00050705` | |
| `test_digit_dp.c` | Tight-bound digit DP; count 1..100 with digit-sum divisible by 3 or 5 | `0x00023432` | |
| `test_suffix_array.c` | Suffix array "banana"; insertion-sort; SA={5,3,1,0,4,2}; first=5 xor=1 | `0x00060501` | |
| `test_house_robber.c` | House Robber rolling DP; 3 arrays; profits={4,12,4}; sum=20 xor=12 | `0x0003140C` | |
| `test_egg_drop.c` | Egg Drop DP (floors testable); n=10/100/36; trials={4,14,6}; sum=24 xor=12 | `0x0003180C` | |
| `test_unique_paths.c` | Grid unique paths 2-D DP; 3×3=6, 3×7=28, 4×4=20; sum=54 xor=14 | `0x0003360E` | |
| `test_regex_match.c` | Regex DP with '.' and '*'; 4 test cases; sum=3 xor=1 | `0x00040301` | |
| `test_max_product.c` | Max product subarray (max+min rolling); 3 arrays; prods={6,0,12}; sum=18 xor=10 | `0x0003120A` | |
| `test_articulation.c` | Tarjan articulation points; 5-node graph; APs={1,3}; count=2 xor=2 | `0x00050202` | |
| `test_sqrt_decomp.c` | Sqrt decomposition range sum; n=9 blksz=3; q1=33 q2=49 | `0x00092131` | |
| `test_dag_longest_path.c` | DAG longest path DP; 6 nodes topo order; max=17 xor=23 | `0x00061117` | |
| `test_edit_distance.c` | Levenshtein edit distance; kitten→sitting=3, abc→yabd=2 | `0x00030802` | |
| `test_max_rect_sum.c` | Max sum sub-rectangle via 2D Kadane; 3×4 matrix; max=21 | `0x000C1501` | |
| `test_fenwick_tree.c` | Fenwick BIT; p[0..4]=9; update[3]+=3; range[2..5]=12 | `0x0008090C` | |
| `test_sliding_window_max.c` | Monotonic deque max; k=3 on {1,3,-1,-3,5,3,6,7}; sum=29 | `0x00061D01` | |
| `test_count_distinct_window.c` | Freq-array distinct count; k=4; all windows=3 | `0x00050F03` | |
| `test_gcd_array.c` | Euclidean GCD+LCM over {12,18,24,36}; gcd=6 lcm=72 | `0x00040648` | |
| `test_primorial.c` | Primorial P(1..5); sum%256=254 xor%256=206 | `0x0005FECE` | |
| `test_gray_code.c` | Gray code G(i)=i^(i>>1); n_codes=8 last=4 | `0x00080304` | |
| `test_fisher_yates.c` | Det. Fisher-Yates shuffle {1..8}; sum=36 xor=8 | `0x00082408` | |
| `test_partition_equal_sum.c` | 0/1 knapsack equal-subset DP; 3 cases | `0x00031C01` | |
| `test_jump_game2.c` | Min-jumps greedy; 3 arrays, sum=7 xor=3 | `0x00030703` | |
| `test_perfect_squares.c` | Min perfect squares DP; 4 cases sum=10 xor=4 | `0x00040A04` | |
| `test_interleave.c` | Interleaving strings DP; 3 cases n_true=2 | `0x00030203` | |
| `test_activity_selection.c` | Greedy interval scheduling; 11 acts, 4 selected | `0x000B0418` | |
| `test_bipartite_matching.c` | Augmenting-path bipartite match K_{3,3}; max=3 | `0x00090303` | |
| `test_mod_exp.c` | Modular exponentiation binary; 3 cases sum=185 xor=5 | `0x0003B905` | |
| `test_gcd_ext.c` | Extended Euclidean; gcd(12,8)=4 (21,14)=7 (45,30)=15 | `0x00031A0C` | |
| `test_matrix_exp.c` | Matrix exp Fibonacci F(10,12,14); sum%256=64 xor%256=222 | `0x000340DE` | |
| `test_derange.c` | Derangements D(3)=2 D(4)=9 D(5)=44; sum=55 xor=39 | `0x00033727` | |
| `test_stirling2.c` | Stirling 2nd kind S(4,2)=7 S(5,3)=25 S(6,3)=90 | `0x00037A44` | |
| `test_bell_num.c` | Bell numbers B(3)=5 B(4)=15 B(5)=52; sum=72 xor=62 | `0x0003483E` | |
| `test_min_window_substr.c` | Min window substring; 3 cases sum=12 xor=2 | `0x00030C02` | |
| `test_max_gap.c` | Max gap sorted; 3 arrays sum=21 xor=5 | `0x00031505` | |
| `test_merge_intervals.c` | Merge overlapping intervals; 3 sets merged counts=3+1+3 | `0x00030701` | |
| `test_wiggle_sort.c` | Wiggle sort alternating; {1,5,1,1,6,4} n_ok=5 xor=6 | `0x00060506` | |
| `test_longest_common_prefix.c` | LCP vertical scan; 3 string arrays sum_len=7 last=5 | `0x00030705` | |
| `test_power_set.c` | Bitmask power set of {1,2,3,4}; total=16 sum_sizes=32 elem_sum=80 | `0x00102050` | |
| `test_maximal_square.c` | Largest square of 1s; 4×5 matrix max_side=2 area=4 | `0x00040405` | |
| `test_bucket_sort.c` | Bucket sort {4,2,8,1,9,3,7,5,6,0}; largest=9 second=8 n=10 | `0x000A0908` | |
| `test_subarray_xor.c` | Count subarrays with XOR=k; c1=4 c2=2 sum=6 xor=6 | `0x00020606` | |
| `test_valid_parentheses.c` | Stack-based bracket validation; 4 strings n_valid=2 len_sum=10 | `0x0004020A` | |
| `test_count_rooms.c` | Grid DFS connected components; 3 grids rooms=3+8+1 | `0x00030C0A` | |
| `test_dependency_order.c` | Kahn BFS toposort; 5-node DAG first=0 last=4 n_edges=5 | `0x00050504` | |
| `test_trie_ops.c` | Flat-array trie insert/search; 6 queries found=4 miss=2 | `0x00060402` | |
| `test_chain_pairs.c` | Greedy longest pair chain; 5 pairs chain=3 xor_b=12 | `0x0005030C` | |
| `test_circular_buffer.c` | Ring buffer head/tail; cap=5 pushes=6 front=4 xpush=7 | `0x00070407` | |
| `test_spiral_matrix.c` | Spiral traversal 3×4; n=12 sum=78 xor=12 | `0x000C4E0C` | |
| `test_max_xor_pair.c` | Brute-force max XOR pairs {3,10,5,25,2,8}; max=28 second=27 | `0x00061C1B` | |
| `test_rotate_image.c` | Rotate 3×3 matrix 90° CW; diag_sum=15 top_left=7 | `0x00030F07` | |
| `test_meeting_rooms.c` | Can-attend-all meetings; 3 sets, 1 valid, sum_end=30 | `0x0003011E` | |
| `test_decode_ways.c` | Digit string decode DP; 4 strings, sum_ways=8, w0=3 | `0x00080301` | |
| `test_two_sum_pairs.c` | Two-pointer pair-sum count; 3 targets, sum_cnts=10 xor=4 | `0x00030A04` | |
| `test_task_scheduler.c` | CPU task cooldown formula; total=9 result=9 maxf=3 | `0x00090903` | |
| `test_consecutive_seq.c` | Longest consecutive run; array1=4 array2=9 | `0x00020409` | |
| `test_dice_combinations.c` | Dice-sum 2D DP; d=3→15 ways, d=2→6 ways | `0x00020F06` | |
| `test_max_points_line.c` | Cross-product collinear check; 6 points max=3 | `0x00060306` | |
| `test_palindrome_num.c` | Digit-reversal palindrome; 6 nums, count=4, xor_low=0x53 | `0x00060453` | |
| `test_balanced_partition.c` | Equal subset sum DP; 4 arrays, 3 balanced, len_sum=14 | `0x0004030E` | |
| `test_anagram_groups.c` | Freq-vector anagram grouping; 6 words, 3 groups max=3 | `0x00030300` | |
| `test_skip_list.c` | Two-level skip list; 8 elems express-lane search; found=2 xor=30 | `0x0003021E` | |
| `test_treap.c` | Treap BST+max-heap; 7 nodes via rotate-up; root=key4 sum=34 | `0x00072204` | |
| `test_turbulent.c` | Longest turbulent subarray dp_inc/dp_dec; n=9 max=5 xor=10 | `0x0009050A` | |
| `test_min_cost_staircase.c` | Min cost staircase DP; 3 tests, sum=23, xor=11 | `0x0003170B` | |
| `test_longest_valid_parens.c` | Longest valid parens DP; 3 strings, sum=6, xor=6 | `0x00030606` | |
| `test_count_digit_ones.c` | Count digit-1s via position formula; n=13/50/100; sum=42 xor=28 | `0x00032A1C` | |
| `test_pascals_row.c` | Pascal row7 in-place; sum=128, C(7,3)=35 | `0x00078023` | |
| `test_largest_div_subset.c` | Largest divisible subset sort+DP; n=6 best={1,2,6,24} xor=29 | `0x0006041D` | |
| `test_subarray_sum_k.c` | Count subarrays with sum=k via prefix+hashmap; 3 cases sum=8 xor=4 | `0x00030804` | |
| `test_max_circular_subarray.c` | Max circular subarray: total−min_sub; 3 cases sum_pos=13 cnt=2 | `0x00030D02` | |
| `test_serialize_bst.c` | Serialize BST as preorder, deserialize with bounds; psum=34 xor=10 | `0x0007220A` | |
| `test_count_primes.c` | Sieve of Eratosthenes: n=50→15, n=100→25, n=30→10; sum=50 xor=28 | `0x0003321C` | |
| `test_min_falling_path.c` | Min falling path in 3×3 grid; ans=13, last-row-sum=40 | `0x00030D28` | |
| `test_k_closest_points.c` | K=2 closest points to origin by dist²; sum_dist2=9 | `0x00040902` | |
| `test_lcs.c` | Longest common subsequence (2-D DP); 3 cases sum=11 xor=3 | `0x00030B03` | |
| `test_monotonic_queue.c` | Sliding window max via monotonic deque; n=8 k=3 sum=29 xor=1 | `0x00081D01` | |

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
236 algorithm patterns using multi-regex heuristics. Run it as a Ghidra post-script
and it emits `semantic_hints.json` alongside the decompiled `.c`:

```bash
analyzeHeadless /tmp/proj RT_hash \
  -import /tmp/test_hash.elf \
  -processor "RISCV:LE:32:ESP32-P4" \
  -scriptPath ghidra_scripts \
  -postScript DetectSemanticPatterns.java /tmp/test_hash_hints.json \
  -deleteProject
```

Pattern families currently covered (260 patterns):

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
| Topological sort | DFS finish-time ordering, Kahn's in-degree decrement + BFS queue, topo order output |
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
| Ternary search | two midpoints m1/m2; (hi-lo)/3 offset; while(hi-lo>2) condition; final linear scan |
| Miller-Rabin primality | extract 2^s factor (d>>=1; s++); squaring loop; composite verdict (r==s) |
| Max rectangle histogram | monotonic stack; pop-while-taller; width = (top<0)?i:i-stk[top]-1 |
| Trapping rain water | two-pointer advance-shorter-side; running max_l/max_r; water+=max-h |
| Jump game (greedy) | if(i>max_reach) early-exit; max_reach=max(max_reach,i+arr[i]) update |
| Gas station (greedy) | tank+=gas-cost; if(tank<0){start=i+1;tank=0}; feasibility via total |
| Bipartite check (BFS 2-coloring) | color[v]=3-color[u] swap; if(color[v]==color[u]) conflict; outer loop for disconnected components |
| Kahn's topological sort | pre-compute in_deg[v]++; seed queue with in_deg==0; --in_deg[v]==0 enqueue; cycle check processed<n |
| Word break DP | dp[0]=1 seed; dp[i-wlen]&&strncmp match; return dp[slen] |
| Counting paths in DAG | if(u==dst) return 1; memo cache-hit check; accumulate over adj; memoize before return |
| Dynamic programming (extra) | 0/1 knapsack 1D reverse iteration, capacity-subproblem table access |
| Euler's totient | `while(n%p==0) n/=p` strip; `result-=result/p` phi-product step; `p*p<=n` trial-div bound |
| Difference array | `D[l]+=delta; D[r+1]-=delta` range update; `acc+=D[i]; A[i]=acc` prefix-sum reconstruct |
| Chinese Remainder Theorem | partial products M_i=M/m_i; iterative mod_inv; accumulate r_i*M_i*inv contribution |
| Longest Bitonic Subsequence | forward LIS + backward LDS; `lbs[i]=lis[i]+lds[i]-1`; global max scan |
| Hamming distance | `popcount(a^b)` pair distance; bit-position count1*(n-count1) total HD |
| Palindrome partition | `is_pal[i][j]` expand-from-ends table; `dp[i]=min(dp[j-1]+1)` cuts DP |
| Array rotation | 3-reversal: reverse(0,n-k-1), reverse(n-k,n-1), reverse(0,n-1) |
| Matrix fast exponentiation | 2×2 multiply; `if n%2==1 result=result*base`; `base=base*base; n>>=1` square-and-halve |
| Tribonacci sequence | `t[i]=t[i-1]+t[i-2]+t[i-3]` 3-term recurrence; seed {0,1,1} |
| Brian Kernighan popcount | `while(x){x&=x-1;count++}` clears lowest set bit each iteration |
| Stock 2-transaction DP | `buy1=max(buy1,-price)` → `sell1` → `buy2` → `sell2` 4-state forward pass |
| Unbounded coin ways | `dp[0]=1; for coin: for j=coin..amt: dp[j]+=dp[j-coin]` (inner loop order preserves unbounded) |
| LCA depth leveling | `while(depth[a]>depth[b]) a=par[a]`; then walk both up until `a==b` |
| Interval merge | `if starts[i]<=cur_end: extend`; `else: emit+reset`; flush last after loop |
| Number of islands DFS | `vis[r][c]=1; dfs(4 neighbors)`; `islands++` per unvisited 1-cell |
| Prefix XOR range query | `px[i+1]=px[i]^arr[i]` build; `xorRange(l,r)=px[r+1]^px[l]` O(1) query |

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
