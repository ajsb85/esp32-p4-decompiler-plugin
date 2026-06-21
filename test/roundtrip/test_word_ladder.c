#include <stdint.h>

/* Word Ladder: find shortest BFS path from beginWord to endWord,
 * transforming exactly one letter at a time; each intermediate in dict.
 * Returns path length (0 if unreachable; endWord must be in dict).
 * g_result encodes (n_tests, result1, result3 + result2). */

#define MAX_W 16
#define MAX_Q 32

static int scmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return *a - *b;
}

static void scpy(char *dst, const char *src) {
    while ((*dst++ = *src++));
}

static int one_diff(const char *a, const char *b) {
    int diff = 0, i = 0;
    while (a[i] && b[i]) {
        if (a[i] != b[i]) diff++;
        i++;
    }
    return (diff == 1) && !a[i] && !b[i];
}

static int word_ladder(const char *begin, const char *end,
                       const char dict[][MAX_W], int nd) {
    char queue[MAX_Q][MAX_W];
    int  dist[MAX_Q];
    int  visited[8];
    int  qh = 0, qt = 0;
    int  end_idx = -1, i;
    for (i = 0; i < nd; i++) {
        visited[i] = 0;
        if (scmp(dict[i], end) == 0) end_idx = i;
    }
    if (end_idx < 0) return 0;
    scpy(queue[qt], begin);
    dist[qt++] = 1;
    while (qh < qt) {
        char cur[MAX_W];
        int  d = dist[qh];
        scpy(cur, queue[qh++]);
        for (i = 0; i < nd; i++) {
            if (visited[i] || !one_diff(cur, dict[i])) continue;
            if (i == end_idx) return d + 1;
            visited[i] = 1;
            scpy(queue[qt], dict[i]);
            dist[qt++] = d + 1;
        }
    }
    return 0;
}

volatile uint32_t g_result;

void test_word_ladder(void) {
    const char d1[][MAX_W] = {"hot","dot","dog","lot","log","cog"};
    const char d2[][MAX_W] = {"hot","dot","dog","lot","log"};
    const char d3[][MAX_W] = {"a","b","c"};
    int r1 = word_ladder("hit", "cog", d1, 6); /* 5 */
    int r2 = word_ladder("hit", "cog", d2, 5); /* 0 */
    int r3 = word_ladder("a",   "c",   d3, 3); /* 2 */
    g_result = (3u << 16) | ((uint32_t)r1 << 8) | (uint32_t)(r3 + r2); /* 0x00030502 */
}

__attribute__((noreturn)) void _start(void) {
    test_word_ladder();
    for (;;);
}
