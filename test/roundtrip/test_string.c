/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 round-trip fixture: string operations
 *
 * Exercises strlen, memcmp, strchr_count, and brute-force substring search.
 *
 * hay = "hello world hello" (17 chars)
 * needle = "hello" (5 chars)
 *
 * strlen("hello world hello") = 17
 * memcmp("hello","hello",5)   = 0  → contrib 0x1000
 * strchr_count(hay,'l')       = 5
 * needle_search(hay,17,"hello",5) = 0  (first match at index 0)
 *
 * g_result = 17 ^ 0x1000 ^ 5 ^ 0 = 0x00001014
 */
#include <stdint.h>

volatile uint32_t g_result = 0;

static uint32_t my_strlen(const char *s)
{
    uint32_t n = 0;
    while (*s++) n++;
    return n;
}

static uint32_t my_memcmp(const uint8_t *a, const uint8_t *b, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++)
        if (a[i] != b[i]) return i + 1;
    return 0;
}

static uint32_t my_strchr_count(const char *s, char c)
{
    uint32_t n = 0;
    while (*s) {
        if (*s == c) n++;
        s++;
    }
    return n;
}

static uint32_t needle_search(const char *hay, uint32_t hlen,
                               const char *needle, uint32_t nlen)
{
    if (nlen == 0 || nlen > hlen) return 0xFFFFFFFFu;
    for (uint32_t i = 0; i <= hlen - nlen; i++) {
        uint32_t j;
        for (j = 0; j < nlen; j++)
            if (hay[i + j] != needle[j]) break;
        if (j == nlen) return i;
    }
    return 0xFFFFFFFFu;
}

void _start(void)
{
    static const char hay[]    = "hello world hello";
    static const char needle[] = "hello";

    uint32_t slen = my_strlen(hay);
    uint32_t mcmp = my_memcmp((const uint8_t *)"hello",
                               (const uint8_t *)"hello", 5);
    uint32_t scnt = my_strchr_count(hay, 'l');
    uint32_t ns   = needle_search(hay, 17u, needle, 5u);

    g_result = slen ^ (mcmp == 0u ? 0x1000u : 0u) ^ scnt ^ ns;
    while (1) {}
}
