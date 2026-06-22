#pragma once
#include <stdint.h>

/* Results from each algorithm test.
 * Each test sets this before printing RESULT: to UART. */
extern volatile uint32_t g_result;

/* Test entry points */
void test_crc32_idf(void);
void test_fibonacci_idf(void);
void test_primes_idf(void);
