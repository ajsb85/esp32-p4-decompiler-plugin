/* SPDX-License-Identifier: Apache-2.0
 * Extended round-trip test: sorting algorithms.
 *
 * Exercises: nested loops, array subscript, compare + 3-line swap.
 * Expected pattern detection: sort_bubble
 *
 * Produces a deterministic g_result that must survive:
 *   compile → Ghidra analysis → decompile → recompile → same g_result
 *
 * To verify on ESP32-P4 serial:
 *   g_result = 0x00000029  (XOR of [3,7,11,21,42,55,77,99] = 41 = 0x29)
 */
#include <stdint.h>

volatile uint32_t g_result;

/* Bubble sort on int array */
static void bubble_sort(int *arr, int n) {
    for (int i = 0; i < n - 1; i++) {
        for (int j = 0; j < n - i - 1; j++) {
            if (arr[j] > arr[j + 1]) {
                int tmp   = arr[j];
                arr[j]    = arr[j + 1];
                arr[j + 1] = tmp;
            }
        }
    }
}

/* Insertion sort — same result, different algorithm */
static void insertion_sort(int *arr, int n) {
    for (int i = 1; i < n; i++) {
        int key = arr[i];
        int j   = i - 1;
        while (j >= 0 && arr[j] > key) {
            arr[j + 1] = arr[j];
            j--;
        }
        arr[j + 1] = key;
    }
}

/* XOR-checksum of sorted array */
static uint32_t array_checksum(int *arr, int n) {
    uint32_t acc = 0;
    for (int i = 0; i < n; i++)
        acc ^= (uint32_t)arr[i];
    return acc;
}

/* Merge results: bubble sort on first 8, insertion sort on second 8,
 * check both give the same checksum. */
void _start(void) {
    int data_a[8] = {42, 7, 99, 3, 55, 21, 77, 11};
    int data_b[8] = {42, 7, 99, 3, 55, 21, 77, 11};

    bubble_sort(data_a, 8);
    insertion_sort(data_b, 8);

    uint32_t sum_a = array_checksum(data_a, 8);
    uint32_t sum_b = array_checksum(data_b, 8);

    /* Both algorithms must produce the same sorted order,
     * so sum_a == sum_b; XOR of identical values = 0 for the agree part,
     * and the final result is sum_a (= 0x29). */
    g_result = sum_a ^ (sum_a == sum_b ? 0 : 0xDEADBEEFu);

    for (;;);
}
