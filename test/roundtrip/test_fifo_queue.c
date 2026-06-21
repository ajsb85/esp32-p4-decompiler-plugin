/* SPDX-License-Identifier: Apache-2.0
 * Extended round-trip test: lock-free single-producer/consumer FIFO.
 *
 * Exercises: modulo indexing, struct with head/tail/count, uint8_t array,
 *            overflow/underflow guards, memcpy-like bulk enqueue.
 *
 * Expected pattern detection: fifo_ring (head/tail % size access pattern)
 *
 * Operations:
 *   1. Enqueue bytes 0x00..0x0F (16 bytes)
 *   2. Dequeue 4 bytes → should get 0x00,0x01,0x02,0x03 → xor=0x00
 *   3. Enqueue 4 more bytes: 0x10,0x11,0x12,0x13
 *   4. Dequeue all 16 remaining bytes, XOR them
 *   5. g_result = xor_of_all_dequeued (both batches)
 *
 * Expected XOR:
 *   First dequeue:  0x00^0x01^0x02^0x03 = 0x00
 *   Second dequeue: 0x04^0x05^0x06^0x07^0x08^0x09^0x0A^0x0B
 *                  ^0x0C^0x0D^0x0E^0x0F^0x10^0x11^0x12^0x13
 *   XOR 0x04..0x0F = 0x04^0x05=0x01, ^0x06=0x07, ^0x07=0x00,
 *                    ^0x08=0x08, ^0x09=0x01, ^0x0A=0x0B, ^0x0B=0x00,
 *                    ^0x0C=0x0C, ^0x0D=0x01, ^0x0E=0x0F, ^0x0F=0x00
 *   XOR 0x10..0x13 = 0x10^0x11=0x01, ^0x12=0x13, ^0x13=0x00
 *   Second batch XOR = 0x00
 *   Total XOR = 0x00 ^ 0x00 = 0x00
 *
 * g_result = 0x00000000 if FIFO is correct.
 * If the decompilation breaks head/tail indexing, the XOR will diverge.
 */
#include <stdint.h>

volatile uint32_t g_result;

#define FIFO_CAP 32u

typedef struct {
    uint8_t  buf[FIFO_CAP];
    uint32_t head;
    uint32_t tail;
    uint32_t count;
} Fifo;

static int fifo_enqueue(Fifo *f, uint8_t b) {
    if (f->count >= FIFO_CAP) return -1;
    f->buf[f->head % FIFO_CAP] = b;
    f->head++;
    f->count++;
    return 0;
}

static int fifo_dequeue(Fifo *f, uint8_t *out) {
    if (f->count == 0) return -1;
    *out = f->buf[f->tail % FIFO_CAP];
    f->tail++;
    f->count--;
    return 0;
}

static uint32_t fifo_enqueue_bulk(Fifo *f, const uint8_t *data, uint32_t len) {
    uint32_t written = 0;
    for (uint32_t i = 0; i < len; i++) {
        if (fifo_enqueue(f, data[i]) < 0) break;
        written++;
    }
    return written;
}

static uint32_t fifo_dequeue_all_xor(Fifo *f) {
    uint32_t acc = 0;
    uint8_t b;
    while (fifo_dequeue(f, &b) == 0)
        acc ^= b;
    return acc;
}

void _start(void) {
    Fifo fifo = {.buf={0}, .head=0, .tail=0, .count=0};

    /* Enqueue 0x00..0x0F */
    static const uint8_t batch1[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
    };
    fifo_enqueue_bulk(&fifo, batch1, 16);

    /* Dequeue first 4 */
    uint32_t xor_a = 0;
    for (int i = 0; i < 4; i++) {
        uint8_t b = 0;
        fifo_dequeue(&fifo, &b);
        xor_a ^= b;
    }

    /* Enqueue 0x10..0x13 */
    static const uint8_t batch2[4] = {0x10,0x11,0x12,0x13};
    fifo_enqueue_bulk(&fifo, batch2, 4);

    /* Dequeue remaining 16 bytes */
    uint32_t xor_b = fifo_dequeue_all_xor(&fifo);

    g_result = xor_a ^ xor_b;
    /* Expected: 0x00 ^ 0x00 = 0x00000000 */

    for (;;);
}
