/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Task Scheduler (idle-time calculation).
 *
 * Calculates minimum CPU intervals to schedule tasks with a cooldown.
 * Formula: max(total_tasks, (max_freq-1)*(cooldown+1) + count_of_max_freq)
 *
 * Distinctive decompiler idioms:
 *   1. `for(i) if(freq[i]>maxf) maxf=freq[i]` — find max frequency
 *   2. `count_maxf++` inside loop — count how many tasks share max frequency
 *   3. `slots=(maxf-1)*(cooldown+1)+count_maxf` — idle-slot formula
 *   4. `result = slots>total ? slots : total` — take max
 *
 * Tasks: A=3, B=3, C=2, D=1; total=9, cooldown=2
 * max_freq=3, count_maxf=2
 * slots=(3-1)*(2+1)+2=8, result=max(9,8)=9
 *
 * g_result = (total<<16)|(result<<8)|max_freq = 0x00090903
 */
#include <stdint.h>

volatile uint32_t g_result;

void test_task_scheduler(void)
{
    int freq[4] = {3, 3, 2, 1};  /* A B C D */
    int ntasks = 4, cooldown = 2;
    int total = 0, maxf = 0, count_maxf = 0;
    int i;

    for (i = 0; i < ntasks; i++) total += freq[i];
    for (i = 0; i < ntasks; i++) if (freq[i] > maxf) maxf = freq[i];
    for (i = 0; i < ntasks; i++) if (freq[i] == maxf) count_maxf++;

    int slots = (maxf - 1) * (cooldown + 1) + count_maxf;
    int result = (slots > total) ? slots : total;
    /* total=9, result=9, maxf=3 */
    g_result = ((uint32_t)total << 16)
             | ((uint32_t)result << 8)
             | (uint32_t)maxf;
}

__attribute__((noreturn)) void _start(void)
{
    test_task_scheduler();
    for (;;);
}
