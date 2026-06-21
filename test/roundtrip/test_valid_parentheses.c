/* SPDX-License-Identifier: Apache-2.0
 * ESP32-P4 decompiler plugin — Valid Parentheses (stack-based) fixture.
 *
 * Validates parentheses strings with three bracket types: (), [], {}.
 * Uses a stack: push open brackets; on close, check top matches then pop.
 *
 * Distinctive decompiler idioms:
 *   1. `if (c=='('||c=='['||c=='{') stk[top++]=c` — push open bracket
 *   2. `if (top==0) return 0` — empty stack on close = invalid
 *   3. `if (c==')'&&t!='(') return 0` — mismatch check
 *   4. `return top==0` — valid iff stack empty at end
 *
 * Test cases: "()[]{}"→1, "([)]"→0, "{[]}"→1, "((("→0
 * n_tests=4, n_valid=2, sum_of_valid_string_lengths=6+4=10
 *
 * g_result = (4<<16)|(n_valid<<8)|(valid_len_sum&0xFF) = 0x0004020A
 */
#include <stdint.h>

volatile uint32_t g_result;

static int is_valid_paren(const char *s)
{
    char stk[64];
    int top = 0;
    for (int i = 0; s[i]; i++) {
        char c = s[i];
        if (c == '(' || c == '[' || c == '{') {
            stk[top++] = c;
        } else {
            if (top == 0) return 0;
            char t = stk[top - 1];
            if ((c == ')' && t != '(') ||
                (c == ']' && t != '[') ||
                (c == '}' && t != '{'))
                return 0;
            top--;
        }
    }
    return top == 0;
}

static int vp_len(const char *s)
{
    /* Volatile prevents -O2 from substituting a libcall */
    const char *volatile p = s;
    int i = 0;
    while (p[i]) i++;
    return i;
}

void test_valid_parentheses(void)
{
    static const char *strs[4] = {"()[]{}", "([)]", "{[]}", "((("};
    int n_valid = 0;
    uint32_t valid_len_sum = 0;

    for (int i = 0; i < 4; i++) {
        if (is_valid_paren(strs[i])) {
            n_valid++;
            valid_len_sum += (uint32_t)vp_len(strs[i]);
        }
    }
    /* n_valid=2, valid_len_sum=6+4=10=0x0A */
    g_result = (4u << 16)
             | ((uint32_t)n_valid << 8)
             | (valid_len_sum & 0xFFu);
}

__attribute__((noreturn)) void _start(void)
{
    test_valid_parentheses();
    for (;;);
}
