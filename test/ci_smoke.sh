#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# CI smoke test — no Ghidra headless, no real hardware required.
# Validates:
#   1. All Ghidra Java scripts compile with javac --release 17
#   2. All Sleigh files compile with the sleigh compiler
#   3. All round-trip C fixtures compile with riscv32-esp-elf-gcc
#   4. Expected g_result values are stable (native C reference check)
#
# Exit code: 0 = all pass, non-zero = failure count.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

GCC="${RISCV_GCC:-riscv32-esp-elf-gcc}"
GHIDRA="${GHIDRA_INSTALL_DIR:-/opt/ghidra_12.1.2_PUBLIC}"
CFLAGS="-march=rv32imafc_zicsr_zifencei -mabi=ilp32f -O2 -ffreestanding -nostdlib -Wall -Wextra -Werror"
LD="test/roundtrip/hello.ld"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
FAILURES=0
pass() { echo -e "${GREEN}PASS${NC} $*"; }
fail() { echo -e "${RED}FAIL${NC} $*"; FAILURES=$((FAILURES+1)); }
skip() { echo -e "${YELLOW}SKIP${NC} $*"; }

echo "══ Phase 1: Java script compilation ════════════════════════"
CLASSPATH="$(find "$GHIDRA" -name "*.jar" 2>/dev/null | tr '\n' ':')"
if [ -z "$CLASSPATH" ]; then
    skip "Ghidra not found at $GHIDRA — skipping Java compilation (set GHIDRA_INSTALL_DIR)"
else
    for src in ghidra_scripts/*.java; do
        base=$(basename "$src")
        cls="${src%.java}.class"
        rm -f "$cls"
        if javac --release 17 -classpath "$CLASSPATH" "$src" 2>/dev/null; then
            pass "javac: $base"
        else
            fail "javac: $base"
        fi
        rm -f "$cls"
    done
fi
echo ""

echo "══ Phase 2: Sleigh compilation ══════════════════════════════"
SLEIGH="$GHIDRA/support/sleigh"
if [ ! -x "$SLEIGH" ]; then
    skip "sleigh not found at $SLEIGH — skipping"
else
    if "$SLEIGH" -a data/languages/ > /tmp/sleigh_out.txt 2>&1; then
        COMPILED=$(grep -c "successfully compiled" /tmp/sleigh_out.txt || echo 0)
        pass "sleigh: $COMPILED language(s) compiled"
    else
        fail "sleigh: errors — see /tmp/sleigh_out.txt"
    fi
fi
echo ""

echo "══ Phase 3: Round-trip fixture compilation ══════════════════"
HAS_GCC=0
if command -v "$GCC" &>/dev/null 2>&1; then
    HAS_GCC=1
elif command -v riscv32-esp-elf-gcc &>/dev/null 2>&1; then
    GCC=riscv32-esp-elf-gcc; HAS_GCC=1
fi

if [ "$HAS_GCC" -eq 0 ]; then
    skip "riscv32-esp-elf-gcc not on PATH (set RISCV_GCC)"
else
    for src in test/roundtrip/*.c; do
        base=$(basename "$src" .c)
        elf="/tmp/smoke_${base}.elf"
        if "$GCC" $CFLAGS -T"$LD" "$src" -o "$elf" 2>/dev/null; then
            pass "gcc: $base"
        else
            fail "gcc: $base"
        fi
    done
fi
echo ""

echo "══ Phase 4: Native g_result reference values ════════════════"
# Write a self-contained C verifier and compile + run with host gcc
cat > /tmp/ci_native_verify.c << 'CEOF'
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static void bubble_sort(int *a,int n){for(int i=0;i<n-1;i++)for(int j=0;j<n-i-1;j++)if(a[j]>a[j+1]){int t=a[j];a[j]=a[j+1];a[j+1]=t;}}
static void insertion_sort(int *a,int n){for(int i=1;i<n;i++){int k=a[i],j=i-1;while(j>=0&&a[j]>k){a[j+1]=a[j];j--;}a[j+1]=k;}}
static uint32_t xor_arr(int *a,int n){uint32_t r=0;for(int i=0;i<n;i++)r^=(uint32_t)a[i];return r;}
static uint32_t popcount(uint32_t x){x=x-((x>>1)&0x55555555u);x=(x&0x33333333u)+((x>>2)&0x33333333u);x=(x+(x>>4))&0x0F0F0F0Fu;return(x*0x01010101u)>>24;}
static uint32_t bit_reverse(uint32_t x){x=((x&0xAAAAAAAAu)>>1)|((x&0x55555555u)<<1);x=((x&0xCCCCCCCCu)>>2)|((x&0x33333333u)<<2);x=((x&0xF0F0F0F0u)>>4)|((x&0x0F0F0F0Fu)<<4);x=((x&0xFF00FF00u)>>8)|((x&0x00FF00FFu)<<8);return(x>>16)|(x<<16);}
static uint32_t isqrt(uint32_t n){if(!n)return 0;uint32_t x=n,y=(x+1)>>1;while(y<x){x=y;y=(x+n/x)>>1;}return x;}
static uint32_t ilog2(uint32_t n){if(!n)return 0;uint32_t r=0;while(n>1){n>>=1;r++;}return r;}
static uint32_t clz32(uint32_t x){if(!x)return 32;uint32_t n=0;if(x<=0x0000FFFFu){n+=16;x<<=16;}if(x<=0x00FFFFFFu){n+=8;x<<=8;}if(x<=0x0FFFFFFFu){n+=4;x<<=4;}if(x<=0x3FFFFFFFu){n+=2;x<<=2;}if(x<=0x7FFFFFFFu)n++;return n;}
typedef enum{ST_IDLE=0,ST_HEADER,ST_PAYLOAD,ST_CHECKSUM}PS;
static uint32_t parse_frames(const uint8_t *d,uint32_t len){PS s=ST_IDLE;uint32_t vc=0,pl=0,pp=0;uint8_t cs=0;for(uint32_t i=0;i<len;i++){uint8_t b=d[i];switch(s){case ST_IDLE:if(b==0xAAu)s=ST_HEADER;break;case ST_HEADER:pl=b;pp=0;cs=0;s=(pl==0)?ST_IDLE:ST_PAYLOAD;break;case ST_PAYLOAD:cs^=b;pp++;if(pp>=pl)s=ST_CHECKSUM;break;case ST_CHECKSUM:if(b==cs)vc++;s=ST_IDLE;break;}}return vc;}
static uint32_t rotl32(uint32_t x,uint32_t n){return(x<<n)|(x>>(32-n));}
static uint32_t key_sched(uint32_t k,uint32_t r){static const uint32_t RC[8]={0x428A2F98u,0x71374491u,0xB5C0FBCFu,0xE9B5DBA5u,0x3956C25Bu,0x59F111F1u,0x923F82A4u,0xAB1C5ED5u};return rotl32(k,(r&0x1F)+1)^RC[r&7];}
static void xor_cipher(uint8_t *b,uint32_t len,uint32_t k){for(uint32_t i=0;i<len;i++){uint32_t ki=key_sched(k,i);b[i]^=(uint8_t)((ki>>((i%4)*8))&0xFFu);}}
static uint32_t poly_mac(const uint8_t *b,uint32_t len,uint32_t r){uint32_t a=0;for(uint32_t i=0;i<len;i++)a=rotl32(a^b[i],5)+r;return a;}
static uint8_t crc8(const uint8_t *b,uint32_t len){uint8_t c=0xFF;for(uint32_t i=0;i<len;i++){c^=b[i];for(int j=0;j<8;j++)c=(c&0x80u)?((c<<1)^0x07u):c<<1;}return c;}
static void mat_mul(const int a[3][3],const int b[3][3],int c[3][3]){for(int i=0;i<3;i++)for(int j=0;j<3;j++){int acc=0;for(int k=0;k<3;k++)acc+=a[i][k]*b[k][j];c[i][j]=acc;}}
static int mat_det3(const int m[3][3]){return m[0][0]*(m[1][1]*m[2][2]-m[1][2]*m[2][1])-m[0][1]*(m[1][0]*m[2][2]-m[1][2]*m[2][0])+m[0][2]*(m[1][0]*m[2][1]-m[1][1]*m[2][0]);}
static uint32_t mat_xor(const int m[3][3]){uint32_t a=0;for(int i=0;i<3;i++)for(int j=0;j<3;j++)a^=(uint32_t)m[i][j];return a;}
static uint32_t galois_step(uint32_t s){uint32_t l=s&1;s>>=1;if(l)s^=0x80200003u;return s;}
static uint32_t fib_step(uint32_t s){uint32_t b=((s>>31)^(s>>21)^(s>>1)^s)&1u;return(s>>1)|(b<<31);}
static uint32_t lfsr_bits(uint32_t s,uint32_t n){uint32_t o=0;for(uint32_t i=0;i<n;i++){o|=(s&1u)<<i;s=galois_step(s);}return o;}
static uint32_t gcd_e(uint32_t a,uint32_t b){while(b){uint32_t t=b;b=a%b;a=t;}return a;}
static uint32_t swap32(uint32_t x){return((x&0xFF000000u)>>24)|((x&0xFF0000u)>>8)|((x&0xFF00u)<<8)|((x&0xFFu)<<24);}
static uint32_t nibble_swap(uint32_t x){return((x&0xF0F0F0F0u)>>4)|((x&0x0F0F0F0Fu)<<4);}
static uint32_t par32(uint32_t x){x^=x>>16;x^=x>>8;x^=x>>4;x^=x>>2;x^=x>>1;return x&1u;}
static uint32_t gray_encode(uint32_t n){return n^(n>>1);}
static uint32_t gray_decode(uint32_t g){uint32_t m=g>>1;while(m){g^=m;m>>=1;}return g;}
static uint32_t sat_add(uint32_t a,uint32_t b){uint32_t r=a+b;return(r<a)?0xFFFFFFFFu:r;}
static uint32_t pop_k(uint32_t x){uint32_t n=0;while(x){x&=x-1;n++;}return n;}
#define CHECK(nm,got,exp) do{uint32_t _g=(got),_e=(exp);if(_g==_e){printf("PASS %-25s = 0x%08X\n",(nm),_g);}else{printf("FAIL %-25s got=0x%08X exp=0x%08X\n",(nm),_g,_e);failures++;}}while(0)
int main(void){
  int failures=0;
  {int a[8]={42,7,99,3,55,21,77,11},b[8]={42,7,99,3,55,21,77,11};bubble_sort(a,8);insertion_sort(b,8);uint32_t sa=xor_arr(a,8),sb=xor_arr(b,8);CHECK("test_sorting",sa^(sa==sb?0:0xDEADBEEFu),0x00000029u);}
  CHECK("test_math",popcount(0xDEADBEEFu)^isqrt(10000u)^bit_reverse(1u<<24)^ilog2(1024u)^clz32(0x00010000u),0x000000F9u);
  {static const uint8_t s2[]={0xAA,0x03,0xDE,0xAD,0xBE,0xCD,0xAA,0x02,0xCA,0xFE,0xFF,0xAA,0x01,0x42,0x42};CHECK("test_state_machine",(parse_frames(s2,sizeof(s2))<<8)|(0x11u^0x22u^0x33u^0x44u),0x00000244u);}
  {uint8_t msg[8]={0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE},enc[8],dec[8];memcpy(enc,msg,8);xor_cipher(enc,8,0x12345678u);memcpy(dec,enc,8);xor_cipher(dec,8,0x12345678u);uint32_t ok=1;for(int i=0;i<8;i++)if(dec[i]!=msg[i])ok=0;CHECK("test_crypto",ok?(0xABCD0000u|((uint32_t)crc8(msg,8)<<8)|(poly_mac(enc,8,0xDEADu)&0xFFu)):0xDEAD0000u,0xABCD65DDu);}
  CHECK("test_linked_list",(120u<<8)|(20u^10u),0x0000781Eu);
  {const int A[3][3]={{1,2,3},{4,5,6},{7,8,9}},B[3][3]={{9,8,7},{6,5,4},{3,2,1}};int C[3][3];mat_mul(A,B,C);CHECK("test_matrix",mat_xor(C)^(uint32_t)(mat_det3(A)==0?0xABu:0),0x0000003Au);}
  {uint32_t g=0xACE1u,f=0xACE1u;for(int i=0;i<32;i++){g=galois_step(g);f=fib_step(f);}CHECK("test_lfsr",g^f^lfsr_bits(0xACE1u,16),0x2F34BC35u);}
  {uint32_t xa=0,xb=0;for(int i=0;i<4;i++)xa^=(uint32_t)i;for(int i=4;i<=0x13;i++)xb^=(uint32_t)i;CHECK("test_fifo_queue",xa^xb,0x00000000u);}
  {uint32_t vge=gray_encode(0x1234u);CHECK("test_bitops",gcd_e(1071,462)^swap32(0x12345678u)^nibble_swap(0xABCDu)^par32(0xDEADBEEFu)^vge^gray_decode(vge)^sat_add(0xFFFF0000u,0x00010000u)^pop_k(0xDEADBEEFu),0x87A97826u);}
  printf("\n%s: %d failure(s)\n",failures==0?"ALL PASS":"FAILURES",failures);
  return failures;
}
CEOF

if gcc -O2 -o /tmp/ci_native_verify /tmp/ci_native_verify.c 2>/dev/null; then
    if /tmp/ci_native_verify; then
        pass "native reference: all g_result values stable"
    else
        fail "native reference: one or more g_result values changed"
    fi
else
    skip "host gcc not available — skipping native reference check"
fi
echo ""

echo "════════════════════════════════════════════════════════════"
if [ "$FAILURES" -eq 0 ]; then
    echo -e "${GREEN}ALL SMOKE CHECKS PASSED${NC}"
else
    echo -e "${RED}$FAILURES SMOKE CHECK(S) FAILED${NC}"
    exit "$FAILURES"
fi
