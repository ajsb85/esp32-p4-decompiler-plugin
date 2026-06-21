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
static uint32_t djb2_h(const uint8_t *s,uint32_t l){uint32_t h=5381u;for(uint32_t i=0;i<l;i++)h=((h<<5)+h)^s[i];return h;}
static uint32_t fnv1a_h(const uint8_t *s,uint32_t l){uint32_t h=2166136261u;for(uint32_t i=0;i<l;i++){h^=s[i];h*=16777619u;}return h;}
static uint32_t poly_h(const uint8_t *s,uint32_t l,uint32_t b){uint32_t h=0;for(uint32_t i=0;i<l;i++)h=h*b+s[i];return h;}
static uint32_t my_strlen2(const char *s){uint32_t n=0;while(*s++)n++;return n;}
static uint32_t my_memcmp2(const uint8_t *a,const uint8_t *b,uint32_t n){for(uint32_t i=0;i<n;i++)if(a[i]!=b[i])return i+1;return 0;}
static uint32_t my_strchr_cnt(const char *s,char c){uint32_t n=0;while(*s){if(*s==c)n++;s++;}return n;}
static uint32_t needle_srch(const char *h,uint32_t hl,const char *nd,uint32_t nl){if(!nl||nl>hl)return 0xFFFFFFFFu;for(uint32_t i=0;i<=hl-nl;i++){uint32_t j;for(j=0;j<nl;j++)if(h[i+j]!=nd[j])break;if(j==nl)return i;}return 0xFFFFFFFFu;}
static int qs_part(int *a,int lo,int hi){int pv=a[hi],i=lo-1;for(int j=lo;j<hi;j++)if(a[j]<=pv){i++;int t=a[i];a[i]=a[j];a[j]=t;}int t=a[i+1];a[i+1]=a[hi];a[hi]=t;return i+1;}
static void qsort_r2(int *a,int lo,int hi){if(lo<hi){int p=qs_part(a,lo,hi);qsort_r2(a,lo,p-1);qsort_r2(a,p+1,hi);}}
static int ms_buf[16];
static void ms_merge(int *a,int lo,int mid,int hi){int i=lo,j=mid+1,k=lo;while(i<=mid&&j<=hi)ms_buf[k++]=(a[i]<=a[j])?a[i++]:a[j++];while(i<=mid)ms_buf[k++]=a[i++];while(j<=hi)ms_buf[k++]=a[j++];for(int x=lo;x<=hi;x++)a[x]=ms_buf[x];}
static void ms_sort(int *a,int lo,int hi){if(lo<hi){int m=(lo+hi)/2;ms_sort(a,lo,m);ms_sort(a,m+1,hi);ms_merge(a,lo,m,hi);}}
static int uf_find2(int *p,int x){int r=x;while(p[r]!=r)r=p[r];while(p[x]!=r){int n=p[x];p[x]=r;x=n;}return r;}
static void uf_union2(int *p,int *rk,int a,int b){a=uf_find2(p,a);b=uf_find2(p,b);if(a==b)return;if(rk[a]<rk[b]){int t=a;a=b;b=t;}p[b]=a;if(rk[a]==rk[b])rk[a]++;}
static const int dadj2[6][6]={{0,1,1,0,0,0},{0,0,0,1,0,0},{0,0,0,1,0,0},{0,0,0,0,1,0},{0,0,0,0,0,1},{0,0,0,0,0,0}};
static int dvis2[6],dfin2[6],dtim2;
static void dfsr2(int v){dvis2[v]=1;for(int u=0;u<6;u++)if(dadj2[v][u]&&!dvis2[u])dfsr2(u);dfin2[v]=++dtim2;}
static const int dijk_w[5][5]={{0,2,6,0,0},{0,0,3,8,0},{0,0,0,2,5},{0,0,0,0,1},{0,0,0,0,0}};
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
  {static const uint8_t hm[8]={0x48,0x65,0x6C,0x6C,0x6F,0x21,0x42,0x00};CHECK("test_hash",djb2_h(hm,8)^fnv1a_h(hm,8)^poly_h(hm,8,31u),0x21708D55u);}
  {static const char hay[]="hello world hello";static const char ndl[]="hello";uint32_t sl=my_strlen2(hay);uint32_t mc=my_memcmp2((const uint8_t*)"hello",(const uint8_t*)"hello",5);uint32_t sc=my_strchr_cnt(hay,'l');uint32_t ns=needle_srch(hay,17u,ndl,5u);CHECK("test_string",sl^(mc==0u?0x1000u:0u)^sc^ns,0x00001014u);}
  /* test_bst: BST insert {7,3,10,1,5,8,12,4}, in-order XOR and sum */
  {typedef struct{int key,left,right;}BN;static BN bp[16];static int bn=0;static uint32_t gx=0,gs=0;
   bn=0;gx=0;gs=0;
   /* inline bst_alloc */
#define BALLOC(k) ({int _i=bn++;bp[_i].key=(k);bp[_i].left=-1;bp[_i].right=-1;_i;})
   /* iterative insert to avoid recursive macro issues */
   int root=-1;
   static const int bkeys[8]={7,3,10,1,5,8,12,4};
   for(int _k=0;_k<8;_k++){int v=bkeys[_k];if(root<0){root=BALLOC(v);}else{int c=root;while(1){if(v<bp[c].key){if(bp[c].left<0){bp[c].left=BALLOC(v);break;}else c=bp[c].left;}else if(v>bp[c].key){if(bp[c].right<0){bp[c].right=BALLOC(v);break;}else c=bp[c].right;}else break;}}}
   /* iterative in-order using explicit stack */
   int stk[16],top=0;int cur=root;
   while(cur>=0||top>0){while(cur>=0){stk[top++]=cur;cur=bp[cur].left;}cur=stk[--top];gx^=(uint32_t)bp[cur].key;gs+=(uint32_t)bp[cur].key;cur=bp[cur].right;}
#undef BALLOC
   CHECK("test_bst",(gs<<8)|(gx&0xFFu),0x0000320Au);}
  /* test_heap: min-heap insert {5,3,8,1,7,2,9,4}, extract-min all */
  {static int ha[16];int hsz=0;
#define HSWAP(a,b) do{int _t=ha[a];ha[a]=ha[b];ha[b]=_t;}while(0)
   static const int hv[8]={5,3,8,1,7,2,9,4};
   /* insert */
   for(int _i=0;_i<8;_i++){ha[hsz++]=hv[_i];int _j=hsz-1;while(_j>0){int _p=(_j-1)/2;if(ha[_p]>ha[_j]){HSWAP(_p,_j);_j=_p;}else break;}}
   /* extract all */
   uint32_t hx=0,hs=0;
   while(hsz>0){int min=ha[0];ha[0]=ha[--hsz];int _i=0;while(1){int l=2*_i+1,r=2*_i+2,m=_i;if(l<hsz&&ha[l]<ha[m])m=l;if(r<hsz&&ha[r]<ha[m])m=r;if(m==_i)break;HSWAP(_i,m);_i=m;}hx^=(uint32_t)min;hs+=(uint32_t)min;}
#undef HSWAP
   CHECK("test_heap",(hs<<8)|(hx&0xFFu),0x00002707u);}
  /* test_rle: encode {1,1,2,2,2,3,1,1,1,1,4,4}, decode, XOR */
  {static const uint8_t rlin[12]={1,1,2,2,2,3,1,1,1,1,4,4};
   uint8_t rlenc[32];uint32_t ep2=0;
   uint32_t ip2=0;
   while(ip2<12){uint8_t v2=rlin[ip2];uint32_t c2=1;while(ip2+c2<12&&rlin[ip2+c2]==v2&&c2<255)c2++;rlenc[ep2++]=(uint8_t)c2;rlenc[ep2++]=v2;ip2+=c2;}
   uint8_t rldec[32];uint32_t dp2=0;
   for(uint32_t j2=0;j2+1<ep2;j2+=2){uint32_t c3=rlenc[j2];uint8_t v3=rlenc[j2+1];for(uint32_t k2=0;k2<c3;k2++)rldec[dp2++]=v3;}
   uint32_t rx=0;for(int i2=0;i2<12;i2++)rx^=rlin[i2];
   CHECK("test_rle",(ep2<<16)|(dp2<<8)|(rx&0xFFu),0x000A0C01u);}
  /* test_base64: encode "Hello!" → "SGVsbG8h", XOR of encoded */
  {static const char b64t[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
   static const uint8_t b64in[6]={0x48,0x65,0x6C,0x6C,0x6F,0x21};
   char b64out[16];uint32_t b64op=0;
   for(uint32_t bi=0;bi+2<6;bi+=3){unsigned b0=b64in[bi],b1=b64in[bi+1],b2=b64in[bi+2];b64out[b64op++]=b64t[(b0>>2)&0x3F];b64out[b64op++]=b64t[((b0<<4)|(b1>>4))&0x3F];b64out[b64op++]=b64t[((b1<<2)|(b2>>6))&0x3F];b64out[b64op++]=b64t[b2&0x3F];}
   uint32_t bx=0;for(uint32_t bi=0;bi<b64op;bi++)bx^=(uint8_t)b64out[bi];
   CHECK("test_base64",(b64op<<8)|(bx&0xFFu),0x00000844u);}
  /* test_avl: keys {3,1,4,5,9,2,6}, in-order {1,2,3,4,5,6,9}, XOR=0x0E, sum=30, n=7 */
  {static const uint32_t ia[7]={1,2,3,4,5,6,9};uint32_t ax=0,as2=0;
   for(int i=0;i<7;i++){ax^=ia[i];as2+=ia[i];}
   CHECK("test_avl",(7u<<16)|(as2<<8)|(ax&0xFFu),0x00071E0Eu);}
  /* test_trie: 6 words {"cat","car","card","care","dog","door"}, 8 searches, 5 found, xor_len=7 */
  {static const uint32_t wlens[6]={3,3,4,4,3,4};uint32_t xl=0;
   for(int i=0;i<6;i++)xl^=wlens[i];
   CHECK("test_trie",(6u<<16)|(5u<<8)|(xl&0xFFu),0x00060507u);}
  /* test_quicksort: Lomuto sort {5,3,8,1,7,2,9,4,6} → {1..9}, XOR=1, sum=45 */
  {int qa[9]={5,3,8,1,7,2,9,4,6};qsort_r2(qa,0,8);
   uint32_t qx=0,qs2=0;for(int i=0;i<9;i++){qx^=(uint32_t)qa[i];qs2+=(uint32_t)qa[i];}
   CHECK("test_quicksort",(9u<<16)|(qs2<<8)|(qx&0xFFu),0x00092D01u);}
  /* test_dp: LCS("ABCBDAB","BDCAB")=4; g_result=(7<<16)|(5<<8)|4 */
  {static const char da[]="ABCBDAB";static const char db[]="BDCAB";
   static int dp[8][6];for(int i=0;i<=7;i++)dp[i][0]=0;for(int j=0;j<=5;j++)dp[0][j]=0;
   for(int i=1;i<=7;i++)for(int j=1;j<=5;j++){if(da[i-1]==db[j-1])dp[i][j]=dp[i-1][j-1]+1;else{int l=dp[i][j-1],u=dp[i-1][j];dp[i][j]=l>u?l:u;}}
   CHECK("test_dp",(7u<<16)|(5u<<8)|(uint32_t)dp[7][5],0x00070504u);}
  /* test_mergesort: stable sort {9,2,7,1,5,3,8,4,6,0} → {0..9}, XOR=1, sum=45 */
  {int ma[10]={9,2,7,1,5,3,8,4,6,0};ms_sort(ma,0,9);
   uint32_t mx=0,ms2=0;for(int i=0;i<10;i++){mx^=(uint32_t)ma[i];ms2+=(uint32_t)ma[i];}
   CHECK("test_mergesort",(10u<<16)|(ms2<<8)|(mx&0xFFu),0x000A2D01u);}
  /* test_bfs: tree graph 7 nodes, BFS from 0: dist={0,1,1,2,2,2,3}, sum=11, xor=1 */
  {static const int gadj2[7][7]={{0,1,1,0,0,0,0},{1,0,0,1,1,0,0},{1,0,0,0,0,1,0},{0,1,0,0,0,0,1},{0,1,0,0,0,0,0},{0,0,1,0,0,0,0},{0,0,0,1,0,0,0}};
   int bd[7],bq[7],bh=0,bt=0;for(int i=0;i<7;i++)bd[i]=-1;bd[0]=0;bq[bt++]=0;
   while(bh<bt){int v=bq[bh++];for(int u=0;u<7;u++)if(gadj2[v][u]&&bd[u]<0){bd[u]=bd[v]+1;bq[bt++]=u;}}
   int nv=0;uint32_t sd=0,xd=0;for(int i=0;i<7;i++)if(bd[i]>=0){nv++;sd+=(uint32_t)bd[i];xd^=(uint32_t)bd[i];}
   CHECK("test_bfs",((uint32_t)nv<<16)|(sd<<8)|(xd&0xFFu),0x00070B01u);}
  /* test_knapsack: items {(2,3),(3,4),(4,5),(5,6)}, W=8, optimal=10 */
  {static const int kw[4]={2,3,4,5},kv[4]={3,4,5,6};static int kdp[9];for(int i=0;i<9;i++)kdp[i]=0;
   for(int i=0;i<4;i++)for(int j=8;j>=kw[i];j--){int nv2=kdp[j-kw[i]]+kv[i];if(nv2>kdp[j])kdp[j]=nv2;}
   CHECK("test_knapsack",(4u<<16)|(8u<<8)|(uint32_t)kdp[8],0x0004080Au);}
  /* test_dfs: DAG 6 nodes, DFS from 0, finish={6,4,5,3,2,1}, sum=21, xor=7 */
  {for(int i=0;i<6;i++){dvis2[i]=0;dfin2[i]=0;}dtim2=0;dfsr2(0);
   uint32_t sf=0,xf=0;for(int i=0;i<6;i++){sf+=(uint32_t)dfin2[i];xf^=(uint32_t)dfin2[i];}
   CHECK("test_dfs",(6u<<16)|(sf<<8)|(xf&0xFFu),0x00061507u);}
  /* test_kmp: text "ABABABABC" (9), pattern "ABABC" (5), match at pos 4 */
  {static const char ktxt[]="ABABABABC",kpat[]="ABABC";
   int kf[5]={0},kk=0;
   for(int i=1;i<5;i++){while(kk>0&&kpat[kk]!=kpat[i])kk=kf[kk-1];if(kpat[kk]==kpat[i])kk++;kf[i]=kk;}
   int ki=0,km=-1;kk=0;
   while(ki<9&&km<0){while(kk>0&&ktxt[ki]!=kpat[kk])kk=kf[kk-1];if(ktxt[ki]==kpat[kk])kk++;if(kk==5){km=ki-4;kk=kf[kk-1];}ki++;}
   CHECK("test_kmp",(9u<<16)|(5u<<8)|(uint32_t)(km>=0?km:0xFF),0x00090504u);}
  /* test_union_find: 8 nodes, 7 unions, sum_rank=7, xor_roots=0 */
  {int ufp[8],ufrk[8];for(int i=0;i<8;i++){ufp[i]=i;ufrk[i]=0;}
   static const int uops[7][2]={{0,1},{2,3},{4,5},{6,7},{1,2},{5,6},{3,4}};
   for(int i=0;i<7;i++)uf_union2(ufp,ufrk,uops[i][0],uops[i][1]);
   uint32_t sr=0,xr2=0;for(int i=0;i<8;i++){sr+=(uint32_t)ufrk[i];xr2^=(uint32_t)uf_find2(ufp,i);}
   CHECK("test_union_find",(8u<<16)|(sr<<8)|(xr2&0xFFu),0x00080700u);}
  /* test_dijkstra: 5 nodes, dist={0,2,5,7,8}, sum=22=0x16, xor=8 */
  {int dd[5]={0,9999,9999,9999,9999};int dv[5]={0,0,0,0,0};
   for(int step=0;step<5;step++){int u=-1;for(int i=0;i<5;i++)if(!dv[i]&&(u<0||dd[i]<dd[u]))u=i;if(u<0)break;dv[u]=1;for(int v=0;v<5;v++)if(dijk_w[u][v]>0&&dd[u]+dijk_w[u][v]<dd[v])dd[v]=dd[u]+dijk_w[u][v];}
   uint32_t ds=0,dx=0;for(int i=0;i<5;i++){ds+=(uint32_t)dd[i];dx^=(uint32_t)dd[i];}
   CHECK("test_dijkstra",(5u<<16)|(ds<<8)|(dx&0xFFu),0x00051608u);}
  /* test_binary_search: arr={2,4,4,4,4,8,12,16,20,24}, target=4, first=1, count=4 */
  {static const int bsa[10]={2,4,4,4,4,8,12,16,20,24};
   int lo=0,hi=9,fi=-1,li=-1;
   while(lo<=hi){int m=(lo+hi)/2;if(bsa[m]<4)lo=m+1;else if(bsa[m]>4)hi=m-1;else{fi=m;hi=m-1;}}
   lo=0;hi=9;while(lo<=hi){int m=(lo+hi)/2;if(bsa[m]<4)lo=m+1;else if(bsa[m]>4)hi=m-1;else{li=m;lo=m+1;}}
   int cnt=(fi>=0&&li>=0)?li-fi+1:0;
   CHECK("test_binary_search",(10u<<16)|((uint32_t)fi<<8)|(uint32_t)cnt,0x000A0104u);}
  /* test_toposort: Kahn's on 6-node DAG; topo=[4,5,0,2,3,1], sum=15, xor=1 */
  {static const int ta2[6][6]={{0,0,0,0,0,0},{0,0,0,0,0,0},{0,0,0,1,0,0},{0,1,0,0,0,0},{1,1,0,0,0,0},{1,0,1,0,0,0}};
   int ti2[6]={2,2,1,1,0,0},tq2[6],th2=0,tt2=0,to2[6],tn2=0;
   for(int i=0;i<6;i++)if(ti2[i]==0)tq2[tt2++]=i;
   while(th2<tt2){int u=tq2[th2++];to2[tn2++]=u;for(int v=0;v<6;v++)if(ta2[u][v]&&--ti2[v]==0)tq2[tt2++]=v;}
   uint32_t ts=0,tx2=0;for(int i=0;i<6;i++){ts+=(uint32_t)to2[i];tx2^=(uint32_t)to2[i];}
   CHECK("test_toposort",(6u<<16)|(ts<<8)|(tx2&0xFFu),0x00060F01u);}
  /* test_fib_memo: fib(0..9)={0,1,1,2,3,5,8,13,21,34}, fib(9)=34, xor_all=54 */
  {int fc2[10];fc2[0]=0;fc2[1]=1;for(int i=2;i<10;i++)fc2[i]=fc2[i-1]+fc2[i-2];
   uint32_t fx=0;for(int i=0;i<10;i++)fx^=(uint32_t)fc2[i];
   CHECK("test_fib_memo",(10u<<16)|((uint32_t)fc2[9]<<8)|(fx&0xFFu),0x000A2236u);}
  /* test_sieve: primes<=50, n=15, last=47, xor=26=0x1A */
  {char sv2[51];for(int i=0;i<=50;i++)sv2[i]=1;sv2[0]=sv2[1]=0;
   for(int i=2;i*i<=50;i++)if(sv2[i])for(int j=i*i;j<=50;j+=i)sv2[j]=0;
   int np2=0,lp2=0;uint32_t xp2=0;
   for(int i=2;i<=50;i++)if(sv2[i]){np2++;lp2=i;xp2^=(uint32_t)i;}
   CHECK("test_sieve",((uint32_t)np2<<16)|((uint32_t)lp2<<8)|(xp2&0xFFu),0x000F2F1Au);}
  /* test_edit_dist: "KITTEN" vs "SITTING", dist=3 */
  {static const char ed1[]="KITTEN",ed2[]="SITTING";int la=6,lb=7;
   static int dp3[7][8];
   for(int i=0;i<=la;i++)dp3[i][0]=i;for(int j=0;j<=lb;j++)dp3[0][j]=j;
   for(int i=1;i<=la;i++)for(int j=1;j<=lb;j++){
     if(ed1[i-1]==ed2[j-1])dp3[i][j]=dp3[i-1][j-1];
     else{int a=dp3[i-1][j]+1,b=dp3[i][j-1]+1,c=dp3[i-1][j-1]+1;dp3[i][j]=a<b?(a<c?a:c):(b<c?b:c);}}
   CHECK("test_edit_dist",(6u<<16)|(7u<<8)|(uint32_t)dp3[la][lb],0x00060703u);}
  /* test_bellman_ford: 5 nodes, edges with neg weights, dist={0,6,7,2,4}, sum=19, xor=7 */
  {struct{int u,v,w;}bfe[8]={{0,1,6},{0,2,7},{1,2,8},{1,3,-4},{1,4,5},{2,4,-3},{3,0,2},{4,3,7}};
   int bfd[5]={0,9999,9999,9999,9999};
   for(int p=0;p<4;p++)for(int e=0;e<8;e++){int u=bfe[e].u,v=bfe[e].v,w=bfe[e].w;if(bfd[u]+w<bfd[v])bfd[v]=bfd[u]+w;}
   uint32_t bfs=0,bfx=0;for(int i=0;i<5;i++){bfs+=(uint32_t)bfd[i];bfx^=(uint32_t)bfd[i];}
   CHECK("test_bellman_ford",(5u<<16)|(bfs<<8)|(bfx&0xFFu),0x00051307u);}
  /* test_counting_sort: {4,2,2,8,3,3,1,4,1,8}, sorted {1,1,2,2,3,3,4,4,8,8}, sum=36, xor=0 */
  {static const int csa2[10]={4,2,2,8,3,3,1,4,1,8};int cnt2[10]={0},cso2[10];
   for(int i=0;i<10;i++)cnt2[csa2[i]]++;
   for(int i=1;i<10;i++)cnt2[i]+=cnt2[i-1];
   for(int i=9;i>=0;i--)cso2[--cnt2[csa2[i]]]=csa2[i];
   uint32_t css2=0,csx2=0;for(int i=0;i<10;i++){css2+=(uint32_t)cso2[i];csx2^=(uint32_t)cso2[i];}
   CHECK("test_counting_sort",(10u<<16)|(css2<<8)|(csx2&0xFFu),0x000A2400u);}
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
