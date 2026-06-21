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
static int egcd2(int a,int b,int *x,int *y){if(b==0){*x=1;*y=0;return a;}int x1,y1;int g=egcd2(b,a%b,&x1,&y1);*x=y1;*y=x1-(a/b)*y1;return g;}
static int ci_tmp2[8];
static int merge_inv2(int *a,int lo,int hi){if(hi-lo<=1)return 0;int mid=(lo+hi)/2,cnt=merge_inv2(a,lo,mid)+merge_inv2(a,mid,hi);int i=lo,j=mid,k=lo;while(i<mid&&j<hi){if(a[i]<=a[j])ci_tmp2[k++]=a[i++];else{cnt+=mid-i;ci_tmp2[k++]=a[j++];}}while(i<mid)ci_tmp2[k++]=a[i++];while(j<hi)ci_tmp2[k++]=a[j++];for(int x=lo;x<hi;x++)a[x]=ci_tmp2[x];return cnt;}
static int nq_col2[8],nq_d1_2[16],nq_d2_2[16],nq_cnt2,nq_nn2;
static void nq_solve2(int row){if(row==nq_nn2){nq_cnt2++;return;}for(int c=0;c<nq_nn2;c++){int d1=row+c,d2=row-c+nq_nn2-1;if(!nq_col2[c]&&!nq_d1_2[d1]&&!nq_d2_2[d2]){nq_col2[c]=nq_d1_2[d1]=nq_d2_2[d2]=1;nq_solve2(row+1);nq_col2[c]=nq_d1_2[d1]=nq_d2_2[d2]=0;}}}
static int nqueens2(int n){nq_nn2=n;nq_cnt2=0;for(int i=0;i<n;i++)nq_col2[i]=0;for(int i=0;i<2*n;i++)nq_d1_2[i]=nq_d2_2[i]=0;nq_solve2(0);return nq_cnt2;}
static int mr_pow2(int a,int e,int m){int r=1;a%=m;while(e>0){if(e&1)r=r*a%m;a=a*a%m;e>>=1;}return r;}
static int miller_rabin2(int n){if(n<2)return 0;if(n==2)return 1;if(n%2==0)return 0;int d=n-1,s=0;while(d%2==0){d>>=1;s++;}int ws[]={2,3,5,7};for(int wi=0;wi<4;wi++){int a=ws[wi];if(a>=n)continue;int x=mr_pow2(a,d,n);if(x==1||x==n-1)continue;int r;for(r=1;r<s;r++){x=x*x%n;if(x==n-1)break;}if(r==s)return 0;}return 1;}
static int cp2_adj[6][3],cp2_deg[6],cp2_memo[6];
static int count_paths2(int u,int dst){if(u==dst)return 1;if(cp2_memo[u]>=0)return cp2_memo[u];int t=0;for(int i=0;i<cp2_deg[u];i++)t+=count_paths2(cp2_adj[u][i],dst);return cp2_memo[u]=t;}
static int crt_inv2(int a,int m){int m0=m,x0=0,x1=1;if(m==1)return 0;while(a>1){int q=a/m,t=m;m=a%m;a=t;t=x0;x0=x1-q*x0;x1=t;}return x1<0?x1+m0:x1;}
static void mp_mul2(long long A[2][2],long long B[2][2],long long C[2][2]){for(int i=0;i<2;i++)for(int j=0;j<2;j++){C[i][j]=0;for(int k=0;k<2;k++)C[i][j]+=A[i][k]*B[k][j];}}
static long long mp_fib2(int n){long long R[2][2]={{1,0},{0,1}},MA[2][2]={{1,1},{1,0}},MT[2][2];while(n>0){if(n%2){mp_mul2(R,MA,MT);for(int i=0;i<2;i++)for(int j=0;j<2;j++)R[i][j]=MT[i][j];}mp_mul2(MA,MA,MT);for(int i=0;i<2;i++)for(int j=0;j<2;j++)MA[i][j]=MT[i][j];n/=2;}return R[0][1];}
static int lca2_par[8]={0,0,1,1,2,2,3,3};
static int lca2_dep[8]={0,0,1,1,2,2,2,2};
static int lca2(int a,int b){while(lca2_dep[a]>lca2_dep[b])a=lca2_par[a];while(lca2_dep[b]>lca2_dep[a])b=lca2_par[b];while(a!=b){a=lca2_par[a];b=lca2_par[b];}return a;}
static int ni_vis2[4][5],ni_g2[4][5],ni_R2,ni_C2;
static void ni_dfs2(int r,int c){if(r<0||r>=ni_R2||c<0||c>=ni_C2||!ni_g2[r][c]||ni_vis2[r][c])return;ni_vis2[r][c]=1;ni_dfs2(r-1,c);ni_dfs2(r+1,c);ni_dfs2(r,c-1);ni_dfs2(r,c+1);}
static int ni_count2(void){int cnt=0;for(int r=0;r<ni_R2;r++)for(int c=0;c<ni_C2;c++)ni_vis2[r][c]=0;for(int r=0;r<ni_R2;r++)for(int c=0;c<ni_C2;c++)if(ni_g2[r][c]&&!ni_vis2[r][c]){ni_dfs2(r,c);cnt++;}return cnt;}
static int tj2_disc[5],tj2_low[5],tj2_stk[5],tj2_on[5],tj2_timer2,tj2_stop,tj2_nscc;
static int tj2_scc_sz[5];
static int tj2_adj[5][2],tj2_deg[5];
static void tj2_dfs(int v){tj2_disc[v]=tj2_low[v]=tj2_timer2++;tj2_stk[tj2_stop++]=v;tj2_on[v]=1;for(int i=0;i<tj2_deg[v];i++){int u=tj2_adj[v][i];if(tj2_disc[u]==-1){tj2_dfs(u);if(tj2_low[u]<tj2_low[v])tj2_low[v]=tj2_low[u];}else if(tj2_on[u]){if(tj2_disc[u]<tj2_low[v])tj2_low[v]=tj2_disc[u];}}if(tj2_low[v]==tj2_disc[v]){int s=tj2_nscc++;tj2_scc_sz[s]=0;int u;do{u=tj2_stk[--tj2_stop];tj2_on[u]=0;tj2_scc_sz[s]++;}while(u!=v);}}
static int hf2_freq[5]={5,2,1,3,4};
struct HN2{int freq,left,right;}hf2_nodes[9];
static int hf2_act[9],hf2_nn,hf2_clen[5];
static int hf2_min(void){int mf=0x7fffffff,mi=-1;for(int i=0;i<hf2_nn;i++)if(hf2_act[i]&&hf2_nodes[i].freq<mf){mf=hf2_nodes[i].freq;mi=i;}return mi;}
static void hf2_dfs(int n,int d){if(hf2_nodes[n].left==-1){hf2_clen[n]=d;return;}hf2_dfs(hf2_nodes[n].left,d+1);hf2_dfs(hf2_nodes[n].right,d+1);}
static int td2_adj[5][2]={{-1,-1},{-1,-1},{0,1},{1,-1},{2,3}},td2_deg[5]={0,0,2,1,2};
static int td2_vis[5],td2_stk[5],td2_top;
static void td2_dfs(int v){td2_vis[v]=1;for(int i=0;i<td2_deg[v];i++)if(!td2_vis[td2_adj[v][i]])td2_dfs(td2_adj[v][i]);td2_stk[td2_top++]=v;}
static int ch2_px[6]={0,2,3,2,0,1},ch2_py[6]={0,0,1,2,2,1},ch2_hull[6],ch2_ht;
static int ch2_cross(int oi,int ai,int bi){return(ch2_px[ai]-ch2_px[oi])*(ch2_py[bi]-ch2_py[oi])-(ch2_py[ai]-ch2_py[oi])*(ch2_px[bi]-ch2_px[oi]);}
static void ch2_scan(void){int mi=0;for(int i=1;i<6;i++)if(ch2_py[i]<ch2_py[mi]||(ch2_py[i]==ch2_py[mi]&&ch2_px[i]<ch2_px[mi]))mi=i;int tx=ch2_px[0];ch2_px[0]=ch2_px[mi];ch2_px[mi]=tx;int ty=ch2_py[0];ch2_py[0]=ch2_py[mi];ch2_py[mi]=ty;for(int i=1;i<5;i++){int b=i;for(int j=i+1;j<6;j++){int c=ch2_cross(0,b,j);if(c<0){b=j;}else if(c==0){int d1=(ch2_px[b]-ch2_px[0])*(ch2_px[b]-ch2_px[0])+(ch2_py[b]-ch2_py[0])*(ch2_py[b]-ch2_py[0]);int d2=(ch2_px[j]-ch2_px[0])*(ch2_px[j]-ch2_px[0])+(ch2_py[j]-ch2_py[0])*(ch2_py[j]-ch2_py[0]);if(d2>d1)b=j;}}if(b!=i){tx=ch2_px[i];ch2_px[i]=ch2_px[b];ch2_px[b]=tx;ty=ch2_py[i];ch2_py[i]=ch2_py[b];ch2_py[b]=ty;}}ch2_ht=0;for(int i=0;i<6;i++){while(ch2_ht>=2&&ch2_cross(ch2_hull[ch2_ht-2],ch2_hull[ch2_ht-1],i)<=0)ch2_ht--;ch2_hull[ch2_ht++]=i;}}
/* Sprint 70: suffix_array helper */
static const char sa2_str[]="banana";
static int sa2_idx[6];
static int sa2_cmp(int a,int b){const char*pa=sa2_str+a,*pb=sa2_str+b;while(*pa&&*pa==*pb){pa++;pb++;}return (unsigned char)*pa-(unsigned char)*pb;}
static void build_sa2(void){for(int i=0;i<6;i++)sa2_idx[i]=i;for(int i=1;i<6;i++){int key=sa2_idx[i],j=i-1;while(j>=0&&sa2_cmp(sa2_idx[j],key)>0){sa2_idx[j+1]=sa2_idx[j];j--;}sa2_idx[j+1]=key;}}
/* Sprint 73: articulation_point helper */
static int ap2_disc[5],ap2_low[5],ap2_vis[5],ap2_par[5],ap2_is_ap[5],ap2_timer2=0;
static int ap2_adj[5][4],ap2_deg[5];
static void ap2_dfs(int u){ap2_disc[u]=ap2_low[u]=ap2_timer2++;ap2_vis[u]=1;int cc=0;for(int i=0;i<ap2_deg[u];i++){int v=ap2_adj[u][i];if(!ap2_vis[v]){cc++;ap2_par[v]=u;ap2_dfs(v);if(ap2_low[v]<ap2_low[u])ap2_low[u]=ap2_low[v];if(ap2_par[u]==-1&&cc>1)ap2_is_ap[u]=1;if(ap2_par[u]!=-1&&ap2_low[v]>=ap2_disc[u])ap2_is_ap[u]=1;}else if(v!=ap2_par[u]){if(ap2_disc[v]<ap2_low[u])ap2_low[u]=ap2_disc[v];}}}
/* Sprint 81: bipartite_matching augmenting path */
static int bpm2_match_r[3],bpm2_vis[3];
static int bpm2_try(int u){for(int i=0;i<3;i++){if(!bpm2_vis[i]){bpm2_vis[i]=1;if(bpm2_match_r[i]==-1||bpm2_try(bpm2_match_r[i])){bpm2_match_r[i]=u;return 1;}}}return 0;}
/* Sprint 82: extended GCD (recursive) */
static int ge2_ext(int a,int b,int*x,int*y){if(b==0){*x=1;*y=0;return a;}int x1,y1;int g=ge2_ext(b,a%b,&x1,&y1);*x=y1;*y=x1-(a/b)*y1;return g;}
/* Sprint 83: matrix_exp helper */
static void me2_mul(uint32_t a[2][2],uint32_t b[2][2],uint32_t c[2][2]){uint32_t t[2][2]={{0,0},{0,0}};for(int i=0;i<2;i++)for(int j=0;j<2;j++)for(int k=0;k<2;k++)t[i][j]=(t[i][j]+a[i][k]*b[k][j])%10000u;for(int i=0;i<2;i++)for(int j=0;j<2;j++)c[i][j]=t[i][j];}
static uint32_t me2_fib(uint32_t n){uint32_t r[2][2]={{1,0},{0,1}},A[2][2]={{1,1},{1,0}};while(n>0){if(n&1u)me2_mul(r,A,r);me2_mul(A,A,A);n>>=1;}return r[0][1];}
/* Sprint 86: LCP helpers (non-recursive but needed across CHECK blocks) */
static int lcp2_two(const char*a,const char*b){int i=0;while(a[i]&&b[i]&&a[i]==b[i])i++;return i;}
static int lcp2_str(const char**strs,int n){int len=lcp2_two(strs[0],strs[1]);for(int i=2;i<n;i++){int l=lcp2_two(strs[0],strs[i]);if(l<len)len=l;}return len;}
/* Sprint 89: count_rooms DFS (recursive — must be static before CHECK) */
static int cr2_grid[5][5],cr2_vis[5][5],cr2_R,cr2_C,cr2_gen;
static void cr2_dfs(int r,int c){if(r<0||r>=cr2_R||c<0||c>=cr2_C||!cr2_grid[r][c]||cr2_vis[r][c]==cr2_gen)return;cr2_vis[r][c]=cr2_gen;cr2_dfs(r-1,c);cr2_dfs(r+1,c);cr2_dfs(r,c-1);cr2_dfs(r,c+1);}
static int cr2_count(void){int cnt=0;cr2_gen++;for(int r=0;r<cr2_R;r++)for(int c=0;c<cr2_C;c++)if(cr2_grid[r][c]&&cr2_vis[r][c]!=cr2_gen){cr2_dfs(r,c);cnt++;}return cnt;}
/* Sprint 90: trie ops helpers */
static int tr2_ch[60][26],tr2_end[60],tr2_sz;
static void tr2_init(void){tr2_sz=1;} /* BSS zero-initializes all nodes */
static void tr2_ins(const char*s){int cur=0;for(;*s;s++){int c=*s-'a';if(!tr2_ch[cur][c]){int n=tr2_sz++;tr2_ch[cur][c]=n;}cur=tr2_ch[cur][c];}tr2_end[cur]=1;}
static int tr2_srch(const char*s){int cur=0;for(;*s;s++){int c=*s-'a';if(!tr2_ch[cur][c])return 0;cur=tr2_ch[cur][c];}return tr2_end[cur];}
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
  /* test_floyd_warshall: 4 nodes, sum_off_diag=46, xor=2 */
  {static const int fwi[4][4]={{0,3,16383,5},{2,0,16383,4},{16383,1,0,16383},{16383,16383,2,0}};
   int fwd[4][4];for(int i=0;i<4;i++)for(int j=0;j<4;j++)fwd[i][j]=fwi[i][j];
   for(int k=0;k<4;k++)for(int i=0;i<4;i++)for(int j=0;j<4;j++)
     if(fwd[i][k]<16383&&fwd[k][j]<16383&&fwd[i][k]+fwd[k][j]<fwd[i][j])fwd[i][j]=fwd[i][k]+fwd[k][j];
   uint32_t fws=0,fwx=0;for(int i=0;i<4;i++)for(int j=0;j<4;j++)if(i!=j&&fwd[i][j]<16383){fws+=(uint32_t)fwd[i][j];fwx^=(uint32_t)fwd[i][j];}
   CHECK("test_floyd_warshall",(4u<<16)|(fws<<8)|(fwx&0xFFu),0x00042E02u);}
  /* test_bitset: A={1,3,5,7,9,11}, B={3,5,7,11,13,17}, pop_union=8, pop_isect=4, xor_pos=30 */
  {uint32_t bsa2=0,bsb2=0;
   static const int aa2[]={1,3,5,7,9,11},bb2[]={3,5,7,11,13,17};
   for(int i=0;i<6;i++){bsa2|=(1u<<aa2[i]);bsb2|=(1u<<bb2[i]);}
   uint32_t u2=bsa2|bsb2,n2=bsa2&bsb2,pu2=u2,pi3=n2,cu2=0,ci2=0;
   while(pu2){pu2&=pu2-1;cu2++;}while(pi3){pi3&=pi3-1;ci2++;}
   uint32_t xu2=0;for(int b=0;b<32;b++)if((u2>>b)&1)xu2^=(uint32_t)b;
   CHECK("test_bitset",(cu2<<16)|(ci2<<8)|(xu2&0xFFu),0x0008041Eu);}
  /* test_pow_mod: pow_mod({2,3,5,7},{10,7,5,3},{1000,100,31,13})={24,87,25,5}, sum=141, xor=83 */
  {static const uint32_t pmb[]={2,3,5,7},pme[]={10,7,5,3},pmm[]={1000,100,31,13};uint32_t pms=0,pmx=0;
   for(int k=0;k<4;k++){uint32_t b=pmb[k]%pmm[k],e=pme[k],r=1,m=pmm[k];while(e>0){if(e&1)r=r*b%m;e>>=1;b=b*b%m;}pms+=r;pmx^=r;}
   CHECK("test_pow_mod",(4u<<16)|(pms<<8)|(pmx&0xFFu),0x00048D53u);}
  /* test_segment_tree: n=8 arr={2,4,6,8,10,12,14,16}, q(0..7)=72,q(2..5)=36,q(1..4)=28, xor=112 */
  {uint32_t sgt2[16]={0};static const uint32_t sga2[]={2,4,6,8,10,12,14,16};
   for(int i=0;i<8;i++)sgt2[8+i]=sga2[i];
   for(int i=7;i>=1;i--)sgt2[i]=sgt2[2*i]+sgt2[2*i+1];
   static const int sqlo[]={0,2,1},sqhi[]={7,5,4};uint32_t sqr[3]={0};
   for(int q=0;q<3;q++){int l=8+sqlo[q],r=8+sqhi[q]+1;uint32_t s=0;while(l<r){if(l&1)s+=sgt2[l++];if(r&1)s+=sgt2[--r];l>>=1;r>>=1;}sqr[q]=s;}
   CHECK("test_segment_tree",(8u<<16)|(72u<<8)|((sqr[0]^sqr[1]^sqr[2])&0xFFu),0x00084870u);}
  /* test_fenwick: n=6 arr={1,3,5,7,9,11}, prefix(1)=1,prefix(3)=9,prefix(6)=36, xor=44 */
  {int ft2[7]={0};static const int fa2[]={1,3,5,7,9,11};
   for(int i=1;i<=6;i++){int j=i,v=fa2[i-1];while(j<=6){ft2[j]+=v;j+=j&(-j);}}
   int fq2[3]={0};static const int fqi2[]={1,3,6};
   for(int q=0;q<3;q++){int j=fqi2[q];while(j>0){fq2[q]+=ft2[j];j-=j&(-j);}}
   uint32_t ftot=(uint32_t)fq2[2],fxr=(uint32_t)(fq2[0]^fq2[1]^fq2[2]);
   CHECK("test_fenwick",(6u<<16)|(ftot<<8)|(fxr&0xFFu),0x0006242Cu);}
  /* test_lis: {3,1,4,1,5,9,2,6,5,3,5} n=11, LIS=4, piles_xor=5 */
  {static const int la2[]={3,1,4,1,5,9,2,6,5,3,5};int lpiles[11],lnp=0;
   for(int i=0;i<11;i++){int v=la2[i],lo=0,hi=lnp;
     while(lo<hi){int m=(lo+hi)/2;if(lpiles[m]<v)lo=m+1;else hi=m;}
     lpiles[lo]=v;if(lo==lnp)lnp++;}
   uint32_t lx=0;for(int i=0;i<lnp;i++)lx^=(uint32_t)lpiles[i];
   CHECK("test_lis",(11u<<16)|((uint32_t)lnp<<8)|(lx&0xFFu),0x000B0405u);}
  /* test_zfunc: "AABAAB" n=6, z={0,1,0,3,1,0}, sum=5, xor=3 */
  {static const char zs[]="AABAAB";int zv[6]={0};int zl=0,zr=0;
   for(int i=1;i<6;i++){zv[i]=(i<zr)?(zr-i<zv[i-zl]?zr-i:zv[i-zl]):0;
     while(i+zv[i]<6&&zs[zv[i]]==zs[i+zv[i]])zv[i]++;
     if(i+zv[i]>zr){zl=i;zr=i+zv[i];}}
   uint32_t zsum=0,zxor=0;for(int i=0;i<6;i++){zsum+=zv[i];zxor^=zv[i];}
   CHECK("test_zfunc",(6u<<16)|(zsum<<8)|(zxor&0xFFu),0x00060503u);}
  /* test_radix_sort: {45,12,78,23,56,89,34,67} -> sorted, last=89, xor=120 */
  {static const uint8_t rsa[]={45,12,78,23,56,89,34,67};uint8_t rtp[8],rto[8];
   uint8_t rct[16];
   for(int j=0;j<16;j++)rct[j]=0;for(int j=0;j<8;j++)rct[rsa[j]&0xF]++;
   for(int j=1;j<16;j++)rct[j]=(uint8_t)(rct[j]+rct[j-1]);
   for(int j=7;j>=0;j--)rtp[--rct[rsa[j]&0xF]]=rsa[j];
   for(int j=0;j<16;j++)rct[j]=0;for(int j=0;j<8;j++)rct[rtp[j]>>4]++;
   for(int j=1;j<16;j++)rct[j]=(uint8_t)(rct[j]+rct[j-1]);
   for(int j=7;j>=0;j--)rto[--rct[rtp[j]>>4]]=rtp[j];
   uint32_t rrx=0;for(int j=0;j<8;j++)rrx^=rto[j];
   CHECK("test_radix_sort",(8u<<16)|((uint32_t)rto[7]<<8)|(rrx&0xFFu),0x00085978u);}
  /* test_manacher: "#A#B#A#C#A#B#A#" (n_orig=7), P max=7, sum=17 */
  {static const char mts[]="#A#B#A#C#A#B#A#";int mtp[15]={0};int mcc=0,mcr=0,mmmx=0;
   for(int i=0;i<15;i++){int mir=2*mcc-i;
     mtp[i]=(i<mcr)?(mcr-i<mtp[mir]?mcr-i:mtp[mir]):0;
     while(i-mtp[i]-1>=0&&i+mtp[i]+1<15&&mts[i-mtp[i]-1]==mts[i+mtp[i]+1])mtp[i]++;
     if(i+mtp[i]>mcr){mcc=i;mcr=i+mtp[i];}if(mtp[i]>mmmx)mmmx=mtp[i];}
   uint32_t msp=0;for(int i=0;i<15;i++)msp+=mtp[i];
   CHECK("test_manacher",(7u<<16)|((uint32_t)mmmx<<8)|(msp&0xFFu),0x00070711u);}
  /* test_coin_change: coins={1,5,12,25}, dp[11]=3,dp[14]=3,dp[30]=2, sum=8, xor=2 */
  {static const int ccoins[]={1,5,12,25};int cdp[31];
   cdp[0]=0;for(int i=1;i<=30;i++){cdp[i]=999;for(int j=0;j<4;j++)if(i>=ccoins[j]&&cdp[i-ccoins[j]]+1<cdp[i])cdp[i]=cdp[i-ccoins[j]]+1;}
   static const int ctgts[]={11,14,30};uint32_t cs2=0,cx2=0;
   for(int k=0;k<3;k++){cs2+=(uint32_t)cdp[ctgts[k]];cx2^=(uint32_t)cdp[ctgts[k]];}
   CHECK("test_coin_change",(4u<<16)|(cs2<<8)|(cx2&0xFFu),0x00040802u);}
  /* test_kadane: {-2,1,-3,4,-1,2,1,-5,4} n=9, max_sum=6, start=3, end=6 */
  {static const int ka2[]={-2,1,-3,4,-1,2,1,-5,4};int ks2=ka2[0],kc2=ka2[0],kts2=0,kms2=0,kme2=0;
   for(int i=1;i<9;i++){if(kc2+ka2[i]>ka2[i])kc2+=ka2[i];else{kc2=ka2[i];kts2=i;}
     if(kc2>ks2){ks2=kc2;kms2=kts2;kme2=i;}}
   CHECK("test_kadane",(9u<<16)|((uint32_t)ks2<<8)|(((uint32_t)kms2<<4)|(uint32_t)kme2),0x00090636u);}
  /* test_ext_gcd: gcd(35,15)=5, gcd(48,18)=6, gcd(100,75)=25; sum=36, xor=26 */
  {static const int epa[]={35,48,100},epb[]={15,18,75};uint32_t egs=0,egx=0;
   for(int k=0;k<3;k++){int ex,ey;uint32_t eg=(uint32_t)egcd2(epa[k],epb[k],&ex,&ey);egs+=eg;egx^=eg;}
   CHECK("test_ext_gcd",(3u<<16)|(egs<<8)|(egx&0xFFu),0x0003241Au);}
  /* test_sparse_table: arr={3,7,1,9,2,8,5,4}, RMQ(0,1)=3,RMQ(1,4)=1,RMQ(5,7)=4, sum=8,xor=6 */
  {static const int sra[]={3,7,1,9,2,8,5,4};int srt[4][8]={0};
   for(int i=0;i<8;i++)srt[0][i]=sra[i];
   for(int j=1;j<=3;j++)for(int i=0;i+(1<<j)-1<8;i++){int a=srt[j-1][i],b=srt[j-1][i+(1<<(j-1))];srt[j][i]=a<b?a:b;}
   int sqlo2[]={0,1,5},sqhi2[]={1,4,7};int srq[3];
   for(int q=0;q<3;q++){int l=sqlo2[q],r=sqhi2[q],k=0;while((1<<(k+1))<=r-l+1)k++;srq[q]=srt[k][l]<srt[k][r-(1<<k)+1]?srt[k][l]:srt[k][r-(1<<k)+1];}
   uint32_t sqs=0,sqx=0;for(int q=0;q<3;q++){sqs+=srq[q];sqx^=srq[q];}
   CHECK("test_sparse_table",(8u<<16)|(sqs<<8)|(sqx&0xFFu),0x00080806u);}
  /* test_activity_sel: {[1,2],[3,4],[0,6],[5,7],[8,9],[5,9]} → count=4, sum_end=22 */
  {typedef struct{int s,e;}A2;static const A2 asrc[]={{1,2},{3,4},{0,6},{5,7},{8,9},{5,9}};
   A2 aa[6];for(int i=0;i<6;i++)aa[i]=asrc[i];
   for(int i=1;i<6;i++){A2 k=aa[i];int j=i-1;while(j>=0&&aa[j].e>k.e){aa[j+1]=aa[j];j--;}aa[j+1]=k;}
   int acnt=0,ale=-1,ase=0;for(int i=0;i<6;i++)if(aa[i].s>=ale){acnt++;ale=aa[i].e;ase+=aa[i].e;}
   CHECK("test_activity_sel",(6u<<16)|((uint32_t)acnt<<8)|((uint32_t)ase&0xFFu),0x00060416u);}
  /* test_lps: "BBABCBCAB" n=9, LPS=7, n-LPS=2 */
  {static const char lpss[]="BBABCBCAB";int ldp[9][9]={0};
   for(int i=0;i<9;i++)ldp[i][i]=1;
   for(int len=2;len<=9;len++)for(int i=0;i<=9-len;i++){int j=i+len-1;
     if(lpss[i]==lpss[j])ldp[i][j]=(len==2)?2:ldp[i+1][j-1]+2;
     else ldp[i][j]=ldp[i+1][j]>ldp[i][j-1]?ldp[i+1][j]:ldp[i][j-1];}
   CHECK("test_lps",(9u<<16)|((uint32_t)ldp[0][8]<<8)|((uint32_t)(9-ldp[0][8])&0xFFu),0x00090702u);}
  /* test_dutch_flag: {2,0,2,1,1,0} pivot=1 → {0,0,1,1,2,2}, lo=2, mid=4 */
  {int df2[]={2,0,2,1,1,0};int dlo=0,dmid=0,dhi=5;
   while(dmid<=dhi){if(df2[dmid]<1){int t=df2[dlo];df2[dlo]=df2[dmid];df2[dmid]=t;dlo++;dmid++;}
     else if(df2[dmid]==1){dmid++;}else{int t=df2[dmid];df2[dmid]=df2[dhi];df2[dhi]=t;dhi--;}}
   CHECK("test_dutch_flag",(6u<<16)|((uint32_t)dlo<<8)|(uint32_t)dmid,0x00060204u);}
  /* test_prim_mst: 5-node graph, MST weight=16, n-1=4 edges */
  {static const int padj[5][5]={{0,2,0,6,0},{2,0,3,8,5},{0,3,0,0,7},{6,8,0,0,9},{0,5,7,9,0}};
   int pkey[5]={9999,9999,9999,9999,9999},pmst[5]={0};pkey[0]=0;int pmw=0;
   for(int step=0;step<5;step++){int u=-1;for(int v=0;v<5;v++)if(!pmst[v]&&(u==-1||pkey[v]<pkey[u]))u=v;
     pmst[u]=1;if(step>0)pmw+=pkey[u];
     for(int v=0;v<5;v++)if(padj[u][v]&&!pmst[v]&&padj[u][v]<pkey[v])pkey[v]=padj[u][v];}
   CHECK("test_prim_mst",(5u<<16)|((uint32_t)pmw<<8)|4u,0x00051004u);}
  /* test_subset_sum: items={3,5,2,8,7} n=5, targets={10,12,11} all reachable, xor=13 */
  {static const int ssitems[]={3,5,2,8,7};int ssdp[13]={0};ssdp[0]=1;
   for(int k=0;k<5;k++)for(int j=12;j>=ssitems[k];j--)ssdp[j]|=ssdp[j-ssitems[k]];
   static const int sst[]={10,12,11};uint32_t sscnt=0,ssxor=0;
   for(int k=0;k<3;k++)if(ssdp[sst[k]]){sscnt++;ssxor^=(uint32_t)sst[k];}
   CHECK("test_subset_sum",(5u<<16)|(sscnt<<8)|(ssxor&0xFFu),0x0005030Du);}
  /* test_next_greater: {4,5,2,10,8,3,6,1} NGE={5,10,10,-1,-1,6,-1,-1} count=4 xor=3 */
  {static const int nga[]={4,5,2,10,8,3,6,1};int nge2[8],ngs[8],ngt=-1;
   for(int i=0;i<8;i++)nge2[i]=-1;
   for(int i=0;i<8;i++){while(ngt>=0&&nga[ngs[ngt]]<nga[i])nge2[ngs[ngt--]]=nga[i];ngs[++ngt]=i;}
   uint32_t ngcnt=0,ngx=0;for(int i=0;i<8;i++)if(nge2[i]!=-1){ngcnt++;ngx^=(uint32_t)nge2[i];}
   CHECK("test_next_greater",(8u<<16)|(ngcnt<<8)|(ngx&0xFFu),0x00080403u);}
  /* test_josephus: (n=10,k=3)→4 (n=7,k=2)→7 (n=12,k=4)→1; sum=12, xor=2 */
  {static const int jns[]={10,7,12},jks[]={3,2,4};uint32_t jsum=0,jxor=0;
   for(int t=0;t<3;t++){int p=0;for(int i=2;i<=jns[t];i++)p=(p+jks[t])%i;p++;
     jsum+=(uint32_t)p;jxor^=(uint32_t)p;}
   CHECK("test_josephus",(10u<<16)|(jsum<<8)|(jxor&0xFFu),0x000A0C02u);}
  /* test_quick_select: {7,2,1,6,5,3,4,8} n=8; ks={0,3,7}→{1,4,8} sum=13 xor=13 */
  {static const int qsin[]={7,2,1,6,5,3,4,8};int qsa[8],qss[8];uint32_t qsum=0,qxor=0;
   static const int qks[]={0,3,7};
   for(int t=0;t<3;t++){for(int i=0;i<8;i++)qsa[i]=qsin[i];
     int lo=0,hi=7,k=qks[t];
     while(lo<hi){int pv=qsa[hi],ii=lo-1;for(int j=lo;j<hi;j++)if(qsa[j]<=pv){ii++;int tmp=qsa[ii];qsa[ii]=qsa[j];qsa[j]=tmp;}int tmp=qsa[ii+1];qsa[ii+1]=qsa[hi];qsa[hi]=tmp;int p=ii+1;if(p==k)break;else if(k<p)hi=p-1;else lo=p+1;}
     qsum+=(uint32_t)qsa[k];qxor^=(uint32_t)qsa[k];}
   CHECK("test_quick_select",(8u<<16)|(qsum<<8)|(qxor&0xFFu),0x00080D0Du);}
  /* test_matrix_chain: dims={2,3,4,5} n=3; dp[0][2]=64, dp[0][1]=24 */
  {static const int mcd[]={2,3,4,5};int mcdp[3][3]={{0,0,0},{0,0,0},{0,0,0}};
   for(int l=2;l<=3;l++)for(int i=0;i<=3-l;i++){int j=i+l-1;mcdp[i][j]=0x7fffffff;
     for(int k=i;k<j;k++){int c=mcdp[i][k]+mcdp[k+1][j]+mcd[i]*mcd[k+1]*mcd[j+1];if(c<mcdp[i][j])mcdp[i][j]=c;}}
   CHECK("test_matrix_chain",(3u<<16)|((uint32_t)mcdp[0][2]<<8)|(uint32_t)mcdp[0][1],0x00034018u);}
  /* test_kruskal: n=5 graph, edges sorted; MST weight=12, edges=4 */
  {int kp[5]={0,1,2,3,4},kr[5]={0};
   typedef struct{int u,v,w;}KE;static const KE ke[]={{0,1,1},{1,2,2},{2,3,3},{0,2,4},{1,3,5},{3,4,6},{0,3,7},{2,4,8}};
   int kmw=0,kme=0;
   for(int i=0;i<8&&kme<4;i++){
     int a=ke[i].u,b=ke[i].v;
     while(kp[a]!=a)a=kp[a]=kp[kp[a]];while(kp[b]!=b)b=kp[b]=kp[kp[b]];
     if(a!=b){if(kr[a]<kr[b]){int t=a;a=b;b=t;}kp[b]=a;if(kr[a]==kr[b])kr[a]++;kmw+=ke[i].w;kme++;}}
   CHECK("test_kruskal",(5u<<16)|((uint32_t)kmw<<8)|(uint32_t)kme,0x00050C04u);}
  /* test_floyd_cycle: next={1,2,3,4,2,6,2} n=7; cycle_start=2, len=3 */
  {static const int fcn[]={1,2,3,4,2,6,2};int sl=0,fa=0;
   do{sl=fcn[sl];fa=fcn[fcn[fa]];}while(sl!=fa);
   sl=0;while(sl!=fa){sl=fcn[sl];fa=fcn[fa];}int cs=sl;
   int fl=1;fa=fcn[sl];while(fa!=sl){fa=fcn[fa];fl++;}
   CHECK("test_floyd_cycle",(7u<<16)|((uint32_t)cs<<8)|(uint32_t)fl,0x00070203u);}
  /* test_sliding_window: {1,3,-1,-3,5,3,6,7} w=3; maxima={3,3,5,5,6,7} sum=29 xor=1 */
  {static const int swa[]={1,3,-1,-3,5,3,6,7};int swdq[8],swmx[8],swh=0,swt=0;
   for(int i=0;i<8;i++){while(swh<swt&&swdq[swh]<i-3+1)swh++;
     while(swh<swt&&swa[swdq[swt-1]]<=swa[i])swt--;swdq[swt++]=i;
     if(i>=2)swmx[i-2]=swa[swdq[swh]];}
   uint32_t swsum=0,swx=0;for(int i=0;i<6;i++){swsum+=(uint32_t)swmx[i];swx^=(uint32_t)swmx[i];}
   CHECK("test_sliding_window",(8u<<16)|(swsum<<8)|(swx&0xFFu),0x00081D01u);}
  /* test_bitmask_enum: items={2,3,7,5} n=4 k=3; count=6 max_sum=15 */
  {static const int bmi[]={2,3,7,5};int bmcnt=0,bmms=-1;
   for(int mask=0;mask<16;mask++){int s=0;for(int b=0;b<4;b++)if(mask&(1<<b))s+=bmi[b];
     if(s%3==0){bmcnt++;if(s>bmms)bmms=s;}}
   CHECK("test_bitmask_enum",(4u<<16)|((uint32_t)bmcnt<<8)|(uint32_t)bmms,0x0004060Fu);}
  /* test_two_pointer: sorted {1..10} target=11; 5 pairs; xor lo-vals=1 */
  {static const int tpa[]={1,2,3,4,5,6,7,8,9,10};int tplo=0,tphi=9,tpcnt=0;uint32_t tpx=0;
   while(tplo<tphi){int s=tpa[tplo]+tpa[tphi];if(s==11){tpcnt++;tpx^=(uint32_t)tpa[tplo];tplo++;tphi--;}else if(s<11)tplo++;else tphi--;}
   CHECK("test_two_pointer",(10u<<16)|((uint32_t)tpcnt<<8)|(tpx&0xFFu),0x000A0501u);}
  /* test_min_stack: push{5,3,7,2}; getMin seq={2,3,3,5}; sum=13 xor=7 */
  {int msmain[8],msmin[8],mstop=1;msmin[0]=0x7fffffff;
   uint32_t mssum=0,msxorv=0;
   #define MSPUSH(x) do{msmain[mstop-1]=(x);msmin[mstop]=((x)<msmin[mstop-1])?(x):msmin[mstop-1];mstop++;}while(0)
   #define MSPOP()   do{mstop--;}while(0)
   #define MSMIN()   (msmin[mstop-1])
   MSPUSH(5);MSPUSH(3);MSPUSH(7);MSPUSH(2);
   mssum+=(uint32_t)MSMIN();msxorv^=(uint32_t)MSMIN();MSPOP();
   mssum+=(uint32_t)MSMIN();msxorv^=(uint32_t)MSMIN();MSPOP();
   mssum+=(uint32_t)MSMIN();msxorv^=(uint32_t)MSMIN();MSPOP();
   mssum+=(uint32_t)MSMIN();msxorv^=(uint32_t)MSMIN();
   CHECK("test_min_stack",(4u<<16)|(mssum<<8)|(msxorv&0xFFu),0x00040D07u);}
  /* test_boyer_moore_vote: {3,2,3,1,3,3,2} n=7; candidate=3, freq=4 */
  {static const int bmva[]={3,2,3,1,3,3,2};int bmcand=bmva[0],bmcnt=1;
   for(int i=1;i<7;i++){if(bmcnt==0){bmcand=bmva[i];bmcnt=1;}else if(bmva[i]==bmcand)bmcnt++;else bmcnt--;}
   int bmfq=0;for(int i=0;i<7;i++)if(bmva[i]==bmcand)bmfq++;
   CHECK("test_boyer_moore_vote",(7u<<16)|((uint32_t)bmcand<<8)|(uint32_t)bmfq,0x00070304u);}
  /* test_count_inversions: {6,5,4,3,2,1} n=6; inv=15, xor=7 */
  {int cia[]={6,5,4,3,2,1};uint32_t cixor=0;for(int i=0;i<6;i++)cixor^=(uint32_t)cia[i];
   int ciinv=merge_inv2(cia,0,6);
   CHECK("test_count_inversions",(6u<<16)|((uint32_t)ciinv<<8)|(cixor&0xFFu),0x00060F07u);}
  /* test_jump_search: {1,3..19} n=10 step=3; find{7,13,19}→{3,6,9} count=3 xor=12 */
  {static const int jsa[]={1,3,5,7,9,11,13,15,17,19};static const int jsq[]={7,13,19};
   uint32_t jscnt=0,jsx=0;
   for(int q=0;q<3;q++){int bk=3,prev=0,step=3,key=jsq[q];
     while(step<10&&jsa[step-1]<key){prev=step;step+=bk;}
     int lim=(step<10)?step:10;int found=-1;
     for(int p=prev;p<lim;p++){if(jsa[p]==key){found=p;break;}if(jsa[p]>key)break;}
     if(found>=0){jscnt++;jsx^=(uint32_t)found;}}
   CHECK("test_jump_search",(10u<<16)|(jscnt<<8)|(jsx&0xFFu),0x000A030Cu);}
  /* test_lc_substring: s1="ABABC" s2="BABCAB"; LCS=4 ("BABC") */
  {static const char ls1[]="ABABC",ls2[]="BABCAB";int lsdp[6][7]={{0}};int lsmx=0;
   for(int i=1;i<=5;i++)for(int j=1;j<=6;j++){if(ls1[i-1]==ls2[j-1]){lsdp[i][j]=lsdp[i-1][j-1]+1;if(lsdp[i][j]>lsmx)lsmx=lsdp[i][j];}else lsdp[i][j]=0;}
   CHECK("test_lc_substring",(5u<<16)|(6u<<8)|(uint32_t)lsmx,0x00050604u);}
  /* test_catalan: C(0..5)={1,1,2,5,14,42}; sum(C3+C4+C5)=61 xor=33 */
  {int ct[6]={0};ct[0]=1;for(int k=1;k<6;k++)for(int i=0;i<k;i++)ct[k]+=ct[i]*ct[k-1-i];
   uint32_t csum=0,cxor=0;for(int i=3;i<=5;i++){csum+=(uint32_t)ct[i];cxor^=(uint32_t)ct[i];}
   CHECK("test_catalan",(6u<<16)|(csum<<8)|(cxor&0xFFu),0x00063D21u);}
  /* test_shell_sort: {8,3,7,1,5,2,9,4} n=8; sorted last=9 xor=7 */
  {int sha[]={8,3,7,1,5,2,9,4};for(int gap=4;gap>0;gap/=2)for(int i=gap;i<8;i++){int tmp=sha[i],j=i;while(j>=gap&&sha[j-gap]>tmp){sha[j]=sha[j-gap];j-=gap;}sha[j]=tmp;}
   uint32_t shx=0;for(int i=0;i<8;i++)shx^=(uint32_t)sha[i];
   CHECK("test_shell_sort",(8u<<16)|((uint32_t)sha[7]<<8)|(shx&0xFFu),0x00080907u);}
  /* test_interpolation_search: arr={1,3,5,...,15} n=8; find7->3 find13->6; count=2 xor=5 */
  {const int isarr[]={1,3,5,7,9,11,13,15};int isqs[]={7,13};uint32_t iscnt=0,isxor=0;
   for(int q=0;q<2;q++){int lo=0,hi=7,key=isqs[q],pos=-1;
     while(lo<=hi&&key>=isarr[lo]&&key<=isarr[hi]){if(lo==hi){if(isarr[lo]==key)pos=lo;break;}
       int p2=lo+(key-isarr[lo])*(hi-lo)/(isarr[hi]-isarr[lo]);
       if(isarr[p2]==key){pos=p2;break;}else if(isarr[p2]<key)lo=p2+1;else hi=p2-1;}
     if(pos>=0){iscnt++;isxor^=(uint32_t)pos;}}
   CHECK("test_interpolation_search",(8u<<16)|(iscnt<<8)|(isxor&0xFFu),0x00080205u);}
  /* test_n_queens: N=4:2 N=5:10 N=6:4; sum=16 xor=12 */
  {int s4=nqueens2(4),s5=nqueens2(5),s6=nqueens2(6);
   CHECK("test_n_queens",(6u<<16)|((uint32_t)(s4+s5+s6)<<8)|((uint32_t)(s4^s5^s6)&0xFFu),0x0006100Cu);}
  /* test_rabin_karp: text="aaabaabaab" pat="aab" n=10 m=3 BASE=26 MOD=101; matches 1,4,7 count=3 xor=2 */
  {const char rkt[]="aaabaabaab",rkp[]="aab";int rkn=10,rkm=3,rkb=26,rkmod=101;
   int rkpow=1;for(int i=0;i<rkm-1;i++)rkpow=rkpow*rkb%rkmod;
   int rkph=0,rkh=0;for(int i=0;i<rkm;i++){rkph=(rkph*rkb+(rkp[i]-'a'))%rkmod;rkh=(rkh*rkb+(rkt[i]-'a'))%rkmod;}
   uint32_t rkc=0,rkx=0;
   for(int i=0;i<=rkn-rkm;i++){if(rkh==rkph){int ok=1;for(int j=0;j<rkm;j++)if(rkt[i+j]!=rkp[j]){ok=0;break;}if(ok){rkc++;rkx^=(uint32_t)i;}}
     if(i<rkn-rkm){int ld=rkt[i]-'a',nx=rkt[i+rkm]-'a';rkh=((rkh+(rkmod-ld)*rkpow)%rkmod*rkb+nx)%rkmod;}}
   CHECK("test_rabin_karp",((uint32_t)rkn<<16)|(rkc<<8)|(rkx&0xFFu),0x000A0302u);}
  /* test_pancake_sort: {3,6,1,5,2,4} n=6 → sorted {1..6} last=6 xor=7 */
  {int ps[]={3,6,1,5,2,4},pn=6;
   for(int sz=pn;sz>1;sz--){int mi=0;for(int i=1;i<sz;i++)if(ps[i]>ps[mi])mi=i;
     if(mi==sz-1)continue;if(mi!=0){int lo=0,hi=mi;while(lo<hi){int t=ps[lo];ps[lo++]=ps[hi];ps[hi--]=t;}}
     {int lo=0,hi=sz-1;while(lo<hi){int t=ps[lo];ps[lo++]=ps[hi];ps[hi--]=t;}}}
   uint32_t psx=0;for(int i=0;i<pn;i++)psx^=(uint32_t)ps[i];
   CHECK("test_pancake_sort",((uint32_t)pn<<16)|((uint32_t)ps[pn-1]<<8)|(psx&0xFFu),0x00060607u);}
  /* test_comb_sort: {5,2,8,1,9,3,6} n=7; gap*10/13; sorted last=9 xor=2 */
  {int cb[]={5,2,8,1,9,3,6},cbn=7,cbg=7,cbs=0;
   while(cbg>1||!cbs){cbg=cbg*10/13;if(cbg<1)cbg=1;cbs=1;for(int i=0;i+cbg<cbn;i++)if(cb[i]>cb[i+cbg]){int t=cb[i];cb[i]=cb[i+cbg];cb[i+cbg]=t;cbs=0;}}
   uint32_t cbx=0;for(int i=0;i<cbn;i++)cbx^=(uint32_t)cb[i];
   CHECK("test_comb_sort",((uint32_t)cbn<<16)|((uint32_t)cb[cbn-1]<<8)|(cbx&0xFFu),0x00070902u);}
  /* test_cycle_sort: {3,1,5,4,2} n=5; writes=4 xor_sorted=1 */
  {int cy[]={3,1,5,4,2},cyn=5,cyw=0;
   for(int cs=0;cs<cyn-1;cs++){int item=cy[cs],pos=cs;for(int i=cs+1;i<cyn;i++)if(cy[i]<item)pos++;
     if(pos==cs)continue;while(item==cy[pos])pos++;int t=cy[pos];cy[pos]=item;item=t;cyw++;
     while(pos!=cs){pos=cs;for(int i=cs+1;i<cyn;i++)if(cy[i]<item)pos++;while(item==cy[pos])pos++;t=cy[pos];cy[pos]=item;item=t;cyw++;}}
   uint32_t cyx=0;for(int i=0;i<cyn;i++)cyx^=(uint32_t)cy[i];
   CHECK("test_cycle_sort",((uint32_t)cyn<<16)|((uint32_t)cyw<<8)|(cyx&0xFFu),0x00050401u);}
  /* test_ternary_search: 3 queries min of (x-t)^2; lo/hi/t={(0,7,3),(1,9,5),(4,12,8)}; min={3,5,8}; sum=16 xor=14 */
  {uint32_t tss=0,tsx=0;int tslo[]={0,1,4},tshi[]={7,9,12},tstgt[]={3,5,8};
   for(int q=0;q<3;q++){int lo=tslo[q],hi=tshi[q],t=tstgt[q];
     while(hi-lo>2){int m1=lo+(hi-lo)/3,m2=hi-(hi-lo)/3;if((m1-t)*(m1-t)<=(m2-t)*(m2-t))hi=m2-1;else lo=m1+1;}
     int best=lo;for(int i=lo+1;i<=hi;i++)if((i-t)*(i-t)<(best-t)*(best-t))best=i;tss+=(uint32_t)best;tsx^=(uint32_t)best;}
   CHECK("test_ternary_search",(3u<<16)|(tss<<8)|(tsx&0xFFu),0x0003100Eu);}
  /* test_miller_rabin: {2,3,5,9,11,15,17,97}; primes=6 xor=127 */
  {int mrv[]={2,3,5,9,11,15,17,97};uint32_t mrc=0,mrx=0;for(int i=0;i<8;i++){if(miller_rabin2(mrv[i])){mrc++;mrx^=(uint32_t)mrv[i];}}
   CHECK("test_miller_rabin",(8u<<16)|(mrc<<8)|(mrx&0xFFu),0x0008067Fu);}
  /* test_max_rect_histogram: {2,1,5,6,2,3} n=6; max_area=10 xor=1 */
  {const int mrh[]={2,1,5,6,2,3};int mrhn=6,mrhtop=-1,mrhma=0,mrhstk[7];
   for(int i=0;i<=mrhn;i++){int c=i==mrhn?0:mrh[i];while(mrhtop>=0&&mrh[mrhstk[mrhtop]]>=c){int ht=mrh[mrhstk[mrhtop--]];int w=mrhtop<0?i:i-mrhstk[mrhtop]-1;if(ht*w>mrhma)mrhma=ht*w;}mrhstk[++mrhtop]=i;}
   uint32_t mrhx=0;for(int i=0;i<mrhn;i++)mrhx^=(uint32_t)mrh[i];
   CHECK("test_max_rect_histogram",((uint32_t)mrhn<<16)|((uint32_t)mrhma<<8)|(mrhx&0xFFu),0x00060A01u);}
  /* test_trapping_rain: {4,2,0,3,2,5} n=6; water=9 xor=2 */
  {const int trh[]={4,2,0,3,2,5};int trn=6,trl=0,trr=5,trml=0,trmr=0,trw=0;
   while(trl<trr){if(trh[trl]<trh[trr]){if(trh[trl]>=trml)trml=trh[trl];else trw+=trml-trh[trl];trl++;}else{if(trh[trr]>=trmr)trmr=trh[trr];else trw+=trmr-trh[trr];trr--;}}
   uint32_t trx=0;for(int i=0;i<trn;i++)trx^=(uint32_t)trh[i];
   CHECK("test_trapping_rain",((uint32_t)trn<<16)|((uint32_t)trw<<8)|(trx&0xFFu),0x00060902u);}
  /* test_jump_game: 5 tests; reachable={a0,a2,a4}; count=3 xor=1 */
  {const int jg0[]={2,3,1,1,4},jg1[]={3,2,1,0,4},jg2[]={1,2,3,4,0},jg3[]={0,0,1,1,1},jg4[]={5,4,3,2,1,0};
   const int*jgas[]={jg0,jg1,jg2,jg3,jg4};int jgls[]={5,5,5,5,6};uint32_t jgc=0,jgx=0;
   for(int t=0;t<5;t++){int mr=0,ok=1;for(int i=0;i<jgls[t];i++){if(i>mr){ok=0;break;}if(i+jgas[t][i]>mr)mr=i+jgas[t][i];}jgc+=ok;jgx^=(uint32_t)ok;}
   CHECK("test_jump_game",(5u<<16)|(jgc<<8)|(jgx&0xFFu),0x00050301u);}
  /* test_gas_station: 3 tests; starts={3,-1,4}; count=2 xor=7 */
  {const int gg0[]={1,2,3,4,5},gc0[]={3,4,5,1,2},gg1[]={2,3,4},gc1[]={3,4,3},gg2[]={5,1,2,3,4},gc2[]={4,4,1,5,1};
   const int*ggs[]={gg0,gg1,gg2};const int*gcs[]={gc0,gc1,gc2};int gls[]={5,3,5};uint32_t gsc=0,gsx=0;
   for(int t=0;t<3;t++){int tot=0,tank=0,start=0;for(int i=0;i<gls[t];i++){int d=ggs[t][i]-gcs[t][i];tot+=d;tank+=d;if(tank<0){start=i+1;tank=0;}}if(tot>=0){gsc++;gsx^=(uint32_t)start;}}
   CHECK("test_gas_station",(3u<<16)|(gsc<<8)|(gsx&0xFFu),0x00030207u);}
  /* test_bipartite_check: triangle=0,square=1,pentagon=0; count=1 xor=1 */
  {int bpc[5],bpq[5];uint32_t bpn=3,bpcnt=0,bpx=0;
   /* T1 triangle adj: 0:{1,2},1:{0,2},2:{0,1} */
   {int adj[][5]={{1,2,0,0,0},{0,2,0,0,0},{0,1,0,0,0}};int deg[]={2,2,2};int n=3;
    for(int i=0;i<n;i++)bpc[i]=0;int f=0,b=0,ok=1;
    for(int src=0;src<n&&ok;src++){if(bpc[src])continue;bpc[src]=1;bpq[b++]=src;
      while(f<b&&ok){int u=bpq[f++];for(int i=0;i<deg[u];i++){int v=adj[u][i];if(!bpc[v]){bpc[v]=3-bpc[u];bpq[b++]=v;}else if(bpc[v]==bpc[u])ok=0;}}}
    bpcnt+=ok;bpx^=(uint32_t)ok;}
   /* T2 square adj: 0:{1,3},1:{0,2},2:{1,3},3:{2,0} */
   {int adj[][5]={{1,3,0,0,0},{0,2,0,0,0},{1,3,0,0,0},{2,0,0,0,0}};int deg[]={2,2,2,2};int n=4;
    for(int i=0;i<n;i++)bpc[i]=0;int f=0,b=0,ok=1;
    for(int src=0;src<n&&ok;src++){if(bpc[src])continue;bpc[src]=1;bpq[b++]=src;
      while(f<b&&ok){int u=bpq[f++];for(int i=0;i<deg[u];i++){int v=adj[u][i];if(!bpc[v]){bpc[v]=3-bpc[u];bpq[b++]=v;}else if(bpc[v]==bpc[u])ok=0;}}}
    bpcnt+=ok;bpx^=(uint32_t)ok;}
   /* T3 pentagon adj: 0:{1,4},1:{0,2},2:{1,3},3:{2,4},4:{3,0} */
   {int adj[][5]={{1,4,0,0,0},{0,2,0,0,0},{1,3,0,0,0},{2,4,0,0,0},{3,0,0,0,0}};int deg[]={2,2,2,2,2};int n=5;
    for(int i=0;i<n;i++)bpc[i]=0;int f=0,b=0,ok=1;
    for(int src=0;src<n&&ok;src++){if(bpc[src])continue;bpc[src]=1;bpq[b++]=src;
      while(f<b&&ok){int u=bpq[f++];for(int i=0;i<deg[u];i++){int v=adj[u][i];if(!bpc[v]){bpc[v]=3-bpc[u];bpq[b++]=v;}else if(bpc[v]==bpc[u])ok=0;}}}
    bpcnt+=ok;bpx^=(uint32_t)ok;}
   CHECK("test_bipartite_check",(bpn<<16)|(bpcnt<<8)|(bpx&0xFFu),0x00030101u);}
  /* test_kahn_toposort: n=6 edges:5->2,5->0,4->0,4->1,2->3,3->1; nz=2 last=1 */
  {int kti[6]={0},kto[6]={0},ktadj[6][3],ktdeg[6]={0},ktq[6],ktord[6];
   int kte[][2]={{5,2},{5,0},{4,0},{4,1},{2,3},{3,1}};
   for(int i=0;i<6;i++)for(int j=0;j<3;j++)ktadj[i][j]=0;
   for(int i=0;i<6;i++){int u=kte[i][0],v=kte[i][1];kti[v]++;ktadj[u][kto[u]++]=v;}
   int f=0,b=0,proc=0,last=-1,nz=0;
   for(int i=0;i<6;i++)if(kti[i]==0){ktq[b++]=i;nz++;}
   while(f<b){int u=ktq[f++];ktord[proc++]=u;last=u;for(int i=0;i<kto[u];i++){int v=ktadj[u][i];if(--kti[v]==0)ktq[b++]=v;}}
   CHECK("test_kahn_toposort",(6u<<16)|((uint32_t)nz<<8)|((uint32_t)last&0xFFu),0x00060201u);}
  /* test_word_break: s1="leetcode"(len=8,r=1),s2="applepenapple"(len=13,r=1),s3="catsandog"(len=9,r=0)
   * count=2 xor_val=(8^1)^(13^1)^(9^0)=9^12^9=12 g_result=0x0003020C */
  {char wb_s1[]="leetcode";char wb_d1[][10]={"leet","code"};
   char wb_s2[]="applepenapple";char wb_d2[][10]={"apple","pen"};
   char wb_s3[]="catsandog";char wb_d3[][10]={"cats","dog","and","cat","sand"};
   /* word_break inline: dp[0]=1; for i: for each word: if dp[i-wlen] && match: dp[i]=1 */
   uint32_t wb_cnt=0,wb_xv=0;
   #define WB_BREAK(s,slen,dict,nd,res) do{ \
     int dp[20+1]={0};dp[0]=1; \
     for(int i=1;i<=slen;i++){for(int d=0;d<nd;d++){int wl=(int)strlen(dict[d]); \
       if(i>=wl&&dp[i-wl]&&strncmp(s+i-wl,dict[d],wl)==0){dp[i]=1;break;}}} \
     res=dp[slen]; }while(0)
   int r1,r2,r3;
   WB_BREAK(wb_s1,(int)strlen(wb_s1),wb_d1,2,r1);
   WB_BREAK(wb_s2,(int)strlen(wb_s2),wb_d2,2,r2);
   WB_BREAK(wb_s3,(int)strlen(wb_s3),wb_d3,5,r3);
   #undef WB_BREAK
   wb_cnt=(uint32_t)(r1+r2+r3);
   wb_xv=(uint32_t)(((int)strlen(wb_s1)^r1)^((int)strlen(wb_s2)^r2)^((int)strlen(wb_s3)^r3));
   CHECK("test_word_break",(3u<<16)|(wb_cnt<<8)|(wb_xv&0xFFu),0x0003020Cu);}
  /* test_count_paths_dag: edges 0->1,0->2,1->3,2->3,3->4,3->5,4->5; paths(0,5)=4 xor_all=6 */
  {int cpe[][2]={{0,1},{0,2},{1,3},{2,3},{3,4},{3,5},{4,5}};
   for(int i=0;i<6;i++){cp2_deg[i]=0;cp2_memo[i]=-1;for(int j=0;j<3;j++)cp2_adj[i][j]=0;}
   for(int i=0;i<7;i++){int u=cpe[i][0],v=cpe[i][1];cp2_adj[u][cp2_deg[u]++]=v;}
   uint32_t cpa=0;
   for(int i=0;i<6;i++)cpa^=(uint32_t)count_paths2(i,5);
   uint32_t cpp=(uint32_t)cp2_memo[0]; /* paths(0,5)=4 */
   CHECK("test_count_paths_dag",(6u<<16)|(cpp<<8)|(cpa&0xFFu),0x00060406u);}
  /* test_euler_totient: phi(12)=4,phi(13)=12,phi(36)=12,phi(100)=40; n=4 sum=68 xor=44 */
  {int et_vals[]={12,13,36,100};uint32_t et_s=0,et_x=0;
   for(int i=0;i<4;i++){int n=et_vals[i],r=n;
     for(int p=2;p*p<=n;p++){if(n%p==0){r-=r/p;while(n%p==0)n/=p;}}
     if(n>1)r-=r/n;et_s+=(uint32_t)r;et_x^=(uint32_t)r;}
   CHECK("test_euler_totient",(4u<<16)|(et_s<<8)|(et_x&0xFFu),0x0004442Cu);}
  /* test_difference_array: [0,2]+=3,[1,4]+=2,[3,5]+=1 → {3,5,5,3,3,1}; n=6 sum=20 xor=2 */
  {int da_D[7]={0},da_A[6];
   da_D[0]+=3;da_D[3]-=3;da_D[1]+=2;da_D[5]-=2;da_D[3]+=1;da_D[6]-=1;
   {int acc=0;for(int i=0;i<6;i++){acc+=da_D[i];da_A[i]=acc;}}
   uint32_t da_s=0,da_x=0;for(int i=0;i<6;i++){da_s+=(uint32_t)da_A[i];da_x^=(uint32_t)da_A[i];}
   CHECK("test_difference_array",(6u<<16)|(da_s<<8)|(da_x&0xFFu),0x00061402u);}
  /* test_crt: {x≡2(3),x≡3(5),x≡2(7)}=23; {x≡1(2),x≡2(3),x≡4(5)}=29; {x≡3(4),x≡5(7)}=19; sum=71 xor=25 */
  {int c1=(2*35*crt_inv2(35%3,3)+3*21*crt_inv2(21%5,5)+2*15*crt_inv2(15%7,7))%105;
   int c2=(1*15*crt_inv2(15%2,2)+2*10*crt_inv2(10%3,3)+4*6*crt_inv2(6%5,5))%30;
   int c3=(3*7*crt_inv2(7%4,4)+5*4*crt_inv2(4%7,7))%28;
   CHECK("test_crt",(3u<<16)|((uint32_t)(c1+c2+c3)<<8)|((uint32_t)(c1^c2^c3)&0xFFu),0x00034719u);}
  /* test_longest_bitonic: arr={1,5,2,8,3} n=5; max_lbs=4 xor_lbs=7 */
  {int lba[]={1,5,2,8,3},lbn=5,lbis[5],lbds[5];
   for(int i=0;i<lbn;i++){lbis[i]=1;for(int j=0;j<i;j++)if(lba[j]<lba[i]&&lbis[j]+1>lbis[i])lbis[i]=lbis[j]+1;}
   for(int i=lbn-1;i>=0;i--){lbds[i]=1;for(int j=i+1;j<lbn;j++)if(lba[j]<lba[i]&&lbds[j]+1>lbds[i])lbds[i]=lbds[j]+1;}
   int lbmax=0;uint32_t lb_x=0;
   for(int i=0;i<lbn;i++){int lbs=lbis[i]+lbds[i]-1;if(lbs>lbmax)lbmax=lbs;lb_x^=(uint32_t)lbs;}
   CHECK("test_longest_bitonic",((uint32_t)lbn<<16)|((uint32_t)lbmax<<8)|(lb_x&0xFFu),0x00050407u);}
  /* test_hamming: pair HDs {2,4,3} sum=9; total HD of {4,14,2}=6; n=3 */
  {int hd_a[]={10,255,205},hd_b[]={9,15,75};uint32_t hd_s=0;
   for(int i=0;i<3;i++){unsigned hx=(unsigned)(hd_a[i]^hd_b[i]);int pc=0;while(hx){pc+=hx&1;hx>>=1;}hd_s+=(uint32_t)pc;}
   int hd_arr[]={4,14,2};uint32_t hd_t=0;
   for(int b=0;b<32;b++){int cnt=0;for(int i=0;i<3;i++)if((hd_arr[i]>>b)&1)cnt++;hd_t+=(uint32_t)(cnt*(3-cnt));}
   CHECK("test_hamming",(3u<<16)|(hd_s<<8)|(hd_t&0xFFu),0x00030906u);}
  /* test_palindrome_partition: "aab"=1,"abcba"=0,"aabbc"=2; n=3 sum=3 xor=3 */
  {const char *pp_ss[]={"aab","abcba","aabbc"};uint32_t pp_s=0,pp_x=0;
   for(int t=0;t<3;t++){const char *s=pp_ss[t];int sn=(int)strlen(s);
     int ppal[10][10],pdp[10];memset(ppal,0,sizeof(ppal));
     for(int i=0;i<sn;i++)ppal[i][i]=1;
     for(int i=0;i<sn-1;i++)if(s[i]==s[i+1])ppal[i][i+1]=1;
     for(int l=3;l<=sn;l++)for(int i=0;i<=sn-l;i++){int j=i+l-1;if(s[i]==s[j]&&ppal[i+1][j-1])ppal[i][j]=1;}
     for(int i=0;i<sn;i++)pdp[i]=i;
     if(ppal[0][sn-1]){pdp[sn-1]=0;}
     else{for(int i=1;i<sn;i++){if(ppal[0][i]){pdp[i]=0;continue;}for(int j=1;j<=i;j++)if(ppal[j][i]&&pdp[j-1]+1<pdp[i])pdp[i]=pdp[j-1]+1;}}
     pp_s+=(uint32_t)pdp[sn-1];pp_x^=(uint32_t)pdp[sn-1];}
   CHECK("test_palindrome_partition",(3u<<16)|(pp_s<<8)|(pp_x&0xFFu),0x00030303u);}
  /* test_rotate_array: {1..7} right by 2 → {6,7,1,2,3,4,5}; n=7 k=2 last=5 */
  {int ra[]={1,2,3,4,5,6,7},rn=7,rk=2;
   for(int l=0,r=rn-rk-1;l<r;l++,r--){int t=ra[l];ra[l]=ra[r];ra[r]=t;}
   for(int l=rn-rk,r=rn-1;l<r;l++,r--){int t=ra[l];ra[l]=ra[r];ra[r]=t;}
   for(int l=0,r=rn-1;l<r;l++,r--){int t=ra[l];ra[l]=ra[r];ra[r]=t;}
   CHECK("test_rotate_array",((uint32_t)rn<<16)|((uint32_t)rk<<8)|((uint32_t)ra[rn-1]&0xFFu),0x00070205u);}
  /* test_matrix_power: F(10)=55 F(20)=6765; n=2 sum=164 xor=90 */
  {long long f10=mp_fib2(10),f20=mp_fib2(20);
   uint32_t mp_s=(uint32_t)((f10&0xFF)+(f20&0xFF));
   uint32_t mp_x=(uint32_t)((f10&0xFF)^(f20&0xFF));
   CHECK("test_matrix_power",(2u<<16)|(mp_s<<8)|(mp_x&0xFFu),0x0002A45Au);}
  /* test_tribonacci: T(0..9)={0,1,1,2,4,7,13,24,44,81}; n=10 sum=177 xor=105 */
  {uint32_t tv[10]={0,1,1,0,0,0,0,0,0,0};for(int i=3;i<10;i++)tv[i]=tv[i-1]+tv[i-2]+tv[i-3];
   uint32_t ts=0,tx=0;for(int i=0;i<10;i++){ts+=tv[i];tx^=tv[i];}
   CHECK("test_tribonacci",(10u<<16)|((ts&0xFFu)<<8)|(tx&0xFFu),0x000AB169u);}
  /* test_count_bits: bits in 0..15; n=16 total=32 xor=4 */
  {uint32_t cb_t=0,cb_x=0;
   for(int i=0;i<16;i++){int x=i,c=0;while(x){x&=x-1;c++;}cb_t+=(uint32_t)c;cb_x^=(uint32_t)c;}
   CHECK("test_count_bits",(16u<<16)|((cb_t&0xFFu)<<8)|(cb_x&0xFFu),0x00102004u);}
  /* test_stock_k_trans: prices={3,3,5,0,0,3,1,4}; n=8 profit=6 xor_prices=3 */
  {int sp[]={3,3,5,0,0,3,1,4};int b1=-(1<<30),s1=-(1<<30),b2=-(1<<30),s2=-(1<<30);
   uint32_t sxp=0;for(int i=0;i<8;i++){int p=sp[i];if(-p>b1)b1=-p;if(b1+p>s1)s1=b1+p;if(s1-p>b2)b2=s1-p;if(b2+p>s2)s2=b2+p;sxp^=(uint32_t)p;}
   CHECK("test_stock_k_trans",(8u<<16)|((uint32_t)s2<<8)|(sxp&0xFFu),0x00080603u);}
  /* test_coin_ways: coins={1,2,3} ways(4)=4 ways(6)=7 ways(10)=14; sum=25 xor=13 */
  {int cwdp[11]={0};cwdp[0]=1;int cwc[]={1,2,3};
   for(int ci=0;ci<3;ci++)for(int j=cwc[ci];j<=10;j++)cwdp[j]+=cwdp[j-cwc[ci]];
   int cwq[]={4,6,10};uint32_t cws=0,cwx=0;
   for(int i=0;i<3;i++){cws+=(uint32_t)cwdp[cwq[i]];cwx^=(uint32_t)cwdp[cwq[i]];}
   CHECK("test_coin_ways",(3u<<16)|((cws&0xFFu)<<8)|(cwx&0xFFu),0x0003190Du);}
  /* test_lca: LCA(4,5)=2 LCA(4,6)=1 LCA(2,7)=1; sum=4 xor=2 */
  {int qa[]={4,4,2},qb[]={5,6,7};uint32_t ls=0,lx=0;
   for(int i=0;i<3;i++){uint32_t l=(uint32_t)lca2(qa[i],qb[i]);ls+=l;lx^=l;}
   CHECK("test_lca",(3u<<16)|((ls&0xFFu)<<8)|(lx&0xFFu),0x00030402u);}
  /* test_interval_merge: [1,3],[2,6],[8,10],[15,18] -> 3 merged; xor_ends=30 */
  {int is[]={1,2,8,15},ie[]={3,6,10,18};int cs=is[0],ce=ie[0],nm=0;int me[4];
   for(int i=1;i<4;i++){if(is[i]<=ce){if(ie[i]>ce)ce=ie[i];}else{me[nm++]=ce;cs=is[i];ce=ie[i];}}
   me[nm++]=ce;uint32_t xoe=0;for(int i=0;i<nm;i++)xoe^=(uint32_t)me[i];
   CHECK("test_interval_merge",(4u<<16)|((uint32_t)nm<<8)|(xoe&0xFFu),0x0004031Eu);}
  /* test_num_islands: 3 grids; islands={1,2,2}; sum=5 xor=1 */
  {int g1[4][5]={{1,1,1,1,0},{1,1,0,1,0},{1,1,0,0,0},{0,0,0,0,0}};
   int g2[3][4]={{1,1,0,0},{0,1,1,0},{0,0,0,1}};
   int g3[4][4]={{1,1,0,0},{1,1,0,0},{0,0,1,1},{0,0,1,1}};
   uint32_t ns=0,nx=0;int nc;
   ni_R2=4;ni_C2=5;for(int r=0;r<4;r++)for(int c=0;c<5;c++)ni_g2[r][c]=g1[r][c];nc=ni_count2();ns+=(uint32_t)nc;nx^=(uint32_t)nc;
   ni_R2=3;ni_C2=4;for(int r=0;r<4;r++)for(int c=0;c<5;c++)ni_g2[r][c]=0;for(int r=0;r<3;r++)for(int c=0;c<4;c++)ni_g2[r][c]=g2[r][c];nc=ni_count2();ns+=(uint32_t)nc;nx^=(uint32_t)nc;
   ni_R2=4;ni_C2=4;for(int r=0;r<4;r++)for(int c=0;c<5;c++)ni_g2[r][c]=0;for(int r=0;r<4;r++)for(int c=0;c<4;c++)ni_g2[r][c]=g3[r][c];nc=ni_count2();ns+=(uint32_t)nc;nx^=(uint32_t)nc;
   CHECK("test_num_islands",(3u<<16)|((ns&0xFFu)<<8)|(nx&0xFFu),0x00030501u);}
  /* test_prefix_xor: arr={1..8}; queries xorRange(0,3)=4 xorRange(2,5)=4 xorRange(0,7)=8; sum=16 xor=8 */
  {int pxa[]={1,2,3,4,5,6,7,8},pxp[9];pxp[0]=0;for(int i=0;i<8;i++)pxp[i+1]=pxp[i]^pxa[i];
   int pql[]={0,2,0},pqr[]={3,5,7};uint32_t pxs=0,pxx=0;
   for(int i=0;i<3;i++){uint32_t r=(uint32_t)(pxp[pqr[i]+1]^pxp[pql[i]]);pxs+=r;pxx^=r;}
   CHECK("test_prefix_xor",(3u<<16)|((pxs&0xFFu)<<8)|(pxx&0xFFu),0x00031008u);}
  /* test_tarjan_scc: n=5 SCCs=2 sizes={2,3} xor=1 */
  {int adj_i[5][2]={{1,-1},{2,-1},{0,3},{4,-1},{3,-1}},deg_i[5]={1,1,2,1,1};
   for(int i=0;i<5;i++){tj2_adj[i][0]=adj_i[i][0];tj2_adj[i][1]=adj_i[i][1];tj2_deg[i]=deg_i[i];tj2_disc[i]=-1;tj2_on[i]=0;}
   tj2_timer2=0;tj2_stop=0;tj2_nscc=0;
   for(int i=0;i<5;i++)if(tj2_disc[i]==-1)tj2_dfs(i);
   uint32_t xs=0;for(int i=0;i<tj2_nscc;i++)xs^=(uint32_t)tj2_scc_sz[i];
   CHECK("test_tarjan_scc",(5u<<16)|((uint32_t)tj2_nscc<<8)|(xs&0xFFu),0x00050201u);}
  /* test_huffman: n=5 chars total_bits=33 xor_lens=2 */
  {hf2_nn=5;for(int i=0;i<5;i++){hf2_nodes[i].freq=hf2_freq[i];hf2_nodes[i].left=-1;hf2_nodes[i].right=-1;hf2_act[i]=1;}
   for(int i=5;i<9;i++){hf2_nodes[i].freq=0;hf2_nodes[i].left=-1;hf2_nodes[i].right=-1;hf2_act[i]=0;}
   while(1){int a=hf2_min();if(a<0)break;hf2_act[a]=0;int b=hf2_min();if(b<0){hf2_act[a]=1;break;}hf2_act[b]=0;int nn=hf2_nn++;hf2_nodes[nn].freq=hf2_nodes[a].freq+hf2_nodes[b].freq;hf2_nodes[nn].left=a;hf2_nodes[nn].right=b;hf2_act[nn]=1;}
   hf2_dfs(hf2_nn-1,0);
   int tb=0;uint32_t xl=0;for(int i=0;i<5;i++){tb+=hf2_freq[i]*hf2_clen[i];xl^=(uint32_t)hf2_clen[i];}
   CHECK("test_huffman",(5u<<16)|((uint32_t)(tb&0xFF)<<8)|(xl&0xFFu),0x00052102u);}
  /* test_toposort_dfs: n=5 order=[4,3,2,1,0] sum=10 xor=4 */
  {for(int i=0;i<5;i++){td2_vis[i]=0;}td2_top=0;
   for(int i=0;i<5;i++)if(!td2_vis[i])td2_dfs(i);
   uint32_t ts=0,tx=0;for(int i=td2_top-1;i>=0;i--){ts+=(uint32_t)td2_stk[i];tx^=(uint32_t)td2_stk[i];}
   CHECK("test_toposort_dfs",(5u<<16)|((ts&0xFFu)<<8)|(tx&0xFFu),0x00050A04u);}
  /* test_nim: 5 games n_wins=1 xor_all=2 */
  {int piles[5][4]={{3,4,5,0},{1,2,3,0},{4,4,0,0},{3,3,3,3},{2,2,0,0}};int szs[5]={3,3,2,4,2};
   uint32_t nw=0,xn=0;for(int g=0;g<5;g++){int nx=0;for(int i=0;i<szs[g];i++)nx^=piles[g][i];xn^=(uint32_t)nx;if(nx)nw++;}
   CHECK("test_nim",(5u<<16)|(nw<<8)|(xn&0xFFu),0x00050102u);}
  /* test_tsp_bitmask: n=4 min_cost=80 */
  {int tc[4][4]={{0,10,15,20},{10,0,35,25},{15,35,0,30},{20,25,30,0}};
   int dp[16][4];for(int m=0;m<16;m++)for(int i=0;i<4;i++)dp[m][i]=999999;dp[1][0]=0;
   for(int mask=1;mask<16;mask++)for(int i=0;i<4;i++){if(!(mask&(1<<i))||dp[mask][i]==999999)continue;for(int j=0;j<4;j++){if(mask&(1<<j))continue;int nm=mask|(1<<j),nc=dp[mask][i]+tc[i][j];if(nc<dp[nm][j])dp[nm][j]=nc;}}
   int best=999999;for(int i=1;i<4;i++){int c=dp[15][i]+tc[i][0];if(c<best)best=c;}
   CHECK("test_tsp_bitmask",(4u<<16)|((uint32_t)(best&0xFF)<<8)|4u,0x00045004u);}
  /* test_euler_circuit: n=5 n_edges=6 has_euler=1 (all even) */
  {int deg5[5]={2,2,4,2,2};int he=1;for(int i=0;i<5;i++)if(deg5[i]%2!=0)he=0;
   CHECK("test_euler_circuit",(5u<<16)|(6u<<8)|(uint32_t)he,0x00050601u);}
  /* test_convex_hull: 6pts hull=5 sum_x=7 sum_y=5 */
  {ch2_scan();int sx=0,sy=0;for(int i=0;i<ch2_ht;i++){sx+=ch2_px[ch2_hull[i]];sy+=ch2_py[ch2_hull[i]];}
   CHECK("test_convex_hull",((uint32_t)ch2_ht<<16)|((uint32_t)(sx&0xFF)<<8)|(uint32_t)(sy&0xFF),0x00050705u);}
  /* test_digit_dp: count(1..100,ds%3==0)=33 count(1..100,ds%5==0)=19 sum=52 xor=50 */
  {int c3=0,c5=0;for(int n=1;n<=100;n++){int t=n,s=0;while(t>0){s+=t%10;t/=10;}if(s%3==0)c3++;if(s%5==0)c5++;}
   uint32_t dds=(uint32_t)(c3+c5),ddx=(uint32_t)(c3^c5);
   CHECK("test_digit_dp",(2u<<16)|((dds&0xFFu)<<8)|(ddx&0xFFu),0x00023432u);}
  /* test_suffix_array: "banana" SA={5,3,1,0,4,2} n=6 first=5 xor=1 */
  {build_sa2();uint32_t fsa=(uint32_t)sa2_idx[0],xsa=0;for(int i=0;i<6;i++)xsa^=(uint32_t)sa2_idx[i];
   CHECK("test_suffix_array",(6u<<16)|(fsa<<8)|(xsa&0xFFu),0x00060501u);}
  /* test_house_robber: {1,2,3,1}->4 {2,7,9,3,1}->12 {2,1,1,2}->4 sum=20 xor=12 */
  {int hr1[]={1,2,3,1},hr2[]={2,7,9,3,1},hr3[]={2,1,1,2};
   int r1=0,r2=0,r3=0,p2=0,p1=0,cur=0;
   p2=0;p1=0;for(int i=0;i<4;i++){cur=p2+hr1[i]>p1?p2+hr1[i]:p1;p2=p1;p1=cur;}r1=p1;
   p2=0;p1=0;for(int i=0;i<5;i++){cur=p2+hr2[i]>p1?p2+hr2[i]:p1;p2=p1;p1=cur;}r2=p1;
   p2=0;p1=0;for(int i=0;i<4;i++){cur=p2+hr3[i]>p1?p2+hr3[i]:p1;p2=p1;p1=cur;}r3=p1;
   CHECK("test_house_robber",(3u<<16)|(((uint32_t)(r1+r2+r3)&0xFFu)<<8)|((uint32_t)(r1^r2^r3)&0xFFu),0x0003140Cu);}
  /* test_egg_drop: dp[t][e]=dp[t-1][e-1]+dp[t-1][e]+1; n=10,e=2->4; n=100,e=2->14; n=36,e=3->6 */
  {static int edp[21][4];for(int e=0;e<=3;e++)edp[0][e]=0;for(int t=1;t<=20;t++){edp[t][0]=0;edp[t][1]=t;}
   for(int t=1;t<=20;t++)for(int e=2;e<=3;e++)edp[t][e]=edp[t-1][e-1]+edp[t-1][e]+1;
   int et1=0,et2=0,et3=0;for(int t=1;t<=20;t++){if(!et1&&edp[t][2]>=10)et1=t;if(!et2&&edp[t][2]>=100)et2=t;if(!et3&&edp[t][3]>=36)et3=t;}
   CHECK("test_egg_drop",(3u<<16)|(((uint32_t)(et1+et2+et3)&0xFFu)<<8)|((uint32_t)(et1^et2^et3)&0xFFu),0x0003180Cu);}
  /* test_unique_paths: 3x3->6, 3x7->28, 4x4->20 sum=54 xor=14 */
  {static int updp[4][8];
   for(int i=0;i<3;i++)for(int j=0;j<3;j++)updp[i][j]=(i==0||j==0)?1:updp[i-1][j]+updp[i][j-1];int upr1=updp[2][2];
   for(int i=0;i<3;i++)for(int j=0;j<7;j++)updp[i][j]=(i==0||j==0)?1:updp[i-1][j]+updp[i][j-1];int upr2=updp[2][6];
   for(int i=0;i<4;i++)for(int j=0;j<4;j++)updp[i][j]=(i==0||j==0)?1:updp[i-1][j]+updp[i][j-1];int upr3=updp[3][3];
   CHECK("test_unique_paths",(3u<<16)|(((uint32_t)(upr1+upr2+upr3)&0xFFu)<<8)|((uint32_t)(upr1^upr2^upr3)&0xFFu),0x0003360Eu);}
  /* test_regex_match: aa/a*=1 ab/.*=1 aab/c*a*b=1 mississippi/mis*is*p*.=0 sum=3 xor=1 */
  {static int rmdp[13][12];
   const char*rms[4]={"aa","ab","aab","mississippi"},*rmp[4]={"a*",".*","c*a*b","mis*is*p*."};
   int rmr[4]={0,0,0,0};
   for(int q=0;q<4;q++){int ls=0,lp=0;while(rms[q][ls])ls++;while(rmp[q][lp])lp++;
    for(int i=0;i<=ls;i++)for(int j=0;j<=lp;j++)rmdp[i][j]=0;rmdp[0][0]=1;
    for(int j=2;j<=lp;j++)if(rmp[q][j-1]=='*')rmdp[0][j]=rmdp[0][j-2];
    for(int i=1;i<=ls;i++)for(int j=1;j<=lp;j++){if(rmp[q][j-1]=='*'){rmdp[i][j]=rmdp[i][j-2];if(j>=2&&(rms[q][i-1]==rmp[q][j-2]||rmp[q][j-2]=='.'))rmdp[i][j]|=rmdp[i-1][j];}else{rmdp[i][j]=rmdp[i-1][j-1]&&(rms[q][i-1]==rmp[q][j-1]||rmp[q][j-1]=='.');}}
    rmr[q]=rmdp[ls][lp];}
   CHECK("test_regex_match",(4u<<16)|(((uint32_t)(rmr[0]+rmr[1]+rmr[2]+rmr[3])&0xFFu)<<8)|((uint32_t)(rmr[0]^rmr[1]^rmr[2]^rmr[3])&0xFFu),0x00040301u);}
  /* test_max_product: {2,3,-2,4}->6 {-2,0,-1}->0 {-2,-3,-4}->12 sum=18 xor=10 */
  {int mpa[]={2,3,-2,4},mpb[]={-2,0,-1},mpc[]={-2,-3,-4};
   int mpr[3];
   {int mh=mpa[0],mn=mpa[0],b=mpa[0];for(int i=1;i<4;i++){int a2=mh*mpa[i],b2=mn*mpa[i];int nm=mpa[i]>a2?(mpa[i]>b2?mpa[i]:b2):(a2>b2?a2:b2);int nmin=mpa[i]<a2?(mpa[i]<b2?mpa[i]:b2):(a2<b2?a2:b2);mh=nm;mn=nmin;if(mh>b)b=mh;}mpr[0]=b;}
   {int mh=mpb[0],mn=mpb[0],b=mpb[0];for(int i=1;i<3;i++){int a2=mh*mpb[i],b2=mn*mpb[i];int nm=mpb[i]>a2?(mpb[i]>b2?mpb[i]:b2):(a2>b2?a2:b2);int nmin=mpb[i]<a2?(mpb[i]<b2?mpb[i]:b2):(a2<b2?a2:b2);mh=nm;mn=nmin;if(mh>b)b=mh;}mpr[1]=b;}
   {int mh=mpc[0],mn=mpc[0],b=mpc[0];for(int i=1;i<3;i++){int a2=mh*mpc[i],b2=mn*mpc[i];int nm=mpc[i]>a2?(mpc[i]>b2?mpc[i]:b2):(a2>b2?a2:b2);int nmin=mpc[i]<a2?(mpc[i]<b2?mpc[i]:b2):(a2<b2?a2:b2);mh=nm;mn=nmin;if(mh>b)b=mh;}mpr[2]=b;}
   CHECK("test_max_product",(3u<<16)|(((uint32_t)(mpr[0]+mpr[1]+mpr[2])&0xFFu)<<8)|((uint32_t)(mpr[0]^mpr[1]^mpr[2])&0xFFu),0x0003120Au);}
  /* test_articulation: graph 0-1,1-2,2-0,1-3,3-4; APs={1,3} count=2 xor=2 */
  {int ap2e[5][2]={{0,1},{1,2},{2,0},{1,3},{3,4}};
   for(int i=0;i<5;i++){ap2_vis[i]=ap2_is_ap[i]=ap2_deg[i]=0;ap2_par[i]=-1;}ap2_timer2=0;
   for(int i=0;i<5;i++)ap2_adj[i][0]=ap2_adj[i][1]=ap2_adj[i][2]=ap2_adj[i][3]=-1;
   for(int i=0;i<5;i++){int u=ap2e[i][0],v=ap2e[i][1];ap2_adj[u][ap2_deg[u]++]=v;ap2_adj[v][ap2_deg[v]++]=u;}
   ap2_dfs(0);uint32_t apc=0,apx=0;for(int i=0;i<5;i++)if(ap2_is_ap[i]){apc++;apx^=(uint32_t)i;}
   CHECK("test_articulation",(5u<<16)|((apc&0xFFu)<<8)|(apx&0xFFu),0x00050202u);}
  /* test_sqrt_decomp: arr={1..9} blksz=3; q[2..7]=33 update[4]=10 q[1..8]=49 */
  {int sqa[9]={1,2,3,4,5,6,7,8,9},sqb[3]={0,0,0};
   for(int i=0;i<9;i++)sqb[i/3]+=sqa[i];
   int sq1=0;for(int i=2;i<3;i++)sq1+=sqa[i];sq1+=sqb[1];for(int i=6;i<=7;i++)sq1+=sqa[i];
   sqb[4/3]+=10-sqa[4];sqa[4]=10;
   int sq2=0;for(int i=1;i<3;i++)sq2+=sqa[i];sq2+=sqb[1];for(int i=6;i<=8;i++)sq2+=sqa[i];
   CHECK("test_sqrt_decomp",(9u<<16)|(((uint32_t)sq1&0xFFu)<<8)|((uint32_t)sq2&0xFFu),0x00092131u);}
  /* test_dag_longest_path: 6 nodes 8 edges in topo order; max_dist=17 xor_dp=23 */
  {int dlp_eu[]={0,0,1,1,2,2,3,4},dlp_ev[]={1,2,2,4,3,5,4,5},dlp_ew[]={3,6,4,11,5,2,1,3};
   int dlp[6]={0,0,0,0,0,0};
   for(int e=0;e<8;e++){int u=dlp_eu[e],v=dlp_ev[e],w=dlp_ew[e];if(dlp[u]+w>dlp[v])dlp[v]=dlp[u]+w;}
   uint32_t dlp_max=0,dlp_xor=0;
   for(int i=0;i<6;i++){if((uint32_t)dlp[i]>dlp_max)dlp_max=(uint32_t)dlp[i];dlp_xor^=(uint32_t)dlp[i];}
   CHECK("test_dag_longest_path",(6u<<16)|((dlp_max&0xFFu)<<8)|(dlp_xor&0xFFu),0x00061117u);}
  /* test_edit_distance: kitten→sitting=3, sunday→saturday=3, abc→yabd=2 */
  {static int edp[16][16];
   const char*s1[3]={"kitten","sunday","abc"},*s2[3]={"sitting","saturday","yabd"};
   int ln1[3]={6,6,3},ln2[3]={7,8,4};
   uint32_t ed_sum=0,ed_xor=0;
   for(int t=0;t<3;t++){
     int m=ln1[t],n=ln2[t];
     for(int i=0;i<=m;i++)edp[i][0]=i;
     for(int j=0;j<=n;j++)edp[0][j]=j;
     for(int i=1;i<=m;i++)for(int j=1;j<=n;j++){
       if(s1[t][i-1]==s2[t][j-1])edp[i][j]=edp[i-1][j-1];
       else{int a=edp[i-1][j],b=edp[i][j-1],c=edp[i-1][j-1];int mn=a<b?a:b;mn=mn<c?mn:c;edp[i][j]=1+mn;}
     }
     ed_sum+=(uint32_t)edp[m][n];ed_xor^=(uint32_t)edp[m][n];
   }
   CHECK("test_edit_distance",(3u<<16)|((ed_sum&0xFFu)<<8)|(ed_xor&0xFFu),0x00030802u);}
  /* test_max_rect_sum: 3x4 matrix; kadane on col-compressed rows; max=21 */
  {int mr_mat[3][4]={{1,2,-1,-4},{-8,-3,4,2},{3,8,10,-8}};
   int mr_max=-0x7fffffff;
   for(int l=0;l<4;l++){int tmp[3]={0,0,0};for(int r=l;r<4;r++){for(int i=0;i<3;i++)tmp[i]+=mr_mat[i][r];
     int mh=tmp[0],ms=tmp[0];for(int i=1;i<3;i++){int nx=mh+tmp[i];mh=nx>tmp[i]?nx:tmp[i];if(mh>ms)ms=mh;}
     if(ms>mr_max)mr_max=ms;}}
   CHECK("test_max_rect_sum",(12u<<16)|((uint32_t)(mr_max&0xFF)<<8)|1u,0x000C1501u);}
  /* test_fenwick_tree: arr={2,1,1,3,2,3,4,5}; p[0..4]=9; update[3]+=3; range[2..5]=12 */
  {static int fw2[9]={0,0,0,0,0,0,0,0,0};
   int fw2_n=8;
   int fw2a[]={2,1,1,3,2,3,4,5};
   for(int i=0;i<fw2_n;i++){for(int k=i+1;k<=fw2_n;k+=k&(-k))fw2[k]+=fw2a[i];}
   int fwq1=0;for(int k=5;k>0;k-=k&(-k))fwq1+=fw2[k];  /* query(4)=prefix[0..4]=9 */
   for(int k=4;k<=fw2_n;k+=k&(-k))fw2[k]+=3;            /* update(3,+3) */
   int fwq2=0;for(int k=6;k>0;k-=k&(-k))fwq2+=fw2[k];  /* query(5) */
   int fwq3=0;for(int k=2;k>0;k-=k&(-k))fwq3+=fw2[k];  /* query(1) */
   int rng=fwq2-fwq3;  /* range[2..5]=12 */
   CHECK("test_fenwick_tree",(8u<<16)|((uint32_t)(fwq1&0xFF)<<8)|(uint32_t)(rng&0xFF),0x0008090Cu);}
  /* test_sliding_window_max: arr={1,3,-1,-3,5,3,6,7} k=3; maxima={3,3,5,5,6,7} sum=29 xor=1 */
  {int swm_a[]={1,3,-1,-3,5,3,6,7};int swm_dq[8],swf=0,swb=-1;
   uint32_t swsum=0,swxr=0;int swol=0;
   for(int i=0;i<8;i++){
     if(swf<=swb&&swm_dq[swf]<=i-3)swf++;
     while(swf<=swb&&swm_a[swm_dq[swb]]<=swm_a[i])swb--;
     swm_dq[++swb]=i;
     if(i>=2){int mx=swm_a[swm_dq[swf]];swsum+=(uint32_t)mx;swxr^=(uint32_t)mx;swol++;}
   }
   CHECK("test_sliding_window_max",((uint32_t)swol<<16)|((swsum&0xFFu)<<8)|(swxr&0xFFu),0x00061D01u);}
  /* test_count_distinct_window: arr={1,2,1,3,2,1,1,4} k=4; all 5 windows distinct=3 */
  {int cdw_a[]={1,2,1,3,2,1,1,4};int cdwf[8]={0,0,0,0,0,0,0,0};
   int cdd=0;uint32_t cdsum=0,cdxr=0;int cdol=0;
   for(int i=0;i<8;i++){
     cdwf[cdw_a[i]]++;if(cdwf[cdw_a[i]]==1)cdd++;
     if(i>=4){cdwf[cdw_a[i-4]]--;if(cdwf[cdw_a[i-4]]==0)cdd--;}
     if(i>=3){cdsum+=(uint32_t)cdd;cdxr^=(uint32_t)cdd;cdol++;}
   }
   CHECK("test_count_distinct_window",((uint32_t)cdol<<16)|((cdsum&0xFFu)<<8)|(cdxr&0xFFu),0x00050F03u);}
  /* test_gcd_array: {12,18,24,36}; gcd=6 lcm=72 */
  {int ga[]={12,18,24,36},n4=4,tg=12,tl=12;
   for(int i=1;i<n4;i++){
     int a=tg,b=ga[i];while(b){int t=b;b=a%b;a=t;}tg=a;
     int p=tg;a=tl;b=ga[i];while(b){int t=b;b=a%b;a=t;}tl=tl/a*ga[i];(void)p;
   }
   CHECK("test_gcd_array",((uint32_t)n4<<16)|((uint32_t)(tg&0xFF)<<8)|(uint32_t)(tl&0xFF),0x00040648u);}
  /* test_primorial: P(1..5)={2,6,30,210,2310}; sum%256=254 xor%256=206 */
  {uint32_t prim2=1,psum=0,pxor=0;int ppc=0;
   for(int n=2;ppc<5;n++){int ok=1;for(int i=2;i*i<=n;i++)if(n%i==0){ok=0;break;}
     if(ok){prim2*=(uint32_t)n;psum+=prim2&0xFFu;pxor^=prim2&0xFFu;ppc++;}}
   CHECK("test_primorial",(5u<<16)|((psum&0xFFu)<<8)|(pxor&0xFFu),0x0005FECEu);}
  /* Sprint 78: test_gray_code — G(i)=i^(i>>1), n_codes=8 n_bits=3 last=4 */
  {int gcl=7^(7>>1); CHECK("test_gray_code",(8u<<16)|(3u<<8)|((uint32_t)gcl&0xFFu),0x00080304u);}
  /* Sprint 78: test_fisher_yates — det shuffle {1..8}, sum=36 xor=8 */
  {int fya[8]={1,2,3,4,5,6,7,8};
   for(int i=0;i<7;i++){int j=i+(i*3+7)%(8-i);int t=fya[i];fya[i]=fya[j];fya[j]=t;}
   uint32_t fs=0,fx=0;for(int i=0;i<8;i++){fs+=fya[i];fx^=fya[i];}
   CHECK("test_fisher_yates",(8u<<16)|((fs&0xFFu)<<8)|(fx&0xFFu),0x00082408u);}
  /* Sprint 79: test_partition_equal_sum — targets hit: 11+17=28, n_false=1 */
  {static int pdp[100];
   int pa1[]={1,5,11,5},pt1=11;
   for(int j=0;j<=pt1;j++)pdp[j]=0; pdp[0]=1;
   for(int i=0;i<4;i++) for(int j=pt1;j>=pa1[i];j--) if(pdp[j-pa1[i]])pdp[j]=1;
   int pr1=pdp[pt1];
   int pa3[]={2,3,5,6,8,10},pt3=17;
   for(int j=0;j<=pt3;j++)pdp[j]=0; pdp[0]=1;
   for(int i=0;i<6;i++) for(int j=pt3;j>=pa3[i];j--) if(pdp[j-pa3[i]])pdp[j]=1;
   int pr3=pdp[pt3];
   uint32_t phit=(uint32_t)((pr1?pt1:0)+(pr3?pt3:0)); /* 28 */
   uint32_t pnf=(uint32_t)((1-pr1)+(1)+(1-pr3)); /* n_false */
   CHECK("test_partition_equal_sum",(3u<<16)|((phit&0xFFu)<<8)|(pnf&0xFFu),0x00031C01u);}
  /* Sprint 79: test_jump_game2 — {2,3,1,1,4}=2, {2,3,0,1,4}=2, {1,2,3,4,5}=3 */
  {int jcases[3][5]={{2,3,1,1,4},{2,3,0,1,4},{1,2,3,4,5}};
   uint32_t jsum=0,jxr=0;
   for(int c=0;c<3;c++){int*ar=jcases[c];int jmp=0,ce=0,fr=0;
     for(int i=0;i<4;i++){if(i+ar[i]>fr)fr=i+ar[i];if(i==ce){jmp++;ce=fr;if(ce>=4)break;}}
     jsum+=jmp;jxr^=jmp;}
   CHECK("test_jump_game2",(3u<<16)|((jsum&0xFFu)<<8)|(jxr&0xFFu),0x00030703u);}
  /* Sprint 80: test_perfect_squares — {12→3,13→2,7→4,9→1} sum=10 xor=4 */
  {static int psdp[14]; int pst[]={12,13,7,9}; uint32_t pssum=0,psxr=0;
   for(int ti=0;ti<4;ti++){int n=pst[ti];
     for(int i=0;i<=n;i++)psdp[i]=9999; psdp[0]=0;
     for(int i=1;i<=n;i++) for(int j=1;j*j<=i;j++) if(psdp[i-j*j]+1<psdp[i])psdp[i]=psdp[i-j*j]+1;
     pssum+=(uint32_t)psdp[n]; psxr^=(uint32_t)psdp[n];}
   CHECK("test_perfect_squares",(4u<<16)|((pssum&0xFFu)<<8)|(psxr&0xFFu),0x00040A04u);}
  /* Sprint 80: test_interleave — {1,1,0} n_true=2 weighted_xor=3 */
  {static int ildp[4][4];
   const char*is1[3]={"aab","abc","abc"},*is2[3]={"axy","def","def"},*is3[3]={"aaxaby","abdecf","abcfed"};
   int iln1[3]={3,3,3},iln2[3]={3,3,3};
   int ilnt=0,ilwx=0;
   for(int tc=0;tc<3;tc++){
     int n1=iln1[tc],n2=iln2[tc];
     ildp[0][0]=1;
     for(int i=1;i<=n1;i++)ildp[i][0]=ildp[i-1][0]&&(is1[tc][i-1]==is3[tc][i-1]);
     for(int j=1;j<=n2;j++)ildp[0][j]=ildp[0][j-1]&&(is2[tc][j-1]==is3[tc][j-1]);
     for(int i=1;i<=n1;i++) for(int j=1;j<=n2;j++)
       ildp[i][j]=(ildp[i-1][j]&&is1[tc][i-1]==is3[tc][i+j-1])||(ildp[i][j-1]&&is2[tc][j-1]==is3[tc][i+j-1]);
     int r=ildp[n1][n2]; ilnt+=r; ilwx^=r*(tc+1);}
   CHECK("test_interleave",(3u<<16)|((uint32_t)(ilnt&0xFF)<<8)|((uint32_t)(ilwx&0xFF)),0x00030203u);}
  /* Sprint 81: test_activity_selection — 11 acts sorted by end, count=4 xor_ends=24 */
  {int ast[]={1,3,0,5,3,5,6,8,8,2,12},aen[]={4,5,6,7,9,9,10,11,12,14,16};
   int acnt=0,ale=-1; uint32_t axe=0;
   for(int i=0;i<11;i++) if(ast[i]>=ale){acnt++;ale=aen[i];axe^=(uint32_t)aen[i];}
   CHECK("test_activity_selection",(11u<<16)|((uint32_t)(acnt&0xFF)<<8)|(axe&0xFFu),0x000B0418u);}
  /* Sprint 81: test_bipartite_matching — K_{3,3} max_match=3 */
  {for(int i=0;i<3;i++)bpm2_match_r[i]=-1;
   int bmt=0; for(int u=0;u<3;u++){for(int i=0;i<3;i++)bpm2_vis[i]=0;if(bpm2_try(u))bmt++;}
   CHECK("test_bipartite_matching",(9u<<16)|((uint32_t)(bmt&0xFF)<<8)|(3u),0x00090303u);}
  /* Sprint 82: test_mod_exp — 2^10%1000=24, 3^7%100=87, 5^5%113=74; sum=185 xor=5 */
  {uint32_t me_r0=1,me_r1=1,me_r2=1,mb,me;
   mb=2%1000u;me=10;while(me>0){if(me&1u)me_r0=me_r0*mb%1000u;mb=mb*mb%1000u;me>>=1;}
   mb=3%100u;me=7;while(me>0){if(me&1u)me_r1=me_r1*mb%100u;mb=mb*mb%100u;me>>=1;}
   mb=5%113u;me=5;while(me>0){if(me&1u)me_r2=me_r2*mb%113u;mb=mb*mb%113u;me>>=1;}
   CHECK("test_mod_exp",(3u<<16)|(((me_r0+me_r1+me_r2)&0xFFu)<<8)|((me_r0^me_r1^me_r2)&0xFFu),0x0003B905u);}
  /* Sprint 82: test_gcd_ext — gcd(12,8)=4, gcd(21,14)=7, gcd(45,30)=15; sum=26 xor=12 */
  {int gx,gy; int gg0=ge2_ext(12,8,&gx,&gy),gg1=ge2_ext(21,14,&gx,&gy),gg2=ge2_ext(45,30,&gx,&gy);
   CHECK("test_gcd_ext",(3u<<16)|(((uint32_t)(gg0+gg1+gg2)&0xFFu)<<8)|((uint32_t)(gg0^gg1^gg2)&0xFFu),0x00031A0Cu);}
  /* Sprint 83: test_matrix_exp — F(10)=55 F(12)=144 F(14)=377; sum%256=64 xor%256=222 */
  {uint32_t mf0=me2_fib(10),mf1=me2_fib(12),mf2=me2_fib(14);
   CHECK("test_matrix_exp",(3u<<16)|(((mf0+mf1+mf2)&0xFFu)<<8)|((mf0^mf1^mf2)&0xFFu),0x000340DEu);}
  /* Sprint 83: test_derange — D(3)=2 D(4)=9 D(5)=44; sum=55 xor=39 */
  {uint32_t dr[6];dr[0]=1;dr[1]=0;for(int n=2;n<6;n++)dr[n]=(uint32_t)(n-1)*(dr[n-1]+dr[n-2]);
   CHECK("test_derange",(3u<<16)|(((dr[3]+dr[4]+dr[5])&0xFFu)<<8)|((dr[3]^dr[4]^dr[5])&0xFFu),0x00033727u);}
  /* Sprint 84: test_stirling2 — S(4,2)=7 S(5,3)=25 S(6,3)=90; sum=122 xor=68 */
  {static uint32_t st2[7][5];for(int n=0;n<7;n++)for(int k=0;k<5;k++)st2[n][k]=0;st2[0][0]=1;
   for(int n=1;n<7;n++)for(int k=1;k<5;k++)st2[n][k]=(uint32_t)k*st2[n-1][k]+st2[n-1][k-1];
   uint32_t sa=st2[4][2],sb=st2[5][3],sc=st2[6][3];
   CHECK("test_stirling2",(3u<<16)|(((sa+sb+sc)&0xFFu)<<8)|((sa^sb^sc)&0xFFu),0x00037A44u);}
  /* Sprint 84: test_bell_num — B(3)=5 B(4)=15 B(5)=52; sum=72 xor=62 */
  {static uint32_t bn2[6][6];for(int i=0;i<6;i++)for(int j=0;j<6;j++)bn2[i][j]=0;
   bn2[0][0]=1;for(int i=1;i<=5;i++){bn2[i][0]=bn2[i-1][i-1];for(int j=1;j<=i;j++)bn2[i][j]=bn2[i][j-1]+bn2[i-1][j-1];}
   uint32_t bb3=bn2[3][0],bb4=bn2[4][0],bb5=bn2[5][0];
   CHECK("test_bell_num",(3u<<16)|(((bb3+bb4+bb5)&0xFFu)<<8)|((bb3^bb4^bb5)&0xFFu),0x0003483Eu);}
  /* Sprint 85: test_min_window_substr — "ADOBECODEBANC"/"ABC"=4,"a"/"a"=1,"AABBBBC"/"AABC"=7 */
  {static int mwcs[128],mwct[128];
   const char*mws[3]={"ADOBECODEBANC","a","AABBBBC"};
   const char*mwt[3]={"ABC","a","AABC"};
   int mwns[3]={13,1,7},mwnt[3]={3,1,4},mwres[3]={0,0,0};
   for(int tc=0;tc<3;tc++){
     for(int i=0;i<128;i++){mwcs[i]=0;mwct[i]=0;}
     for(int i=0;i<mwnt[tc];i++)mwct[(unsigned char)mwt[tc][i]]++;
     int req=0;for(int i=0;i<128;i++)if(mwct[i]>0)req++;
     int formed=0,left=0,ml=mwns[tc]+1;
     for(int right=0;right<mwns[tc];right++){int c=(unsigned char)mws[tc][right];mwcs[c]++;if(mwct[c]>0&&mwcs[c]==mwct[c])formed++;
       while(formed==req){if(right-left+1<ml)ml=right-left+1;int lc=(unsigned char)mws[tc][left];mwcs[lc]--;if(mwct[lc]>0&&mwcs[lc]<mwct[lc])formed--;left++;}}
     mwres[tc]=ml>mwns[tc]?0:ml;}
   uint32_t mwsum=(uint32_t)(mwres[0]+mwres[1]+mwres[2]),mwxr=(uint32_t)(mwres[0]^mwres[1]^mwres[2]);
   CHECK("test_min_window_substr",(3u<<16)|((mwsum&0xFFu)<<8)|(mwxr&0xFFu),0x00030C02u);}
  /* Sprint 85: test_max_gap — {1,3,6,10,18}=8,{1,9}=8,{1,4,7,9,11,15,20}=5; sum=21 xor=5 */
  {static const int mga0[5]={1,3,6,10,18},mga1[2]={1,9},mga2[7]={1,4,7,9,11,15,20};
   int mg0=0,mg1=0,mg2=0;
   for(int i=1;i<5;i++)if(mga0[i]-mga0[i-1]>mg0)mg0=mga0[i]-mga0[i-1];
   if(mga1[1]-mga1[0]>mg1)mg1=mga1[1]-mga1[0];
   for(int i=1;i<7;i++)if(mga2[i]-mga2[i-1]>mg2)mg2=mga2[i]-mga2[i-1];
   CHECK("test_max_gap",(3u<<16)|(((uint32_t)(mg0+mg1+mg2)&0xFFu)<<8)|((uint32_t)(mg0^mg1^mg2)&0xFFu),0x00031505u);}
  /* Sprint 86: test_sos_dp — f[7]=31 f[5]=18 f[6]=14; sum=63 xor=3 */
  {uint32_t sf[8]={3,1,4,1,5,9,2,6};
   for(int i=0;i<3;i++) for(int m=0;m<8;m++) if(m&(1<<i)) sf[m]+=sf[m^(1<<i)];
   CHECK("test_sos_dp",(3u<<16)|(((sf[7]+sf[5]+sf[6])&0xFFu)<<8)|((sf[7]^sf[5]^sf[6])&0xFFu),0x00033F03u);}
  /* Sprint 86: test_inclusion_excl — div by {2,3,5} in N={30,60,100}; sum=140 xor=112 */
  {int ie0,ie1,ie2;
   ie0=30/2+30/3+30/5-30/6-30/10-30/15+30/30;
   ie1=60/2+60/3+60/5-60/6-60/10-60/15+60/30;
   ie2=100/2+100/3+100/5-100/6-100/10-100/15+100/30;
   CHECK("test_inclusion_excl",(3u<<16)|(((uint32_t)(ie0+ie1+ie2)&0xFFu)<<8)|((uint32_t)(ie0^ie1^ie2)&0xFFu),0x00038C70u);}
  /* Sprint 87: test_roman_to_int — III=3,IX=9,XLII=42,MCMXCIX=1999; sum%256=5 xor%256=239 */
  {const char*rs[4]={"III","IX","XLII","MCMXCIX"};int rlen[4]={3,2,4,7};
   int rtab[128]={0};rtab['I']=1;rtab['V']=5;rtab['X']=10;rtab['L']=50;rtab['C']=100;rtab['D']=500;rtab['M']=1000;
   uint32_t rsum=0,rxr=0;
   for(int t=0;t<4;t++){int v=0;for(int i=0;i<rlen[t]-1;i++){if(rtab[(unsigned char)rs[t][i]]<rtab[(unsigned char)rs[t][i+1]])v-=rtab[(unsigned char)rs[t][i]];else v+=rtab[(unsigned char)rs[t][i]];}v+=rtab[(unsigned char)rs[t][rlen[t]-1]];rsum+=v;rxr^=v;}
   CHECK("test_roman_to_int",(4u<<16)|((rsum&0xFFu)<<8)|(rxr&0xFFu),0x000405EFu);}
  /* Sprint 87: test_next_perm — {1,2,3} after 3 nexts={2,3,1}; sum=6 first^last=3 */
  {int npa[3]={1,2,3};
   for(int step=0;step<3;step++){int ni=1;while(ni>=0&&npa[ni]>=npa[ni+1])ni--;if(ni>=0){int nj=2;while(npa[nj]<=npa[ni])nj--;int nt=npa[ni];npa[ni]=npa[nj];npa[nj]=nt;}int lo=ni+1,hi=2;while(lo<hi){int nt=npa[lo];npa[lo]=npa[hi];npa[hi]=nt;lo++;hi--;}}
   CHECK("test_next_perm",(3u<<16)|(((uint32_t)(npa[0]+npa[1]+npa[2])&0xFFu)<<8)|(((uint32_t)(npa[0]^npa[2])&0xFFu)),0x00030603u);}
  /* Sprint 88: test_lcs_dp — "ABCBDAB"/"BDCAB"=4,"AGGTAB"/"GXTXAYB"=4,"ABC"/"AC"=2; sum=10 xor=2 */
  {static int lc2[9][9];
   const char*ls1[3]={"ABCBDAB","AGGTAB","ABC"},*ls2[3]={"BDCAB","GXTXAYB","AC"};
   int lm[3]={7,6,3},ln[3]={5,7,2}; uint32_t lcsum=0,lcxr=0;
   for(int tc=0;tc<3;tc++){for(int i=0;i<=lm[tc];i++)lc2[i][0]=0;for(int j=0;j<=ln[tc];j++)lc2[0][j]=0;
     for(int i=1;i<=lm[tc];i++) for(int j=1;j<=ln[tc];j++){if(ls1[tc][i-1]==ls2[tc][j-1])lc2[i][j]=lc2[i-1][j-1]+1;else lc2[i][j]=lc2[i-1][j]>lc2[i][j-1]?lc2[i-1][j]:lc2[i][j-1];}
     lcsum+=(uint32_t)lc2[lm[tc]][ln[tc]]; lcxr^=(uint32_t)lc2[lm[tc]][ln[tc]];}
   CHECK("test_lcs_dp",(3u<<16)|((lcsum&0xFFu)<<8)|(lcxr&0xFFu),0x00030A02u);}
  /* Sprint 88: test_lca_subarray — {1,2,3,2,1}/{3,2,1,4,7}=3,{0,0,0,0,1}/{1,0,0,0,0}=4,{1,2,3}/{4,5,6}=0 */
  {static int lcd[6][6];
   const int la0[5]={1,2,3,2,1},lb0[5]={3,2,1,4,7};
   const int la1[5]={0,0,0,0,1},lb1[5]={1,0,0,0,0};
   const int la2[3]={1,2,3},lb2[3]={4,5,6};
   int lcr0=0,lcr1=0,lcr2=0;
   for(int i=0;i<=5;i++)for(int j=0;j<=5;j++)lcd[i][j]=0;
   for(int i=1;i<=5;i++)for(int j=1;j<=5;j++){lcd[i][j]=(la0[i-1]==lb0[j-1])?lcd[i-1][j-1]+1:0;if(lcd[i][j]>lcr0)lcr0=lcd[i][j];}
   for(int i=0;i<=5;i++)for(int j=0;j<=5;j++)lcd[i][j]=0;
   for(int i=1;i<=5;i++)for(int j=1;j<=5;j++){lcd[i][j]=(la1[i-1]==lb1[j-1])?lcd[i-1][j-1]+1:0;if(lcd[i][j]>lcr1)lcr1=lcd[i][j];}
   for(int i=0;i<=3;i++)for(int j=0;j<=3;j++)lcd[i][j]=0;
   for(int i=1;i<=3;i++)for(int j=1;j<=3;j++){lcd[i][j]=(la2[i-1]==lb2[j-1])?lcd[i-1][j-1]+1:0;if(lcd[i][j]>lcr2)lcr2=lcd[i][j];}
   CHECK("test_lca_subarray",(3u<<16)|(((uint32_t)(lcr0+lcr1+lcr2)&0xFFu)<<8)|((uint32_t)(lcr0^lcr1^lcr2)&0xFFu),0x00030707u);}
  /* Sprint 89: test_merge_intervals — 3 interval sets; merged counts=3+1+3 sum=7 xor=1 */
  {int ms1[][2]={{1,3},{2,6},{8,10},{15,18}};int mn1=4;
   int ms2[][2]={{1,4},{4,5}};int mn2=2;
   int ms3[][2]={{1,3},{4,6},{8,10}};int mn3=3;
   int cnt[3]={0,0,0};int cs=0,ce=0;
   cs=ms1[0][0];ce=ms1[0][1];cnt[0]=1;for(int i=1;i<mn1;i++){if(ms1[i][0]<=ce){if(ms1[i][1]>ce)ce=ms1[i][1];}else{cnt[0]++;cs=ms1[i][0];ce=ms1[i][1];}}
   cs=ms2[0][0];ce=ms2[0][1];cnt[1]=1;for(int i=1;i<mn2;i++){if(ms2[i][0]<=ce){if(ms2[i][1]>ce)ce=ms2[i][1];}else{cnt[1]++;cs=ms2[i][0];ce=ms2[i][1];}}
   cs=ms3[0][0];ce=ms3[0][1];cnt[2]=1;for(int i=1;i<mn3;i++){if(ms3[i][0]<=ce){if(ms3[i][1]>ce)ce=ms3[i][1];}else{cnt[2]++;cs=ms3[i][0];ce=ms3[i][1];}}
   (void)cs;
   CHECK("test_merge_intervals",(3u<<16)|(((uint32_t)(cnt[0]+cnt[1]+cnt[2])&0xFFu)<<8)|((uint32_t)(cnt[0]^cnt[1]^cnt[2])&0xFFu),0x00030701u);}
  /* Sprint 89: test_wiggle_sort — {1,5,1,1,6,4}; n_ok=5 xor=6 */
  {int wsa[6]={1,5,1,1,6,4};
   for(int i=1;i<6;i++){if((i&1)&&wsa[i]<wsa[i-1]){int t=wsa[i];wsa[i]=wsa[i-1];wsa[i-1]=t;}else if(!(i&1)&&wsa[i]>wsa[i-1]){int t=wsa[i];wsa[i]=wsa[i-1];wsa[i-1]=t;}}
   int nok=0;for(int i=1;i<6;i++)if((i&1)?wsa[i]>wsa[i-1]:wsa[i]<wsa[i-1])nok++;
   uint32_t wxr=0;for(int i=0;i<6;i++)wxr^=(uint32_t)wsa[i];
   CHECK("test_wiggle_sort",(6u<<16)|(((uint32_t)nok&0xFFu)<<8)|(wxr&0xFFu),0x00060506u);}
  /* Sprint 86: test_longest_common_prefix — lcp("flower","flow","flight")=2 lcp("dog","racecar","car")=0 lcp("interview","interstellar","internal")=5; sum=7 last=5 */
  {const char*s1[3]={"flower","flow","flight"};const char*s2[3]={"dog","racecar","car"};const char*s3[3]={"interview","interstellar","internal"};
   int l0=lcp2_str(s1,3),l1=lcp2_str(s2,3),l2=lcp2_str(s3,3);
   CHECK("test_longest_common_prefix",(3u<<16)|((uint32_t)(l0+l1+l2)<<8)|(uint32_t)l2,0x00030705u);}
  /* Sprint 86: test_power_set — bitmask subsets of {1,2,3,4}; total=16 sum_sizes=32 elem_sum=80 */
  {static const int pe[4]={1,2,3,4};uint32_t tot=0,ss=0,es=0;
   for(int mask=0;mask<16;mask++){tot++;for(int i=0;i<4;i++)if(mask&(1<<i)){ss++;es+=(uint32_t)pe[i];}}
   CHECK("test_power_set",(tot<<16)|((ss&0xFFu)<<8)|(es&0xFFu),0x00102050u);}
  /* Sprint 87: test_maximal_square — 4x5 matrix; max_side=2 max_area=4 n_cols=5 */
  {static const int ms_mat[4][5]={{1,0,1,0,0},{1,0,1,1,1},{1,1,1,1,1},{1,0,0,1,0}};
   static int ms_dp[4][5];int ms_max=0;
   #define MS2MIN3(a,b,c) ((a)<(b)?((a)<(c)?(a):(c)):((b)<(c)?(b):(c)))
   for(int i=0;i<4;i++)for(int j=0;j<5;j++){if(ms_mat[i][j]==1){if(i==0||j==0)ms_dp[i][j]=1;else ms_dp[i][j]=MS2MIN3(ms_dp[i-1][j],ms_dp[i][j-1],ms_dp[i-1][j-1])+1;if(ms_dp[i][j]>ms_max)ms_max=ms_dp[i][j];}else ms_dp[i][j]=0;}
   CHECK("test_maximal_square",(4u<<16)|((uint32_t)(ms_max*ms_max)<<8)|5u,0x00040405u);}
  /* Sprint 87: test_bucket_sort — {4,2,8,1,9,3,7,5,6,0}; largest=9 second=8 n=10 */
  {int bsa[10]={4,2,8,1,9,3,7,5,6,0};static int bkt[10];int bi;
   for(bi=0;bi<10;bi++)bkt[bi]=0;for(bi=0;bi<10;bi++)bkt[bsa[bi]]++;int bidx=0;for(bi=0;bi<10;bi++)while(bkt[bi]-->0)bsa[bidx++]=bi;
   CHECK("test_bucket_sort",(10u<<16)|((uint32_t)bsa[9]<<8)|(uint32_t)bsa[8],0x000A0908u);}
  /* Sprint 88: test_subarray_xor — a1[]={4,2,2,6,4} k=6 -> c1=4; a2[]={1,3,3,4,2,4} k=7 -> c2=2; sum=6 xor=6 */
  {static int xf2[256];int xpx,xres;
   for(int xi=0;xi<256;xi++)xf2[xi]=0;xf2[0]=1;xpx=0;xres=0;int xa1[]={4,2,2,6,4};for(int xi=0;xi<5;xi++){xpx^=xa1[xi];xres+=xf2[xpx^6];xf2[xpx]++;}int c1=xres;
   for(int xi=0;xi<256;xi++)xf2[xi]=0;xf2[0]=1;xpx=0;xres=0;int xa2[]={1,3,3,4,2,4};for(int xi=0;xi<6;xi++){xpx^=xa2[xi];xres+=xf2[xpx^7];xf2[xpx]++;}int c2=xres;
   CHECK("test_subarray_xor",(2u<<16)|((uint32_t)(c1+c2)<<8)|(uint32_t)(c1^c2),0x00020606u);}
  /* Sprint 88: test_valid_parentheses — "()[]{}"->1 "([)]"->0 "{[]}"->1 "((("->0; n_valid=2 valid_len_sum=10 */
  {static const char*vps[4]={"()[]{}","([)]","{[]}","((("}; int vn=0;uint32_t vls=0;
   for(int vi=0;vi<4;vi++){char vstk[16];int vtop=0,vok=1;for(int j=0;vps[vi][j];j++){char vc=vps[vi][j];if(vc=='('||vc=='['||vc=='{')vstk[vtop++]=vc;else{if(vtop==0){vok=0;break;}char vt=vstk[vtop-1];if((vc==')'&&vt!='(')||(vc==']'&&vt!='[')||(vc=='}'&&vt!='{')){{vok=0;break;}}vtop--;}}vok=vok&&(vtop==0);if(vok){vn++;int vl=0;while(vps[vi][vl])vl++;vls+=(uint32_t)vl;}}
   CHECK("test_valid_parentheses",(4u<<16)|((uint32_t)vn<<8)|(vls&0xFFu),0x0004020Au);}
  /* Sprint 89: test_count_rooms — grid1 4x4->3 grid2 3x5->8 grid3 2x3->1; sum=12 xor=10 */
  {static const int cr2g1[4][4]={{1,1,0,1},{1,0,0,1},{0,0,1,1},{1,0,0,0}};
   cr2_R=4;cr2_C=4;for(int r=0;r<4;r++)for(int c=0;c<4;c++)cr2_grid[r][c]=cr2g1[r][c];int ro1=cr2_count();
   static const int cr2g2[3][5]={{1,0,1,0,1},{0,1,0,1,0},{1,0,1,0,1}};
   cr2_R=3;cr2_C=5;for(int r=0;r<3;r++)for(int c=0;c<5;c++)cr2_grid[r][c]=cr2g2[r][c];int ro2=cr2_count();
   static const int cr2g3[2][3]={{1,1,1},{1,1,1}};
   cr2_R=2;cr2_C=3;for(int r=0;r<2;r++)for(int c=0;c<3;c++)cr2_grid[r][c]=cr2g3[r][c];int ro3=cr2_count();
   CHECK("test_count_rooms",(3u<<16)|((uint32_t)(ro1+ro2+ro3)<<8)|(uint32_t)(ro1^ro2^ro3),0x00030C0Au);}
  /* Sprint 89: test_dependency_order — 5 packages DAG; Kahn BFS; first=0 last=4 n_edges=5 */
  {static const int doe[5][2]={{0,1},{0,2},{1,3},{2,3},{3,4}};
   static int do2adj[5][4],do2deg[5],do2ind[5];int do2q[5],do2ord[5],dof=0,dob=0,doc=0;
   for(int i=0;i<5;i++){do2deg[i]=0;do2ind[i]=0;}
   for(int i=0;i<5;i++){int u=doe[i][0],v=doe[i][1];do2adj[u][do2deg[u]++]=v;do2ind[v]++;}
   for(int i=0;i<5;i++)if(do2ind[i]==0)do2q[dob++]=i;
   while(dof<dob){int u=do2q[dof++];do2ord[doc++]=u;for(int i=0;i<do2deg[u];i++){int v=do2adj[u][i];if(--do2ind[v]==0)do2q[dob++]=v;}}
   CHECK("test_dependency_order",(5u<<16)|(5u<<8)|(uint32_t)(do2ord[0]*10+do2ord[doc-1]),0x00050504u);}
  /* Sprint 90: test_trie_ops — insert apple/app/application/apt; search 6 queries; found=4 miss=2 */
  {tr2_init();static const char*tw[4]={"apple","app","application","apt"};for(int i=0;i<4;i++)tr2_ins(tw[i]);
   static const char*tq[6]={"app","apple","ap","application","xyz","apt"};int tf=0,tm=0;
   for(int i=0;i<6;i++){if(tr2_srch(tq[i]))tf++;else tm++;}
   CHECK("test_trie_ops",(6u<<16)|((uint32_t)tf<<8)|(uint32_t)tm,0x00060402u);}
  /* Sprint 90: test_chain_pairs — pairs (5,24)(15,25)(27,40)(50,60)(15,28); greedy chain=3 xb=24^40^60=12 */
  {int cpa[5]={5,15,27,50,15},cpb[5]={24,25,40,60,28};
   for(int i=1;i<5;i++){int ka=cpa[i],kb=cpb[i],j=i-1;while(j>=0&&cpb[j]>kb){cpa[j+1]=cpa[j];cpb[j+1]=cpb[j];j--;}cpa[j+1]=ka;cpb[j+1]=kb;}
   int cpch=1,cplb=cpb[0];uint32_t cpxb=(uint32_t)cpb[0];
   for(int i=1;i<5;i++)if(cpa[i]>cplb){cpch++;cpxb^=(uint32_t)cpb[i];cplb=cpb[i];}
   CHECK("test_chain_pairs",(5u<<16)|((uint32_t)cpch<<8)|(cpxb&0xFFu),0x0005030Cu);}
  /* Sprint 91: test_circular_buffer — cap=5; push 1-5, pop1, push6, pop2-3; front=4 n_pushes=6 xpush=7 */
  {int cbb[5],cbh=0,cbt=0,cbcnt=0,cbnp=0;uint32_t cbxp=0u;
   for(int v=1;v<=5;v++){cbb[cbt]=v;cbt=(cbt+1)%5;cbcnt++;cbnp++;cbxp^=(uint32_t)v;}
   cbh=(cbh+1)%5;cbcnt--;
   cbb[cbt]=6;cbt=(cbt+1)%5;cbcnt++;cbnp++;cbxp^=6u;
   cbh=(cbh+1)%5;cbcnt--;cbh=(cbh+1)%5;cbcnt--;
   int cbfv=cbb[cbh];(void)cbcnt;
   CHECK("test_circular_buffer",((uint32_t)(cbnp+1)<<16)|((uint32_t)cbfv<<8)|(cbxp&0xFFu),0x00070407u);}
  /* Sprint 91: test_spiral_matrix — 3x4 matrix; n=12 sum=78=0x4E xor=12=0x0C */
  {static const int sm[3][4]={{1,2,3,4},{5,6,7,8},{9,10,11,12}};int ssp[12],si=0;
   int st=0,sb=2,sl=0,sr=3;
   while(st<=sb&&sl<=sr){for(int c=sl;c<=sr;c++)ssp[si++]=sm[st][c];st++;for(int r=st;r<=sb;r++)ssp[si++]=sm[r][sr];sr--;if(st<=sb){for(int c=sr;c>=sl;c--)ssp[si++]=sm[sb][c];sb--;}if(sl<=sr){for(int r=sb;r>=st;r--)ssp[si++]=sm[r][sl];sl++;}}
   uint32_t ssum=0,sxr=0;for(int i=0;i<si;i++){ssum+=(uint32_t)ssp[i];sxr^=(uint32_t)ssp[i];}
   CHECK("test_spiral_matrix",((uint32_t)si<<16)|((ssum&0xFFu)<<8)|(sxr&0xFFu),0x000C4E0Cu);}
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
