// PacketPy eBPF VM — transparent UDP packet rewriter (TC/clsact classifier).
// Executes PacketPy bytecode (loaded into ppy_program) against each matching
// UDP packet and rewrites the payload in place. Generic: no app-specific logic.
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

// VM limits. MAX_INSNS is kept at a value the kernel verifier accepts for this
// interpreter shape; raising it past the verifier's instruction budget makes
// the program fail to load (the original v0.2 advertised 128 but never loaded).
#define MAX_INSNS 64
#define MAX_REGS 24

enum {
 OP_NOP=0, OP_MOVI=1, OP_MOV=2, OP_ADD=3, OP_SUB=4, OP_AND=5, OP_OR=6, OP_XOR=7,
 OP_SHL=8, OP_SHR=9, OP_MUL=10, OP_DIV=11, OP_MOD=12,
 OP_CMPEQ=20, OP_CMPNE=21, OP_CMPLT=22, OP_CMPLE=23, OP_CMPGT=24, OP_CMPGE=25,
 OP_JZ=30, OP_JNZ=31, OP_JMP=32,
 OP_LOAD8=40, OP_LOAD16LE=41, OP_LOAD16BE=42, OP_LOADBITS=43,
 OP_STORE8=44, OP_STORE16LE=45, OP_STORE16BE=46, OP_STOREBITS=47,
 OP_STATE_LD=50, OP_STATE_ST=51, OP_META=52,
 OP_RAND=53, OP_TIME=54, OP_TRACE=55, OP_PARAM=56,
 OP_ACCEPT=60, OP_DROP=61,
};

// meta ids, must match META in packetpy.py
enum { M_DIR=1, M_SPORT=2, M_DPORT=3, M_PLEN=4, M_IPSRC=5, M_IPDST=6, M_TTL=7 };
// stats counter indices, must match STAT_NAMES in packetpy.py
enum { S_SEEN=0, S_ACCEPT=1, S_DROP=2, S_MODIFIED=3, S_ERROR=4, S_TRACE=5 };

struct ppy_insn { __u8 op,dst,src,aux; __s32 imm,off,extra; };

struct {
 __uint(type, BPF_MAP_TYPE_ARRAY);
 __uint(max_entries, MAX_INSNS);
 __type(key, __u32);
 __type(value, struct ppy_insn);
} ppy_program SEC(".maps");

struct {
 __uint(type, BPF_MAP_TYPE_ARRAY);
 __uint(max_entries, 64);
 __type(key, __u32);
 __type(value, __u64);
} ppy_state SEC(".maps");

// config: 0 port, 1 PC ifindex, 2 BOX ifindex, 3 instruction count, 4 debug flag
struct {
 __uint(type, BPF_MAP_TYPE_ARRAY);
 __uint(max_entries, 16);
 __type(key, __u32);
 __type(value, __u64);
} ppy_config SEC(".maps");

// runtime counters, readable with `packetpy stats`. Single entry holding all
// counters, so the datapath looks it up once per packet (key 0) and then does
// cheap atomic adds on the returned pointer — no per-exit map lookup.
struct ppy_counters { __u64 c[16]; };
struct {
 __uint(type, BPF_MAP_TYPE_ARRAY);
 __uint(max_entries, 1);
 __type(key, __u32);
 __type(value, struct ppy_counters);
} ppy_stats SEC(".maps");

// live control values (Param/Toggle/Choice/Number/Button), set from userspace,
// read-only in the datapath. The panel writes these to change a running script
// without recompiling or reloading.
#define MAX_PARAMS 32
struct {
 __uint(type, BPF_MAP_TYPE_ARRAY);
 __uint(max_entries, MAX_PARAMS);
 __type(key, __u32);
 __type(value, __u64);
} ppy_params SEC(".maps");

static __always_inline __u64 cfg(__u32 k){ __u64 *v=bpf_map_lookup_elem(&ppy_config,&k); return v?*v:0; }

static __always_inline int load8(struct __sk_buff *skb,__u32 o,__u64 *out){ __u8 v=0; if(bpf_skb_load_bytes(skb,o,&v,1)<0)return -1;*out=v;return 0; }
static __always_inline int load16le(struct __sk_buff *skb,__u32 o,__u64 *out){ __u8 b[2]; if(bpf_skb_load_bytes(skb,o,b,2)<0)return -1;*out=(__u16)b[0]|((__u16)b[1]<<8);return 0; }
static __always_inline int load16be(struct __sk_buff *skb,__u32 o,__u64 *out){ __u8 b[2]; if(bpf_skb_load_bytes(skb,o,b,2)<0)return -1;*out=((__u16)b[0]<<8)|b[1];return 0; }
static __always_inline int store8(struct __sk_buff *skb,__u32 o,__u64 v){ __u8 b=(__u8)v; return bpf_skb_store_bytes(skb,o,&b,1,0); }
static __always_inline int store16le(struct __sk_buff *skb,__u32 o,__u64 v){ __u8 b[2]={(__u8)v,(__u8)(v>>8)}; return bpf_skb_store_bytes(skb,o,b,2,0); }
static __always_inline int store16be(struct __sk_buff *skb,__u32 o,__u64 v){ __u8 b[2]={(__u8)(v>>8),(__u8)v}; return bpf_skb_store_bytes(skb,o,b,2,0); }
static __always_inline int load_bits(struct __sk_buff *skb,__u32 payload,__u32 bitoff,__u32 width,__u64*out){
 if(width<1||width>16)return -1; __u32 bo=bitoff>>3, sh=bitoff&7; __u8 b[4]={0};
 if(bpf_skb_load_bytes(skb,payload+bo,b,4)<0)return -1;
 __u32 raw=(__u32)b[0]|((__u32)b[1]<<8)|((__u32)b[2]<<16)|((__u32)b[3]<<24);
 __u32 mask=width==16?0xffffu:((1u<<width)-1u); *out=(raw>>sh)&mask; return 0;
}
static __always_inline int store_bits(struct __sk_buff *skb,__u32 payload,__u32 bitoff,__u32 width,__u64 val){
 if(width<1||width>16)return -1; __u32 bo=bitoff>>3,sh=bitoff&7;__u8 b[4]={0};
 if(bpf_skb_load_bytes(skb,payload+bo,b,4)<0)return -1;
 __u32 raw=(__u32)b[0]|((__u32)b[1]<<8)|((__u32)b[2]<<16)|((__u32)b[3]<<24);
 __u32 mask=width==16?0xffffu:((1u<<width)-1u); raw=(raw&~(mask<<sh))|(((__u32)val&mask)<<sh);
 b[0]=raw;b[1]=raw>>8;b[2]=raw>>16;b[3]=raw>>24; return bpf_skb_store_bytes(skb,payload+bo,b,4,0);
}

// Terminal path, expanded at every exit: zero the UDP checksum if the payload
// was rewritten, record counters on the already-resolved stats pointer (st may
// be NULL in the impossible case the lookup failed), and return the verdict.
// `st` increments are atomic BPF instructions, not helper calls, so duplicating
// this at each exit stays within the verifier's budget.
#define PPY_RET(drop) do{ \
   if(modified){ __u16 _z=0; bpf_skb_store_bytes(skb,uoff+6,&_z,2,0); } \
   if(st){ st->c[S_SEEN]+=1; st->c[S_TRACE]+=n_trace; st->c[S_ERROR]+=n_err; \
           if(modified)st->c[S_MODIFIED]+=1; st->c[(drop)?S_DROP:S_ACCEPT]+=1; } \
   return (drop)?TC_ACT_SHOT:TC_ACT_OK; \
 }while(0)

SEC("classifier")
int packetpy_vm(struct __sk_buff *skb){
 __u8 hdr[42]; if(bpf_skb_load_bytes(skb,0,hdr,sizeof(hdr))<0)return TC_ACT_OK;
 __u16 eth=((__u16)hdr[12]<<8)|hdr[13]; if(eth!=ETH_P_IP)return TC_ACT_OK;
 __u8 ihl=(hdr[14]&0x0f)*4; if(ihl<20)return TC_ACT_OK; if(hdr[23]!=IPPROTO_UDP)return TC_ACT_OK;
 /* Skip IPv4 fragments (MF set or non-zero fragment offset): only the first
    fragment carries the UDP header and offsets would be meaningless. Pass them
    through untouched. */
 __u16 fragbits=((__u16)hdr[20]<<8)|hdr[21]; if(fragbits & 0x3fff)return TC_ACT_OK;
 __u8 ttl=hdr[22];
 __u32 uoff=14+ihl; __u8 ub[8]; if(bpf_skb_load_bytes(skb,uoff,ub,8)<0)return TC_ACT_OK;
 __u16 sport=((__u16)ub[0]<<8)|ub[1], dport=((__u16)ub[2]<<8)|ub[3]; __u16 port=(__u16)cfg(0); if(sport!=port&&dport!=port)return TC_ACT_OK;
 __u32 poff=uoff+8; __u16 ulen=((__u16)ub[4]<<8)|ub[5]; __u32 plen=ulen>=8?ulen-8:0;
 /* Clamp the payload length to the bytes actually present, so every VM bound
    check is against real data, whatever the UDP length header claims. */
 if(poff>skb->len)return TC_ACT_OK;
 __u32 avail=skb->len-poff; if(plen>avail)plen=avail;
 __u32 pcif=(__u32)cfg(1), boxif=(__u32)cfg(2); __u64 direction=0; if(skb->ifindex==pcif)direction=1; else if(skb->ifindex==boxif)direction=2;
 __u64 debug=cfg(4);
 __u32 ipsrc=((__u32)hdr[26]<<24)|((__u32)hdr[27]<<16)|((__u32)hdr[28]<<8)|hdr[29];
 __u32 ipdst=((__u32)hdr[30]<<24)|((__u32)hdr[31]<<16)|((__u32)hdr[32]<<8)|hdr[33];
 if(debug)bpf_printk("ppy: match dir=%u sport=%u dport=%u",(__u32)direction,sport,dport);

 __u64 r[MAX_REGS]={0}; __s32 pc=0; __u32 count=(__u32)cfg(3); if(count>MAX_INSNS)count=MAX_INSNS;
 int modified=0; __u64 n_trace=0, n_err=0;
 __u32 szero=0; struct ppy_counters *st=bpf_map_lookup_elem(&ppy_stats,&szero);
 #pragma clang loop unroll(disable)
 for(int step=0; step<MAX_INSNS; step++){
  if(pc<0||(__u32)pc>=count)break; __u32 key=(__u32)pc; struct ppy_insn *in=bpf_map_lookup_elem(&ppy_program,&key); if(!in)break;
  __u8 d=in->dst,s=in->src; __s32 imm=in->imm; if(d>=MAX_REGS||s>=MAX_REGS){n_err++;PPY_RET(0);} __s32 next=pc+1;
  switch(in->op){
   case OP_NOP:break; case OP_MOVI:r[d]=(__s64)imm;break; case OP_MOV:r[d]=r[s];break;
   case OP_ADD:r[d]+=r[s];break; case OP_SUB:r[d]-=r[s];break; case OP_AND:r[d]&=r[s];break;case OP_OR:r[d]|=r[s];break;case OP_XOR:r[d]^=r[s];break;
   case OP_SHL:r[d]<<=(r[s]&63);break;case OP_SHR:r[d]>>=(r[s]&63);break;case OP_MUL:r[d]*=r[s];break;
   case OP_DIV:r[d]=r[s]?r[d]/r[s]:0;break; case OP_MOD:r[d]=r[s]?r[d]%r[s]:0;break;
   case OP_CMPEQ:r[d]=(r[d]==r[s]);break;case OP_CMPNE:r[d]=(r[d]!=r[s]);break;case OP_CMPLT:r[d]=((__s64)r[d]<(__s64)r[s]);break;case OP_CMPLE:r[d]=((__s64)r[d]<=(__s64)r[s]);break;case OP_CMPGT:r[d]=((__s64)r[d]>(__s64)r[s]);break;case OP_CMPGE:r[d]=((__s64)r[d]>=(__s64)r[s]);break;
   case OP_JZ:if(!r[s])next=pc+imm;break; case OP_JNZ:if(r[s])next=pc+imm;break; case OP_JMP:next=pc+imm;break;
   case OP_LOAD8:if(r[s]>=plen||load8(skb,poff+(__u32)r[s],&r[d])<0){n_err++;PPY_RET(0);};break;
   case OP_LOAD16LE:if(r[s]+2>plen||load16le(skb,poff+(__u32)r[s],&r[d])<0){n_err++;PPY_RET(0);};break;
   case OP_LOAD16BE:if(r[s]+2>plen||load16be(skb,poff+(__u32)r[s],&r[d])<0){n_err++;PPY_RET(0);};break;
   case OP_LOADBITS:if((r[s]+imm+7)/8>plen||load_bits(skb,poff,(__u32)r[s],imm,&r[d])<0){n_err++;PPY_RET(0);};break;
   case OP_STORE8:if(r[d]>=plen||store8(skb,poff+(__u32)r[d],r[s])<0){n_err++;PPY_RET(0);};modified=1;break;
   case OP_STORE16LE:if(r[d]+2>plen||store16le(skb,poff+(__u32)r[d],r[s])<0){n_err++;PPY_RET(0);};modified=1;break;
   case OP_STORE16BE:if(r[d]+2>plen||store16be(skb,poff+(__u32)r[d],r[s])<0){n_err++;PPY_RET(0);};modified=1;break;
   case OP_STOREBITS:if((r[d]+imm+7)/8>plen||store_bits(skb,poff,(__u32)r[d],imm,r[s])<0){n_err++;PPY_RET(0);};modified=1;break;
   case OP_STATE_LD:{__u32 k=(__u32)imm&63;__u64*v=bpf_map_lookup_elem(&ppy_state,&k);r[d]=v?*v:0;break;}
   case OP_STATE_ST:{__u32 k=(__u32)imm&63;__u64 v=r[s];bpf_map_update_elem(&ppy_state,&k,&v,BPF_ANY);break;}
   case OP_META: if(imm==M_DIR)r[d]=direction;else if(imm==M_SPORT)r[d]=sport;else if(imm==M_DPORT)r[d]=dport;else if(imm==M_PLEN)r[d]=plen;else if(imm==M_IPSRC)r[d]=ipsrc;else if(imm==M_IPDST)r[d]=ipdst;else if(imm==M_TTL)r[d]=ttl;break;
   case OP_RAND:r[d]=bpf_get_prandom_u32();break;
   case OP_TIME:r[d]=bpf_ktime_get_ns();break;
   case OP_PARAM:{__u32 k=(__u32)imm&(MAX_PARAMS-1);__u64*v=bpf_map_lookup_elem(&ppy_params,&k);r[d]=v?*v:0;break;}
   case OP_TRACE:n_trace++;break;
   case OP_ACCEPT:PPY_RET(0);
   case OP_DROP:PPY_RET(1);
   default:{n_err++;PPY_RET(0);};
  }
  pc=next;
 }
 PPY_RET(0);
}
char LICENSE[] SEC("license")="GPL";
