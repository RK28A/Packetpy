#!/usr/bin/env python3
import argparse, ast, json, struct, subprocess, sys
from dataclasses import dataclass
from pathlib import Path

# PacketPy bytecode v0.3
OPS = {
    'NOP':0, 'MOVI':1, 'MOV':2, 'ADD':3, 'SUB':4, 'AND':5, 'OR':6, 'XOR':7,
    'SHL':8, 'SHR':9, 'MUL':10, 'DIV':11, 'MOD':12,
    'CMPEQ':20, 'CMPNE':21, 'CMPLT':22, 'CMPLE':23, 'CMPGT':24, 'CMPGE':25,
    'JZ':30, 'JNZ':31, 'JMP':32,
    'LOAD8':40, 'LOAD16LE':41, 'LOAD16BE':42, 'LOADBITS':43,
    'STORE8':44, 'STORE16LE':45, 'STORE16BE':46, 'STOREBITS':47,
    'STATE_LD':50, 'STATE_ST':51, 'META':52, 'RAND':53, 'TIME':54, 'TRACE':55,
    'ACCEPT':60, 'DROP':61,
}
OPN = {v:k for k,v in OPS.items()}
MAX_INSNS = 64
MAX_REGS = 24
INS = struct.Struct('<BBBBiii')  # op,dst,src,aux,imm,off,extra = 16 bytes

# meta ids must match enum in packetpy_vm.bpf.c
META = {'direction':1,'udp_src':2,'udp_dst':3,'payload_len':4,'ip_src':5,'ip_dst':6,'ip_ttl':7}
CONST = {'PC_TO_BOX':1,'BOX_TO_PC':2,'True':1,'False':0}
# stats counter indices must match enum in packetpy_vm.bpf.c
STAT_NAMES = ['seen','accept','drop','modified','error','trace']

class CompileError(Exception): pass

@dataclass
class I:
    op:int; dst:int=0; src:int=0; aux:int=0; imm:int=0; off:int=0; extra:int=0
    def pack(self): return INS.pack(self.op,self.dst,self.src,self.aux,self.imm,self.off,self.extra)
    def text(self, pc, names=None):
        tag = f" ; {names.get(pc)}" if names and pc in names else ""
        return f"{pc:03d} {OPN.get(self.op,self.op):10} d={self.dst:02d} s={self.src:02d} a={self.aux:02d} imm={self.imm} off={self.off} x={self.extra}{tag}"

class Compiler(ast.NodeVisitor):
    def __init__(self, packet_config=None):
        self.code=[]; self.port=0; self.state={}; self.state_init=[]
        self.vars={}; self.free=list(range(MAX_REGS-1,-1,-1)); self.helpers={}
        self.event=None; self.notes={}; self.log_labels=[]
        self.packet_config = packet_config or {"constants": {}, "fields": {}}
        self.packet_constants = {k:int(v) for k,v in self.packet_config.get("constants", {}).items() if isinstance(v,(int,bool))}
        self.packet_fields = self.packet_config.get("fields", {})

    def err(self,node,msg): raise CompileError(f"line {getattr(node,'lineno','?')}: {msg}")
    def emit(self,name,dst=0,src=0,aux=0,imm=0,off=0,extra=0,note=None):
        if len(self.code)>=MAX_INSNS: raise CompileError(f"program exceeds {MAX_INSNS} VM instructions")
        self.code.append(I(OPS[name],dst,src,aux,imm,off,extra))
        if note: self.notes[len(self.code)-1]=note
        return len(self.code)-1
    def alloc(self):
        if not self.free: raise CompileError(f"out of VM registers (max {MAX_REGS})")
        return self.free.pop()
    def release(self,r):
        if r not in self.vars.values() and r not in self.free: self.free.append(r)
    def varreg(self,name):
        if name not in self.vars:
            self.vars[name]=self.alloc()
        return self.vars[name]

    def compile(self, src):
        tree=ast.parse(src)
        for n in tree.body:
            if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Name) and n.value.func.id=='State':
                name=n.targets[0].id
                if len(n.value.args)!=1 or not isinstance(n.value.args[0],ast.Constant) or not isinstance(n.value.args[0].value,int): self.err(n,'State() needs one integer literal')
                if name in self.state: self.err(n,'duplicate state')
                if len(self.state)>=64: self.err(n,'at most 64 State() slots')
                self.state[name]=len(self.state); self.state_init.append(int(n.value.args[0].value) & 0xffffffffffffffff)
            elif isinstance(n,ast.FunctionDef):
                dec_udp=False
                for d in n.decorator_list:
                    if isinstance(d,ast.Call) and isinstance(d.func,ast.Name) and d.func.id=='udp':
                        dec_udp=True
                        for kw in d.keywords:
                            if kw.arg=='port' and isinstance(kw.value,ast.Constant): self.port=int(kw.value.value)
                if dec_udp:
                    if self.event is not None: self.err(n,'only one @udp event supported')
                    self.event=n
                else:
                    self.helpers[n.name]=n
            elif isinstance(n,(ast.Import,ast.ImportFrom)):
                self.err(n,'import is not supported in PacketPy scripts')
        if not self.event: raise CompileError('missing @udp(port=...) function')
        if not self.port: raise CompileError('@udp needs a non-zero port')
        if not (0 < self.port <= 65535): raise CompileError('@udp port must be 1..65535')
        for st in self.event.body: self.compile_stmt(st)
        if not self.code or self.code[-1].op not in (OPS['ACCEPT'],OPS['DROP']): self.emit('ACCEPT')
        return self

    def compile_stmt(self,n):
        if isinstance(n,ast.Assign):
            if len(n.targets)!=1 or not isinstance(n.targets[0],ast.Name): self.err(n,'only simple variable assignment supported')
            name=n.targets[0].id
            if name in META or name in CONST or name in self.packet_constants: self.err(n,f'cannot assign to reserved name {name!r}')
            r=self.expr(n.value)
            if name in self.state: self.emit('STATE_ST',src=r,imm=self.state[name],note=f'{name} =')
            else:
                d=self.varreg(name)
                if d!=r: self.emit('MOV',dst=d,src=r,note=f'{name} =')
            self.release(r); return
        if isinstance(n,ast.AugAssign) and isinstance(n.target,ast.Name):
            name=n.target.id
            left=self.load_name(name); right=self.expr(n.value)
            opmap={ast.Add:'ADD',ast.Sub:'SUB',ast.BitAnd:'AND',ast.BitOr:'OR',ast.BitXor:'XOR',ast.LShift:'SHL',ast.RShift:'SHR',ast.Mult:'MUL',ast.Div:'DIV',ast.FloorDiv:'DIV',ast.Mod:'MOD'}
            opname=opmap.get(type(n.op))
            if not opname:self.err(n,'unsupported augmented operator')
            self.emit(opname,dst=left,src=right)
            if name in self.state:self.emit('STATE_ST',src=left,imm=self.state[name],note=f'{name} {opname.lower()}=')
            else:
                d=self.varreg(name)
                if d!=left:self.emit('MOV',dst=d,src=left)
            self.release(right); self.release(left); return
        if isinstance(n,ast.If):
            c=self.expr(n.test); jz=self.emit('JZ',src=c,imm=0); self.release(c)
            for s in n.body:self.compile_stmt(s)
            if n.orelse:
                jmp=self.emit('JMP',imm=0); self.code[jz].imm=len(self.code)-jz
                for s in n.orelse:self.compile_stmt(s)
                self.code[jmp].imm=len(self.code)-jmp
            else:self.code[jz].imm=len(self.code)-jz
            return
        if isinstance(n,ast.For):
            if not isinstance(n.target,ast.Name) or not isinstance(n.iter,ast.Call) or not isinstance(n.iter.func,ast.Name) or n.iter.func.id!='range': self.err(n,'for only supports range()')
            vals=[]
            for a in n.iter.args:
                if not isinstance(a,ast.Constant) or not isinstance(a.value,int): self.err(n,'range arguments must be integer literals')
                vals.append(a.value)
            if len(vals)==1: start,stop,step=0,vals[0],1
            elif len(vals)==2:start,stop=vals;step=1
            elif len(vals)==3:start,stop,step=vals
            else:self.err(n,'range expects 1..3 args')
            if step==0:self.err(n,'range step must not be 0')
            seq=list(range(start,stop,step))
            if len(seq)>32:self.err(n,'loop unroll limit is 32 iterations')
            vr=self.varreg(n.target.id)
            for v in seq:
                self.emit('MOVI',dst=vr,imm=v)
                for s in n.body:self.compile_stmt(s)
            return
        if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call):
            call=n.value
            if isinstance(call.func,ast.Name) and call.func.id in ('accept','pass_packet'):
                self.emit('ACCEPT');return
            if isinstance(call.func,ast.Name) and call.func.id=='drop': self.emit('DROP');return
            if isinstance(call.func,ast.Name) and call.func.id=='log':
                self.emit_log(call); return
            if isinstance(call.func,ast.Name) and call.func.id=='write_field':
                if len(call.args)!=3 or not isinstance(call.args[0],ast.Constant) or not isinstance(call.args[0].value,str):
                    self.err(n,'write_field("name", base_byte_offset, value)')
                self.emit_field_write(n,call.args[0].value,call.args[1],call.args[2]); return
            if isinstance(call.func,ast.Attribute) and isinstance(call.func.value,ast.Name) and call.func.value.id=='payload':
                meth=call.func.attr
                if meth in ('set_u8','set_u16le','set_u16be','set_bits'):
                    if meth=='set_bits':
                        if len(call.args)!=3:self.err(n,'set_bits(offset,width,value)')
                        off=self.expr(call.args[0]); width=self.const_int(call.args[1]); val=self.expr(call.args[2])
                        if width<1 or width>16:self.err(n,'bit width must be 1..16')
                        self.emit('STOREBITS',dst=off,src=val,imm=width); self.release(off); self.release(val);return
                    if len(call.args)!=2:self.err(n,f'{meth}(offset,value)')
                    off=self.expr(call.args[0]); val=self.expr(call.args[1]); op={'set_u8':'STORE8','set_u16le':'STORE16LE','set_u16be':'STORE16BE'}[meth]
                    self.emit(op,dst=off,src=val); self.release(off);self.release(val);return
            r=self.expr(call); self.release(r);return
        if isinstance(n,ast.Return):
            self.err(n,'return is only allowed in single-expression helper functions')
        if isinstance(n,ast.Pass): return
        self.err(n,f'unsupported statement {type(n).__name__}')

    def emit_log(self, call):
        # log("label", value) -> records a TRACE marker; value is evaluated for
        # side effects/debug and the label is kept in metadata for `packetpy stats`.
        if not (1 <= len(call.args) <= 2) or not isinstance(call.args[0],ast.Constant) or not isinstance(call.args[0].value,str):
            self.err(call,'log("label"[, value])')
        label=call.args[0].value
        if len(call.args)==2:
            r=self.expr(call.args[1])
            self.emit('TRACE',src=r,imm=len(self.log_labels),note=f'log {label!r}')
            self.release(r)
        else:
            self.emit('TRACE',imm=len(self.log_labels),note=f'log {label!r}')
        self.log_labels.append(label)

    def const_int(self,n):
        if isinstance(n,ast.Constant) and isinstance(n.value,int): return int(n.value)
        if isinstance(n,ast.UnaryOp) and isinstance(n.op,ast.USub) and isinstance(n.operand,ast.Constant) and isinstance(n.operand.value,int): return -int(n.operand.value)
        if isinstance(n,ast.Name) and n.id in self.packet_constants: return self.packet_constants[n.id]
        self.err(n,'expected integer literal')

    def load_name(self,name):
        if name in CONST:
            r=self.alloc();self.emit('MOVI',dst=r,imm=CONST[name]);return r
        if name in self.packet_constants:
            r=self.alloc();self.emit('MOVI',dst=r,imm=self.packet_constants[name]);return r
        if name in META:
            r=self.alloc();self.emit('META',dst=r,imm=META[name]);return r
        if name in self.state:
            r=self.alloc();self.emit('STATE_LD',dst=r,imm=self.state[name]);return r
        if name in self.vars:
            r=self.alloc();self.emit('MOV',dst=r,src=self.vars[name]);return r
        raise CompileError(f"unknown name {name}")

    def packet_field(self, node, name):
        f = self.packet_fields.get(name)
        if not isinstance(f, dict):
            self.err(node, f'unknown packet field {name!r}')
        kind=f.get('kind')
        if kind not in ('bits','u8','u16le','u16be'):
            self.err(node, f'field {name!r} has unsupported kind {kind!r}')
        try:
            off=int(f.get('offset',0))
        except Exception:
            self.err(node, f'field {name!r} has invalid offset')
        if off<0: self.err(node, f'field {name!r} has negative offset')
        width=int(f.get('width',1)) if kind=='bits' else None
        if kind=='bits' and not (1 <= width <= 16):
            self.err(node, f'field {name!r}: bit width must be 1..16')
        return kind,off,width

    def emit_field_read(self, node, name, base_node):
        kind, off, width = self.packet_field(node,name)
        base=self.expr(base_node); add=self.alloc(); self.emit('MOVI',dst=add,imm=off)
        if kind=='bits':
            sh=self.alloc(); self.emit('MOVI',dst=sh,imm=3); self.emit('SHL',dst=base,src=sh); self.release(sh)
            self.emit('ADD',dst=base,src=add); self.release(add)
            out=self.alloc(); self.emit('LOADBITS',dst=out,src=base,imm=width,note=f'read {name}'); self.release(base); return out
        self.emit('ADD',dst=base,src=add); self.release(add)
        out=self.alloc(); op={'u8':'LOAD8','u16le':'LOAD16LE','u16be':'LOAD16BE'}[kind]
        self.emit(op,dst=out,src=base,note=f'read {name}'); self.release(base); return out

    def emit_field_write(self, node, name, base_node, value_node):
        kind, off, width = self.packet_field(node,name)
        base=self.expr(base_node); add=self.alloc(); self.emit('MOVI',dst=add,imm=off)
        if kind=='bits':
            sh=self.alloc(); self.emit('MOVI',dst=sh,imm=3); self.emit('SHL',dst=base,src=sh); self.release(sh)
            self.emit('ADD',dst=base,src=add); self.release(add)
            val=self.expr(value_node); self.emit('STOREBITS',dst=base,src=val,imm=width,note=f'write {name}'); self.release(base); self.release(val); return
        self.emit('ADD',dst=base,src=add); self.release(add)
        val=self.expr(value_node); op={'u8':'STORE8','u16le':'STORE16LE','u16be':'STORE16BE'}[kind]
        self.emit(op,dst=base,src=val,note=f'write {name}'); self.release(base); self.release(val)

    def expr(self,n):
        if isinstance(n,ast.Constant) and isinstance(n.value,(int,bool)):
            r=self.alloc();self.emit('MOVI',dst=r,imm=int(n.value));return r
        if isinstance(n,ast.Name): return self.load_name(n.id)
        if isinstance(n,ast.Attribute) and isinstance(n.value,ast.Name):
            key=f'{n.value.id}.{n.attr}'
            amap={'udp.src_port':'udp_src','udp.dst_port':'udp_dst','ip.src':'ip_src','ip.dst':'ip_dst','ip.ttl':'ip_ttl'}
            if key in amap:return self.load_name(amap[key])
            self.err(n,f'unknown attribute {key}')
        if isinstance(n,ast.IfExp):
            # value_if_true if cond else value_if_false
            c=self.expr(n.test); out=self.alloc()
            jz=self.emit('JZ',src=c,imm=0); self.release(c)
            t=self.expr(n.body); self.emit('MOV',dst=out,src=t); self.release(t)
            jmp=self.emit('JMP',imm=0); self.code[jz].imm=len(self.code)-jz
            f=self.expr(n.orelse); self.emit('MOV',dst=out,src=f); self.release(f)
            self.code[jmp].imm=len(self.code)-jmp
            return out
        if isinstance(n,ast.UnaryOp):
            if isinstance(n.op,ast.USub):
                a=self.expr(n.operand); z=self.alloc();self.emit('MOVI',dst=z,imm=0);self.emit('SUB',dst=z,src=a);self.release(a);return z
            if isinstance(n.op,ast.Invert):
                a=self.expr(n.operand); m=self.alloc();self.emit('MOVI',dst=m,imm=-1);self.emit('XOR',dst=a,src=m);self.release(m);return a
            if isinstance(n.op,ast.Not):
                a=self.expr(n.operand); z=self.alloc();self.emit('MOVI',dst=z,imm=0);self.emit('CMPEQ',dst=a,src=z);self.release(z);return a
        if isinstance(n,ast.BinOp):
            l=self.expr(n.left);r=self.expr(n.right)
            opmap={ast.Add:'ADD',ast.Sub:'SUB',ast.BitAnd:'AND',ast.BitOr:'OR',ast.BitXor:'XOR',ast.LShift:'SHL',ast.RShift:'SHR',ast.Mult:'MUL',ast.Div:'DIV',ast.FloorDiv:'DIV',ast.Mod:'MOD'}
            op=opmap.get(type(n.op))
            if not op:self.err(n,'unsupported binary operator')
            self.emit(op,dst=l,src=r);self.release(r);return l
        if isinstance(n,ast.Compare) and len(n.ops)==1 and len(n.comparators)==1:
            l=self.expr(n.left);r=self.expr(n.comparators[0]); mp={ast.Eq:'CMPEQ',ast.NotEq:'CMPNE',ast.Lt:'CMPLT',ast.LtE:'CMPLE',ast.Gt:'CMPGT',ast.GtE:'CMPGE'};op=mp.get(type(n.ops[0]))
            if not op:self.err(n,'unsupported comparison')
            self.emit(op,dst=l,src=r);self.release(r);return l
        if isinstance(n,ast.BoolOp):
            vals=n.values
            if not vals:self.err(n,'empty bool expression')
            r=self.expr(vals[0])
            op='AND' if isinstance(n.op,ast.And) else 'OR'
            for v in vals[1:]:
                t=self.expr(v);self.emit(op,dst=r,src=t);self.release(t)
            return r
        if isinstance(n,ast.Call):
            if isinstance(n.func,ast.Name) and n.func.id=='read_field':
                if len(n.args)!=2 or not isinstance(n.args[0],ast.Constant) or not isinstance(n.args[0].value,str):
                    self.err(n,'read_field("name", base_byte_offset)')
                return self.emit_field_read(n,n.args[0].value,n.args[1])
            if isinstance(n.func,ast.Name) and n.func.id in ('rand','random') and not n.args:
                r=self.alloc();self.emit('RAND',dst=r);return r
            if isinstance(n.func,ast.Name) and n.func.id in ('now','ktime') and not n.args:
                r=self.alloc();self.emit('TIME',dst=r);return r
            if isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name) and n.func.value.id=='payload':
                meth=n.func.attr
                if meth in ('u8','u16le','u16be'):
                    if len(n.args)!=1:self.err(n,f'{meth}(offset)')
                    off=self.expr(n.args[0]); out=self.alloc(); op={'u8':'LOAD8','u16le':'LOAD16LE','u16be':'LOAD16BE'}[meth]
                    self.emit(op,dst=out,src=off);self.release(off);return out
                if meth=='bits':
                    if len(n.args)!=2:self.err(n,'bits(offset,width)')
                    off=self.expr(n.args[0]); width=self.const_int(n.args[1]); out=self.alloc()
                    if width<1 or width>16:self.err(n,'bit width must be 1..16')
                    self.emit('LOADBITS',dst=out,src=off,imm=width);self.release(off);return out
            if isinstance(n.func,ast.Name) and n.func.id in ('min','max') and len(n.args)==2:
                a=self.expr(n.args[0]);b=self.expr(n.args[1]); cmpop='CMPLE' if n.func.id=='min' else 'CMPGE'; c=self.alloc();self.emit('MOV',dst=c,src=a);self.emit(cmpop,dst=c,src=b)
                out=self.alloc(); jz=self.emit('JZ',src=c,imm=0);self.emit('MOV',dst=out,src=a);jmp=self.emit('JMP',imm=0);self.code[jz].imm=len(self.code)-jz;self.emit('MOV',dst=out,src=b);self.code[jmp].imm=len(self.code)-jmp
                self.release(a);self.release(b);self.release(c);return out
            if isinstance(n.func,ast.Name) and n.func.id=='clamp' and len(n.args)==3:
                # clamp(x, lo, hi) == min(max(x, lo), hi)
                x=self.expr(n.args[0]); lo=self.expr(n.args[1]); hi=self.expr(n.args[2])
                c=self.alloc();self.emit('MOV',dst=c,src=x);self.emit('CMPGE',dst=c,src=lo)
                t=self.alloc();jz=self.emit('JZ',src=c,imm=0);self.emit('MOV',dst=t,src=x);jmp=self.emit('JMP',imm=0);self.code[jz].imm=len(self.code)-jz;self.emit('MOV',dst=t,src=lo);self.code[jmp].imm=len(self.code)-jmp
                c2=self.alloc();self.emit('MOV',dst=c2,src=t);self.emit('CMPLE',dst=c2,src=hi)
                out=self.alloc();jz2=self.emit('JZ',src=c2,imm=0);self.emit('MOV',dst=out,src=t);jmp2=self.emit('JMP',imm=0);self.code[jz2].imm=len(self.code)-jz2;self.emit('MOV',dst=out,src=hi);self.code[jmp2].imm=len(self.code)-jmp2
                for rr in (x,lo,hi,c,t,c2):self.release(rr)
                return out
            if isinstance(n.func,ast.Name) and n.func.id=='abs' and len(n.args)==1:
                a=self.expr(n.args[0]); zero=self.alloc();self.emit('MOVI',dst=zero,imm=0); c=self.alloc();self.emit('MOV',dst=c,src=a);self.emit('CMPLT',dst=c,src=zero); jz=self.emit('JZ',src=c,imm=0); tmp=self.alloc();self.emit('MOVI',dst=tmp,imm=0);self.emit('SUB',dst=tmp,src=a);self.emit('MOV',dst=a,src=tmp);self.release(tmp);self.code[jz].imm=len(self.code)-jz;self.release(zero);self.release(c);return a
            if isinstance(n.func,ast.Name) and n.func.id in self.helpers:
                fn=self.helpers[n.func.id]
                if len(fn.body)!=1 or not isinstance(fn.body[0],ast.Return) or fn.body[0].value is None:self.err(n,'helper functions must contain exactly one return expression')
                if len(fn.args.args)!=len(n.args):self.err(n,'helper argument count mismatch')
                old=dict(self.vars); argregs=[]
                for p,a in zip(fn.args.args,n.args):
                    rr=self.expr(a); self.vars[p.arg]=rr; argregs.append(rr)
                out=self.expr(fn.body[0].value)
                self.vars=old
                for rr in argregs:self.release(rr)
                return out
        self.err(n,f'unsupported expression {type(n).__name__}')


def default_config_for(script_path):
    sp=Path(script_path).resolve()
    candidates=[sp.parent.parent/'config'/'fields.json', Path('/opt/packetpy/config/fields.json')]
    for c in candidates:
        if c.exists(): return c
    return None

def load_packet_config(path):
    if not path: return {"constants":{},"fields":{}}
    p=Path(path)
    try: data=json.loads(p.read_text())
    except FileNotFoundError: raise CompileError(f'packet config not found: {p}')
    except json.JSONDecodeError as e: raise CompileError(f'bad packet config {p}: {e}')
    if not isinstance(data,dict): raise CompileError('packet config root must be an object')
    data.setdefault('constants',{}); data.setdefault('fields',{})
    return data

def compile_file(path, config_path=None):
    if config_path is None: config_path=default_config_for(path)
    cfg=load_packet_config(config_path)
    c=Compiler(cfg).compile(Path(path).read_text())
    blob=b''.join(i.pack() for i in c.code)
    meta={'version':3,'port':c.port,'instructions':len(c.code),'max_instructions':MAX_INSNS,
          'states':c.state,'state_init':c.state_init,'log_labels':c.log_labels,
          'packet_config':str(config_path) if config_path else None}
    return c,blob,meta

def run(cmd,check=True,capture=False):
    return subprocess.run(cmd,check=check,text=True,capture_output=capture)

def hexbytes(b): return [f'{x:02x}' for x in b]

def map_update(pin,key_bytes,val_bytes):
    run(['bpftool','map','update','pinned',pin,'key','hex',*hexbytes(key_bytes),'value','hex',*hexbytes(val_bytes)])

def map_lookup_u64(pin,key):
    r=run(['bpftool','-j','map','lookup','pinned',pin,'key','hex',*hexbytes(struct.pack('<I',key))],capture=True)
    j=json.loads(r.stdout); vals=j.get('value') or j.get('formatted',{}).get('value')
    if isinstance(vals,list):
        bs=bytes(int(x,16) if isinstance(x,str) else int(x) for x in vals)
        return struct.unpack_from('<Q',bs.ljust(8,b'\x00'))[0]
    return int(vals)

def disasm(c, meta):
    out=[f"# UDP/{meta['port']}  {len(c.code)}/{MAX_INSNS} instructions"]
    if meta['states']: out.append('# state: '+', '.join(f'{k}={c.state_init[v]}' for k,v in meta['states'].items()))
    if meta['log_labels']: out.append('# logs: '+', '.join(f'[{i}] {l!r}' for i,l in enumerate(meta['log_labels'])))
    for pc,i in enumerate(c.code): out.append(i.text(pc,c.notes))
    return '\n'.join(out)

def cmd_build(a):
    c,blob,meta=compile_file(a.script,a.config); out=Path(a.out or (str(Path(a.script).with_suffix('.ppyb')))); out.write_bytes(blob); Path(str(out)+'.json').write_text(json.dumps(meta,indent=2))
    print(f'compiled {len(c.code)} instructions -> {out}')
    print(disasm(c,meta))

def cmd_load(a):
    c,blob,meta=compile_file(a.script,a.config)
    prog=a.prog_map; state=a.state_map; config=a.config_map; stats=a.stats_map
    zero=bytes(16)
    for idx in range(MAX_INSNS):
        val=blob[idx*16:(idx+1)*16] if idx < len(c.code) else zero
        map_update(prog,struct.pack('<I',idx),val)
    for name,idx in c.state.items(): map_update(state,struct.pack('<I',idx),struct.pack('<Q',c.state_init[idx]))
    def ifindex(name):
        p=Path(f'/sys/class/net/{name}/ifindex')
        if not p.exists(): raise CompileError(f'interface {name!r} not found')
        return int(p.read_text())
    pcidx=ifindex(a.pc_if); boxidx=ifindex(a.box_if)
    vals=[c.port,pcidx,boxidx,len(c.code),1 if a.debug else 0]
    for idx,v in enumerate(vals): map_update(config,struct.pack('<I',idx),struct.pack('<Q',v))
    if a.reset_stats and stats and Path(stats).exists():
        map_update(stats,struct.pack('<I',0),bytes(16*8))
    print(f'loaded {len(c.code)} instructions, UDP/{c.port}, {a.pc_if}={pcidx}, {a.box_if}={boxidx}, debug={"on" if a.debug else "off"}')

def cmd_check(a):
    c,_,meta=compile_file(a.script,a.config); print(json.dumps(meta,indent=2)); print(disasm(c,meta))

def cmd_disasm(a):
    c,_,meta=compile_file(a.script,a.config); print(disasm(c,meta))

def cmd_stats(a):
    stats=a.stats_map
    if not Path(stats).exists(): print(f'stats map not found: {stats} (is packetpy loaded?)',file=sys.stderr); sys.exit(1)
    r=run(['bpftool','-j','map','lookup','pinned',stats,'key','hex','00','00','00','00'],capture=True)
    j=json.loads(r.stdout); raw=j.get('value') or j.get('formatted',{}).get('value') or []
    bs=bytes(int(x,16) if isinstance(x,str) else int(x) for x in raw)
    counts=list(struct.unpack_from('<16Q',bs.ljust(128,b'\x00')))
    if a.json:
        print(json.dumps({n:counts[i] for i,n in enumerate(STAT_NAMES)},indent=2))
    else:
        print('PacketPy runtime stats')
        for i,n in enumerate(STAT_NAMES): print(f'  {n:10} {counts[i]}')

def cmd_debug(a):
    config=a.config_map
    if not Path(config).exists(): print(f'config map not found: {config}',file=sys.stderr); sys.exit(1)
    val=1 if a.state=='on' else 0
    map_update(config,struct.pack('<I',4),struct.pack('<Q',val))
    print(f'debug {a.state}. Trace output: sudo cat /sys/kernel/debug/tracing/trace_pipe')

def main():
    p=argparse.ArgumentParser(prog='packetpy'); sp=p.add_subparsers(dest='cmd',required=True)
    PROG='/sys/fs/bpf/packetpy/maps/ppy_program'; STATE='/sys/fs/bpf/packetpy/maps/ppy_state'
    CONFIG='/sys/fs/bpf/packetpy/maps/ppy_config'; STATS='/sys/fs/bpf/packetpy/maps/ppy_stats'
    q=sp.add_parser('check',help='compile and show bytecode');q.add_argument('script');q.add_argument('--config');q.set_defaults(fn=cmd_check)
    q=sp.add_parser('disasm',help='compile and print disassembly only');q.add_argument('script');q.add_argument('--config');q.set_defaults(fn=cmd_disasm)
    q=sp.add_parser('build',help='compile to .ppyb');q.add_argument('script');q.add_argument('-o','--out');q.add_argument('--config');q.set_defaults(fn=cmd_build)
    q=sp.add_parser('load',help='compile and load into the kernel maps');q.add_argument('script');q.add_argument('--config');q.add_argument('--pc-if',default='eth0');q.add_argument('--box-if',default='eth1')
    q.add_argument('--debug',action='store_true',help='enable kernel trace_pipe output');q.add_argument('--reset-stats',action='store_true',help='zero the stats counters on load')
    q.add_argument('--prog-map',default=PROG);q.add_argument('--state-map',default=STATE);q.add_argument('--config-map',default=CONFIG);q.add_argument('--stats-map',default=STATS);q.set_defaults(fn=cmd_load)
    q=sp.add_parser('stats',help='print runtime packet counters');q.add_argument('--stats-map',default=STATS);q.add_argument('--json',action='store_true');q.set_defaults(fn=cmd_stats)
    q=sp.add_parser('debug',help='toggle kernel trace output at runtime');q.add_argument('state',choices=['on','off']);q.add_argument('--config-map',default=CONFIG);q.set_defaults(fn=cmd_debug)
    a=p.parse_args()
    try:a.fn(a)
    except CompileError as e: print('compile error:',e,file=sys.stderr);sys.exit(2)
    except subprocess.CalledProcessError as e: print('command failed:',e,file=sys.stderr);sys.exit(e.returncode or 1)
if __name__=='__main__':main()
