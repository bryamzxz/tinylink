#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Bryam (bryamzxz)
"""Prove that compiled code touches an IRAM object with 32-bit accesses only.

Round 1.3.4 (D6): mapreq.c's jsmn token table lives in IRAM, which on the
ESP32 only takes 32-bit loads and stores — an l8ui / l16ui / l16si / s8i /
s16i there is a LoadStoreError. This reads one object file (objdump -d -r)
and follows, by abstract interpretation, every register and stack slot that
may hold an address inside the given section:

  * sources: an l32r whose literal is relocated against the section;
  * propagation: moves and arithmetic (any register operand tainted taints
    the result), stack slots (s32i/l32i on a1), calls into functions of the
    same object (arguments a10..a15 -> a2..a7, return a2 -> a10), to a
    fixed point over every function's control flow, zero-overhead loops
    included;
  * failures: a narrow load / store whose base may point into the section;
    a tainted value passed to a function outside the object (memcpy,
    strncmp, esp_log, ...) or through an unresolved function pointer;
    a tainted value stored anywhere but the own stack frame; an address of
    the section in initialised data; an opcode the checker does not model. Spills to the own frame are followed and
    listed (a callee could only reach one out of bounds).

Conservative: any register operand that may hold such an address taints
an arithmetic result, arguments are the a10.. registers written since the
previous call, a fixed-arity C function reads only its own; a finding
can be a false alarm, a pass cannot miss an access the code makes.
tools/iram_check_neg.c holds planted violations it must flag (tools/README.md).
An object in which nothing reaches the section fails too (wrong file, or
an objdump whose output this no longer parses), so a pass is never vacuous.

Exit 0 with a per-function report when nothing can reach the section with a
narrow access. Usage:

  python tools/iram_access_check.py --objdump <xtensa-esp32-elf-objdump> \\
      --section .iram.bss [--verbose] \\
      build/esp-idf/tinylink/CMakeFiles/__idf_tinylink.dir/src/mapreq.c.obj

components/tinylink/CMakeLists.txt runs it after every build of the
component.
"""
import argparse
import re
import subprocess
import sys

NARROW = {'l8ui', 'l16ui', 'l16si', 's8i', 's16i'}
LOADS32 = {'l32i', 'l32i.n', 'l32ai'}
STORES32 = {'s32i', 's32i.n', 's32ri'}
BRANCH = {'beq', 'bne', 'bge', 'blt', 'bgeu', 'bltu', 'bany', 'bnone', 'ball', 'bnall',
          'bbc', 'bbs', 'beqz', 'bnez', 'bgez', 'bltz', 'beqz.n', 'bnez.n', 'beqi', 'bnei',
          'bgei', 'blti', 'bgeui', 'bltui', 'bbci', 'bbsi'}
# Register-to-register / immediate ALU ops: result = f(register operands).
ALU = {'mov', 'mov.n', 'add', 'add.n', 'addi', 'addi.n', 'addmi', 'addx2', 'addx4', 'addx8',
       'sub', 'subx2', 'subx4', 'subx8', 'and', 'or', 'xor', 'neg', 'abs', 'slli', 'srli',
       'srai', 'sll', 'srl', 'sra', 'src', 'extui', 'min', 'max', 'minu', 'maxu', 'nsa',
       'nsau', 'sext', 'clamps', 'mull', 'muluh', 'mulsh', 'quou', 'quos', 'remu', 'rems'}
# Conditional moves keep the old value or take the source: result = old | src.
CMOV = {'moveqz', 'movnez', 'movltz', 'movgez'}
CONST = {'movi', 'movi.n'}
# No register result that can carry an address.
NOREG = {'nop', 'nop.n', 'isync', 'memw', 'ssl', 'ssr', 'ssai', 'ssa8l', 'ssa8b',
         'wsr.lbeg', 'wsr.lend', 'wsr.lcount', 'wsr.sar', 'entry'}
SPECIAL_READ = {'rsr.lbeg', 'rsr.lend', 'rsr.lcount', 'rsr.sar'}
# Fixed-arity libc / IDF functions: how many argument registers they read.
ARITY = {'atoi': 1, 'strtoull': 3, 'strtoul': 3, 'strtol': 3, 'memcpy': 3, 'memmove': 3,
         'memset': 3, 'memcmp': 3, 'strncmp': 3, 'strcmp': 2, 'strlen': 1, 'strnlen': 2,
         'esp_get_free_heap_size': 0, 'heap_caps_get_largest_free_block': 1}


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout


def parse_relocs(od, obj):
    """(section, offset) -> relocation value text, for every section."""
    rel, cur = {}, None
    for line in run([od, '-r', obj]).splitlines():
        m = re.match(r'RELOCATION RECORDS FOR \[(.+)\]:', line)
        if m:
            cur = m.group(1)
            continue
        m = re.match(r'([0-9a-f]+) (\S+)\s+(\S+)$', line.strip())
        if m and cur:
            rel.setdefault((cur, int(m.group(1), 16)), []).append((m.group(2), m.group(3)))
    return rel


class Insn:
    __slots__ = ('addr', 'op', 'args', 'size', 'rel')

    def __init__(self, addr, op, args, size):
        self.addr, self.op, self.args, self.size, self.rel = addr, op, args, size, []


def parse_text(od, obj):
    """function name -> {addr: Insn}; each function is its own .text.<fn>."""
    funcs, cur, last = {}, None, None
    for line in run([od, '-d', '-r', obj]).splitlines():
        m = re.match(r'^[0-9a-f]+ <(.+)>:$', line)
        if m:
            name = m.group(1)
            cur = None if name.startswith('.literal') else funcs.setdefault(name, {})
            last = None
            continue
        if cur is None:
            continue
        m = re.match(r'^\s+([0-9a-f]+):\s+R_XTENSA_(\S+)\s+(\S+)', line)
        if m and last is not None:
            last.rel.append((m.group(2), m.group(3)))
            continue
        m = re.match(r'^\s+([0-9a-f]+):\t([0-9a-f ]+?)\s*\t(\S+)\s*(.*)$', line)
        if not m:
            continue
        op = m.group(3)
        if op.startswith('.'):
            last = None
            continue
        args = re.sub(r'\s*<[^>]*>', '', m.group(4)).strip()
        args = [a.strip() for a in args.split(',')] if args else []
        last = Insn(int(m.group(1), 16), op, args, len(m.group(2).replace(' ', '')) // 2)
        cur[last.addr] = last
    return funcs


def reg(x):
    return int(x[1:]) if re.fullmatch(r'a\d+', x or '') else None


def imm(x):
    return int(x, 0)


class Checker:
    def __init__(self, funcs, rel, section):
        self.funcs, self.rel, self.section = funcs, rel, section
        self.entry = {f: frozenset() for f in funcs}    # tainted params (a2..a7)
        self.exits = {f: frozenset() for f in funcs}    # tainted a2..a7 at return
        self.errors, self.touch, self.narrow_seen = [], {}, {}
        self.spills = {}       # f -> {frame offset: insn} (tainted s32i to a1)
        self.notes = []
        self.addr_taken = {}   # f -> frame offsets whose address is formed (None: unknown)

    def literal(self, insn):
        """Relocation value of the literal an l32r loads, or None."""
        for kind, val in insn.rel:
            if kind != 'SLOT0_OP':
                continue
            m = re.match(r'(\.literal[^+]*)(?:\+0x([0-9a-f]+))?$', val)
            if m:
                hit = self.rel.get((m.group(1), int(m.group(2) or '0', 16)), [])
                return hit[0][1] if hit else None
        return None

    def points_into(self, val):
        return val is not None and (val == self.section or val.startswith(self.section + '+')
                                    or val.startswith(self.section + '-'))

    def callee(self, insn, lit_of):
        """Call target name for call8 / callx8 (via the l32r that loaded it)."""
        if insn.op == 'call8':
            for kind, val in insn.rel:
                if kind == 'SLOT0_OP':
                    return re.sub(r'\+0x[0-9a-f]+$', '', val)
            return None
        r = reg(insn.args[0])
        v = lit_of.get(r)
        return v if isinstance(v, str) else None

    def succ(self, f, insn, loops):
        code = self.funcs[f]
        nxt = insn.addr + insn.size
        target = None
        for kind, val in insn.rel:
            m = re.match(r'\.text\.' + re.escape(f) + r'(?:\+0x([0-9a-f]+))?$', val)
            if kind == 'SLOT0_OP' and m:
                target = int(m.group(1) or '0', 16)
        if target is None and (insn.op in BRANCH or insn.op in ('j', 'loop', 'loopnez', 'loopgtz')):
            target = int(insn.args[-1], 16)   # resolved by objdump, no relocation
        if insn.op in ('ret', 'ret.n', 'retw', 'retw.n', 'ill', 'break', 'break.n'):
            out = []
        elif insn.op == 'j':
            out = [target]
        elif insn.op == 'jx':
            raise SystemExit(f'{f}: indirect jump at {insn.addr:#x} — not modelled')
        elif insn.op in BRANCH:
            out = [nxt, target]
        elif insn.op in ('loop', 'loopnez', 'loopgtz'):
            out = [nxt] + ([target] if insn.op != 'loop' else [])
        else:
            out = [nxt]
        for lbeg, lend in loops:
            if nxt == lend and insn.op not in ('j',) and insn.addr >= lbeg:
                out.append(lbeg)
        return [a for a in out if a is not None and a in code]

    def analyse(self, f):
        code = self.funcs[f]
        if not code:
            return
        loops = []
        text_off = lambda v: (int(re.match(r'\.text\.' + re.escape(f) + r'(?:\+0x([0-9a-f]+))?$',
                                           v).group(1) or '0', 16)
                              if v and re.match(r'\.text\.' + re.escape(f) + r'(?:\+0x[0-9a-f]+)?$', v)
                              else None)
        seq = [code[k] for k in sorted(code)]
        for n, i in enumerate(seq):
            if i.op not in ('loop', 'loopnez', 'loopgtz'):
                continue
            end = next((text_off(v) for k, v in i.rel if k == 'SLOT0_OP' and text_off(v) is not None),
                       None)
            # The assembler's long-loop expansion: `loop` to a placeholder
            # end, LBEG := that end (rsr.lend / wsr.lbeg), LEND := an
            # address from a literal (l32r / wsr.lend). The body is
            # [placeholder, real end).
            nxt = seq[n + 1:n + 6]
            if len(nxt) >= 2 and nxt[0].op == 'rsr.lend' and nxt[1].op == 'wsr.lbeg':
                lend = None
                for j in nxt[2:]:
                    if j.op == 'l32r':
                        lend = text_off(self.literal(j))
                    if j.op == 'wsr.lend':
                        break
                if lend is None:
                    raise SystemExit(f'{f}: long loop at {i.addr:#x} without a literal end')
                loops.append((end, lend))
            loops.append((i.addr + i.size, end))
        start = min(code)
        init = (frozenset(r for r in range(2, 8) if r in self.entry[f]), frozenset(), {},
                frozenset(range(2, 8)))
        state = {start: init}
        work = [start]
        exit_taint = set()
        while work:
            a = work.pop()
            regs, slots, lits, wr = state[a]
            regs, slots, lits, wr = set(regs), set(slots), dict(lits), set(wr)
            i = code[a]
            self.step(f, i, regs, slots, lits, wr, exit_taint)
            for s in self.succ(f, i, loops):
                new = (frozenset(regs), frozenset(slots), lits, frozenset(wr))
                old = state.get(s)
                if old is None:
                    state[s] = new
                    work.append(s)
                else:
                    mr, ms, mw = old[0] | new[0], old[1] | new[1], old[3] | new[3]
                    ml = {k: v for k, v in old[2].items() if new[2].get(k) == v}
                    if mr != old[0] or ms != old[1] or ml != old[2] or mw != old[3]:
                        state[s] = (mr, ms, ml, mw)
                        work.append(s)
        ex = frozenset(exit_taint)
        if ex != self.exits[f]:
            self.exits[f] = self.exits[f] | ex
            return True
        return False

    def err(self, f, i, msg):
        e = f'{f}+{i.addr:#x}: {i.op} {",".join(i.args)} — {msg}'
        if e not in self.errors:
            self.errors.append(e)

    def step(self, f, i, regs, slots, lits, wr, exit_taint):
        op, a = i.op, i.args
        t = lambda x: reg(x) in regs
        # every op below that writes a register writes its first operand
        if a and reg(a[0]) is not None and op not in STORES32 and op not in ('s8i', 's16i') \
                and op not in BRANCH and op not in ('loop', 'loopnez', 'loopgtz', 'callx8', 'jx'):
            wr.add(reg(a[0]))
        if op in NARROW or op in LOADS32 or op in STORES32 or op == 's32c1i':
            dst, base, off = reg(a[0]), reg(a[1]), imm(a[2])
            if base in regs:
                self.touch.setdefault(f, set()).add(op)
                if op in NARROW:
                    self.err(f, i, f'{op} through a pointer into {self.section}')
            if op in NARROW:
                self.narrow_seen[f] = self.narrow_seen.get(f, 0) + 1
            if op in STORES32 or op in ('s8i', 's16i', 's32c1i'):
                if dst in regs:
                    if base == 1:
                        slots.add(off)
                        self.spills.setdefault(f, {})[off] = i
                    else:
                        self.err(f, i, 'pointer into the section stored outside the frame')
                elif base == 1:
                    slots.discard(off)
                if op == 's32c1i':
                    regs.discard(dst)
                return
            # load
            lits.pop(dst, None)
            if base == 1 and off in slots and op in LOADS32:
                regs.add(dst)
            else:
                regs.discard(dst)
            return
        if op == 'l32r':
            d = reg(a[0])
            val = self.literal(i)
            lits.pop(d, None)
            if self.points_into(val):
                regs.add(d)
            else:
                regs.discard(d)
                # a function: `name` (global) or `.text.name` (static, by
                # its section symbol)
                m = re.fullmatch(r'(?:\.text\.)?([^.+][^+]*)', val or '')
                if m:
                    lits[d] = m.group(1)
            return
        if op in CONST or op in SPECIAL_READ:
            regs.discard(reg(a[0]))
            lits.pop(reg(a[0]), None)
            if op in CONST:
                lits[reg(a[0])] = imm(a[1])
            return
        if op in ALU:
            d = reg(a[0])
            src = [x for x in a[1:] if reg(x) is not None]
            if 1 in (reg(x) for x in src) and d != 1:
                # an address inside the own frame is formed
                other = [reg(x) for x in src if reg(x) != 1]
                if op in ('mov', 'mov.n') or (op == 'or' and not other):
                    off = 0
                elif op in ('addi', 'addi.n', 'addmi'):
                    off = imm(a[2])
                elif op in ('add', 'add.n') and len(other) == 1 and isinstance(lits.get(other[0]), int):
                    off = lits[other[0]]
                else:
                    off = None
                self.addr_taken.setdefault(f, set()).add(off)
            lits.pop(d, None)
            if any(t(x) for x in src):
                regs.add(d)
            else:
                regs.discard(d)
            return
        if op in CMOV:
            if t(a[1]):
                regs.add(reg(a[0]))
            lits.pop(reg(a[0]), None)
            return
        if op in BRANCH or op in ('j', 'loop', 'loopnez', 'loopgtz') or op in NOREG:
            return
        if op in ('call8', 'callx8'):
            target = self.callee(i, lits)
            # Arguments are a10.. as written since the previous call (a call
            # clobbers a10..a15, so nothing older can be one); a known
            # fixed-arity C function reads only its first ones.
            n = ARITY.get(target, 6)
            args = frozenset(r - 8 for r in range(10, 10 + n) if r in regs and r in wr)
            if args:
                if target in self.funcs:
                    if not args <= self.entry[target]:
                        self.entry[target] = self.entry[target] | args
                        self.dirty.add(target)
                else:
                    self.err(f, i, f'pointer into the section passed to '
                                   f'{target or "an unresolved function pointer"} '
                                   f'(a{",a".join(str(r + 8) for r in sorted(args))})')
            ret = self.exits.get(target, frozenset()) if target in self.funcs else frozenset()
            for r in range(10, 16):      # clobbered; a10 = the callee's a2
                regs.discard(r)
                lits.pop(r, None)
            wr.difference_update(range(10, 16))
            wr.add(10)
            if 2 in ret:
                regs.add(10)
            if target in self.funcs:
                self.callers.setdefault(target, set()).add(f)
            return
        if op in ('ret', 'ret.n', 'retw', 'retw.n'):
            if 2 in regs:
                exit_taint.add(2)      # the return value
            return
        self.err(f, i, 'opcode not modelled')

    def run(self):
        self.callers = {}
        self.dirty = set(self.funcs)
        while self.dirty:
            f = self.dirty.pop()
            if self.analyse(f):
                self.dirty |= self.callers.get(f, set())
        # A pointer spilled to the own frame is followed through its reload
        # above. A callee handed the address of a local cannot reach a
        # spill slot (it is not part of any object) without an
        # out-of-bounds access — a different bug, which the host ASan suite
        # covers for this code — so spills are listed, not failed.
        for f, slots in sorted(self.spills.items()):
            taken = self.addr_taken.get(f)
            bases = ', '.join('?' if o is None else f'{o:#x}' for o in
                              sorted(taken or (), key=lambda o: -1 if o is None else o)) or '-'
            self.notes.append(f'{f}: spilled to frame slot(s) '
                              f'{", ".join(f"{o:#x}" for o in sorted(slots))} '
                              f'(address-taken locals at: {bases})')
        return self.errors


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--objdump', required=True)
    ap.add_argument('--section', required=True, help='e.g. .iram.bss')
    ap.add_argument('--verbose', action='store_true', help='per-function report')
    ap.add_argument('obj')
    args = ap.parse_args()
    rel = parse_relocs(args.objdump, args.obj)
    funcs = parse_text(args.objdump, args.obj)
    ck = Checker(funcs, rel, args.section)
    errors = ck.run()
    # The only way in is a code literal: an address of the section kept in
    # data (a static pointer, a table) would be loaded back untracked.
    for (sec, off), rs in sorted(rel.items()):
        if sec.startswith(('.literal', '.debug', '.xt.')):
            continue
        for kind, val in rs:
            if kind == 'R_XTENSA_32' and ck.points_into(val):
                errors.append(f'{sec}+{off:#x}: the address of {args.section} is stored in data '
                              f'— not tracked, keep it out of initialised data')
    name = args.obj.rsplit('/', 1)[-1]
    if not ck.touch and not errors:
        errors = [f'nothing in {len(funcs)} functions reaches {args.section}: wrong object, '
                  f'or objdump output this checker no longer parses']
    if args.verbose or errors:
        print(f'{args.obj}: {len(funcs)} functions')
        for f in sorted(ck.touch):
            params = ','.join(f'a{r}' for r in sorted(ck.entry[f])) or '-'
            print(f'  touches {args.section}: {f:44s} via {" ".join(sorted(ck.touch[f]))}'
                  f'  (tainted params: {params}; other narrow accesses: {ck.narrow_seen.get(f, 0)})')
        for r in ck.notes:
            print(f'  note: {r}')
        for f in sorted(f for f in funcs if ck.entry[f] and f not in ck.touch):
            print(f'  receives a pointer but never dereferences it: {f}')
    if errors:
        print(f'iram_access_check: {name}: FAIL, {len(errors)} finding(s)')
        for e in errors:
            print('  ' + e)
        return 1
    print(f'iram_access_check: {name}: OK — {len(ck.touch)} functions reach {args.section}, '
          f'all through 32-bit loads / stores')
    return 0


if __name__ == '__main__':
    sys.exit(main())
