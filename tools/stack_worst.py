#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Bryam (bryamzxz)
"""Static worst-case stack depth per FreeRTOS task (ESP32, Xtensa LX6).

Build the firmware once with per-function stack usage and call graphs
(scratch build dir; the flags do not change code generation):

    EXTRA_CFLAGS="-fstack-usage -fcallgraph-info=su,da" \
    EXTRA_CXXFLAGS="-fstack-usage -fcallgraph-info=su,da" \
        idf.py -B <dir> -DSDKCONFIG=<dir>/sdkconfig reconfigure build

then run

    tools/stack_worst.py --build <dir> --toolchain <xtensa-esp-elf/bin> \
        --rom-elf <esp-rom-elfs>/esp32_rev0_rom.elf --cache-dir <dir> [--summary]

Graph sources:
  * GCC `.ci` files (one per C/C++ TU): frames = the `entry a1, N`
    immediates, direct calls, indirect call sites with source locations.
    Every object is cross-checked against its relocations: `.ci` misses
    libcalls (memset, 64-bit shifts/divides), ipa-split `.part` calls and
    IPA-ICF thunks (tls_io_write_full -> tls_io_read_full); those edges
    are added, and indirect sites without a location get one from DWARF.
  * precompiled archive members from the linker map (Wi-Fi / PHY blobs,
    libc_nano, libgcc, libstdc++, asm): `objdump -dr` with relocations
    (R_XTENSA_SLOT0_OP on call<n>, R_XTENSA_ASM_EXPAND on the -mlongcalls
    l32r feeding a callx<n>). A small register tracker decodes blob
    `callx` targets loaded as `*ptr + field` (2 900 of them go through the
    Wi-Fi OS adapter table g_wifi_osi_funcs) and resolves them through the
    data-section relocations of the statically initialised table.
  * the ESP32 ROM ELF (esp-rom-elfs; it carries .xt.prop, so its linear
    disassembly is reliable) for ROM code, matched by address through the
    final ELF's absolute ROM symbols.

Stack model (Xtensa windowed ABI, call8): a function's frame is its
`entry a1, N` immediate, which already holds the 16-B base save area and
the extra save area the window-overflow handlers spill into (min 32 B per
frame); `-fstack-usage` reports exactly N. On top of the chain each task
stack holds: the alignment of pxTopOfStack (<= 16 B), the coprocessor save
area (XT_CP_SIZE = 144 B on the ESP32; the TLS area is 0 B in this
image), one interrupt frame at the deepest point (XT_STK_FRMSZ = 192 B,
which includes the interruptee's base save area; nested interrupts and
ISR bodies run on the ISR stack) and the 16-B canary that
CONFIG_FREERTOS_CHECK_STACKOVERFLOW_CANARY checks (TASK_OVERHEAD = 368 B).
With CONFIG_FREERTOS_TASK_FUNCTION_WRAPPER, vPortTaskWrapper's frame is
added too.

Indirect calls: project RULES (by caller, call-site source text, blob
site, task), context-sensitive FORWARDERS (a function that calls a
pointer it was given is cloned per caller; the pointer resolves to what
the caller loads), registrars (`reg:`: callbacks stored for a dispatcher
-- esp_timer, sys_timeout, tcpip_callback -- are the functions loaded by
the callers of the registration function). What stays unresolved is
listed with the stack depth at the site (headroom = alloc - 368 - depth).
CUT (edges) and PRUNE (subtrees) remove runtime-infeasible combinations,
each with its reason; --no-cut gives the bound without them. Recursion is
reported per task (back edges, costed once).
"""

import argparse
import collections
import os
import pickle
import re
import subprocess
import sys

# ---------------------------------------------------------------------------
# Stack model constants (see module docstring)
TOP_ALIGN = 16          # pxTopOfStack aligned down to 16 B (worst case)
CPSA = 144              # XT_CP_SIZE (12 + XT_CP_SA_SIZE 128 + 4)
ISR_FRAME = 192         # XT_STK_FRMSZ, _xt_lowint1: addmi -256 / addi +64
CANARY = 16             # 4 words of 0xa5 at pxStack
TASK_OVERHEAD = TOP_ALIGN + CPSA + ISR_FRAME + CANARY

ROM_LO, ROM_HI = 0x40000000, 0x40070000

NODE_RE = re.compile(
    r'^node: \{ title: "((?:[^"\\]|\\.)*)" label: "((?:[^"\\]|\\.)*)"(.*)\}\s*$')
EDGE_RE = re.compile(
    r'^edge: \{ sourcename: "((?:[^"\\]|\\.)*)" targetname: "((?:[^"\\]|\\.)*)"'
    r'(?: label: "((?:[^"\\]|\\.)*)")? \}\s*$')
SU_RE = re.compile(r'^(\d+) bytes \(([^)]*)\)$')


class Node:
    __slots__ = ('key', 'name', 'frame', 'qual', 'origin', 'loc', 'calls',
                 'indirect', 'taken')

    def __init__(self, key, name, frame, qual, origin, loc=''):
        self.key = key
        self.name = name
        self.frame = frame
        self.qual = qual
        self.origin = origin
        self.loc = loc
        self.calls = []       # (target ref, site)
        self.indirect = []    # site strings
        self.taken = set()    # functions whose address this one loads


def bare(key):
    """Function name of a node key ('path/x.c:fn$constprop$0' -> 'fn')."""
    key = key.split('@@', 1)[0]
    name = key.rsplit(':', 1)[-1]
    return re.split(r'[$.]', name)[0] if not name.startswith('.') else name


# ---------------------------------------------------------------------------
# GCC -fcallgraph-info
CI_LOCALS = {}      # .ci path -> {object symbol name: node title}
SAME_ADDR = {}      # (object, section, offset) -> function names (aliases)
RELOCS = {}         # (object, section, offset) -> R_XTENSA_32 target ("sym+0xN")
DATA_SYMS = {}      # data symbol -> (object, section, offset)
DATA_SIZE = {}      # data symbol -> size
TABLE_FUNCS = {}    # table symbol -> [(function name, object)] (cfg TABLE_GROUPS)
FUNC_AT = {}        # (object, section, offset) -> (function name, global?)
ALIAS_KEYS = {}     # alias name -> node key (filled by crosscheck_ci)
CI_FILES = []


def load_ci(build_dir):
    nodes = {}
    dup = collections.Counter()
    for root, _dirs, files in os.walk(build_dir):
        if os.sep + 'bootloader' + os.sep in root + os.sep:
            continue          # separate project, never on a task stack
        for fn in files:
            if not fn.endswith('.ci'):
                continue
            path = os.path.join(root, fn)
            local = {}
            edges = []
            with open(path, encoding='utf-8', errors='replace') as f:
                for line in f:
                    m = NODE_RE.match(line)
                    if m:
                        title, label = m.group(1), m.group(2)
                        parts = label.split('\\n')
                        if len(parts) >= 3:
                            s = SU_RE.match(parts[2])
                            if s:
                                local[title] = Node(title, parts[0],
                                                    int(s.group(1)), s.group(2),
                                                    'ci', parts[1])
                        continue
                    m = EDGE_RE.match(line)
                    if m:
                        edges.append(m.groups())
            for src, dst, site in edges:
                site = site or path[:-3] + ' (no loc)'
                n = local.get(src)
                if n is None:
                    continue
                if dst == '__indirect_call':
                    n.indirect.append(site)
                else:
                    n.calls.append((dst, site))
            m_ = {}
            for t in local:
                suffix = t.rsplit(':', 1)[-1]
                m_[suffix] = t
                m_.setdefault(suffix.replace('$', '.'), t)
            CI_LOCALS[path] = m_
            CI_FILES.append(path)
            for title, n in local.items():
                old = nodes.get(title)
                if old is None:
                    nodes[title] = n
                    continue
                # Same title in two TUs (header static inline, or a
                # source built twice): keep the larger frame, union calls.
                dup[title] += 1
                old.frame = max(old.frame, n.frame)
                old.calls.extend(n.calls)
                old.indirect.extend(n.indirect)
    return nodes, dup


# ---------------------------------------------------------------------------
# Linker map: archive members that are not covered by a .ci
def linked_members(map_path, build_dir):
    members = collections.defaultdict(set)
    with open(map_path, encoding='utf-8', errors='replace') as f:
        for line in f:
            if line.startswith('Discarded input sections'):
                break
            m = re.match(r'^(\S+\.a)\(([^)]+)\)', line)
            if m:
                ar = m.group(1)
                if not os.path.isabs(ar):
                    ar = os.path.normpath(os.path.join(build_dir, ar))
                members[ar].add(m.group(2))
    out = {}
    for ar, mems in members.items():
        need = set()
        for mem in mems:
            if ar.startswith(os.path.abspath(build_dir)) and \
                    re.search(r'\.(c|cpp|cc)\.obj$', mem):
                continue          # compiled from source here: has a .ci
            need.add(mem)
        if need:
            out[ar] = need
    return out


SYM_RE = re.compile(r'^([0-9a-f]{8}) (.{7}) (\S+)\s+([0-9a-f]{8}) (.*)$')
HDR_RE = re.compile(r'^(\S+):\s+file format ')
FUNC_RE = re.compile(r'^([0-9a-f]{8}) <(.+)>:$')
REL_RE = re.compile(r'^\s+([0-9a-f]+): (R_XTENSA_\w+)\s+(\S+)')
INSN_RE = re.compile(r'^\s+([0-9a-f]+):\t(\S+)\s*(.*)$')
CALL_MN = {'call0', 'call4', 'call8', 'call12'}
CALLX_MN = {'callx0', 'callx4', 'callx8', 'callx12'}


def run(cmd):
    return subprocess.run(cmd, check=True, capture_output=True, text=True,
                          errors='replace').stdout


class ObjFunc:
    __slots__ = ('name', 'glob', 'frame', 'calls', 'indirect', 'sect', 'taken')

    def __init__(self, name, glob, sect=None):
        self.name = name
        self.glob = glob
        self.sect = sect
        self.frame = None
        self.calls = []      # (target name, local?, offset)
        self.indirect = []   # offsets
        self.taken = set()   # (function name, local?) loaded by l32r, not called


def parse_objects(objdump, paths, wanted=None, scope=''):
    """objdump -t / -r / -dr over object files or archives.

    Returns {member: [ObjFunc]}; member is the object path (plain object
    files) or the member name (archives). Calls come from relocations, so
    -mlongcalls l32r/callx pairs (R_XTENSA_ASM_EXPAND on the l32r) and
    intra-section call<n> without relocation are both direct calls; a
    callx whose register was not loaded by such an l32r is indirect. For
    indirect calls a small register tracker records how the target was
    loaded (`*ptr+off` = field `off` of the struct a global pointer points
    to, `[sym+off]` = word at a global), resolved later through the
    data-section relocations (TABLES in the project config)."""
    syms = collections.defaultdict(dict)   # member -> name -> (sect, off, glob, func)
    bysect = collections.defaultdict(lambda: collections.defaultdict(dict))
    member = None
    for line in run([objdump, '-t'] + list(paths)).splitlines():
        m = HDR_RE.match(line)
        if m:
            member = m.group(1)
            continue
        if wanted is not None and member not in wanted:
            continue
        m = SYM_RE.match(line)
        if not m:
            continue
        val, flags, sect, _size, name = m.groups()
        if sect == '*UND*':
            continue
        func = flags[6] == 'F'
        glob = flags[0] in 'gu' or flags[1] == 'w'
        syms[member][name] = (sect, int(val, 16), glob, func)
        mk = scope + member
        if func:
            bysect[member][sect].setdefault(int(val, 16), name)
            grp = SAME_ADDR.setdefault((mk, sect, int(val, 16)), [])
            grp.append(name)
            FUNC_AT.setdefault((mk, sect, int(val, 16)), (name, glob))
        elif flags[6] == 'O':
            if glob or name not in DATA_SYMS:
                DATA_SYMS[name] = (mk, sect, int(val, 16))
                DATA_SIZE[name] = int(_size, 16)
    member = sect_r = None
    for line in run([objdump, '-r'] + list(paths)).splitlines():
        m = HDR_RE.match(line)
        if m:
            member = m.group(1)
            continue
        if line.startswith('RELOCATION RECORDS FOR ['):
            sect_r = line[len('RELOCATION RECORDS FOR ['):].rstrip(':').rstrip(']')
            continue
        if wanted is not None and member not in wanted:
            continue
        p_ = line.split()
        if len(p_) == 3 and p_[1] == 'R_XTENSA_32':
            RELOCS[(scope + member, sect_r, int(p_[0], 16))] = p_[2]

    def target(mem, ref):
        m = re.match(r'^(.+?)(?:\+0x([0-9a-f]+))?$', ref)
        sym, off = m.group(1), int(m.group(2) or '0', 16)
        if sym.startswith('.'):
            name = bysect[mem].get(sym, {}).get(off)
            if not name:
                return None
            return name, not syms[mem][name][2]
        s = syms[mem].get(sym)
        if s is None:
            return sym, False                 # undefined here: global ref
        if not s[3]:
            return None                       # data symbol
        return sym, not s[2]

    result = collections.defaultdict(list)
    state = {'member': None, 'sect': None, 'insns': [], 'pend': {}}
    NOWRITE = ('s32i', 's32i.n', 's16i', 's8i', 's32e', 'ssi', 'ssip', 'wsr', 'wur',
               'memw', 'nop', 'nop.n', 'isync', 'dsync', 'esync', 'extw', 'j', 'jx',
               'ret', 'ret.n', 'retw', 'retw.n', 'entry', 'loop', 'loopnez', 'loopgtz')

    def lit_value(mk, rels):
        for rt, r in rels:
            if rt == 'R_XTENSA_SLOT0_OP':
                mm = re.match(r'^(.+?)(?:\+0x([0-9a-f]+))?$', r)
                return RELOCS.get((mk, mm.group(1), int(mm.group(2) or '0', 16)))
        return None

    def flush():
        mem, sect = state['member'], state['sect']
        if sect is None or (wanted is not None and mem not in wanted):
            return
        funcs = sorted(bysect[mem].get(sect, {}).items())
        if not funcs:
            return
        mk = scope + mem
        fi = 0
        fn = None
        expand = {}
        regs = {}
        snap = {}          # branch target offset -> merged register state
        prev_mn = ''
        for off, mn, ops in state['insns']:
            while fi < len(funcs) and funcs[fi][0] <= off:
                name = funcs[fi][1]
                fn = ObjFunc(name, syms[mem][name][2], sect)
                result[mem].append(fn)
                expand = {}
                regs = {}
                snap = {}
                prev_mn = ''
                fi += 1
            if off in snap:
                if prev_mn in ('j', 'j.l', 'ret', 'ret.n', 'retw', 'retw.n', 'jx'):
                    regs = dict(snap[off])
                else:
                    # fall-through meets a branch: keep what either path knew
                    # (optimistic merge; a resolution heuristic, logged)
                    regs = {**snap[off], **regs}
            prev_mn = mn
            if (mn.startswith('b') or mn == 'j') and ops:
                mtg = re.search(r'([0-9a-f]+) <', ops)
                if mtg:
                    t_ = int(mtg.group(1), 16)
                    if t_ > off:
                        prev = snap.get(t_)
                        snap[t_] = dict(regs) if prev is None else {**regs, **prev}
            if fn is None:
                continue
            if fn.frame is None:
                if mn == 'entry':
                    fn.frame = int(ops.split(',')[1].strip(), 0)
                elif mn in ('addi', 'addmi') and ops.replace(' ', '').startswith('a1,a1,-'):
                    fn.frame = -int(ops.split(',')[2].strip(), 0)
            rels = state['pend'].get(off, ())
            opl = [o.strip() for o in ops.split(',')] if ops else []
            dst = opl[0].split()[0] if opl else ''
            if mn == 'l32r':
                expand.pop(dst, None)
                for rt, ref in rels:
                    if rt == 'R_XTENSA_ASM_EXPAND':
                        expand[dst] = ref
                v = lit_value(mk, rels)
                if v:
                    mm = re.match(r'^(.+?)(?:\+0x([0-9a-f]+))?$', v)
                    regs[dst] = ('addr', mm.group(1), int(mm.group(2) or '0', 16))
                    if dst not in expand:
                        t_ = target(mem, v)
                        if t_:
                            fn.taken.add(t_)
                else:
                    regs.pop(dst, None)
                continue
            if mn in ('l32i', 'l32i.n') and len(opl) == 3:
                b = regs.get(opl[1])
                imm = int(opl[2], 0)
                if b and b[0] == 'addr':
                    regs[dst] = ('mem', b[1], b[2] + imm)
                elif b and b[0] == 'mem':
                    regs[dst] = ('field', b[1], b[2], imm)
                else:
                    regs[dst] = ('fieldunk', imm)
                expand.pop(dst, None)
                continue
            if (mn in ('mov', 'mov.n') and len(opl) == 2) or \
                    (mn == 'or' and len(opl) == 3 and opl[1] == opl[2]):
                if opl[1] in regs:
                    regs[dst] = regs[opl[1]]
                else:
                    regs.pop(dst, None)
                if opl[1] in expand:
                    expand[dst] = expand[opl[1]]
                continue
            if mn in CALL_MN or mn in CALLX_MN:
                ref = None
                if mn in CALL_MN:
                    for rt, r in rels:
                        if rt in ('R_XTENSA_SLOT0_OP', 'R_XTENSA_ASM_EXPAND'):
                            ref = r
                    if ref is None and not rels:
                        mm = re.search(r'<(.+?)(?:\+0x([0-9a-f]+))?>', ops)
                        if mm and '+' not in mm.group(0):
                            ref = mm.group(1)
                else:
                    ref = expand.get(ops.strip())
                t = target(mem, ref) if ref else None
                if t:
                    fn.calls.append((t[0], t[1], off))
                else:
                    d = regs.get(ops.strip()) if mn in CALLX_MN else None
                    fn.indirect.append((off, d))
                # the callee's window covers a8..a15 of a call8 caller
                for r_ in range(8, 16):
                    regs.pop('a%d' % r_, None)
                    expand.pop('a%d' % r_, None)
                continue
            if mn == 'j':
                for rt, r in rels:
                    if rt == 'R_XTENSA_SLOT0_OP':
                        t = target(mem, r)
                        if t and t[0] != fn.name:
                            fn.calls.append((t[0], t[1], off))
            if mn not in NOWRITE and not mn.startswith('b') and dst:
                regs.pop(dst, None)
                expand.pop(dst, None)

    for line in run([objdump, '-dr', '--no-show-raw-insn'] + list(paths)).splitlines():
        m = HDR_RE.match(line)
        if m:
            flush()
            state.update(member=m.group(1), sect=None, insns=[], pend={})
            continue
        if line.startswith('Disassembly of section '):
            flush()
            state.update(sect=line[len('Disassembly of section '):].rstrip(':'),
                         insns=[], pend={})
            continue
        if wanted is not None and state['member'] not in wanted:
            continue
        m = REL_RE.match(line)
        if m:
            state['pend'].setdefault(int(m.group(1), 16), []).append((m.group(2), m.group(3)))
            continue
        m = INSN_RE.match(line)
        if m:
            state['insns'].append((int(m.group(1), 16), m.group(2), m.group(3)))
    flush()
    for funcs in result.values():
        for f in funcs:
            if f.frame is None:
                f.frame = 0
    return result


def desc_str(d):
    if not d:
        return ''
    if d[0] == 'field':
        return ' [*%s+%d:%d]' % (d[1], d[2], d[3])
    if d[0] == 'mem':
        return ' [%s+%d]' % (d[1], d[2])
    if d[0] == 'fieldunk':
        return ' [?+%d]' % d[1]
    return ''


def table_target(sym, off):
    """Function stored at sym+off in a statically initialised table."""
    loc = DATA_SYMS.get(sym)
    if loc is None:
        return None
    mk, sect, base = loc
    v = RELOCS.get((mk, sect, base + off))
    if v is None:
        return None
    mm = re.match(r'^(.+?)(?:\+0x([0-9a-f]+))?$', v)
    name, add = mm.group(1), int(mm.group(2) or '0', 16)
    if name.startswith('.'):
        f = FUNC_AT.get((mk, name, add))
        return (f[0], mk) if f else None
    return (name, mk)


def resolve_tables(nodes, tables, log):
    """Turn blob indirect sites whose target was decoded as a field of a
    static table (directly, or through a pointer listed in `tables`) into
    call edges."""
    n_ok = n_left = 0
    for n in list(nodes.values()):
        if n.origin != 'obj' or not n.indirect:
            continue
        keep = []
        for site in n.indirect:
            m = re.search(r' \[\*(\w+)\+(\d+):(\d+)\]$', site)
            tgt = None
            if m and m.group(1) in tables and m.group(2) == '0':
                tgt = table_target(tables[m.group(1)], int(m.group(3)))
            m2 = re.search(r' \[(\w+)\+(\d+)\]$', site)
            if m2:
                tgt = table_target(m2.group(1), int(m2.group(2)))
            m3 = re.search(r' \[\?\+(\d+)\]$', site)
            if m3 and tables.get('?') and re.match(tables.get('?scope', '.'), site):
                tgt = table_target(tables['?'], int(m3.group(1)))
                if tgt:
                    log.append('table: assumed %s+%s at %s -> %s'
                               % (tables['?'], m3.group(1), site, tgt[0]))
            if tgt is None:
                keep.append(site)
                n_left += 1
                continue
            name, mk = tgt
            k = name if name in nodes else None
            if k is None and mk.endswith('.obj'):
                k = CI_LOCALS.get(mk[:-4] + '.ci', {}).get(name)
            if k is None:
                k = ALIAS_KEYS.get(name, name)
            n.calls.append((k, site + ' -> ' + name))
            n_ok += 1
        n.indirect = keep
    log.append('table: resolved %d blob indirect calls, %d left' % (n_ok, n_left))


def load_archive(objdump, ar, wanted, nodes):
    """Nodes for the wanted members of a precompiled archive (no .ci)."""
    base = os.path.basename(ar)
    for mem, funcs in parse_objects(objdump, [ar], wanted, scope=ar + ':').items():
        def key(name, local):
            return '%s(%s):%s' % (base, mem, name) if local else name
        for f in funcs:
            k = key(f.name, not f.glob)
            if k in nodes and nodes[k].origin == 'ci':
                continue
            n = Node(k, f.name, f.frame, 'static', 'obj', '%s(%s)' % (base, mem))
            n.calls = [(key(t, loc), '%s+0x%x' % (f.name, off)) for t, loc, off in f.calls]
            n.indirect = ['%s(%s) %s+0x%x%s' % (base, mem, f.name, off, desc_str(d))
                          for off, d in f.indirect]
            n.taken = {key(t, loc) for t, loc in f.taken}
            nodes[k] = n


def addr2line_sites(addr2line, obj, sect, offs):
    """Source file:line of call sites in a relocatable object (DWARF)."""
    try:
        out = run([addr2line, '-e', obj, '-j', sect, '-a'] + ['0x%x' % o for o in offs])
    except subprocess.CalledProcessError:
        return []
    res = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith('0x') or line.startswith('??'):
            continue
        res.append(re.sub(r' \(discriminator \d+\)$', '', line))
    return res


def crosscheck_ci(objdump, ci_files, nodes, log, addr2line=None):
    """Add direct calls the .ci files miss (GCC records no edge for the
    calls inside IPA-ICF thunks, e.g. tls_io_write_full -> tls_io_read_full)
    and check the .ci frames against the `entry` immediates."""
    added = mism = 0
    objs = []
    for ci in ci_files:
        obj = ci[:-3] + '.obj'
        if os.path.exists(obj):
            objs.append((obj, ci))
    for i in range(0, len(objs), 80):
        chunk = objs[i:i + 80]
        SAME_ADDR.clear()
        res = parse_objects(objdump, [o for o, _ in chunk])
        cimap = dict(chunk)
        for (obj, _sect, _off), names in SAME_ADDR.items():
            if len(names) < 2:
                continue
            titles = CI_LOCALS.get(cimap.get(obj), {})
            keys = [nm for nm in names if nm in nodes] + \
                [titles[nm] for nm in names if titles.get(nm) in nodes]
            if not keys:
                continue
            k = keys[0]
            prefix = k.rsplit(':', 1)[0] + ':' if ':' in k else ''
            for nm in names:
                for a in (nm, prefix + nm):
                    if a not in nodes:
                        ALIAS_KEYS[a] = k
        for obj, ci in chunk:
            titles = CI_LOCALS.get(ci, {})
            for f in res.get(obj, []):
                k = f.name if f.glob else titles.get(f.name)
                n = nodes.get(k) if k else None
                if n is None:
                    continue
                if n.frame != f.frame and f.frame:
                    mism += 1
                    log.append('frame mismatch %s: ci %d obj %d' % (k, n.frame, f.frame))
                    n.frame = max(n.frame, f.frame)
                if any('(no loc)' in x for x in n.indirect) and not f.indirect:
                    # GCC's placeholder with no callx behind it in the object
                    n.indirect = [x for x in n.indirect if '(no loc)' not in x]
                    log.append('no-loc indirect in %s: none in object, dropped' % k)
                if addr2line and f.indirect and any('(no loc)' in x for x in n.indirect):
                    sites = addr2line_sites(addr2line, obj, f.sect, [o for o, _ in f.indirect])
                    n.indirect = [x for x in n.indirect if '(no loc)' not in x]
                    # each callx can expand to several inlined frames: the
                    # innermost (first) line is the call expression
                    for site in sites:
                        if site.rsplit(':', 1)[-1].isdigit():
                            site = site + ':0'
                        if site not in n.indirect:
                            n.indirect.append(site)
                    log.append('no-loc indirect in %s -> %s' % (k, sites))
                for t, loc in f.taken:
                    n.taken.add(titles.get(t, t) if loc else t)
                have = {bare(t) if not isinstance(t, int) else t for t, _ in n.calls}
                for t, loc, off in f.calls:
                    tk = titles.get(t) if loc else t
                    if tk is None:
                        tk = t
                    if bare(tk) in have or tk in have:
                        continue
                    n.calls.append((tk, 'obj %s+0x%x (not in .ci)' % (f.name, off)))
                    have.add(bare(tk))
                    added += 1
                    log.append('added %s -> %s' % (k, tk))
    return added, mism


# ---------------------------------------------------------------------------
# ROM
def load_rom(objdump, nm, rom_elf):
    funcs = {}
    for line in run([nm, '-S', rom_elf]).splitlines():
        p = line.split()
        if len(p) == 4 and p[2] in 'TtWw':
            a = int(p[0], 16)
            funcs.setdefault(a, (p[3], int(p[1], 16)))
    starts = sorted(funcs)
    # literal values for the l32r -> callx tracking
    try:
        from elftools.elf.elffile import ELFFile
        f = open(rom_elf, 'rb')
        elf = ELFFile(f)
        segs = [(s['sh_addr'], s['sh_size'], s.data()) for s in elf.iter_sections()
                if s['sh_type'] == 'SHT_PROGBITS' and s['sh_addr']]
    except Exception:          # pragma: no cover
        segs = []

    def word(addr):
        for a, sz, data in segs:
            if a <= addr < a + sz - 3:
                o = addr - a
                return int.from_bytes(data[o:o + 4], 'little')
        return None

    nodes = {}
    cur = None
    lastdef = {}
    out = run([objdump, '-d', '--no-show-raw-insn', rom_elf])
    import bisect
    for line in out.splitlines():
        m = FUNC_RE.match(line)
        if m:
            a = int(m.group(1), 16)
            if a in funcs:
                name = funcs[a][0]
                cur = Node('rom:' + name, name, None, 'static', 'rom', '0x%08x' % a)
                nodes[a] = cur
                lastdef = {}
            continue
        m = INSN_RE.match(line)
        if not m or cur is None:
            continue
        mn, ops = m.group(2), m.group(3)
        if cur.frame is None:
            if mn == 'entry':
                cur.frame = int(ops.split(',')[1].strip(), 0)
            elif mn in ('addi', 'addmi') and ops.replace(' ', '').startswith('a1,a1,-'):
                cur.frame = -int(ops.split(',')[2].strip(), 0)
        if mn == 'l32r':
            r, lit = ops.split(',')[0].strip(), ops.split(',')[1].split()[0]
            lastdef[r] = word(int(lit, 16))
            continue
        if mn in CALL_MN:
            t = int(ops.split()[0], 16)
            cur.calls.append((t, mn))
        elif mn in CALLX_MN:
            r = ops.strip()
            v = lastdef.get(r)
            if v is not None and v in funcs:
                cur.calls.append((v, mn + '(l32r)'))
            else:
                cur.indirect.append('ROM %s callx %s' % (cur.name, r))
        dst = ops.split(',')[0].strip() if ops else ''
        if dst in lastdef and mn not in ('s32i', 's32i.n', 's8i', 's16i', 'bnez', 'beqz'):
            lastdef.pop(dst, None)
    for n in nodes.values():
        if n.frame is None:
            n.frame = 0
        # resolve call addresses to function starts
        res = []
        for t, site in n.calls:
            i = bisect.bisect_right(starts, t) - 1
            if i >= 0:
                res.append(('rom:' + funcs[starts[i]][0], site))
        n.calls = res
    return {n.key: n for n in nodes.values()}


def elf_rom_names(nm, elf):
    names = {}
    for line in run([nm, elf]).splitlines():
        p = line.split()
        if len(p) == 3:
            a = int(p[0], 16)
            if ROM_LO <= a < ROM_HI:
                names[p[2]] = a
    return names


# ---------------------------------------------------------------------------
class Graph:
    def __init__(self, nodes, rom, rom_names, rom_by_addr, wraps, cfg):
        self.nodes = nodes
        self.rom = rom
        self.rom_names = rom_names
        self.rom_by_addr = rom_by_addr
        self.wraps = wraps
        self.cfg = cfg
        self.byname = collections.defaultdict(list)
        for k in nodes:
            self.byname[bare(k)].append(k)
        for k in rom:
            self.byname.setdefault(bare(k), []).append(k)
        self.srccache = {}
        self._exp = {}
        self.task = None
        self.cut = set()
        self.prefix_next = {}

    def expand(self, spec):
        """Target spec -> node keys: name | file.c:name | re:<regex> |
        file:<path substring> | @group."""
        if spec in self._exp:
            return self._exp[spec]
        out = []
        if spec.startswith('@'):
            for x in self.cfg['GROUPS'][spec[1:]]:
                out.extend(self.expand(x))
        elif spec.startswith('table:'):
            for name, mk in TABLE_FUNCS.get(spec[6:], ()):
                k = name if name in self.nodes else None
                if k is None and mk.endswith('.obj'):
                    k = CI_LOCALS.get(mk[:-4] + '.ci', {}).get(name)
                if k is None:
                    k = self.resolve(name)
                if k:
                    out.append(k)
        elif spec.startswith('reg:'):
            # functions whose address is loaded by a caller of a registrar
            # (esp_timer_create, sys_timeout, tcpip_callback, ...): the
            # callbacks a dispatcher can run
            regs = set()
            for r_ in spec[4:].split(','):
                regs.update(self.expand(r_))
            rev = self.reverse()
            for rk in regs:
                for ck in rev.get(rk, ()):
                    n = self.node(ck)
                    for t in (n.taken if n else ()):
                        tk = self.resolve(t) or self.lookup(bare(t))
                        if tk:
                            out.append(tk)
        elif spec.startswith('re:'):
            rx = re.compile(spec[3:])
            out = [k for name, ks in self.byname.items() if rx.fullmatch(name) for k in ks
                   if not k.startswith('?')]
        elif spec.startswith('file:'):
            sub = spec[5:]
            out = [k for k, n in self.nodes.items()
                   if n.origin == 'ci' and sub in n.loc.rsplit(':', 2)[0]]
        elif ':' in spec and not spec.startswith('/'):
            f, name = spec.rsplit(':', 1)
            out = [k for k in self.byname.get(name, [])
                   if (f in k or f in self.nodes[k].loc) and k.rsplit(':', 1)[-1] == name]
        else:
            k = self.lookup(spec) or self.resolve(spec)
            out = [k] if k else []
        self._exp[spec] = sorted(set(out))
        return self._exp[spec]

    def reverse(self):
        if getattr(self, '_rev', None) is None:
            self._rev = collections.defaultdict(set)
            for k, n in self.nodes.items():
                for ref, _site in n.calls:
                    t = self.resolve(ref) if isinstance(ref, str) else None
                    if t:
                        self._rev[t].add(k)
        return self._rev

    def lookup(self, name):
        """Unique node key for a bare function name (entry points, rules)."""
        if name in self.nodes:
            return name
        ks = [k for k in self.byname.get(name, []) if k.rsplit(':', 1)[-1] == name]
        if len(ks) == 1:
            return ks[0]
        if name in self.rom_names:
            return self.rom_key(name)
        return None

    def rom_key(self, name):
        a = self.rom_names[name]
        k = self.rom_by_addr.get(a)
        if k:
            return k
        return None

    def resolve(self, ref):
        if isinstance(ref, str):
            name = ref
            if name in self.wraps:
                name = '__wrap_' + name
            elif name.startswith('__real_') and name[7:] in self.wraps:
                name = name[7:]
            if name in self.nodes:
                return name
            if '.' in name and name.replace('.', '$') in self.nodes:
                return name.replace('.', '$')
            if name in ALIAS_KEYS:
                return ALIAS_KEYS[name]
            if name.startswith('rom:') and name in self.rom:
                return name
            if name in self.rom_names:
                k = self.rom_key(name)
                if k:
                    return k
            return None
        return None

    def node(self, key):
        if '@@' in key:
            key = key.split('@@', 1)[0]
        return self.nodes.get(key) or self.rom.get(key)

    def fwd_taken(self, key):
        """Functions whose address the context (and the forwarder chain) loads."""
        parts = key.split('@@')
        out = set()
        for k in parts[1:]:
            for kk in k.split('|'):
                n = self.node(kk)
                if n is not None:
                    out |= n.taken
        n = self.node(parts[0])
        if n is not None:
            out |= n.taken
        res = []
        for t in out:
            tk = self.resolve(t) or self.lookup(bare(t)) if isinstance(t, str) else None
            if tk:
                res.append(tk)
        return sorted(set(res))

    def src_line(self, site):
        m = re.match(r'^(.*):(\d+):(\d+)$', site)
        if not m:
            return ''
        path, ln = m.group(1), int(m.group(2))
        if path not in self.srccache:
            try:
                with open(path, encoding='utf-8', errors='replace') as f:
                    self.srccache[path] = f.read().splitlines()
            except OSError:
                self.srccache[path] = []
        lines = self.srccache[path]
        # the call expression may continue on following lines
        return ' '.join(l.strip() for l in lines[ln - 1:ln + 1]) if ln <= len(lines) else ''

    def indirect_targets(self, key, site):
        """(targets, rule) for one indirect call site; targets None = unresolved."""
        caller = bare(key)
        key = key.split('@@', 1)[0]
        text = self.src_line(site)
        for rule in self.cfg['RULES']:
            if 'tasks' in rule and self.task not in rule['tasks']:
                continue
            if 'caller' in rule and not re.fullmatch(rule['caller'], caller):
                continue
            if 'site' in rule and not re.search(rule['site'], site):
                continue
            mt = None
            if 'text' in rule:
                mt = re.search(rule['text'], text)
                if not mt:
                    continue
            if mt is not None and mt.groups() and '{' in ''.join(rule['targets']):
                g1 = next((g for g in mt.groups() if g), None)
                if g1 is None:
                    return [], rule.get('why', '')
                gm = rule.get('fmap', {}).get(g1, g1)
                if gm is None:
                    return [], rule.get('why', '') + ' (field %s: NULL)' % g1
                return [t.replace('{1}', g1).replace('{m}', gm) for t in rule['targets']], \
                    rule.get('why', '')
            return rule['targets'], rule.get('why', '')
        return None, text

    def succ(self, key, report):
        out = self._succ(key, report)
        fw = self.cfg.get('FORWARDERS', {})
        if fw:
            base, _, ctx = key.partition('@@')
            res = []
            for t, site in out:
                if bare(t) in fw and not t.startswith('?'):
                    # context: nearest non-forwarder caller + forwarder chain
                    if ctx:
                        t = '%s@@%s|%s' % (t, ctx, base)
                    else:
                        t = '%s@@%s' % (t, base)
                res.append((t, site))
            out = res
        if not self.cut:
            return out
        cb = bare(key)
        keep = []
        for t, site in out:
            if (cb, bare(t)) in self.cut:
                report['pruned'].add((cb, bare(t)))
                continue
            keep.append((t, site))
        return keep

    def _succ(self, key, report):
        if key in self.prefix_next:
            return [(self.prefix_next[key], 'entry')]
        n = self.node(key)
        if n is None:
            return []
        out = []
        for ref, site in n.calls:
            t = self.resolve(ref)
            if t is None:
                est = self.cfg['LEAF'].get(bare(ref) if isinstance(ref, str) else ref)
                if est is None:
                    est = self.cfg['LEAF_DEFAULT']
                    report['unknown'][ref] = (est, key)
                else:
                    report['known_leaf'][ref] = est
                t = '?leaf:' + str(ref)
                self.nodes.setdefault(t, Node(t, str(ref), est, 'estimate', 'leaf'))
            out.append((t, site))
        fwrx = self.cfg.get('FORWARDERS', {}).get(bare(key.split('@@')[0]))
        for site in n.indirect:
            if fwrx is not None and '@@' in key and \
                    (fwrx == '*' or re.search(fwrx, self.src_line(site))):
                tk = [t for t in self.fwd_taken(key) if bare(t) != bare(key)]
                report['resolved'][(key, site)] = (['ctx:' + bare(t) for t in tk],
                                                   'forwarded from context')
                if not tk:
                    report['unresolved'].setdefault((key, site), 'forwarder: nothing '
                                                    'address-taken in context')
                for t in tk:
                    out.append((t, site + ' (ctx) -> ' + bare(t)))
                continue
            targets, why = self.indirect_targets(key, site)
            if targets is None:
                report['unresolved'].setdefault((key, site), why)
                b = self.cfg['UNRESOLVED_BOUND']
                t = '?indirect:%s@%s' % (bare(key), site)
                self.nodes.setdefault(t, Node(t, '<indirect %s>' % site, b, 'bound', 'leaf'))
                out.append((t, site))
                continue
            report['resolved'][(key, site)] = (targets, why)
            excl = {t[1:] for t in targets if t.startswith('!')}
            for tn in targets:
                if tn.startswith('!'):
                    continue
                tks = [k for k in self.expand(tn) if bare(k) not in excl]
                if not tks and not tn.startswith(('re:', 'file:')):
                    report['unknown'][tn] = (self.cfg['LEAF_DEFAULT'], key)
                for tk in tks:
                    out.append((tk, site + ' -> ' + bare(tk)))
        return out

    def analyse(self, entry_keys, prune=()):
        """Longest path from the entry chain. Back edges are cut and listed."""
        report = {'unknown': {}, 'known_leaf': {}, 'unresolved': {}, 'resolved': {},
                  'cycles': [], 'reach': set(), 'pruned': set()}
        prune = set(prune)
        rx_ = [p_[3:] for p_ in prune if p_.startswith('re:')]
        prune_rx = re.compile('|'.join('(?:%s)' % r for r in rx_)) if rx_ else None
        # iterative DFS, collect DAG edges
        root = '<task>'
        adj = {root: [(k, 'entry') for k in entry_keys]}
        color = {root: 1}
        order = []
        stack = [(root, iter(adj[root]))]
        path = [root]
        while stack:
            k, it = stack[-1]
            nxt = next(it, None)
            if nxt is None:
                color[k] = 2
                order.append(k)
                stack.pop()
                path.pop()
                continue
            t, _site = nxt
            if bare(t) in prune or t in prune or (prune_rx and prune_rx.fullmatch(bare(t))):
                continue
            c = color.get(t, 0)
            if c == 1:
                i = path.index(t)
                report['cycles'].append(tuple(path[i:]) + (t,))
                continue
            if c == 2:
                continue
            color[t] = 1
            adj[t] = [e for e in self.succ(t, report)
                      if not (bare(e[0]) in prune or e[0] in prune or
                              (prune_rx and prune_rx.fullmatch(bare(e[0]))))]
            stack.append((t, iter(adj[t])))
            path.append(t)
        report['reach'] = set(order)
        # longest path on the DAG: reverse post-order is topological; an edge
        # to an earlier position is a back edge (recursion, listed above)
        topo = list(reversed(order))
        pos = {k: i for i, k in enumerate(topo)}
        best = {root: 0}
        pred = {}
        for k in topo:
            if k not in best:
                continue
            for t, site in adj.get(k, []):
                if pos.get(t, -1) <= pos[k]:
                    continue
                n = self.node(t)
                v = best[k] + (n.frame if n else 0)
                if v > best.get(t, -1):
                    best[t] = v
                    pred[t] = (k, site)
        report['best'] = best
        report['pred'] = pred
        deepest = max(best, key=lambda x: best[x])
        p = []
        k = deepest
        while k != root:
            pk, site = pred[k]
            p.append((k, site))
            k = pk
        p.reverse()
        report['path'] = p
        report['depth'] = best[deepest]
        return report


# ---------------------------------------------------------------------------
def build_graph(args, cfg):
    cache = os.path.join(args.cache_dir, 'stack_worst.cache') if args.cache_dir else None
    stamp = (os.path.getmtime(args.elf), os.path.getmtime(os.path.abspath(__file__)))
    if cache and os.path.exists(cache):
        with open(cache, 'rb') as f:
            data = pickle.load(f)
        if data.get('stamp') == stamp:
            nodes, rom, rom_names, dup = data['nodes'], data['rom'], data['rom_names'], data['dup']
            ALIAS_KEYS.update(data['aliases'])
            TABLE_FUNCS.update(data.get('tables', {}))
            CI_LOCALS.update(data.get('ci_locals', {}))
            return nodes, rom, rom_names, dup
    nodes, dup = load_ci(args.build)
    log = []
    added, mism = crosscheck_ci(args.objdump, CI_FILES, nodes, log,
                                os.path.join(args.toolchain, 'xtensa-esp32-elf-addr2line'))
    with open(os.path.join(args.cache_dir or '.', 'crosscheck.log'), 'w') as f:
        f.write('added %d calls, %d frame mismatches\n' % (added, mism))
        f.write('\n'.join(log) + '\n')
    for ar, mems in sorted(linked_members(args.map, args.build).items()):
        load_archive(args.objdump, ar, mems, nodes)
    resolve_tables(nodes, cfg.get('TABLES', {}), log)
    for sym in cfg.get('TABLE_GROUPS', ()):
        TABLE_FUNCS[sym] = []
        for off in range(0, DATA_SIZE.get(sym, 0), 4):
            t = table_target(sym, off)
            if t:
                TABLE_FUNCS[sym].append(t)
    with open(os.path.join(args.cache_dir or '.', 'crosscheck.log'), 'a') as f:
        f.write('\n'.join(x for x in log if x.startswith('table')) + '\n')
    rom = load_rom(args.objdump, args.nm, args.rom_elf)
    rom_names = elf_rom_names(args.nm, args.elf)
    if cache:
        with open(cache, 'wb') as f:
            pickle.dump({'stamp': stamp, 'nodes': nodes, 'rom': rom,
                         'rom_names': rom_names, 'dup': dup, 'aliases': ALIAS_KEYS,
                         'tables': TABLE_FUNCS, 'ci_locals': CI_LOCALS}, f)
    return nodes, rom, rom_names, dup


def wraps_from_ninja(build_dir):
    w = set()
    try:
        with open(os.path.join(build_dir, 'build.ninja'), encoding='utf-8',
                  errors='replace') as f:
            for m in re.finditer(r'--wrap=(\w+)', f.read()):
                w.add(m.group(1))
    except OSError:
        pass
    return w


def short(key):
    if '@@' in key:
        base, ctx = key.split('@@', 1)
        return '%s [ctx %s]' % (short(base), ctx.split('|')[0].rsplit(':', 1)[-1].replace('$', '.'))
    s = key
    s = re.sub(r'^.*/(components|managed_components|src|lib)/', '', s)
    s = s.replace('$', '.')
    return s


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--build', required=True, help='instrumented build dir')
    ap.add_argument('--elf')
    ap.add_argument('--map')
    ap.add_argument('--rom-elf', required=True)
    ap.add_argument('--toolchain', required=True, help='dir with xtensa-esp32-elf-*')
    ap.add_argument('--cache-dir')
    ap.add_argument('--task', action='append', help='only these tasks')
    ap.add_argument('--frames', type=int, default=12, help='frames to print per path')
    ap.add_argument('--all-frames', action='store_true')
    ap.add_argument('--indirect', action='store_true', help='list every indirect site')
    ap.add_argument('--top', type=int, default=0,
                    help='also print the N deepest distinct leaves per task')
    ap.add_argument('--why', help='print the deepest path through this function')
    ap.add_argument('--entry', help='override the task entry (keeps the task rules); '
                                    'a>b chains count the prefix frames')
    ap.add_argument('--dump', action='append', help='print one node (name or key)')
    ap.add_argument('--expand', action='append', help='print what a target spec expands to')
    ap.add_argument('--blob-sites', action='store_true',
                    help='histogram of unresolved blob indirect-call descriptors')
    ap.add_argument('--summary', action='store_true',
                    help='one line per task + unresolved callers (compact)')
    ap.add_argument('--residual', choices=('osi', 'zero'), default='osi',
                    help='bound for blob indirect calls the tracker could not decode: '
                         'any OS-adapter entry (default) or nothing')
    ap.add_argument('--no-cut', action='store_true',
                    help='keep the runtime-infeasible edges listed in CUT')
    args = ap.parse_args()
    # linked_members tells compiled-here archives (graph from .ci) from
    # precompiled ones by path prefix: a relative --build made every
    # project archive "precompiled", duplicating each function and losing
    # the task entries (round 1.3.4, D4).
    args.build = os.path.abspath(args.build)
    args.elf = args.elf or os.path.join(args.build, 'tinylink.elf')
    args.map = args.map or os.path.join(args.build, 'tinylink.map')
    args.objdump = os.path.join(args.toolchain, 'xtensa-esp32-elf-objdump')
    args.nm = os.path.join(args.toolchain, 'xtensa-esp32-elf-nm')

    cfg = project_config()
    if args.residual == 'zero':
        cfg['GROUPS']['residual'] = []
    nodes, rom, rom_names, dup = build_graph(args, cfg)
    if args.blob_sites:
        c = collections.Counter()
        for n in nodes.values():
            for site in n.indirect:
                if n.origin == 'obj':
                    m = re.search(r' \[(.*)\]$', site)
                    c[m.group(1).split(':')[0] if m else '<untracked> ' + n.loc.split('(')[0]] += 1
        for k, v in c.most_common(60):
            print('%5d  %s' % (v, k))
        return
    # rom name -> key, through the final ELF's absolute ROM symbols
    addr_key = {int(n.loc, 16): k for k, n in rom.items()}
    g = Graph(nodes, rom, rom_names, addr_key, wraps_from_ninja(args.build), cfg)
    for spec in args.expand or ():
        ks = g.expand(spec)
        print('%s -> %d: %s' % (spec, len(ks), ' '.join(sorted(bare(k) for k in ks))))
    if args.expand:
        return
    if args.dump:
        for d in args.dump:
            ks = [g.lookup(d)] if g.lookup(d) else [k for k in g.byname.get(d, [])]
            if not ks:
                print('%s: not found' % d)
            for k in ks:
                n = g.node(k)
                print('%s  frame=%s %s origin=%s loc=%s' % (k, n.frame, n.qual, n.origin, n.loc))
                for ref, site in n.calls:
                    print('    call %s -> %s  @%s' % (ref, g.resolve(ref), short(site)))
                for site in n.indirect:
                    print('    indirect @%s  | %s' % (short(site), g.src_line(site)[:100]))
        return

    for task in cfg['TASKS']:
        if args.task and task['name'] not in args.task:
            continue
        variants = task.get('variants') or [{'name': '', 'entry': task['entry']}]
        if args.entry:
            variants = [{'name': 'entry', 'entry': [args.entry]}]
        results = []
        for var in variants:
            keys = []
            for e in var['entry']:
                chain = e.split('>')
                ks = [g.lookup(c) for c in chain]
                if None in ks:
                    print('!! entry %s not found' % e)
                    continue
                if len(ks) > 1:
                    name = '<%s>' % '>'.join(bare(k) for k in ks[:-1])
                    # keyed by the whole entry: two entries with one prefix
                    # (long_poll_task>a, long_poll_task>b) shared one node,
                    # and the second's target replaced the first's
                    pre = '%s%s' % (name, bare(ks[-1]))
                    g.nodes[pre] = Node(pre, name, sum(g.node(k).frame for k in ks[:-1]),
                                        'prefix', 'prefix')
                    g.prefix_next[pre] = ks[-1]
                    keys.append(pre)
                else:
                    keys.append(ks[0])
            g.task = task['name']
            g.cut = set() if args.no_cut else \
                set(cfg['CUT']) | set(task.get('cut', ())) | set(var.get('cut', ()))
            prune = set() if args.no_cut else \
                set(cfg['PRUNE']) | set(task.get('prune', ())) | set(var.get('prune', ()))
            results.append((var, g.analyse(keys, prune)))
        for var, r in results:
            if len(results) > 1:
                print('  variant %-12s chain %5d  static %5d  (%s)'
                      % (var['name'], r['depth'], r['depth'] + TASK_OVERHEAD,
                         ', '.join(var['entry'])))
        var, rep = max(results, key=lambda x: x[1]['depth'])
        wrapper = g.lookup('vPortTaskWrapper') if task.get('wrapper', True) else None
        wr = g.node(wrapper).frame if wrapper else 0
        static = rep['depth'] + wr + (TASK_OVERHEAD if task.get('wrapper', True) else 0) \
            + task.get('extra', 0)
        print('=' * 78)
        print('%s  alloc=%s  static worst=%d B (chain %d + wrapper %d + overhead %d%s)'
              % (task['name'], task.get('alloc', '?'), static, rep['depth'], wr,
                 TASK_OVERHEAD if task.get('wrapper', True) else 0,
                 (' + extra %d' % task['extra']) if task.get('extra') else ''))
        if task.get('note'):
            print('  note: ' + task['note'])
        path = rep['path']
        show = path if args.all_frames else path[:args.frames]
        cum = wr + TOP_ALIGN + CPSA
        for k, site in show:
            n = g.node(k)
            cum += n.frame
            print('  %6d %5d  %s' % (cum, n.frame, short(k)))
        if len(path) > len(show):
            rest = sum(g.node(k).frame for k, _ in path[len(show):])
            print('  ...    (+%d B in %d more frames, leaf %s)'
                  % (rest, len(path) - len(show), short(path[-1][0])))
        if args.why:
            cands = [k for k in rep['best'] if bare(k) == args.why]
            target = max(cands, key=lambda k: rep['best'][k]) if cands else None
            if target in rep['best']:
                p = []
                k = target
                while k != '<task>':
                    pk, site = rep['pred'][k]
                    p.append(k)
                    k = pk
                print('  -- deepest path to %s: %d B (chain)' % (args.why, rep['best'][target]))
                for k in reversed(p):
                    print('       %5d  %s' % (g.node(k).frame, short(k)))
        if args.top:
            best = rep['best']
            leaves = sorted(((v, k) for k, v in best.items() if k != '<task>'),
                            reverse=True)
            seen = set()
            print('  -- deepest distinct chains (top %d):' % args.top)
            for v, k in leaves:
                # report the frame chain's distinct "branch" below the entry
                chain = []
                kk = k
                while kk != '<task>':
                    chain.append(kk)
                    kk = rep['pred'][kk][0]
                key2 = bare(k)
                if key2 in seen:
                    continue
                seen.add(key2)
                print('     %6d  %s  via %s' % (v, short(k), ' > '.join(bare(x) for x in reversed(chain[-6:-1]))))
                if len(seen) >= args.top:
                    break
        unres = rep['unresolved']
        if args.summary:
            byc = collections.defaultdict(lambda: [0, 0, ''])
            for (k, site), text in unres.items():
                e = byc[short(k)]
                e[0] += 1
                e[1] = max(e[1], rep['best'].get(k, 0))
                e[2] = e[2] or (text[:60] if text else short(site)[:60])
            for c, (cnt, d, t) in sorted(byc.items(), key=lambda x: -x[1][1]):
                print('    U %5d x%-2d %-50s | %s' % (d, cnt, c[:50], t))
            for ref, (est, k) in sorted(rep['unknown'].items(), key=lambda x: str(x[0])):
                print('    L %5d     %s (from %s)' % (rep['best'].get(k, 0), short(str(ref)), short(k)))
            continue
        if unres:
            print('  unresolved indirect calls (each costed %d B):' % cfg['UNRESOLVED_BOUND'])
            for (k, site), text in sorted(unres.items(), key=lambda x: -rep['best'].get(x[0][0], 0)):
                print('    depth %5d  %s  @ %s  | %s'
                      % (rep['best'].get(k, 0), short(k), short(site), text[:90]))
        if rep['unknown']:
            print('  unknown leaves (costed %d B each):' % cfg['LEAF_DEFAULT'])
            for ref, (est, k) in sorted(rep['unknown'].items(), key=lambda x: str(x[0])):
                print('    %s  (from %s, depth %d)' % (ref, short(k), rep['best'].get(k, 0)))
        if rep['cycles']:
            seen = set()
            print('  recursion (back edges cut, each cycle costed once):')
            for c in rep['cycles']:
                sig = frozenset(c)
                if sig in seen:
                    continue
                seen.add(sig)
                cost = sum(g.node(k).frame for k in c[:-1])
                print('    %5d B/iter  %s' % (cost, ' > '.join(bare(k) for k in c)))
        pr = sorted(set(cfg['PRUNE']) | set(task.get('prune', ())) | set(var.get('prune', ())))
        if pr and not args.no_cut:
            print('  pruned subtrees (see PRUNE): ' + ', '.join(pr))
        if rep['pruned']:
            print('  cut edges (runtime-infeasible, see CUT): ' +
                  ', '.join('%s>%s' % e for e in sorted(rep['pruned'])))
        if args.indirect:
            print('  resolved indirect sites:')
            for (k, site), (targets, why) in sorted(rep['resolved'].items()):
                print('    %s @ %s -> %s' % (short(k), short(site), ','.join(targets)))


# ---------------------------------------------------------------------------
# Project configuration (tinylink on feat/opt-1.3.3)
#
# RULES: first match wins. `caller` is a regex on the calling function's
# bare name, `text` a regex on the call site's source line (.ci sites
# only), `site` a regex on the site string (blob / ROM sites). targets:
# see Graph.expand; [] = the pointer is NULL / never set in this image.
def R(caller=None, text=None, targets=(), why='', site=None, tasks=None, fmap=None):
    """fmap: the rule's text regex captures a struct field; `{1}` in a
    target is the field, `{m}` is fmap[field] (default: the field)."""
    r = {'targets': list(targets), 'why': why}
    if fmap is not None:
        r['fmap'] = fmap
    if tasks:
        r['tasks'] = set(tasks)
    if caller:
        r['caller'] = caller
    if text:
        r['text'] = text
    if site:
        r['site'] = site
    return r


# Tasks that own UDP sockets only (WG socket, telemetry, /stats, STUN): the
# TCP halves of the socket API are unreachable on them. (Tunnel TCP that
# C1-S feeds into ip4_input on wg_rx is lwIP-internal, not the socket API.)
UDP_ONLY = [('lwip_sendto', 'lwip_send'), ('lwip_recvfrom', 'lwip_recv_tcp'),
            ('lwip_recvmsg', 'lwip_recv_tcp'), ('lwip_readv', 'lwip_recv_tcp'),
            ('lwip_recvfrom', 'lwip_recv_tcp_from')]


def project_config():
    LP, DERP, RX, TX, TLM, TIT, TMR = ('tinylink_lp', 'tinylink_derp', 'wg_rx', 'wg_tx',
                                       'tinylink_tlm', 'tiT', 'esp_timer')
    rules = [
        # ---- tinylink ------------------------------------------------------
        R('derp_run_loop', r'\bcb\(', ['derp_sup_event_cb'],
          'derp_client_run(.., derp_sup_event_cb) (tinylink.c:1055); the smoke '
          'run is main-task only'),
        R('derp_run_loop', r'\bsend\(', ['derp_send_frame_locked'],
          'derp_client.c:415'),
        R('h2_io_on_data', r'h2_cb', ['mapreq.c:stream_chunk_cb'],
          'h2_post_json_stream(.., stream_chunk_cb): mapreq_run_stream only'),
        # round 1.3.7 (B1): the endpoint push riding with the map stream
        R('h2_drive_request', r'side->cb', ['mapreq.c:push_side_done'],
          'h2_post_json_stream_side(.., push_side_done, ..): run_stream_in only'),
        # (side_closed, inlined); round 1.3.7 review: the push's outcome
        R('push_side_done', r'on_push', ['tinylink.c:ep_push_done'],
          'mapreq_run_stream(.., ep_push_done): long_poll_task only'),
        R('mapreq_run_stream', r'on_push', ['tinylink.c:ep_push_done'],
          'the one-shot fallback (run_stream_in, inlined)'),
        # round 1.3.4 (D2): the streaming parser's framing calls the frame
        # handler back, which calls the netmap handler
        R('mapresp_stream_feed', r'on_frame', ['mapreq.c:stream_frame'],
          'mapresp_stream_init(.., stream_frame, ..): run_stream_in only'),
        R('stream_frame', r'on_netmap', ['long_poll_handler'],
          'mapreq_run_stream(.., long_poll_handler)'),
        # tls_io_write_full is an IPA-ICF thunk of tls_io_read_full, so the
        # `rd` site serves both directions; the adapter depends on the task.
        R('tls_io_read_full', r'\brd\(', ['ts2021_conn_read', 'ts2021_conn_write'],
          'ts2021_client.c:176/200 (:80 and :443, round 1.3.5)', tasks=[LP]),
        R('tls_io_read_full', r'\brd\(', ['derp_tls_read_raw', 'derp_tls_write_raw',
                                          'derp_tls_read', 'derp_tls_write'],
          'derp_client.c: the login (_raw), the recv loop, the frame writes '
          '(derp_tls_write, round 1.3.9)', tasks=[DERP, RX, TX, TLM]),
        R('tls_io_read_full', r'\brd\(', ['ts2021_conn_read', 'ts2021_conn_write',
                                          'derp_tls_read_raw', 'derp_tls_write_raw',
                                          'derp_tls_read', 'derp_tls_write',
                                          'key_tls_write'], 'all adapters'),
        R('tls_io_read_full', r's_poll_hook', ['tl_wdt_feed'],
          'tls_io_set_poll_hook(tl_wdt_feed), tinylink.c:165'),
        R('handle_transport', r'cb\(p', ['wg_rx_inject'],
          'wg_netif_set_rx_callback(wg_rx_inject), wg_lwip.c:343'),
        R('rx_task', r'stun_cb', ['stun_response_handler'], 'tinylink.c:1977'),
        R('rx_task', r'path_stale_cb', ['on_wg_path_stale'], 'tinylink.c:1829'),
        R('tx_task_fn', r'relay_cb', ['tinylink_relay_via_derp'], 'tinylink.c:1841'),
        # the re-send's sender (rescue_relay, inlined; round 1.3.9: was
        # left unresolved, costed 0 B)
        R('tx_rescue', r'relay_cb', ['tinylink_relay_via_derp'],
          'wg_netif_set_relay_callback(tinylink_relay_via_derp)'),
        R('wg_tai64n_now', r's_persist_fn', ['tai64n_persist_cb'], 'tinylink.c:194'),
        R('telemetry_task', r'persist_hook\(\)', ['app_wifi.c:hint_persist'],
          'tinylink_set_persist_hook(hint_persist), app_wifi.c (round 1.3.7)'),
        R(None, r'tl_psk_memset\(', ['memset'],
          'wifi_psk.h scrub: a volatile pointer to memset (round 1.3.8)'),
        R('_printf_float', r'pfunc', ['__ssputs_r', '__sfputs_r'],
          'tl_libc_stubs.c float stub'),
        # ---- log / ROM console ----------------------------------------------
        R(None, r'vprint_func\[', ['vprintf', 'esp_rom_vprintf'],
          'esp_log_vprint_func = vprintf (never replaced); ROM vprintf in '
          'constrained context'),
        R('esp_log_util_is_constrained', r'esp_log_cache_enabled',
          ['spi_flash_cache_enabled'], 'esp_log_util_set_cache_enabled_cb'),
        R('esp_rom_output_to_channels', r'_putc1', ['esp_rom_output_putc'],
          'esp_rom_sys.c:37'),
        R('esp_rom_output_to_channels', r'_putc2', ['esp_rom_output_noop',
                                                    'esp_rom_output_putc'], 'esp_rom_sys.c:43'),
        R('heap_caps_alloc_failed', r'alloc_failed_callback', [],
          'no heap_caps_register_failed_alloc_callback in the image'),
        R('tlsf_walk_pool', r'pool_walker', ['multi_heap.c:multi_heap_get_info_tlsf',
                                             'multi_heap.c:multi_heap_dump_tlsf'],
          'multi_heap.c:376/427 (no heap walker users)'),
        # ---- newlib stdio (libc_nano, no .ci: by site) ----------------------
        R(r'_printf_common|_printf_i|_vfprintf_r|_svfprintf_r', None,
          ['__sfputs_r', '__ssputs_r'], 'pfunc of nano vfprintf', site=r'libc_nano'),
        R(r'__sflush_r|_fflush_r|__sfvwrite_r|__swrite|__srefill_r|_fclose_r', None,
          ['__swrite', '__sread', '__sseek', '__sclose'],
          'FILE->_write/_read/_seek/_close = stdio.c defaults', site=r'libc_nano'),
        # ---- VFS --------------------------------------------------------------
        R(r'esp_vfs_\w+|_\w+_r|call_end_selects|vfs_\w+',
          r'CHECK_AND_CALL\w*\(\w+, *\w+, *\w+, *(\w+)|->(?:vfs->)?(?:select->)?(\w+)\(',
          [r're:(uart|console|lwip)_{m}'],
          'VFS entries per field: UART, console (esp_vfs_console), lwIP sockets',
          fmap={'socket_select': 'select', 'get_socket_select_semaphore':
                'get_socket_select_semaphore'}),
        # ---- mbedTLS -------------------------------------------------------
        R('mbedtls_platform_zeroize', r'memset_func', ['memset'], ''),
        R('mbedtls_calloc', None, ['esp_mbedtls_mem_calloc'],
          'CONFIG_MBEDTLS_INTERNAL_MEM_ALLOC'),
        R('mbedtls_free', None, ['esp_mbedtls_mem_free'],
          'CONFIG_MBEDTLS_INTERNAL_MEM_ALLOC'),
        R('ecp_modp', r'modp', [r're:ecp_mod_p(192|224|256|384|521|255|448)\w*'],
          'NIST_OPTIM reducers (P-256, P-384, Curve25519 enabled)'),
        R(r'mbedtls_ecdsa_sign\w*|ecdsa_sign\w*', r'f_rng', ['mbedtls_hmac_drbg_random',
                                                            'mbedtls_ctr_drbg_random'],
          'deterministic ECDSA signing (unused here)'),
        R(None, r'f_rng\b|->f_rng\(', ['mbedtls_ctr_drbg_random'],
          'esp_tls_mbedtls.c:154: the only f_rng, inherited by ECP blinding'),
        R(None, r'f_entropy', ['mbedtls_entropy_func'], 'ctr_drbg seed'),
        R(None, r'mbedtls_cipher_get_base\(|cipher_info->base', ['file:cipher_wrap.c'],
          'cipher_wrap.c base tables (all of them: conservative)'),
        R(None, r'->(add|get)_padding\(',
          [r're:(add|get)_(pkcs|one_and_zeros|zeros_and_len|zeros|no)_padding'], ''),
        R(None, r'->verify_func\(', [r're:(rsa|eckey|ecdsa)_verify_wrap\w*'], 'pk_wrap.c'),
        R(None, r'->sign_func\(', [r're:(rsa|eckey|ecdsa)_sign_wrap\w*'], 'pk_wrap.c'),
        R(None, r'->get_bitlen\(', [r're:(rsa|eckey)_get_bitlen'], 'pk_wrap.c'),
        R(None, r'->can_do\(', [r're:(rsa|eckey|eckeydh|ecdsa)_can_do'], 'pk_wrap.c'),
        R(None, r'->ctx_alloc_func\(', [r're:(rsa|eckey)_alloc_wrap', 'file:cipher_wrap.c'],
          'pk_wrap.c / cipher_wrap.c'),
        R(None, r'->ctx_free_func\(', [r're:(rsa|eckey)_free_wrap', 'file:cipher_wrap.c'],
          'pk_wrap.c / cipher_wrap.c'),
        R(None, r'->(decrypt_func|encrypt_func|check_pair_func|debug_func|'
                r'sign_rs_func|verify_rs_func|rs_alloc_func|rs_free_func)\(', [],
          'RSA decrypt/encrypt, check_pair, debug, restartable: unused by a TLS 1.2 '
          'ECDHE client'),
        R(r'rsa_alt_\w+', None, [], 'RSA-alt keys: never set up (mbedtls_pk_setup_rsa_alt)'),
        R(None, r'update_checksum', [r're:ssl_update_checksum_\w+'], ''),
        R(None, r'calc_verify', [r're:ssl_calc_verify_tls_\w+'], ''),
        R(None, r'calc_finished', [r're:ssl_calc_finished_tls_\w+'], ''),
        R(None, r'tls_prf\(', [r're:tls_prf_sha(256|384)', 'tls_prf_generic'], ''),
        R(None, r'f_recv_timeout', [], 'mbedtls_ssl_set_bio(.., NULL) in esp-tls'),
        R(None, r'f_send\(', ['mbedtls_net_send'], 'esp_tls_mbedtls.c:208'),
        R(None, r'f_recv\(', ['mbedtls_net_recv'], 'esp_tls_mbedtls.c:208'),
        R(None, r'f_get_timer|f_set_timer|f_export_keys|f_set_cache|f_get_cache|f_sni|'
                r'f_ca_cb|f_psk|f_cookie|f_cert_cb|f_async', [],
          'not configured on our client configs'),
        R(None, r'f_vrfy\(', ['tl_verify_cb', 'esp_crt_verify_callback'],
          'tl_crt_bundle_attach, tl_time.c:169'),
        R('mbedtls_x509_crt_parse_der_internal', r'\bcb\(', [],
          'ext callback: only mbedtls_x509_crt_parse_der_with_ext_cb sets it'),
        R('mbedtls_asn1_traverse_sequence_of', r'\bcb\(', ['asn1_get_sequence_of_cb'],
          'mbedtls_asn1_get_sequence_of'),
        # ---- esp-tls -------------------------------------------------------
        R(None, r'tls->read\(', ['esp_mbedtls_read'], 'esp_tls.c:547 (TLS only)'),
        R(None, r'tls->write\(', ['esp_mbedtls_write'], 'esp_tls.c:548 (TLS only)'),
        R(None, r'crt_bundle_attach', ['tl_crt_bundle_attach'],
          'cfg.crt_bundle_attach in ts2021/derp/control_key'),
        R(None, r'set_server_cfg', [], 'server side only'),
        # ---- in-tree HTTP/2 (round 1.3.4, D1; nghttp2's callback set before) --
        R(None, r'\bfn\(ctx, &f\)', ['h2_core.c:field_cb'],
          'hpack_dec_feed(.., field_cb, h): h2_core.c block_bytes only'),
        # ---- lwIP ------------------------------------------------------------
        R('tcpip_send_msg_wait_sem', r'fn\(', [r're:lwip_netconn_do_\w+'],
          'netconn API messages, run in the caller under LOCK_TCPIP_CORE'),
        R('tcpip_api_call', r'fn\(', [r're:netifapi_do_\w+', 'tcp_do_abort'],
          'netifapi.c, api_msg.c:923'),
        R(None, r'API_EVENT|conn->callback', ['event_callback'], 'sockets.c'),
        R(None, r'netif->output\(', ['etharp_output', 'wg_lwip_ip4_output'],
          'wlanif.c:227, wg_lwip.c:214'),
        R(None, r'netif->linkoutput\(', ['wlanif.c:low_level_output'],
          'wlanif.c:232 (Ethernet framing only on the Wi-Fi netif; the tunnel calls '
          'wg_lwip_linkoutput directly from wg_lwip_ip4_output)'),
        R(None, r'igmp_mac_filter', [], 'no MAC filter hook on our netifs'),
        R('pbuf_free', r'custom_free_function', ['esp_pbuf_free'], 'esp_pbuf_ref.c:56'),
        R(r'esp_netif_free_rx_buffer|esp_pbuf_free', r'driver_free_rx_buffer', ['wifi_free'],
          'wifi_netif.c:87 (tunnel: NULL)'),
        R(r'esp_netif_transmit_wrap', r'driver_transmit_wrap', ['wifi_transmit_wrap'],
          'only the Wi-Fi driver sets transmit_wrap (wifi_netif.c:86)'),
        R(r'esp_netif_transmit\w*', r'driver_transmit\w*\)?\(', ['wifi_transmit', 'wg_transmit'],
          'wifi_netif.c:85, wg_lwip.c:256'),
        R('esp_netif_attach', r'post_attach', ['wifi_driver_start', 'wg_post_attach'],
          'wifi_netif.c:111, wg_lwip.c:319'),
        R(r'esp_netif_lwip_ipc_call\w*|esp_netif_api_cb', r'api_fn\(', [r're:esp_netif_\w+_api'],
          'esp_netif_lwip.c *_api functions (fallback; FORWARDERS resolve it per caller)'),
        R(None, None, ['esp_netif_netstack_buf_free'], 'wifi_default.c:65 '
          'esp_wifi_internal_reg_netstack_buf_cb', site=r'\[s_netstack_free\+'),
        R(None, None, ['esp_netif_netstack_buf_ref'], 'wifi_default.c:65 '
          'esp_wifi_internal_reg_netstack_buf_cb', site=r'\[s_netstack_ref\+'),
        R('sntp_sync_time', r'time_sync_notification_cb', ['on_sntp_sync'],
          'tl_time.c:124 sntp_set_time_sync_notification_cb'),
        # ---- entropy / cache / spi_flash -------------------------------------
        R('entropy_gather_internal', r'f_source', ['mbedtls_platform_entropy_poll',
                                                   'mbedtls_hardware_poll', 'mbedtls_nv_seed_poll'],
          'entropy.c:44-54'),
        R(None, r'esp_log_vprintf\(', ['vprintf', 'esp_rom_vprintf'], 'log_print.h:39 inline'),
        R('cache_sync', r'cache_writeback_psram', [], 'NULL: no PSRAM (cache_esp32.c:15)'),
        R('cache_sync', r'cache_flush', ['Cache_Flush_rom', 'Cache_Flush'], 'cache_esp32.c:14'),
        R(None, r'rom_spiflash_api_funcs->', ['esp_flash_api.c:spiflash_start_prog',
                                              'esp_flash_api.c:spiflash_end_default',
                                              'esp_flash_api.c:check_chip_pointer_default',
                                              'esp_flash_api.c:flash_end_flush_cache'],
          'esp_flash_api.c:176 esp_flash_api_funcs_patched'),
        R(None, r'chip_drv->(\w+)\(', [r're:spi_flash_chip_(generic|issi|gd|mxic|winbond)_{m}'],
          'per field across the registered flash chip drivers (sdkconfig: ISSI, GD, '
          'MXIC, Winbond + generic; one is active at run time)',
          fmap={'get_chip_write_protect': 'get_write_protect',
                'set_chip_write_protect': 'set_write_protect',
                'program_page': 'page_program', 'sus_setup': 'suspend_cmd_conf',
                'get_chip_caps': 'get_caps', 'get_protected_regions': None,
                'set_protected_regions': None}),
        R(None, r'host->driver->(\w+)\(', [r're:memspi_host_{1}(_hs)?', r're:spi_flash_hal_{1}'],
          'ESP_FLASH_DEFAULT_HOST_DRIVER (memspi_host_driver.h)',
          fmap={'host_status': 'check_status', 'flush_cache': None, 'check_suspend': None}),
        R(None, r'SET_FLASH_ERASE_STATUS|CHECK_WRITE_ADDRESS|os_func->',
          ['file:spi_flash_os_func_app.c'], 'spi_flash_os_func_app.c'),
        R(None, r'rdsr_func|wrsr_func', [r're:spi_flash_common_(read|write)_status_\w+'],
          'spi_flash_chip_generic.c'),
        R(None, r'flash_encryption_check|flash_encryption->', [r're:spi_flash_encryption_hal_\w+'],
          'esp_flash_encryption_default (spi_flash_chip_generic.c:55)'),
        R(r'bg_enable|bg_disable|spi_bus_lock_\w+', r'bg_(en|dis)able\(', [],
          'bg handlers only on a shared SPI1 bus with other devices (none)'),
        R(r'prv\w+|xRingbuffer\w+|vRingbuffer\w+', r'pxRingbuffer->',
          [r're:prv(GetItem|CheckItemFits|GetCurMaxSize|ReturnItem|CopyItem|AcquireItem|'
           r'SendItemDone)\w*'], 'ringbuf.c item ops'),
        R('esp_efuse_utility_process', r'func_proc', [r're:esp_efuse_utility_(?!process)\w+'],
          'efuse utility callbacks'),
        R('esp_phy_enable', r's_wifi_mac_time_update_cb', ['esp_wifi_internal_update_mac_time'],
          'registered by esp_wifi'),
        # ---- lwIP callbacks ----------------------------------------------------
        R(r'tcp_\w+', r'TCP_EVENT_(ERR|RECV|SENT|POLL|ACCEPT|CONNECTED|CLOSED)',
          ['{m}'], 'api_msg.c callbacks (no listening pcbs: accept never set)',
          fmap={'ERR': 'err_tcp', 'RECV': 'recv_tcp', 'SENT': 'sent_tcp', 'POLL': 'poll_tcp',
                'ACCEPT': None, 'CONNECTED': 'lwip_netconn_do_connected', 'CLOSED': 'recv_tcp'}),
        R(r'tcp_\w+', r'->(errf|recv|sent|poll|connected)\(',
          ['{m}'], 'api_msg.c callbacks',
          fmap={'errf': 'err_tcp', 'recv': 'recv_tcp', 'sent': 'sent_tcp', 'poll': 'poll_tcp',
                'connected': 'lwip_netconn_do_connected'}),
        R('udp_input', r'->recv\(', ['recv_udp', 'dhcp_recv', 'dns_recv', 'sntp_recv'],
          'netconn UDP, DHCP client, DNS, SNTP'),
        R('raw_input', r'->recv\(', ['recv_raw'], 'netconn RAW (unused)'),
        R('dns_call_found', r'found\)', ['lwip_netconn_do_dns_found'],
          'netconn_gethostbyname (getaddrinfo in esp-tls / stun_probe.c:111)'),
        R('netif_invoke_ext_callback', r'callback_fn', ['esp_netif_lwip.c:netif_callback_fn'],
          'esp_netif_lwip.c:866'),
        R('netif_add', r'init\(netif\)', ['wlanif_init_sta', 'wlanif_init', 'wg_lwip.c:wg_lwip_netif_init',
                                          r're:\w*wg\w*_netif_init\w*', r're:wlanif_init\w*'],
          'esp_netif lwip_init_fn (Wi-Fi STA, tunnel)'),
        R('netifapi_do_netif_common', r'errtfunc|voidfunc',
          ['netif_set_up', 'netif_set_down', 'netif_set_link_up', 'netif_set_link_down',
           'netif_set_default', 'dhcp_start', 'dhcp_stop', 'dhcp_release_and_stop',
           'dhcp_renew', 'dhcp_inform', 'dhcp_release', 'netif_remove'],
          'netifapi.h wrappers'),
        R('esp_netif_find_if_api', r'fn\(', [], 'esp_netif_find_if: no callers outside tests'),
        R(r'vPortTCBPreDeleteHook|prvDeleteTCB', r'DelCallback', [],
          'pthread TLS keys unused (no deletion callbacks registered)'),
        R(r'_reclaim_reent', None, ['_cleanup_r'], 'reent->__cleanup', site='libc_nano'),
        R(r'_ZN10__cxxabiv111__terminateEPFvvE|_Znwj|_Znaj|_ZnwjRKSt9nothrow_t', None, ['abort'],
          'std::terminate -> abort; new_handler unset', site='libstdc'),
        # ---- UART / console VFS ------------------------------------------------
        R(r'uart_\w+', r'rx_func|tx_func|get_avail_data_len_func',
          [r're:uart_(rx|tx)_char\w*', r're:uart_get_avail_data_len\w*'], 'uart_vfs.c s_ctx'),
        R(r'console_\w+', r'primary_vfs->', [r're:uart_(start|end)_select'],
          'vfs_console -> UART'),
        # ---- NVS (inline wrappers that dispatch virtually) ---------------------
        R(r'nvs_\w+|_ZN14NVSHandleEntry\w+', r'delete|set_typed_item|get_typed_item|'
          r'erase_item|set_blob|set_string|get_string|commit|get_item_size',
          [r're:_ZN3nvs15NVSHandleSimple\w+', r're:_ZNK3nvs15NVSHandleSimple\w+'],
          'NVSHandleSimple virtuals'),
        # ---- dispatchers: tiT, esp_timer, IPC ---------------------------------
        R('tcpip_thread', r'tcpip_init_done', [], 'boot only (tcpip_init callback)'),
        R('tcpip_thread', r'input_fn', ['ethernet_input', 'ip4_input', 'ip_input'],
          'tcpip_input: ethernet_input (Wi-Fi, NETIF_FLAG_ETHARP) / ip_input'),
        R('tcpip_thread', r'cb\.function|cb_wait\.function',
          ['reg:tcpip_callback,tcpip_try_callback,tcpip_callbackmsg_new,'
           'tcpip_callback_wait,pbuf_free_callback,mem_free_callback'],
          'functions posted with tcpip_callback & co. (address-taken by their callers)'),
        R('sys_check_timeouts', r'handler\(', ['reg:sys_timeout,sys_timeout_abs,sys_timeouts_init'],
          'sys_timeout handlers (address-taken by the callers of sys_timeout)'),
        R('lwip_cyclic_timer', r'handler\(', ['tcp_tmr', 'ip_reass_tmr', 'etharp_tmr',
                                              'dhcp_coarse_tmr', 'dhcp_fine_tmr', 'igmp_tmr',
                                              'dns_tmr'], 'lwip_cyclic_timers[] (timeouts.c)'),
        R('timer_process_alarm', r'callback', ['reg:esp_timer_create,ets_timer_setfn,'
                                               'esp_coex_common_timer_setfn_wrapper',
                                               '!wifi_event_handler'],
          'every esp_timer / ets_timer callback in the image (address-taken by the '
          'callers of esp_timer_create / ets_timer_setfn, incl. the Wi-Fi blob via '
          'timer_setfn_wrapper)'),
        R('esp_ipc_call_and_wait', r'func\(', [],
          'func runs on the ipc task; inline only when the caller is that ipc '
          'task (esp_ipc.c:135), never one of the tasks analysed here'),
        R('esp_vfs_select', r'socket_select\(', ['lwip_select'], 'vfs_lwip.c:101'),
        R('wifi_gpio_debug', None, [], 'debug GPIO hook, NULL unless registered',
          site=r'wifi_gpio_debug'),
        R(None, None, ['@phy_rom'], 'ROM PHY helpers through g_phyFuns: bounded by the '
          'deepest rom_* chain in the ROM', site=r'\[\*g_phyFuns\+'),
        # residual blob indirect calls whose loaded pointer the tracker lost
        # (branchy code): bounded by every entry of the OS adapter table
        R(None, None, ['@residual'], 'bound: any g_wifi_osi_funcs entry (--residual)',
          site=r'lib(pp|net80211|core|mesh|espnow)\.a\(.*\+0x[0-9a-f]+$'),
        # ---- esp_system ------------------------------------------------------
        R('esp_restart', r'shutdown_handlers', ['esp_wifi_stop'], 'wifi_default.c:273'),
        # ---- NVS (C++ virtuals) ----------------------------------------------
        R(None, r'mPartition->', [r're:_ZN3nvs12NVSPartition\w+',
                                  r're:_ZNK3nvs12NVSPartition\w+'],
          'NVSPartition (CONFIG_NVS_ENCRYPTION off: flash encryption is not enabled)'),
        R(None, r'handle->|sHandle->', [r're:_ZN3nvs15NVSHandleSimple\w+',
                                        r're:_ZNK3nvs15NVSHandleSimple\w+'],
          'NVSHandleSimple'),
    ]
    cut = [
        # esp_tls_conn_new_sync completes the TLS handshake before the first
        # read or write; renegotiation (CONFIG_MBEDTLS_SSL_RENEGOTIATION) and
        # TLS 1.3 post-handshake messages are compiled out, so these calls
        # never reach the handshake. The handshake itself is costed where it
        # runs (esp_tls_conn_new_sync -> esp_mbedtls_handshake).
        ('mbedtls_ssl_read', 'mbedtls_ssl_handshake'),
        ('mbedtls_ssl_write', 'mbedtls_ssl_handshake'),
        ('__wrap_mbedtls_ssl_read', 'mbedtls_ssl_handshake'),
        ('__wrap_mbedtls_ssl_write', 'mbedtls_ssl_handshake'),
    ]
    cut += [
        # pbuf_alloc frees only the PBUF_POOL segments it allocated itself;
        # those never carry a custom_free_function (Wi-Fi RX buffers).
        ('pbuf_alloc', 'pbuf_free'),
        # lwIP frees a socket from event_callback/done_socket only when it was
        # closed while another task was still inside a call on it; tinylink
        # closes its sockets from their owner (wg_netif_stop stops the
        # workers first, TLS sockets belong to one task).
        ('done_socket', 'netconn_delete'), ('done_socket', 'free_socket_free_elements'),
        # lazy creation of a static newlib lock on first use: the stdio and
        # libc locks are all taken first during boot on main.
        ('lock_acquire_generic', 'lock_init_generic'),
        # lwip_socket deletes the netconn it just created only when no socket
        # slot is free: a fresh netconn has no connected pcb to close.
        ('lwip_socket', 'netconn_delete'),
        # explicit CBC IV: TLS here is AES-GCM only (mbedtls_user_config.h:
        # "TLS uses GCM only (and CBC is not negotiated)")
        ('mbedtls_ssl_encrypt_buf', 'mbedtls_ctr_drbg_random'),
        # CTR_DRBG reseed inside a random request: every esp_tls connection
        # seeds its own DRBG (esp_tls_mbedtls.c:145) and draws far fewer than
        # MBEDTLS_CTR_DRBG_RESEED_INTERVAL (10 000) requests (handshake only;
        # GCM records draw none); prediction resistance is off. The seed
        # itself (mbedtls_ctr_drbg_seed -> entropy) is costed where it runs.
        ('mbedtls_ctr_drbg_random_with_add', 'mbedtls_ctr_drbg_reseed'),
        ('mbedtls_ctr_drbg_random_with_add', 'mbedtls_ctr_drbg_reseed_internal'),
        # TLS 1.2 renegotiation (compiled in until round 1.3.x, off now): a
        # Go crypto/tls server never sends HelloRequest
        ('ssl_tls12_handle_hs_message_post_handshake', 'mbedtls_ssl_start_renegotiation'),
        # tlsf_walk_pool falls back to its printf dump walker only for a NULL
        # walker; every caller passes one (multi_heap.c:376/427/443)
        ('tlsf_walk_pool', 'default_walker'),
        # flash encryption is off: no partition is encrypted
        ('esp_partition_write', 'esp_flash_write_encrypted'),
        ('esp_partition_read', 'esp_flash_read_encrypted'),
    ]
    prune = [
        # crash paths: an assert / abort reboots the device whatever the stack
        '__assert_func', 'abort', 'esp_system_abort', 'panic_abort', '__assert',
        'esp_panic_handler', 'xt_unhandled_exception',
        # no queue sets in the image (xQueueAddToSet has no caller)
        'prvNotifyQueueSetContainer',
        # boot-only lazy inits: newlib stdio (__sinit on main's first printf),
        # the partition table (nvs_flash_init at boot)
        '__sinit', 'ensure_partitions_loaded',
        # full PHY init + RF calibration (refcount 0 -> 1): esp_wifi_start in
        # bringup only; Wi-Fi is never stopped except right before esp_restart
        'esp_phy_load_cal_and_init',
        # every TLS context here is a client (esp_tls client configs); the
        # server state machine is linked (server session tickets are on in
        # sdkconfig) but conf->endpoint never selects it
        'mbedtls_ssl_handshake_server_step', '__wrap_mbedtls_ssl_handshake_server_step',
        'mbedtls_ssl_tls13_handshake_server_step',
        '__wrap_mbedtls_ssl_tls13_handshake_server_step',
        # TLS 1.2 renegotiation (compiled in up to the May-2026 builds): Go
        # crypto/tls servers never send HelloRequest
        'mbedtls_ssl_start_renegotiation', 'mbedtls_ssl_renegotiate',
        # Wi-Fi mesh and SoftAP are never started (STA only, no esp_mesh_init)
        r're:esp_mesh_\w+', r're:mesh_\w+', r're:hostap_\w+', r're:ieee80211_hostapd_\w+',
    ]
    return {
        'PRUNE': prune,
        'UNRESOLVED_BOUND': 0,
        'LEAF_DEFAULT': 0,
        'LEAF': {'block_absorb_post_hook': 0},   # weak, undefined (poisoning off)
        'GROUPS': {'phy_rom': [r're:rom_\w+'], 'residual': ['table:g_wifi_osi_funcs']},
        # global function-table pointers used by the precompiled blobs ->
        # the statically initialised table they point to at run time
        # '?': a blob field call whose base register the tracker lost is
        # assumed to be an OS-adapter call (the dominant pattern), resolved
        # by its field offset; every such assumption is logged.
        'TABLES': {'g_osi_funcs_p': 'g_wifi_osi_funcs', '?': 'g_wifi_osi_funcs',
                   '?scope': r'lib(net80211|pp|core)\.a'},
        'TABLE_GROUPS': ['g_wifi_osi_funcs'],
        # functions that call a function pointer received as an argument:
        # cloned per calling context, the pointer resolved to the functions
        # whose address the context loads (regex on the call site text, or
        # '*' for every indirect site in the function)
        'FORWARDERS': {
            'netconn_apimsg': '*', 'tcpip_send_msg_wait_sem': r'fn\(',
            'tcpip_api_call': r'fn\(', 'tcpip_callback': '*', 'tcpip_try_callback': '*',
            'netifapi_netif_common': '*', 'netifapi_do_netif_common': r'func\(',
            'esp_netif_lwip_ipc_call': '*', 'esp_netif_lwip_ipc_call_msg': r'api_fn',
            'esp_netif_lwip_ipc_call_fn': '*', 'esp_netif_lwip_ipc_call_get_netif': '*',
            'esp_netif_api_cb': r'api_fn',
            # (tls_io_{read,write}_full and derp_run_loop take several
            # pointers each: the task-scoped RULES above resolve them better)
            'mbedtls_asn1_traverse_sequence_of': r'\bcb\(',
            'mbedtls_asn1_get_sequence_of': '*',
            'tlsf_walk_pool': r'pool_walker',
            'multi_heap_walk': '*', 'esp_netif_find_if': '*',
            'heap_caps_walk': '*',
        },
        'RULES': rules,
        'CUT': cut,
        'TASKS': [
            {'name': LP, 'alloc': 7168, 'entry': ['long_poll_task'],
             'variants': [
                 # the map stream: ensure_control_conn (TLS + Noise connect),
                 # mapreq_run_stream (h2 stream, netmap handler, data plane
                 # start/update, DISCO pre-punch), wedge restart
                 # (round 1.3.7: the push rides with it; push_endpoints_in
                 # is only the fallback one-shot, below)
                 {'name': 'stream', 'entry': ['long_poll_task'],
                  'prune': ['register_node', 'mapreq_push_endpoints',
                            'mapreq.c:push_endpoints_in']},
                 # one-shot POSTs (h2_post_json: h2_cb == NULL, so no
                 # stream_chunk_cb below them)
                 {'name': 'one-shot', 'entry': ['long_poll_task>register_node',
                                                'long_poll_task>mapreq_run_stream>'
                                                'push_endpoints_in'],
                  'prune': ['stream_chunk_cb']},
             ]},
            {'name': DERP, 'alloc': 8192, 'entry': ['derp_supervised_task']},
            {'name': RX, 'alloc': 8192, 'entry': ['rx_task'], 'cut': UDP_ONLY},
            {'name': TX, 'alloc': 5120, 'entry': ['tx_task_fn'], 'cut': UDP_ONLY},
            {'name': TLM, 'alloc': 4608, 'entry': ['telemetry_task'],
             'cut': UDP_ONLY},
            # boot STUN probe (round 1.3.5): DNS + select / sendto /
            # recvfrom on the WG socket while the register runs; exits.
            {'name': 'tinylink_stun', 'alloc': 5120, 'entry': ['stun_boot_task'],
             'cut': UDP_ONLY},
            {'name': TIT, 'alloc': 4608, 'entry': ['tcpip_thread']},
            # CONFIG_ESP_TIMER_TASK_STACK_SIZE (round 1.3.3, B18)
            {'name': TMR, 'alloc': 4608, 'entry': ['timer_task']},
            # early Wi-Fi PSK (round 1.3.8): PBKDF2 on CPU 1 while the
            # driver starts (app_wifi.c PSK_TASK_STACK); exits.
            # Its vTaskDelete(NULL) is a self-delete: prvDeleteTCB runs on
            # the idle task (tasks.c vTaskDelete, xIsCurRunning).
            {'name': 'wifi_psk', 'alloc': 2048, 'entry': ['psk_task'],
             'cut': [('vTaskDelete', 'prvDeleteTCB')]},
            # bringup (app_main): register, dataplane start, spawns; exits.
            # CONFIG_ESP_MAIN_TASK_STACK_SIZE (round 1.3.4, D4)
            {'name': 'main', 'alloc': 8192, 'entry': ['main_task']},
        ],
    }


if __name__ == '__main__':
    sys.setrecursionlimit(100000)
    main()
