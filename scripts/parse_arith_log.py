#!/usr/bin/env python3
"""
Simple parser for ARITH_DEBUG log to correlate mul_crt_poly -> reduce_double_crt_poly
by h_comp address and component index. Prints AFTER-reduction coeff snapshots for
selected h_comp addresses.
"""
import re
import sys

if len(sys.argv) < 2:
    print("Usage: parse_arith_log.py /path/to/arith_trace.log [h_comp1 h_comp2 ...]")
    sys.exit(1)

path = sys.argv[1]
targets = set(sys.argv[2:])

mul_re = re.compile(r"\[ARITH\] mul_crt_poly: depth=(\d+), comp=(\d+), crt_f=(0x[0-9a-f]+), crt_g=(0x[0-9a-f]+), h_comp=(0x[0-9a-f]+), first-dcoeffs: (.*)$")
reduce_after_re = re.compile(r"\[ARITH\] reduce_double_crt_poly: depth=(\d+), comp=(\d+) AFTER reduction \(first 4 coeffs\): (.*)$")
reduce_before_re = re.compile(r"\[ARITH\] reduce_double_crt_poly: depth=(\d+), comp=(\d+) BEFORE reduction \(first 4 double coeffs\): (.*)$")

# We'll scan sequentially and link the most recent mul's h_comp to subsequent reduce AFTER entries
hcomp_pending = []  # stack of seen h_comp in order (we'll track last seen)
results = {}  # h_comp -> comp -> after-list

with open(path, 'r', errors='ignore') as f:
    for line in f:
        line = line.rstrip('\n')
        m = mul_re.search(line)
        if m:
            depth, comp, crt_f, crt_g, h_comp, dcoeffs = m.groups()
            # record last-seen h_comp
            hcomp_pending.append(h_comp)
            # optionally record mul details
            results.setdefault(h_comp, {}).setdefault('mul', []).append({
                'depth': int(depth), 'comp': int(comp), 'crt_f': crt_f, 'crt_g': crt_g, 'first_dcoeffs': dcoeffs.strip()
            })
            continue
        m2 = reduce_after_re.search(line)
        if m2:
            depth, comp, coeffs = m2.groups()
            comp = int(comp)
            # assign to most recent h_comp if present
            if hcomp_pending:
                h = hcomp_pending[-1]
                results.setdefault(h, {}).setdefault('reduce_after', {})[comp] = [int(x) for x in re.findall(r"-?\d+", coeffs)][:4]
            continue

# Print summary for targets or top few h_comp
if not targets:
    # show top 5 h_comp keys
    keys = list(results.keys())[:10]
else:
    keys = list(targets)

for k in keys:
    print(f"h_comp={k}")
    info = results.get(k)
    if not info:
        print("  <no data found>")
        continue
    muls = info.get('mul', [])
    for mm in muls[-4:]:
        print(f"  mul comp={mm['comp']} crt_f={mm['crt_f']} crt_g={mm['crt_g']} first-dcoeffs={mm['first_dcoeffs']}")
    rafter = info.get('reduce_after', {})
    for comp_i in sorted(rafter.keys()):
        print(f"  reduce_after comp={comp_i} coeffs={rafter[comp_i]}")
    print('')

# Also show any h_comp starting with 0x5d8f5e3d6 (common pattern) for quick glance
if not targets:
    extras = [x for x in results.keys() if x.startswith('0x5d8f5e3d6')][:8]
    if extras:
        print('Extras (some h_comp starting with 0x5d8f5e3d6):')
        for k in extras:
            vals = results[k].get('reduce_after', {})
            print(f"  {k}: {vals}")
