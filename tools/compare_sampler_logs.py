#!/usr/bin/env python3
import re
import sys
from collections import defaultdict

# Files to analyze
LOG_KEYS = {
    'keygen': '/tmp/arith_keygen_diag.log',
    'sample': '/tmp/arith_sample_diag.log',
    'module': '/tmp/arith_module_sample.log',
}

# Parameters
Q = 1073741441  # PARAM_Q observed in repo notes
MAX_COEFFS = 16  # how many coefficients to compare per component

TAG_RE = re.compile(r'\[ARITH DUMP\]\s+([A-Za-z0-9_%-]+):.*?:\s*(.*)$')

# Read logs and extract tagged numeric dumps
def parse_log(path):
    tags = {}
    try:
        with open(path,'r') as f:
            for line in f:
                m = TAG_RE.search(line)
                if m:
                    tag = m.group(1).strip()
                    nums = m.group(2).strip()
                    if nums:
                        parts = nums.split()
                        # convert to int if possible
                        vals = []
                        for p in parts:
                            try:
                                vals.append(int(p))
                            except:
                                # ignore non-int tokens
                                pass
                        if vals:
                            tags[tag] = vals
    except FileNotFoundError:
        print(f'WARNING: log not found: {path}')
    return tags

# Load all logs
all_tags = {k: parse_log(v) for k,v in LOG_KEYS.items()}

# Helper to collect keys of interest per component
# We'll build dicts mapping base_tag-> {comp_index: [vals]}
COMP_RE = re.compile(r'(_comp_)(\d+)$')

def split_component_tags(tags):
    out = defaultdict(dict)
    for tag, vals in tags.items():
        m = COMP_RE.search(tag)
        if m:
            base = tag[:m.start(1)]
            comp_idx = int(m.group(2))
            out[base][comp_idx] = vals
        else:
            # also accept tags that embed comp info differently (e.g., _i_0_comp_0)
            m2 = re.search(r'(_comp_)?(\d+)$', tag)
            if m2:
                # fall back: last numeric suffix
                try:
                    comp_idx = int(m2.group(2))
                    base = tag[:m2.start(2)-len(m2.group(1))] if m2.group(1) else tag
                    out[base][comp_idx] = vals
                except:
                    out[tag][-1] = vals
            else:
                out[tag][-1] = vals
    return out

parsed = {k: split_component_tags(v) for k,v in all_tags.items()}

# Convenience to fetch by base tag across logs
# Useful substrings we want to match in logs
SUBSTRINGS = [
    'lhs_AplusB', 'mpk_beta', 'beta_s0', 'lhs_AplusB',
    'SAMPLE_u', 'SAMPLE_v_before_hinv', 'SAMPLE_v_attr', 'Aomega', 'Bomega',
    'ENCRYPT_beta_s0', 'KEYGEN_Aomega', 'KEYGEN_Bomega_sum',
]

def find_bases(container, substr):
    # return any tags that contain the substring (case-sensitive)
    return [b for b in container.keys() if substr in b]

report_lines = []

# Compare two component dicts
def compare_components(a_comps, b_comps, tagA, tagB):
    comps = sorted(set(list(a_comps.keys()) + list(b_comps.keys())))
    for comp in comps:
        a_vals = a_comps.get(comp)
        b_vals = b_comps.get(comp)
        if a_vals is None or b_vals is None:
            report_lines.append(f'COMP {comp}: missing data for one side (a_present={a_vals is not None}, b_present={b_vals is not None})')
            continue
        L = min(len(a_vals), len(b_vals), MAX_COEFFS)
        for i in range(L):
            a = a_vals[i]
            b = b_vals[i]
            if a != b:
                # compute helpful diagnostics
                diff = a - b
                modq = (a - b) % Q
                signed_wrap = None
                if a >= 2**31 or b >= 2**31:
                    # show signed interpretations
                    a_signed = a - (1<<32) if a >= (1<<31) else a
                    b_signed = b - (1<<32) if b >= (1<<31) else b
                    signed_wrap = (a_signed, b_signed)
                report_lines.append(f'MISMATCH comp={comp} idx={i}: {tagA}={a} vs {tagB}={b}  diff={diff}  (mod Q -> {modq})' + (f'  signed_view={signed_wrap}' if signed_wrap else ''))
                # return after first mismatch for this comp
                break
        else:
            report_lines.append(f'COMP {comp}: first {L} coeffs equal between {tagA} and {tagB}')

# Attempt comparisons
# 1) KEYGEN_lhs_AplusB_comp vs KEYGEN_mpk_beta_comp
lhs_bases = find_bases(parsed['keygen'], 'KEYGEN_lhs_AplusB_comp')
mpk_bases = find_bases(parsed['keygen'], 'KEYGEN_mpk_beta_comp')
if lhs_bases and mpk_bases:
    # take first matching base
    a_base = lhs_bases[0]
    b_base = mpk_bases[0]
    report_lines.append(f'Comparing KeyGen LHS ({a_base}) vs MPK beta ({b_base})')
    compare_components(parsed['keygen'][a_base], parsed['keygen'][b_base], a_base, b_base)
else:
    report_lines.append('KeyGen LHS or MPK beta tags not found in keygen log')

# 2) ENCRYPT_beta_s0_comp vs KEYGEN_lhs_AplusB_comp (encrypt vs sampled lhs)
encrypt_bases = find_bases(parsed['module'], 'ENCRYPT_beta_s0_comp') or find_bases(parsed.get('sample',{}), 'ENCRYPT_beta_s0_comp') or find_bases(parsed.get('keygen',{}),'ENCRYPT_beta_s0_comp')
if not encrypt_bases:
    # try any log
    for k in parsed:
        encrypt_bases = find_bases(parsed[k], 'ENCRYPT_beta_s0_comp')
        if encrypt_bases: break

if encrypt_bases and lhs_bases:
    a_base = encrypt_bases[0]
    b_base = lhs_bases[0]
    report_lines.append(f'Comparing ENCRYPT beta*s0 ({a_base}) vs KeyGen LHS ({b_base})')
    # find appropriate container where ENCRYPT tag occurred
    container = None
    for k in parsed:
        if a_base in parsed[k]:
            container = parsed[k]
            break
    if container:
        compare_components(container[a_base], parsed['keygen'][b_base], a_base, b_base)
else:
    report_lines.append('ENCRYPT_beta_s0 or KEYGEN_lhs_AplusB tags not found for cross-compare')

# 3) SAMPLE_v_before_hinv_comp vs KEYGEN_Aomega_comp (expect same)
v_bases = find_bases(parsed['sample'], 'SAMPLE_v_before_hinv_comp')
omega_bases = find_bases(parsed['keygen'], 'KEYGEN_Aomega_comp')
if v_bases and omega_bases:
    a_base = v_bases[0]
    b_base = omega_bases[0]
    report_lines.append(f'Comparing SAMPLE v_before_hinv ({a_base}) vs KEYGEN Aomega ({b_base})')
    compare_components(parsed['sample'][a_base], parsed['keygen'][b_base], a_base, b_base)
else:
    report_lines.append('SAMPLE_v_before_hinv or KEYGEN_Aomega tags not found')

# 4) Module sampler small t outputs: report signedness pattern
# Find any SAMPLE_module_t_out_i_* tags
mod_tags = [t for t in parsed['module'].keys() if 'SAMPLE_module_t_out' in t]
if mod_tags:
    report_lines.append('\nModule sampler t outputs detected; checking smallness / signed-wrap pattern (showing first comp)')
    for ttag in sorted(mod_tags)[:6]:
        comps = parsed['module'][ttag]
        for comp_idx, vals in list(comps.items())[:1]:
            # examine first few vals
            sample = vals[:MAX_COEFFS]
            wrapped = any(v >= (1<<31) for v in sample)
            report_lines.append(f'{ttag} comp={comp_idx} sample={sample} wrapped={wrapped}')
else:
    report_lines.append('No module sampler t_out tags found in module log')

# Print concise summary
print('\n'.join(report_lines))

# End
