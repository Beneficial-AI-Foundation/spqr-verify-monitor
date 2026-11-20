"""Write forged copies of a tamper_early trace, to test the monitor's delivery check.

Usage: python3 -I make-forged-traces.py <tamper_early trace> <output dir>

forge1: the original of the first tamper event was never sent.
forge2: the tampered copy has another chunk index (and its recv too).
forge3: a later operation has tamper(copy, original) and receives the original again.
forge4: the tamper operation receives the original, a later operation the copy.
forge5: two tamper events in one operation.
Each must fail the delivery check.
"""
import json, sys

src, out = sys.argv[1], sys.argv[2]
L = open(src).read().splitlines()
J = lambda x: json.dumps(x, separators=(',', ':'))
def write(name, lines):
    open(f'{out}/{name}.jsonl', 'w').write('\n'.join(lines) + '\n')

i = next(k for k, l in enumerate(L) if '"f":"tamper"' in l)
e = json.loads(L[i]); m, t = e['args']; P = e['p']
j = next(k for k in range(i + 1, len(L)) if '"f":"States::recv"' in L[k])
k = next(k for k in range(j + 1, len(L))
         if '"f":"States::recv"' in L[k] and json.loads(L[k])['p'] == P)

e1 = json.loads(L[i]); d = e1['args'][0]['data']
e1['args'][0]['data'] = ('ff' if d[:2] != 'ff' else '00') + d[2:]
A = list(L); A[i] = J(e1); write('forge1', A)

e2 = json.loads(L[i]); e2['args'][1]['index'] += 1
r = json.loads(L[j]); r['args'][2]['index'] += 1
A = list(L); A[i] = J(e2); A[j] = J(r); write('forge2', A)

r = json.loads(L[k]); ev = dict(e); ev['op'] = r['op']; ev['args'] = [t, m]; r['args'][2] = m
A = list(L); A[k] = J(r); A.insert(k, J(ev)); write('forge3', A)

r1 = json.loads(L[j]); r1['args'][2] = m; r2 = json.loads(L[k]); r2['args'][2] = t
A = list(L); A[j] = J(r1); A[k] = J(r2); write('forge4', A)

A = list(L); A.insert(i + 1, L[i]); write('forge5', A)
