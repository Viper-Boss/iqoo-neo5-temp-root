"""CP-SAT definitive solver: substitution alphabet over base64-of-ASCII."""
from ortools.sat.python import cp_model

conf = open(r'Q:\Deepseek\_neo5\br\recovery\last_server_cJSON.conf','r',encoding='utf-8').read().strip()
param = open(r'Q:\Deepseek\_neo5\br\request_param.txt','r').read().strip()

syms = sorted(set(conf) | set(param))
idx = {s: i for i, s in enumerate(syms)}

model = cp_model.CpModel()
V = [model.NewIntVar(0, 63, f'v{i}') for i in range(len(syms))]
model.AddAllDifferent(V)

PRINT_LO, PRINT_HI = 0x20, 0x7e
NEWLINES = {10, 13, 9}

def add_string(s):
    n = len(s)
    for g in range(0, n - 3, 4):
        s0, s1, s2, s3 = s[g:g+4]
        v0, v1, v2, v3 = V[idx[s0]], V[idx[s1]], V[idx[s2]], V[idx[s3]]
        # division constraints
        k1 = model.NewIntVar(0, 3, f'k{g}_1')
        r1_ = model.NewIntVar(0, 15, f'r{g}_1')
        model.AddDivisionEquality(k1, v1, 16)
        model.Add(r1_ == v1 - k1 * 16)
        k2 = model.NewIntVar(0, 15, f'k{g}_2')
        r2_ = model.NewIntVar(0, 3, f'r{g}_2')
        model.AddDivisionEquality(k2, v2, 4)
        model.Add(r2_ == v2 - k2 * 4)
        b0 = model.NewIntVar(0, 255, f'b{g}_0')
        model.Add(b0 == v0 * 4 + k1)
        b1 = model.NewIntVar(0, 255, f'b{g}_1')
        model.Add(b1 == r1_ * 16 + k2)
        b2 = model.NewIntVar(0, 255, f'b{g}_2')
        model.Add(b2 == r2_ * 16 + v3)
        for b in (b0, b1, b2):
            ok = model.NewBoolVar('')
            model.Add(b >= PRINT_LO); model.Add(b <= PRINT_HI)
    r = n % 4
    if r == 2:
        v0, v1 = V[idx[s[-2]]], V[idx[s[-1]]]
        k1 = model.NewIntVar(0, 3, 'tk1')
        model.AddDivisionEquality(k1, v1, 16)
        b0 = model.NewIntVar(0, 255, 'tb0')
        model.Add(b0 == v0 * 4 + k1)
        model.Add(b0 >= PRINT_LO); model.Add(b0 <= PRINT_HI)
    elif r == 3:
        v0, v1, v2 = V[idx[s[-3]]], V[idx[s[-2]]], V[idx[s[-1]]]
        k1 = model.NewIntVar(0, 3, 'tk1')
        model.AddDivisionEquality(k1, v1, 16)
        r1_ = model.NewIntVar(0, 15, 'tr1')
        model.Add(r1_ == v1 - k1 * 16)
        b0 = model.NewIntVar(0, 255, 'tb0')
        model.Add(b0 == v0 * 4 + k1)
        k2 = model.NewIntVar(0, 15, 'tk2')
        model.AddDivisionEquality(k2, v2, 4)
        b1 = model.NewIntVar(0, 255, 'tb1')
        model.Add(b1 == r1_ * 16 + k2)
        model.Add(b0 >= PRINT_LO); model.Add(b0 <= PRINT_HI)
        model.Add(b1 >= PRINT_LO); model.Add(b1 <= PRINT_HI)

add_string(conf)
add_string(param)

solver = cp_model.CpSolver()
solver.parameters.max_time_in_seconds = 120
status = solver.Solve(model)
print('status:', solver.StatusName(status))

def decode(m, s):
    vals = [m[ch] for ch in s]
    out = []
    for g in range(0, len(vals)-3, 4):
        v0,v1,v2,v3 = vals[g:g+4]
        out.append((v0<<2)|(v1>>4)); out.append(((v1&15)<<4)|(v2>>2)); out.append(((v2&3)<<4)|v3)
    r = len(vals)%4
    if r == 2: out.append((vals[-2]<<2)|(vals[-1]>>4))
    elif r == 3:
        out.append((vals[-3]<<2)|(vals[-2]>>4)); out.append(((vals[-2]&15)<<4)|(vals[-1]>>2))
    return bytes(out)

if status in (cp_model.OPTIMAL, cp_model.FEASIBLE):
    m = {s: solver.Value(V[i]) for s, i in idx.items()}
    # collect multiple solutions
    sols = [m]
    for k in range(4):
        model.AddAllowedAssignments(V, [ [solver.Value(v) for v in V] ])
        # forbid current solution: at least one var differs
        diff = [model.NewBoolVar('') for _ in V]
        for i, v in enumerate(V):
            model.AddAllowedAssignments([v], [[solver.Value(v)]])
        # simpler: add constraint sum of (v_i != cur_i) >= 1
        bools = []
        for i, v in enumerate(V):
            b = model.NewBoolVar('')
            model.Add(v != solver.Value(v)).OnlyEnforceIf(b)
            model.Add(v == solver.Value(v)).OnlyEnforceIf(b.Not())
            bools.append(b)
        model.Add(sum(bools) >= 1)
        st = solver.Solve(model)
        if st not in (cp_model.OPTIMAL, cp_model.FEASIBLE):
            break
        sols.append({s: solver.Value(V[i]) for s, i in idx.items()})

    print(f'found {len(sols)} solutions')
    WORDS = [b'http', b'vivo', b'.zip', b'PD2055', b'url', b'size', b'md5', b'model']
    for si, m in enumerate(sols):
        pt = decode(m, conf); ptp = decode(m, param)
        hits = sum(pt.count(w) for w in WORDS) + sum(ptp.count(w) for w in WORDS)
        print(f'\n=== solution {si} (word hits: {hits}) ===')
        print('CONF :', pt[:200])
        print('PARAM:', ptp[:150])
        if si == 0 or hits:
            open(rf'Q:\Deepseek\_neo5\br\conf_pt_{si}.txt','wb').write(pt)
            open(rf'Q:\Deepseek\_neo5\br\param_pt_{si}.txt','wb').write(ptp)
            import json
            json.dump(m, open(rf'Q:\Deepseek\_neo5\br\alphabet_{si}.json','w'))


