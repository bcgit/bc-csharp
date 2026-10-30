import re,json,sys,collections
S=sys.argv[1]
files=[f for f in json.load(open(S+'/closure_files.json')) if not f.startswith('_')]
prov=json.load(open(S+'/prov.json'))
def expand(g):
    m=re.search(r'\{([^}]*)\}',g)
    if not m: return [g]
    return sum([expand(g[:m.start()]+o+g[m.end():]) for o in m.group(1).split(',')],[])
def comp(path):
    out=[]
    for line in open(path):
        g=line.strip()
        if not g: continue
        for e in expand(g):
            r=re.escape(e).replace(r'\*\*/','(?:.*/)?').replace(r'\*\*','.*').replace(r'\*','[^/]*')
            out.append((g,re.compile('^'+r+'$',re.I)))
    return out
D=comp(S+'/deny4.txt'); A=comp(S+'/allow4.txt'); Acs=[(g,re.compile(p.pattern)) for g,p in A]
denied={}; allowed=[]
for f in files:
    g=next((g for g,p in D if p.match(f)),None)
    if not g: continue
    if any(p.match(f) for _,p in A):
        allowed.append(f+('' if any(p.match(f) for _,p in Acs) else '  [allow matched only case-insensitively]')); continue
    denied[f]=g
print('closure(.cs, excl roots/stub):',len(files),' denied:',len(denied))
print('allowed:',allowed)
for g,c in collections.Counter(denied.values()).most_common(): print(f'  {c:3d} {g}')
# entry edges: referrer not denied
entry=collections.defaultdict(set)
for f in denied:
    for r in prov.get(f,[]):
        rf,name=r.rsplit(':',1)
        if rf not in denied: entry[rf].add(f'{f.split("/")[-1]}({name})')
print('ENTRY referrers (kept file -> denied file(type)):')
for rf in sorted(entry): print(' ',rf,'->',', '.join(sorted(entry[rf])))
c=collections.Counter(f.split('/')[0] for f in files); print('per top dir:',dict(sorted(c.items())))
c2=collections.Counter(f.split('/')[0] for f in files if f not in denied); print('per top dir minus denied:',dict(sorted(c2.items())), sum(c2.values()))
