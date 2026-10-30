import os,re,json,sys,subprocess,collections,time
S,src,rootsf,maxit,extra=sys.argv[1],sys.argv[2],sys.argv[3],int(sys.argv[4]),sys.argv[5:]
I=json.load(open(S+'/index.json')); idx=I['idx']; nsf=I['ns']
files=set(l.strip() for l in open(rootsf) if l.strip() and not l.startswith('#'))
usingre=re.compile(r'^\s*using\s+(?:\w+\s*=\s*)?([\w\.]+)\s*;',re.M)
nsre=re.compile(r'^\s*namespace\s+([\w\.]+)',re.M)
def ctx(p):
    t=open(os.path.join(src,p),encoding='utf-8-sig',errors='replace').read()
    m=nsre.search(t); ns=m.group(1) if m else ''
    parts=ns.split('.'); chain=['.'.join(parts[:i]) for i in range(1,len(parts)+1)]
    return set(chain+usingre.findall(t))
err=re.compile(r'^(.*?)\((\d+),\d+\): error (CS\d+): (.*?) \[')
prov=collections.defaultdict(set); codes=collections.Counter(); amb=[]; nsonly=[]; unres=collections.Counter()
stubs=set()
for it in range(maxit):
    nsonly.clear()
    with open(S+'/proj/files.props','w') as f:
        f.write('<Project><ItemGroup>\n')
        for p in sorted(files): f.write(f'<Compile Include="{src}/{p}" Link="{p}"/>\n')
        f.write('</ItemGroup></Project>\n')
    t0=time.time()
    r=subprocess.run(['dotnet','build',S+'/proj/Closure.csproj','--no-restore','-nologo','-v:q','-clp:NoSummary']+extra,capture_output=True,text=True)
    out=r.stdout
    errs=set()
    for line in out.splitlines():
        m=err.match(line.strip())
        if m: errs.add((m.group(1),m.group(3),m.group(4)))
    add=set(); itcodes=collections.Counter(e[1] for e in errs); codes.update(itcodes)
    for path,code,msg in errs:
        rel=os.path.relpath(path,src) if path.startswith(src) else path
        q=re.findall(r"'([^']+)'",msg)
        if code in('CS0246','CS0103') and q:
            name=q[0].split('<')[0]
            c=idx.get(name,[]); ok=ctx(rel) if os.path.exists(os.path.join(src,rel)) else set()
            c2=[x for x in c if x[0] in ok] or []
            if len(c2)>1: amb.append((name,rel,[x[1] for x in c2]))
            if c2:
                add.update(x[1] for x in c2)
                [prov[x[1]].add(rel+":"+name) for x in c2]
            else:
                # maybe namespace
                cand=[n for n in nsf if n.split('.')[-1]==name and any(n.startswith(u+'.') or n==u+'.'+name for u in ok|{''})]
                if cand: nsonly.append((name,rel,cand))
                else: unres[(code,name)]+=1
        elif code=='CS0234' and len(q)>=2:
            name,ns=q[0].split('<')[0],q[1]
            c=[x for x in idx.get(name,[]) if x[0]==ns]
            if c:
                add.update(x[1] for x in c)
                [prov[x[1]].add(rel+":"+name) for x in c]
            elif ns+'.'+name in nsf or any(k.startswith(ns+'.'+name+'.') for k in nsf): nsonly.append((name,rel,[ns+'.'+name]))
            else: unres[(code,name)]+=1
        else:
            unres[(code,msg[:90])]+=1
    nss=set(c[0] for _,_,c in nsonly)-stubs
    if nss:
        stubs|=nss
        open(src+'/_roots/_nsstubs.cs','w').write(''.join(f'namespace {n} {{ }}\n' for n in sorted(stubs)))
        add.add('_roots/_nsstubs.cs')
    new=add-files
    print(f'it{it}: files={len(files)} errors={len(errs)} codes={dict(itcodes)} +{len(new)} ({time.time()-t0:.0f}s)',flush=True)
    if not errs: print('CLEAN'); break
    if not new and not nss:
        print('STALLED'); break
    files|=new
json.dump(sorted(files),open(S+'/closure_files.json','w')); json.dump({k:sorted(v) for k,v in prov.items()},open(S+'/prov.json','w'))
print('codes total',dict(codes))
print('namespace-only errors (sample):',len(nsonly)); [print('  ',x) for x in nsonly[:15]]
print('ambiguous resolutions:',len(amb)); [print('  ',x) for x in amb[:15]]
print('unresolved:'); [print('  ',k,v) for k,v in unres.most_common(25)]
