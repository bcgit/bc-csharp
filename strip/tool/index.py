import os,re,json,sys
root=sys.argv[1]
idx={}  # simple name -> list of (ns, file)
nsfiles={}
decl=re.compile(r'^\s*(?:(?:public|internal|private|protected|static|sealed|abstract|partial|readonly|ref|unsafe|new)\s+)*(?:class|struct|interface|enum|delegate\s+[\w<>\[\],\s\.]+?)\s+(\w+)',re.M)
nsre=re.compile(r'^\s*namespace\s+([\w\.]+)',re.M)
for d,_,fs in os.walk(root):
    for f in fs:
        if not f.endswith('.cs'): continue
        p=os.path.relpath(os.path.join(d,f),root)
        t=open(os.path.join(d,f),encoding='utf-8-sig',errors='replace').read()
        m=nsre.search(t); ns=m.group(1) if m else ''
        nsfiles.setdefault(ns,[]).append(p)
        for n in set(decl.findall(t)):
            idx.setdefault(n,[]).append([ns,p])
json.dump({'idx':idx,'ns':nsfiles},open(sys.argv[2],'w'))
print(len(idx),'names',len(nsfiles),'namespaces')
dups={k:v for k,v in idx.items() if len(v)>1}
print('ambiguous simple names:',len(dups))
