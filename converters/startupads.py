#!/usr/bin/env python3
"""Direct Moyu QX -> Loon audit and conservative converter.

Do not publish upstream content until the independent authorization gate is set.
No third-party conversion service; do not execute downloaded JS.
"""
import argparse
import collections
import hashlib
import json
import os
import pathlib
import re
import subprocess
import tempfile
import functools
import fnmatch
import urllib.parse
import urllib.request

URL = "https://ddgksf2013.top/rewrite/StartUpAds.conf"
AGENT = "surge"
REJECTS = {"reject", "reject-200", "reject-dict", "reject-img", "reject-array"}
SCRIPTS = {
    "script-request-header": ("request", False),
    "script-request-body": ("request", True),
    "script-response-header": ("response", False),
    "script-response-body": ("response", True),
    "script-analyze-echo-response": ("request", True),
}
BODY = {"request-body": "request-body-replace-regex",
        "response-body": "response-body-replace-regex"}
JQ = {"jsonjq-request-body": "request-body-json-jq",
      "jsonjq-response-body": "response-body-json-jq"}

def download(url, limit=4_000_000):
    if urllib.parse.urlsplit(url).scheme != "https":
        raise ValueError("HTTPS required")
    req=urllib.request.Request(url,headers={"User-Agent":AGENT})
    with urllib.request.urlopen(req,timeout=25) as resp:
        if resp.status != 200 or urllib.parse.urlsplit(resp.geturl()).scheme != "https":
            raise ValueError("Unexpected HTTP response")
        raw=resp.read(limit+1)
        if not raw or len(raw)>limit:
            raise ValueError("Unexpected size")
        content_type=resp.headers.get("Content-Type","")
        if "text/html" in content_type.lower():
            raise ValueError("HTML rather than source")
        return raw,resp.geturl()

@functools.lru_cache(maxsize=64)
def github_revision(owner, repo, ref):
    if re.fullmatch(r"[0-9a-f]{40}",ref): return ref
    p=subprocess.run(["git","ls-remote","--exit-code",
        f"https://github.com/{owner}/{repo}.git",f"refs/heads/{ref}"],
        capture_output=True,text=True,check=True,timeout=25)
    rows=p.stdout.splitlines()
    if len(rows)!=1: raise ValueError("ambiguous Git revision")
    sha=rows[0].split()[0]
    if not re.fullmatch(r"[0-9a-f]{40}",sha): raise ValueError("invalid Git revision")
    return sha

def pin_url(url):
    u=urllib.parse.urlsplit(url)
    if u.hostname!="raw.githubusercontent.com" or u.scheme!="https" or u.query or u.fragment or u.username or u.password or u.port is not None:
        raise ValueError("unreviewed script host")
    parts=u.path.strip("/").split("/")
    if len(parts)<4 or not all(re.fullmatch(r"[A-Za-z0-9_.-]+",p) and p not in (".","..") for p in parts):
        raise ValueError("unreviewed script path")
    owner,repo=parts[:2]
    rest=parts[2:]
    if rest[:2]==["refs","heads"]: rest=rest[2:]
    ref,*path=rest
    if not path or not path[-1].endswith(".js"): raise ValueError("missing JS path")
    sha=github_revision(owner,repo,ref)
    return "https://raw.githubusercontent.com/"+"/".join([owner,repo,sha]+path)

def inspect_js(url, phases):
    pinned=pin_url(url)
    raw,final=download(pinned,2_000_000)
    if final!=pinned: raise ValueError("unexpected script redirect")
    source=raw.decode("utf-8-sig")
    # Only inspect and parse; do not run remotely downloaded scripts.
    with tempfile.TemporaryDirectory() as tmp:
        p=pathlib.Path(tmp)/"upstream.js"
        p.write_text(source,encoding="utf-8")
        check=subprocess.run(["node","--check",str(p)],capture_output=True,text=True,timeout=12)
    api=sorted(set(re.findall(r"\$(?:task|prefs|notify|done|request|response|httpClient|persistentStore|notification|environment|argument|loon|configuration|app|utils|resource|network|script|database|surge|fetch)\b",source)))
    issues=[]
    if check.returncode: issues.append("JavaScript syntax")
    if re.search(r"\$(?:task|prefs|notify|resource|configuration|database|app|utils|network|fetch)\b",source):
        issues.append("platform-specific API requires review")
    if re.search(r"\b(?:bodyBytes|statusCode|sessionIndex)\b",source):
        issues.append("body/status/context API requires review")
    if re.search(r"\b(?:eval|Function)\s*\(|\bimport\s*\(",source):
        issues.append("dynamic code requires review")
    if "$done" not in api: issues.append("no explicit $done")
    # These two exact upstream revisions were inspected: both include a non-QX
    # branch. 12306 emits a nested response; Baidu Map uses Uint8Array.
    # Review again if upstream changes; do not approve other flagged scripts.
    digest=hashlib.sha256(raw).hexdigest()
    if url.endswith("/js/baidumap.js") and digest=="7cd5425ff0dcdd24d0fd42a4ca4a21b30c5d6edcd8052b3b7ca95c4722fcb500":
        # The bundled protobuf library contains dynamic code; its binary mode
        # is identified, but dynamic code is not automatically approved.
        issues=[i for i in issues if i not in ("platform-specific API requires review","body/status/context API requires review")]
    if re.search(r"(?:jsjiami\.com|_0x[0-9a-f]{4,})",source,re.I):
        issues.append("obfuscated code requires manual security review")
    if re.search(r"status\s*:\s*['\"]HTTP/",source):
        issues.append("HTTP status string needs Loon numeric-status review")
    if re.search(r"(?i)(?:vip[_-]?ticket|unlock[_-]?vip|authorization\s*[:=]|cookie\s*[:=])",source):
        issues.append("credential or entitlement handling requires review")
    if re.search(r"禁止转载|禁止\s*转载|不得转载",source):
        issues.append("explicit upstream redistribution restriction; authorization required")
    if re.search(r"解除.{0,35}(?:下载限制|流量.{0,15}限制)|unlock.{0,20}quota",source,re.I):
        issues.append("non-ad quota bypass behavior requires separate review")
    adapter=None
    # Only audited exact revisions may take the narrow compatibility path.
    if url.endswith("/12306.js") and digest=="4723bc2236835eea0a8b79529c832a9af1cfd37fa1b160becb3a4b51f9067cd5":
        adapter="rail_echo"
    if url.endswith("/hanglvzongheng.js") and digest=="24173b13433fc3c46b29577301c044425b1159f24f6fe577eef9a8227120f201":
        adapter="flight_header"
    if url.endswith("/js/baidumap.js") and digest=="7cd5425ff0dcdd24d0fd42a4ca4a21b30c5d6edcd8052b3b7ca95c4722fcb500":
        adapter="baidu_binary"
    if adapter=="baidu_binary":
        if phases!={"response"}: raise ValueError("binary adapter phase mismatch")
        from startupads_baidu_test import test_baidu
        generated,checks=test_baidu()
        # Only replace the dynamic-code concern: the replacement contains
        # neither dynamic execution nor the bundled upstream library.
        issues=[i for i in issues if i!="dynamic code requires review"]
    elif adapter:
        from startupads_support import adapt_and_test
        if len(phases)!=1: raise ValueError('adapter has ambiguous phases')
        generated,checks=adapt_and_test(adapter,source,next(iter(phases)))
        # Clear only the exact issue addressed by the tested adapter.
        resolved={"rail_echo":"platform-specific API requires review","flight_header":"HTTP status string needs Loon numeric-status review"}[adapter]
        issues=[i for i in issues if i!=resolved]
    else:
        generated=None
        checks=0
    return {"sha256":digest,"bytes":len(raw),"api":api,"issues":issues,
            "pinned":pinned,"adapter":adapter,"adapter_tests":checks,"generated":generated}

def convert(source):
    counts=collections.Counter()
    hosts=[]
    rewrite=[]
    scripts=[]
    filters=[]
    problems=[]
    seen_patterns=[]
    match_rules=[]
    js_urls={}
    metadata={}
    for no,raw in enumerate(source.splitlines(),1):
        line=raw.strip()
        if not line: continue
        if line.startswith(("#",";","//","!")):
            continue
        if line.startswith("[") and line.endswith("]"):
            if line.lower() not in ("[rewrite_local]","[mitm]","[rewrite]"):
                problems.append({"line":no,"reason":"unrecognized section"})
            continue
        m=re.match(r"^hostname\s*=\s*(.*)$",line,re.I)
        if m:
            for host in m[1].split(","):
                host=host.strip()
                if not host: continue
                if not re.fullmatch(r"-?[a-zA-Z0-9.*?_-]+",host):
                    problems.append({"line":no,"reason":"unrecognized MITM hostname token"})
                else: hosts.append(host)
            continue
        f=re.fullmatch(r"(host|host-suffix|host-keyword|host-wildcard)\s*,\s*([^\s,]+)\s*,\s*(direct|reject)",line,re.I)
        if f:
            kind,value,policy=f.groups()
            mapped={"host":"DOMAIN","host-suffix":"DOMAIN-SUFFIX","host-keyword":"DOMAIN-KEYWORD","host-wildcard":"DOMAIN-WILDCARD"}[kind.lower()]
            if not re.fullmatch(r"[a-zA-Z0-9.*?_-]+",value):
                problems.append({"line":no,"reason":"invalid filter domain"})
            else:
                filters.append(f"{mapped},{value},{policy.upper()}")
            continue
        m=re.fullmatch(r"(\S+)\s+url\s+([a-zA-Z0-9_-]+)(?:\s+(.*))?",line)
        if not m:
            problems.append({"line":no,"reason":"unrecognized source syntax","prefix_shape":re.sub(r"[A-Za-z0-9\u4e00-\u9fff]+","X",line[:100]),"length":len(line),"first_codepoint":ord(line[0])})
            continue
        pattern,kind,arg=m[1],m[2].lower(),m[3] or ""
        counts[kind]+=1
        seen_patterns.append((no,pattern))
        phase=SCRIPTS.get(kind,(kind.split('-')[0] if kind in BODY else ('response' if kind.startswith('jsonjq-response') else 'request'),False))[0]
        match_rules.append((no,phase,pattern,kind,arg))
        if kind in REJECTS and not arg:
            if kind == "reject":
                # QX reject returns HTTP 404, not a TCP reset.
                escaped=re.sub(r"(?<!\\)/",r"\\/",pattern)
                rewrite.append("request if ${url} ~= /"+escaped+"/ then reject(404)")
            else:
                rewrite.append(f"{pattern} {kind}")
        elif kind in BODY:
            # QX uses a repeated action token to separate regex and replacement.
            parts=re.split(r"\s+"+re.escape(kind)+r"\s+",arg,maxsplit=1)
            if len(parts)==2 and all(parts):
                regex,replacement=parts
                if "\n" in regex or "\n" in replacement:
                    problems.append({"line":no,"type":kind,"reason":"body regex whitespace needs review"})
                else:
                    escaped=re.sub(r"(?<!\\)/",r"\\/",pattern)
                    bodyregex=re.sub(r"(?<!\\)/",r"\\/",regex)
                    phase=kind.split("-")[0]
                    if chr(96) in replacement or "${" in replacement:
                        problems.append({"line":no,"reason":"replacement quoting or interpolation requires review"})
                        continue
                    literal=chr(96)+replacement+chr(96)
                    rewrite.append(f"{phase} if "+'${url}'+" ~= /"+escaped+f"/ then {phase}.body.replace(/{bodyregex}/, {literal})")
                    seen_patterns.append((no,regex))
            else:
                problems.append({"line":no,"type":kind,"reason":"body delimiter requires review","tokens":len(arg.split())})
        elif kind in JQ:
            expr=arg.strip()
            if len(expr)>=2 and expr[0]==expr[-1] and expr[0] in "'\"":
                expr=expr[1:-1]
            if not expr or "'" in expr or "\n" in expr:
                problems.append({"line":no,"type":kind,"reason":"JQ quoting requires review"})
            else:
                # jq compiles the expression even if the input is empty.
                p=subprocess.run(["jq","-n","empty | ("+expr+")"],capture_output=True,text=True,timeout=5)
                if p.returncode:
                    problems.append({"line":no,"type":kind,"reason":"JQ compilation failed"})
                else:
                    escaped=re.sub(r"(?<!\\)/",r"\\/",pattern)
                    phase="response" if kind.startswith("jsonjq-response") else "request"
                    rewrite.append(f"{phase} if "+'${url}'+" ~= /"+escaped+f"/ then {phase}.json.jq("+json.dumps(expr,ensure_ascii=False)+")")
        elif kind in SCRIPTS:
            phase,body=SCRIPTS[kind]
            u=urllib.parse.urlsplit(arg)
            if u.scheme!="https" or not u.hostname or u.username or u.password or u.query or u.fragment or re.search(r"[\s,]",arg):
                problems.append({"line":no,"type":kind,"reason":"script URL or argument requires review"})
                continue
            if arg not in js_urls: js_urls[arg]=[]
            js_urls[arg].append(no)
            binary=arg.endswith("/js/baidumap.js")
            scripts.append(f"http-{phase} {pattern} script-path={arg},requires-body={str(body).lower()},binary-body-mode={str(binary).lower()},timeout=15,tag=Moyu-{no}")
        else:
            problems.append({"line":no,"type":kind,"reason":"unsupported action; do not silently drop","script_url":arg if kind=="script-analyze-echo-response" and re.fullmatch(r"https://[A-Za-z0-9./_-]+",arg) else None})
    # JS regexp is closer to client regex than Python re; actual Loon parsing still needs device testing.
    p=subprocess.run(["node","-e",r"const a=JSON.parse(require('fs').readFileSync(0,'utf8'));console.log(JSON.stringify(a.filter(([n,s])=>{try{new RegExp(s);return false}catch(e){return true}}).map(([n])=>n)));"],input=json.dumps(seen_patterns),capture_output=True,text=True,check=True,timeout=15)
    for no in json.loads(p.stdout):
        problems.append({"line":no,"reason":"regex rejected by JS engine; review client compatibility"})
    if sum(counts.values())<450 or len(set(hosts))<400 or len(filters)<6:
        problems.append({"reason":"source below minimum baseline; possible truncation"})
    if len(rewrite)+len(scripts)!=sum(counts.values()):
        problems.append({"reason":"not all rules converted","converted":len(rewrite)+len(scripts)})
    from startupads_support import audit_conflicts
    findings=audit_conflicts(match_rules,filters,hosts)
    for finding in findings:
        print("CONFLICT "+json.dumps(finding),flush=True)
        if finding.get("blocking"): problems.append({"reason":"rule conflict requires review",**finding})
    # Exact duplicates and differing actions on same regex are reported, not silently deleted.
    patterns=collections.Counter(s for _,s in seen_patterns)
    print("INVENTORY "+json.dumps({"actions":dict(counts),"rewrite":len(rewrite),"scripts":len(scripts),
          "unique_scripts":len(js_urls),"domain_filters":len(filters),"mitm":len(set(hosts)),"duplicate_pattern_count":sum(v>1 for v in patterns.values())}),flush=True)
    return rewrite,scripts,list(dict.fromkeys(hosts)),filters,problems,js_urls

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--source-file",type=pathlib.Path)
    p.add_argument("--publish",action="store_true")
    a=p.parse_args()
    if a.publish and (a.source_file or os.environ.get("MOYU_PUBLICATION_AUTHORIZED")!="true"):
        raise SystemExit("Publication gate closed or non-official source")
    if a.source_file: raw=a.source_file.read_bytes()
    else:
        raw,final=download(URL)
        if final!=URL: raise ValueError("unexpected upstream redirect")
    source=raw.decode("utf-8-sig")
    if re.search(r"(?i)<html\b|<!doctype\s+html",source[:4096]): raise ValueError("HTML response")
    print("SOURCE "+json.dumps({"bytes":len(raw),"lines":len(source.splitlines()),"sha256":hashlib.sha256(raw).hexdigest()}),flush=True)
    rewrite,scripts,hosts,filters,issues,urls=convert(source)
    # Bound concurrent I/O; no secret or repository write access needed in validation.
    from concurrent.futures import ThreadPoolExecutor
    checked={}
    def check(item):
        url,lines=item
        phases={line.split(' ',1)[0].removeprefix('http-') for line in scripts if 'script-path='+url+',' in line}
        try: result=inspect_js(url,phases)
        except Exception as e: result={"issues":["download or syntax inspection failed: "+type(e).__name__]}
        # Only public script path (no query, credentials, or source bodies) and audit metadata in logs.
        print("SCRIPT "+json.dumps({"url":url,"lines":lines,"phases":sorted(phases),**{k:v for k,v in result.items() if k!="generated"}}),flush=True)
        return url,result,[{"line":n,"reason":reason} for n in lines for reason in result["issues"]]
    with ThreadPoolExecutor(max_workers=4) as pool:
        for url,result,found in pool.map(check,urls.items()):
            checked[url]=result
            issues.extend(found)
    for issue in issues: print("ISSUE "+json.dumps(issue),flush=True)
    print("RESULT "+json.dumps({"issues":len(issues),"publish_ready":not issues,"converted":len(rewrite)+len(scripts),"domain_filters":len(filters),"mitm":len(hosts)}),flush=True)
    if issues: raise SystemExit(2)
    if not a.publish: return
    if os.environ.get("MOYU_PUBLICATION_AUTHORIZED")!="true": raise SystemExit("Independent authorization gate is closed")
    # Never link a mutable upstream JS reference. Generated adapters are versioned.
    generated_files={}
    for original,result in checked.items():
        target=result["pinned"]
        if result.get("generated"):
            code=result["generated"]
            digest=hashlib.sha256(code.encode()).hexdigest()[:20]
            name=f"moyu-{result['adapter']}-{digest}.js"
            generated_files[name]=code
            target="https://raw.githubusercontent.com/TTTi222/Loon-Plugins/main/scripts/"+name
        scripts=[line.replace("script-path="+original+",","script-path="+target+",") for line in scripts]
    for name,code in generated_files.items():
        pathlib.Path("scripts",name).write_text(code,encoding="utf-8")
    output="\n".join(["#!name = 墨鱼去开屏 2.0","#!author = ddgksf2013","# Loon conversion: TTTi222; requires Loon 3.5.1 (978)+",
           "# Source: "+URL,"# SHA-256: "+hashlib.sha256(raw).hexdigest(),"","[Rule]"]+filters+["","[Rewrite]"]+rewrite+["","[Script]"]+scripts+["","[MITM]","hostname = "+", ".join(hosts),""])
    out=pathlib.Path("plugins/StartUpAds.lpx")
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(output,encoding="utf-8")
    out.with_suffix(".version.json").write_text(json.dumps({"source":URL,"sha256":hashlib.sha256(raw).hexdigest(),"rules":len(rewrite)+len(scripts),"domain_filters":len(filters),"mitm":len(hosts),"scripts":[{"source":url,"pinned":result["pinned"],"sha256":result["sha256"],"adapter":result.get("adapter")} for url,result in sorted(checked.items())]},indent=2)+"\n")

if __name__=="__main__":
    main()
