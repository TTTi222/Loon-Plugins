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

def inspect_js(url):
    raw,final=download(url,2_000_000)
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
    if re.search(r"(?i)(?:vip[_-]?ticket|unlock[_-]?vip|authorization\s*[:=]|cookie\s*[:=])",source):
        issues.append("credential or entitlement handling requires review")
    return {"sha256":hashlib.sha256(raw).hexdigest(),"bytes":len(raw),"api":api,"issues":issues,
            "redirected":final!=url}

def convert(source):
    counts=collections.Counter()
    hosts=[]
    rewrite=[]
    scripts=[]
    problems=[]
    seen_patterns=[]
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
        m=re.fullmatch(r"(\S+)\s+url\s+([a-zA-Z0-9_-]+)(?:\s+(.*))?",line)
        if not m:
            problems.append({"line":no,"reason":"unrecognized source syntax","prefix_shape":re.sub(r"[A-Za-z0-9\u4e00-\u9fff]+","X",line[:100]),"length":len(line),"first_codepoint":ord(line[0])})
            continue
        pattern,kind,arg=m[1],m[2].lower(),m[3] or ""
        counts[kind]+=1
        seen_patterns.append((no,pattern))
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
                if re.search(r"\s",regex) or "\n" in replacement:
                    problems.append({"line":no,"type":kind,"reason":"body regex whitespace needs review"})
                else:
                    escaped=re.sub(r"(?<!\\)/",r"\\/",pattern)
                    bodyregex=re.sub(r"(?<!\\)/",r"\\/",regex)
                    phase=kind.split("-")[0]
                    literal=chr(96)+replacement.replace(chr(96),chr(96)*2)+chr(96)
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
                else: rewrite.append(f"{pattern} {JQ[kind]} '{expr}'")
        elif kind in SCRIPTS:
            phase,body=SCRIPTS[kind]
            u=urllib.parse.urlsplit(arg)
            if u.scheme!="https" or not u.hostname or u.username or u.password or u.query or u.fragment or re.search(r"[\s,]",arg):
                problems.append({"line":no,"type":kind,"reason":"script URL or argument requires review"})
                continue
            if arg not in js_urls: js_urls[arg]=[]
            js_urls[arg].append(no)
            scripts.append(f"http-{phase} {pattern} script-path={arg},requires-body={str(body).lower()},binary-body-mode=false,timeout=15,tag=Moyu-{no}")
        else:
            problems.append({"line":no,"type":kind,"reason":"unsupported action; do not silently drop","script_url":arg if kind=="script-analyze-echo-response" and re.fullmatch(r"https://[A-Za-z0-9./_-]+",arg) else None})
    # JS regexp is closer to client regex than Python re; actual Loon parsing still needs device testing.
    p=subprocess.run(["node","-e",r"const a=JSON.parse(require('fs').readFileSync(0,'utf8'));console.log(JSON.stringify(a.filter(([n,s])=>{try{new RegExp(s);return false}catch(e){return true}}).map(([n])=>n)));"],input=json.dumps(seen_patterns),capture_output=True,text=True,check=True,timeout=15)
    for no in json.loads(p.stdout):
        problems.append({"line":no,"reason":"regex rejected by JS engine; review client compatibility"})
    if sum(counts.values())<450 or len(set(hosts))<400:
        problems.append({"reason":"source below minimum baseline; possible truncation"})
    if len(rewrite)+len(scripts)!=sum(counts.values()):
        problems.append({"reason":"not all rules converted","converted":len(rewrite)+len(scripts)})
    # Exact duplicates and differing actions on same regex are reported, not silently deleted.
    patterns=collections.Counter(s for _,s in seen_patterns)
    print("INVENTORY "+json.dumps({"actions":dict(counts),"rewrite":len(rewrite),"scripts":len(scripts),
          "unique_scripts":len(js_urls),"mitm":len(set(hosts)),"duplicate_pattern_count":sum(v>1 for v in patterns.values())}),flush=True)
    return rewrite,scripts,list(dict.fromkeys(hosts)),problems,js_urls

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--source-file",type=pathlib.Path)
    p.add_argument("--publish",action="store_true")
    a=p.parse_args()
    raw=a.source_file.read_bytes() if a.source_file else download(URL)[0]
    source=raw.decode("utf-8-sig")
    if re.search(r"(?i)<html\b|<!doctype\s+html",source[:4096]): raise ValueError("HTML response")
    print("SOURCE "+json.dumps({"bytes":len(raw),"lines":len(source.splitlines()),"sha256":hashlib.sha256(raw).hexdigest()}),flush=True)
    rewrite,scripts,hosts,issues,urls=convert(source)
    # Bound concurrent I/O; no secret or repository write access needed in validation.
    from concurrent.futures import ThreadPoolExecutor
    def check(item):
        url,lines=item
        try: result=inspect_js(url)
        except Exception as e: result={"issues":["download or syntax inspection failed: "+type(e).__name__]}
        # Only public script path (no query, credentials, or source bodies) and audit metadata in logs.
        print("SCRIPT "+json.dumps({"url":url,"lines":lines,**result}),flush=True)
        return [{"line":n,"reason":reason} for n in lines for reason in result["issues"]]
    with ThreadPoolExecutor(max_workers=4) as pool:
        for found in pool.map(check,urls.items()): issues.extend(found)
    for issue in issues: print("ISSUE "+json.dumps(issue),flush=True)
    print("RESULT "+json.dumps({"issues":len(issues),"publish_ready":not issues,"converted":len(rewrite)+len(scripts),"mitm":len(hosts)}),flush=True)
    if issues: raise SystemExit(2)
    if not a.publish: return
    if os.environ.get("MOYU_PUBLICATION_AUTHORIZED")!="true": raise SystemExit("Independent authorization gate is closed")
    output="\n".join(["#!name = 墨鱼去开屏 2.0","#!author = ddgksf2013","# Loon conversion: TTTi222",
           "# Source: "+URL,"# SHA-256: "+hashlib.sha256(raw).hexdigest(),"","[Rewrite]"]+rewrite+["","[Script]"]+scripts+["","[MITM]","hostname = "+", ".join(hosts),""])
    out=pathlib.Path("plugins/StartUpAds.lpx")
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(output,encoding="utf-8")
    out.with_suffix(".version.json").write_text(json.dumps({"source":URL,"sha256":hashlib.sha256(raw).hexdigest(),"rules":len(rewrite)+len(scripts),"mitm":len(hosts)},indent=2)+"\n")

if __name__=="__main__":
    main()
