#!/usr/bin/env python3
"""HelloBike QX -> Loon; strict routes and fail-open runtime compatibility."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.request import Request, urlopen

UPSTREAM = "ZenmoFeiShi/Qx"
HOSTS = {"api.hellobike.com", "taxiapi.hellobike.com", "marketingapi.hellobike.com",
         "entertainment.hellobike.com", "api-htp.beizi.biz", "adservice.sigmob.cn",
         "tm.sigmob.cn", "mi.gdt.qq.com", "v2mi.gdt.qq.com", "resource.51downapp.cn"}
SAMPLES = [
    ("script-echo-response", "https://resource.51downapp.cn/f414fbc17c411b4e986ba8891c738a49.json?md5=e5230c919f7e3f3af3256161fbfaa0e2&hbe_qx_ui=1.3"),
    ("script-response-body", "https://api.hellobike.com/secretkey"),
    ("script-request-body", "https://api.hellobike.com/api"),
    ("script-response-body", "https://api.hellobike.com/api"),
    ("script-response-body", "https://taxiapi.hellobike.com/api"),
]
REJECT_SAMPLES = [
    "https://api-htp.beizi.biz/mb/sdk0/json",
    "https://adservice.sigmob.cn/hb/v2/ad",
    "https://tm.sigmob.cn/waterfall/v1",
    "https://mi.gdt.qq.com/gdt_mview.fcg",
]

def get(url):
    with urlopen(Request(url, headers={"User-Agent": "Loon-Plugins-sync"}), timeout=45) as r:
        data = r.read(2_000_001)
    if not data or len(data) > 2_000_000:
        raise ValueError("Invalid upstream file size")
    return data.decode("utf-8-sig")

# Use local persistent storage only. Never clear the global store.
# Loon does not document QX sessionIndex; original direct request-body fallback
# is retained. Do not synthesize session IDs or guess across concurrent requests.
SHIM = r"""
/* Loon compatibility layer; upstream author TG@ZenMoFiShi. */
(function (loonDone, loonRequest, loonResponse) {
    const $request = loonRequest;
    const $response = loonResponse && Object.assign({}, loonResponse, {
        statusCode: Number(loonResponse.status || loonResponse.statusCode)
    });
    const $prefs = {
        valueForKey: key => $persistentStore.read("LoonHelloBike:" + key),
        setValueForKey: (value, key) => $persistentStore.write(value, "LoonHelloBike:" + key),
        removeValueForKey: key => $persistentStore.write(undefined, "LoonHelloBike:" + key)
    };
    const $notify = (title, subtitle, message) => {
        if (typeof $notification !== "undefined")
            $notification.post(title, subtitle, message.replace("QX 本机", "Loon 本机"));
    };
    const $done = result => {
        result = result || {};
        if (!loonResponse && typeof result.status === "string") {
            const match = /^HTTP\/\d(?:\.\d)?\s+(\d{3})\b/.exec(result.status);
            if (!match) return loonDone({});
            return loonDone({response: {status: Number(match[1]), headers: result.headers || {}, body: result.body || ""}});
        }
        return loonDone(result);
    };
"""
END_SHIM = '\n})( $done, typeof $request === "undefined" ? {} : $request, typeof $response === "undefined" ? undefined : $response );\n'

def adapt_js(js):
    # Contract changes require review. No unreviewed changed JS is published.
    expected = ["$prefs.valueForKey", "$prefs.setValueForKey", "$prefs.removeValueForKey",
                "$notify(", ".sessionIndex", "function hbeTakeContext", "var hbeDirect = hbeRequestMeta(hbeRequest)",
                "function hbeCapitalTemplateEcho", "hbeResponse.statusCode", "hbeRes.statusCode"]
    if not all(x in js for x in expected):
        raise ValueError("Changed upstream API contract")
    for bad in ("$task", "$httpClient", "$fetch", "$response.bodyBytes", "$request.bodyBytes"):
        if bad in js:
            raise ValueError("Unexpected upstream API: " + bad)
    return SHIM + js + END_SHIM

def convert(source, js_url):
    headers, rewrites, scripts, hosts = [], [], [], []
    seen, rejected = set(), set()
    expected_urls = {f"https://raw.githubusercontent.com/{UPSTREAM}/main/easybike-ad.js",
                     f"https://raw.githubusercontent.com/{UPSTREAM}/refs/heads/main/easybike-ad.js"}
    for raw in source.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#!"):
            headers.append(line)
            continue
        if line.startswith("#"):
            continue
        if line.startswith("hostname"):
            if hosts or "=" not in line:
                raise ValueError("Unexpected hostname declaration")
            hosts = [h.strip() for h in line.split("=", 1)[1].split(",")]
            continue
        m = re.fullmatch(r"(.+?)\s+url\s+reject-200", line)
        if m:
            pattern = m[1]
            matches = [i for i,u in enumerate(REJECT_SAMPLES) if re.search(pattern,u)]
            if len(matches) != 1 or matches[0] in rejected:
                raise ValueError("Changed ad reject route")
            rejected.add(matches[0])
            rewrites.append(pattern + " reject-200")
            continue
        m = re.fullmatch(r"(.+?)\s+url\s+(script-echo-response|script-request-body|script-response-body)\s+(\S+)", line)
        if not m or m[3] not in expected_urls:
            raise ValueError("Unsupported rule: " + line)
        pattern, kind = m[1], m[2]
        matches = [i for i,(k,u) in enumerate(SAMPLES) if kind == k and re.search(pattern,u)]
        if len(matches) != 1 or matches[0] in seen:
            raise ValueError("Changed script route")
        idx = matches[0]
        seen.add(idx)
        phase = "response" if kind == "script-response-body" else "request"
        body = "false" if kind == "script-echo-response" else "true"
        scripts.append(f"http-{phase} {pattern} script-path={js_url},requires-body={body},binary-body-mode=false,timeout=20,tag=HelloBike-{idx+1}")
    if seen != set(range(5)) or rejected != set(range(4)) or set(hosts) != HOSTS or len(hosts) != 10:
        raise ValueError("Changed route or MITM inventory")
    if not any(h.startswith("#!author") for h in headers):
        raise ValueError("Missing upstream author")
    return "\n".join(headers + ["# Loon: safe pass-through when request context is unavailable.", "", "[Rewrite]"] + rewrites +
                     ["", "[Script]"] + scripts + ["", "[MITM]", "hostname = " + ", ".join(hosts), ""])

def main():
    ref = subprocess.check_output(["git","ls-remote","--exit-code",f"https://github.com/{UPSTREAM}.git","refs/heads/main"],text=True,timeout=45).strip()
    commit, branch = ref.split()
    if branch != "refs/heads/main" or not re.fullmatch(r"[a-f0-9]{40}",commit):
        raise ValueError("Invalid upstream revision")
    base = f"https://raw.githubusercontent.com/{UPSTREAM}/{commit}"
    js = adapt_js(get(base + "/easybike-ad.js"))
    digest = hashlib.sha256(js.encode()).hexdigest()
    rel = f"scripts/easybike-ad-{digest[:20]}.js"
    repo = os.environ.get("GITHUB_REPOSITORY","TTTi222/Loon-Plugins")
    plugin = convert(get(base + "/helloobike.snippet"),f"https://raw.githubusercontent.com/{repo}/main/{rel}")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp)/"hello.js"
        path.write_text(js,encoding="utf-8")
        subprocess.run(["node","--check",str(path)],check=True)
        test = Path(tmp)/"test.cjs"
        test.write_text(r"""
const fs=require('node:fs'), vm=require('node:vm'), assert=require('node:assert/strict');
const js=fs.readFileSync(process.argv[2],'utf8'), store=new Map();
function run(req,res) {
  const results=[];
  vm.runInNewContext(js,{$request:req,$response:res,$done:x=>results.push(x),
    $persistentStore:{read:k=>store.get(k),write:(v,k)=>{if(v===undefined)store.delete(k);else store.set(k,v);return true;}},
    $notification:{post(){}},console:{log(){}}},{timeout:4000});
  assert.equal(results.length,1);
  return results[0];
}
const api='https://api.hellobike.com/api';
const req={url:api,method:'POST',headers:{},body:JSON.stringify({action:'homepage.startup.popupWindow'})};
const body=JSON.stringify({code:0,data:[{popupWindowType:'marketAd',popupWindowData:{}},{popupWindowType:'keep',popupWindowData:{}}]});
assert.equal(Object.keys(run(req,undefined)).length,0);
const result=run(req,{status:200,body});
assert.equal(typeof result.body,'string');
assert.equal(JSON.parse(result.body).data.length,1);
assert.equal(JSON.parse(result.body).data[0].popupWindowType,'keep');
assert.equal(Object.keys(run({...req,body:undefined},{status:200,body})).length,0);
assert.equal(Object.keys(run(req,{status:500,body})).length,0);
assert.equal(Object.keys(run(req,{status:200,body:'invalid'})).length,0);
const echo=run({url:'https://resource.51downapp.cn/f414fbc17c411b4e986ba8891c738a49.json?md5=e5230c919f7e3f3af3256161fbfaa0e2&hbe_qx_ui=1.3',method:'GET',headers:{}},undefined);
assert.equal(echo.response.status,200);
assert.ok(JSON.parse(echo.response.body));
console.log('Mock tests passed: request, popup cleanup, missing context, HTTP error, invalid data, echo');
""",encoding="utf-8")
        subprocess.run(["node",str(test),str(path)],check=True)
    print("Static checks passed: 4 rewrites, 5 scripts, 10 MITM hosts",commit)
    if os.environ.get("PUBLISH_AUTHORIZED") != "true":
        print("Dry run only")
        return
    for name, content in [(rel,js),("plugins/helloobike.lpx",plugin),("plugins/helloobike.version.json",json.dumps({"upstream":UPSTREAM,"commit":commit,"sha256":digest,"limitations":"request body required for direct correlation; no invented sessionIndex"},indent=2)+"\n")]:
        dest=Path(name)
        dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_text(content,encoding="utf-8")

if __name__=="__main__":
    main()
