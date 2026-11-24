#!/usr/bin/env python3
"""Strict QX MT.snippet -> Loon converter; upstream JS remains upstream-hosted."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.request import Request, urlopen

UPSTREAM = "ZenmoFeiShi/Qx"
ROUTES = [
    "https://apimobile.meituan.com/aggroup/indexTab",
    "https://feedguess.meituan.com/lycoris/scene/gwc_feed1_2265",
    "https://mt-personalcenter.meituan.com/usercenter/display",
    "https://apimobile.meituan.com/group/v1/deal/searchpage/defaultword",
    "https://apimobile.meituan.com/group/v1/deal/searchpage/hotword/city/divide/hotrecommend/",
    "https://assistify.meituan.com/assistant/getAppClientHornConfig",
    "https://mop.meituan.com/mop/entry/shoppingCartEntry",
    "https://mop.meituan.com/api/entryModule/startupPicture",
]
HOSTS = {"apimobile.meituan.com", "feedguess.meituan.com", "mop.meituan.com",
         "mt-personalcenter.meituan.com", "assistify.meituan.com",
         "httpdns.meituan.com", "httpdnsmultiapi.meituan.com"}

def get(url):
    with urlopen(Request(url, headers={"User-Agent": "Loon-Plugins-sync"}), timeout=45) as r:
        data = r.read(2_000_001)
    if not data or len(data) > 2_000_000:
        raise ValueError("Invalid upstream file size")
    return data.decode("utf-8-sig")

def convert(source, script_url):
    headers, rules, rewrites, scripts, hosts = [], [], [], [], []
    seen_routes = set()
    counts = {"host": 0, "host-wildcard": 0, "ip-cidr": 0, "ip6-cidr": 0}
    allowed_scripts = {f"https://raw.githubusercontent.com/{UPSTREAM}/refs/heads/main/MT.js",
                       f"https://raw.githubusercontent.com/{UPSTREAM}/main/MT.js"}
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
        m = re.fullmatch(r"(host|host-wildcard|ip-cidr|ip6-cidr)\s*,\s*([^,\s]+)\s*,\s*reject", line, re.I)
        if m:
            kind, value = m.groups()
            kind = kind.lower()
            counts[kind] += 1
            if kind.startswith("ip"):
                net = ipaddress.ip_network(value, strict=True)
                if net.version != (4 if kind == "ip-cidr" else 6):
                    raise ValueError("IP family mismatch")
                rule = ("IP-CIDR" if net.version == 4 else "IP-CIDR6") + "," + str(net) + ",REJECT,no-resolve"
            elif kind == "host-wildcard":
                if not re.fullmatch(r"[a-zA-Z0-9.*?-]+", value) or "*" not in value:
                    raise ValueError("Unsupported glob")
                rule = "DOMAIN-WILDCARD," + value + ",REJECT"
            else:
                if not re.fullmatch(r"[a-zA-Z0-9.-]+", value):
                    raise ValueError("Invalid hostname")
                rule = "DOMAIN," + value + ",REJECT"
            if rule in rules:
                raise ValueError("Duplicate network rule")
            rules.append(rule)
            continue
        m = re.fullmatch(r"(.+?)\s+url\s+reject", line)
        if m:
            re.compile(m[1])
            rewrites.append(m[1] + " reject")
            continue
        m = re.fullmatch(r"(.+?)\s+url\s+script-response-body\s+(\S+)", line)
        if not m or m[2] not in allowed_scripts:
            raise ValueError("Unsupported rule: " + line)
        pattern = m[1]
        matches = [i for i, url in enumerate(ROUTES) if re.search(pattern, url)]
        if len(matches) != 1 or matches[0] in seen_routes:
            raise ValueError("Changed or overlapping response route")
        idx = matches[0]
        seen_routes.add(idx)
        scripts.append(f"http-response {pattern} script-path={script_url},requires-body=true,binary-body-mode=false,timeout=15,tag=MT-response-{idx+1}")
    if set(hosts) != HOSTS or len(hosts) != len(HOSTS):
        raise ValueError("Changed MITM hosts: review required")
    if seen_routes != set(range(len(ROUTES))) or len(rewrites) != 2 or len(set(rewrites)) != 2:
        raise ValueError("Changed response/rewrite routes: review required")
    if not all(counts.values()):
        raise ValueError("Missing rule category")
    if not any(h.startswith("#!author") for h in headers):
        raise ValueError("Missing upstream author")
    result = "\n".join(headers + ["#!desc = Loon compatibility conversion; upstream JS referenced directly",
        "# Requires Loon Build 1008+ for DOMAIN-WILDCARD.", "", "[Rule]"] + rules +
        ["", "[Rewrite]"] + rewrites + ["", "[Script]"] + scripts +
        ["", "[MITM]", "hostname = " + ", ".join(hosts), ""])
    print("Network rules:", counts, "Rewrite:", len(rewrites), "Scripts:", len(scripts), "MITM:", len(hosts))
    return result

def main():
    commit = json.loads(get(f"https://api.github.com/repos/{UPSTREAM}/commits/main"))["sha"]
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError("Invalid upstream commit")
    base = f"https://raw.githubusercontent.com/{UPSTREAM}/{commit}"
    js = get(base + "/MT.js")
    # No adapted JS is stored or published. Pin the tested revision.
    if "bodyBytes" in js or re.search(r"\$(task|prefs)\b", js):
        raise ValueError("New incompatible API: review required")
    for token in ("$request.url", "$response.body", "$done(", "JSON.parse"):
        if token not in js:
            raise ValueError("Changed text API: review required")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "MT.js"
        path.write_text(js, encoding="utf-8")
        subprocess.run(["node", "--check", str(path)], check=True)
        # Exercise the actual upstream JS in a mock Loon text environment.
        fixture = Path(tmp) / "smoke.cjs"
        fixture.write_text(r"""
const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
const js = fs.readFileSync(process.argv[2], 'utf8');
const cases = [
  ['/aggroup/indexTab', {data:{resource:{tabArea:[{tabName:'homepage'},{tabName:'mine'},{tabName:'video'},{tabName:'xiaotuan'}]}}}, o=>o.data.resource.tabArea.length===2],
  ['/lycoris/scene/gwc_feed1_2265', {data:[1]}, o=>o.data.length===0 && o.bottom===true],
  ['/usercenter/display', {children:[{name:'mine_cross_recommend'},{name:'keep'}]}, o=>o.children.length===1 && o.children[0].name==='keep'],
  ['/searchpage/defaultword', {searchIntroduceResponse:{defaultWordRes:{defaultWordItems:[1]},HotWordInfos:[1]}}, o=>o.searchIntroduceResponse.defaultWordRes.defaultWordItems.length===0 && o.searchIntroduceResponse.HotWordInfos.length===0],
  ['/searchpage/hotword/city/divide/hotrecommend/', {data:{segmentsV2:[{hotwordSegments:[{pageName:'EntranceHotwordsV2Hotwords'}]}],aiSearchBubble:{bubbleTexts:[1]}}}, o=>o.data.segmentsV2.length===0 && o.data.aiSearchBubble.bubbleTexts.length===0],
  ['/assistant/getAppClientHornConfig', {data:JSON.stringify({skills:{a:1}})}, o=>Object.keys(JSON.parse(o.data).skills).length===0],
  ['/mop/entry/shoppingCartEntry', {resourcesMap:{topBannerArea:[1]}}, o=>o.resourcesMap.topBannerArea.length===0],
  ['/api/entryModule/startupPicture', {data:{resource:{startupPicArea:[1]}}}, o=>o.data.resource.startupPicArea.length===0]
];
function run(url, body) {
  const results=[];
  vm.runInNewContext(js, {$request:{url:'https://example.test'+url},$response:{body},$done:v=>results.push(v),console:{log(){}}}, {timeout:2000});
  assert.equal(results.length,1);
  return results[0];
}
for (const [url, body, check] of cases) {
  const result = run(url, JSON.stringify(body));
  assert.equal(typeof result.body,'string',url);
  assert.ok(check(JSON.parse(result.body)),url);
}
assert.equal(Object.keys(run('/aggroup/indexTab','invalid json')).length,0);
assert.equal(Object.keys(run('/unknown','{}')).length,0);
console.log('8 mock response routes and 2 pass-through cases passed');
""", encoding="utf-8")
        subprocess.run(["node", str(fixture), str(path)], check=True)
    output = convert(get(base + "/MT.snippet"), base + "/MT.js")
    print("Static checks passed; upstream commit:", commit)
    if os.environ.get("PUBLISH_AUTHORIZED") != "true":
        print("Dry run only: publication disabled.")
        return
    path = Path("plugins/MT.lpx")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(output, encoding="utf-8")
    Path("plugins/MT.version.json").write_text(json.dumps({
        "upstream": UPSTREAM, "commit": commit,
        "script_sha256": hashlib.sha256(js.encode()).hexdigest(),
        "script_hosting": "upstream", "minimum_loon_build": 1008
    }, indent=2)+"\n", encoding="utf-8")

if __name__ == "__main__":
    main()
