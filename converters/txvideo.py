#!/usr/bin/env python3
"""Convert the known TxvideoAD QX format to Loon; fail closed on unsupported changes."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.request import Request, urlopen

UPSTREAM = "ZenmoFeiShi/Qx"
SCRIPT = "Txvideoad.js"
SNIPPET = "TxvideoAD.snippet"
EXPECTED_HOSTS = {"i.video.qq.com", "iacc.qq.com", "config.ab.qq.com", "rdelivery.qq.com"}

def get(url):
    with urlopen(Request(url, headers={"User-Agent": "Loon-Plugins-sync"}), timeout=45) as r:
        data = r.read(2_000_001)
    if not data or len(data) > 2_000_000:
        raise ValueError("Invalid upstream file size")
    return data.decode("utf-8-sig")

def adapt_js(source):
    replacements = {
        "$request.bodyBytes": "$request.body",
        "$response.bodyBytes": "$response.body",
        "bodyBytes: toBuf(r)": "body: r",
    }
    for old, new in replacements.items():
        count = 2 if old == "bodyBytes: toBuf(r)" else 1
        if source.count(old) != count:
            raise ValueError("Unexpected API pattern; manual review required: " + old)
        source = source.replace(old, new)
    if "bodyBytes" in source:
        raise ValueError("Unconverted binary API")
    return source

def adapt_rules(source, js_url):
    headers, rules, scripts, hosts = [], [], [], []
    seen = set()
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
        m = re.fullmatch(r"host\s*,\s*([a-zA-Z0-9.-]+)\s*,\s*reject", line, re.I)
        if m:
            rules.append("DOMAIN," + m[1] + ",REJECT")
            continue
        m = re.fullmatch(r"(.+?)\s+url\s+script-(request|response)-body\s+(\S+)", line)
        if not m:
            raise ValueError("Unsupported QX rule: " + line)
        pattern, kind, url = m.groups()
        if url not in {f"https://raw.githubusercontent.com/{UPSTREAM}/refs/heads/main/{SCRIPT}", f"https://raw.githubusercontent.com/{UPSTREAM}/main/{SCRIPT}"}:
            raise ValueError("Unexpected script URL")
        re.compile(pattern)
        # Match sample URLs rather than guessing the body mode from script filename.
        samples = {
            "i.video.qq.com": "https://i.video.qq.com/",
            "iacc.qq.com": "https://iacc.qq.com/",
            "config.ab.qq.com": "https://config.ab.qq.com/tab/GetTabRemoteConfig",
            "rdelivery.qq.com": "https://rdelivery.qq.com/v1/sdkconfig/get",
        }
        matched = [host for host, sample in samples.items() if re.search(pattern, sample)]
        if len(matched) != 1:
            raise ValueError("Ambiguous script pattern")
        host = matched[0]
        key = (kind, host)
        if key in seen:
            raise ValueError("Duplicate script")
        seen.add(key)
        binary = "false" if host == "rdelivery.qq.com" else "true"
        scripts.append(f"http-{kind} {pattern} script-path={js_url},requires-body=true,binary-body-mode={binary},timeout=15,tag=Txvideo-{kind}-{host}")
    expected = {("request", "i.video.qq.com")} | {("response", h) for h in EXPECTED_HOSTS}
    if seen != expected or set(hosts) != EXPECTED_HOSTS or len(hosts) != 4:
        raise ValueError("Changed script routes or MITM hosts: manual review required")
    if len(rules) != 2 or len(set(rules)) != 2:
        raise ValueError("Changed domain rules: manual review required")
    return "\n".join(headers + ["", "[Rule]"] + rules + ["", "[Script]"] + scripts + ["", "[MITM]", "hostname = " + ", ".join(hosts), ""])

def main():
    commit = json.loads(get(f"https://api.github.com/repos/{UPSTREAM}/commits/main"))["sha"]
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError("Invalid upstream commit")
    base = f"https://raw.githubusercontent.com/{UPSTREAM}/{commit}"
    js = adapt_js(get(f"{base}/{SCRIPT}"))
    repository = os.environ.get("GITHUB_REPOSITORY", "TTTi222/Loon-Plugins")
    # Content-addressed script URL avoids mismatched plugin/script versions.
    digest = hashlib.sha256(js.encode()).hexdigest()
    rel_js = f"scripts/Txvideoad-{digest[:20]}.js"
    plugin = adapt_rules(get(f"{base}/{SNIPPET}"), f"https://raw.githubusercontent.com/{repository}/main/{rel_js}")
    with tempfile.TemporaryDirectory() as tmp:
        check = Path(tmp) / "check.js"
        check.write_text(js, encoding="utf-8")
        subprocess.run(["node", "--check", str(check)], check=True)
    print("Static checks passed: 2 domain rules, 5 scripts (4 binary, 1 text), 4 MITM hosts")
    print("Upstream commit:", commit)
    print("Adapted script SHA256:", digest)
    if os.environ.get("PUBLISH_AUTHORIZED") != "true":
        print("Dry run only; publication is disabled pending upstream permission.")
        return
    for name, content in [(rel_js, js), ("plugins/TxvideoAD.lpx", plugin), ("plugins/TxvideoAD.version.json", json.dumps({"upstream": UPSTREAM, "commit": commit, "sha256": digest}, indent=2)+"\n")]:
        path = Path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

if __name__ == "__main__":
    main()
