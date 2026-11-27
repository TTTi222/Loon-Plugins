"""Moyu converter support: narrow tested adaptations and conservative conflict audit."""
import collections
import fnmatch
import json
import pathlib
import re
import subprocess

# Independent Loon implementations of the inspected ad-only behavior.
# Original rule author: ddgksf2013. No upstream credentials or opaque code included.
ADAPTERS = {
    "rail_echo": r"""
(function(){
  try {
    var input=JSON.parse($request.body);
    if (!input || typeof input !== "object" || Array.isArray(input)) return $done({});
    var value;
    if (input.placementNo === "0007") {
      value={code:"00",materialsList:[{billMaterialsId:"6491",filePath:"ddgksf2013",creativeType:1}],advertParam:{skipTime:1}};
    } else if (input.placementNo === "G0054") {
      value={code:"00",materialsList:[{}]};
    } else {
      value={code:"00",message:"无广告返回"};
    }
    return $done({response:{status:200,headers:{"Content-Type":"application/json; charset=utf-8"},body:JSON.stringify(value)}});
  } catch (_) { return $done({}); }
})();
""",
    "flight_header": r"""
(function(){
  var headers=($request && $request.headers)||{};
  var key=Object.keys(headers).find(function(k){return k.toLowerCase()==="rpid";});
  var value=key && headers[key];
  if(typeof value==="string" && (value.includes("10000012")||value.includes("1000019"))) {
    return $done({response:{status:404,headers:{},body:""}});
  }
  return $done({});
})();
"""
}

def adapt_and_test(name, source):
    # Pinning and exact digest checking are the caller's responsibility.
    # Refuse a semantic mismatch even if a caller accidentally changes the digest.
    required={"rail_echo":("placementNo","0007","G0054","$request.body","$done"),
              "flight_header":("10000012","1000019","rpid","HTTP/1.1 404","$done")}
    if not all(s in source for s in required[name]): raise ValueError("adapter source mismatch")
    code="// Loon adaptation; original ad behavior: ddgksf2013\n"+ADAPTERS[name].strip()+"\n"
    tests={
      "rail_echo":[
        [{"body":'{"placementNo":"0007"}'},200,"0007"],
        [{"body":'{"placementNo":"G0054"}'},200,"G0054"],
        [{"body":'{"placementNo":"other"}'},200,"other"],
        [{"body":"invalid"},None,None],
        [{"body":"null"},None,None],
        [{},None,None]],
      "flight_header":[
        [{"headers":{"rpid":"10000012"}},404,None],
        [{"headers":{"Rpid":"1000019"}},404,None],
        [{"headers":{"RPID":"xx10000012xx"}},404,None],
        [{"headers":{"rpid":"ordinary"}},None,None],
        [{"headers":{}},None,None],
        [{},None,None]]
    }[name]
    harness=r"""
const vm=require("vm"), assert=require("assert");
const data=JSON.parse(require("fs").readFileSync(0,"utf8"));
for (const [request,status,placement] of data.tests) {
  let calls=[];
  vm.runInNewContext(data.code,{$request:request,$done:x=>calls.push(x)},{timeout:500});
  assert.equal(calls.length,1);
  const result=calls[0];
  if(status===null) assert.equal(Object.keys(result).length,0);
  else {
    assert.equal(result.response.status,status);
    if(placement!==null) {
      const body=JSON.parse(result.response.body);
      assert.equal(body.code,"00");
      if(placement==="0007"){assert.equal(body.advertParam.skipTime,1);assert.equal(body.materialsList[0].creativeType,1);}
      if(placement==="G0054")assert.equal(Object.keys(body.materialsList[0]).length,0);
      if(placement==="other")assert.equal(body.message,"无广告返回");
    }
  }
}
console.log(data.tests.length);
"""
    proc=subprocess.run(["node","-e",harness],input=json.dumps({"code":code,"tests":tests}),text=True,capture_output=True,timeout=10,check=True)
    return code,int(proc.stdout.strip())

def pattern_key(p):
    return p.replace(r"\/","/")

def read_existing(root):
    for name in ("TxvideoAD.lpx","MT.lpx","helloobike.lpx"):
        file=root/"plugins"/name
        if not file.is_file(): raise ValueError("existing plugin missing: "+name)
        section=""
        for no,line in enumerate(file.read_text(encoding="utf-8-sig").splitlines(),1):
            line=line.strip()
            if not line or line.startswith("#"):continue
            if line.startswith("["):section=line;continue
            if section=="[Script]":
                m=re.match(r"http-(request|response)\s+(\S+)\s+(.+)",line)
                if m:yield (name,no,m[1],m[2],"script",m[3])
            elif section=="[Rewrite]":
                m=re.match(r"(\S+)\s+(\S+)",line)
                if m:yield (name,no,"request",m[1],m[2],line)
            elif section=="[Rule]":
                bits=line.split(",")
                if len(bits)>=3 and bits[0].startswith("DOMAIN"):yield (name,no,"filter",bits[1],bits[0],bits[2])
            elif section=="[MITM]" and line.startswith("hostname"):
                for host in line.partition("=")[2].split(","):
                    yield (name,no,"mitm",host.strip(),"hostname","")

def literal_prefix(pattern):
    # Conservative literal URL prefix only; not a proof of regex intersection.
    p=pattern_key(pattern)
    p=p.removeprefix("^").replace("https?://","https://",1)
    if not p.startswith(("https://","http://")):return None
    out=""
    i=0
    while i<len(p):
        c=p[i]
        if c=="\\" and i+1<len(p) and p[i+1] in ".-/_":
            out+=p[i+1];i+=2;continue
        if c in r".+?*()[]{}$|\\":break
        out+=c;i+=1
    return out if "/" in out.split("://",1)[-1] else None

def audit_conflicts(rules,filters,hosts,root=None):
    if root is None:root=pathlib.Path(__file__).resolve().parent.parent
    existing=list(read_existing(root))
    findings=[]
    groups=collections.defaultdict(list)
    for no,phase,pattern,kind,arg in rules:groups[(phase,pattern_key(pattern))].append((no,kind,arg))
    for (phase,_),entries in groups.items():
        if len(entries)>1:
            actions={(kind,arg) for _,kind,arg in entries}
            # Multiple same-phase actions may be deliberate sequential rewrites,
            # but cannot be considered compatible until order is reviewed.
            findings.append({"kind":"internal_exact","phase":phase,"lines":[n for n,_,_ in entries],"blocking":len(actions)>1})
    for no,phase,pattern,kind,arg in rules:
        a=literal_prefix(pattern)
        for name,other_no,other_phase,other_pattern,other_kind,other_arg in existing:
            if phase!=other_phase:continue
            exact=pattern_key(pattern)==pattern_key(other_pattern)
            b=literal_prefix(other_pattern)
            if exact:
                findings.append({"kind":"existing_exact","line":no,"plugin":name,"other_line":other_no,"blocking":True})
            elif a and b and (a.startswith(b) or b.startswith(a)):
                findings.append({"kind":"possible_url_overlap","line":no,"plugin":name,"other_line":other_no,"blocking":True})
    for name,no,phase,pattern,kind,arg in existing:
        if phase=="mitm":
            if any(fnmatch.fnmatchcase(pattern,h) or fnmatch.fnmatchcase(h,pattern) for h in hosts if not h.startswith("-")):
                findings.append({"kind":"shared_mitm","plugin":name,"other_line":no,"host":pattern,"blocking":False})
        elif phase=="filter":
            for rule in filters:
                t,domain,policy=rule.split(",")
                if domain.lower()==pattern.lower():
                    findings.append({"kind":"shared_filter","plugin":name,"other_line":no,"domain":domain,"blocking":policy!=arg})
    return findings
