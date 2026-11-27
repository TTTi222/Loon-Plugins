"""Synthetic packet tests for independent Baidu adapter; no upstream JS execution."""
import hashlib
import json
import pathlib
import struct
import subprocess

def v(n):
    out=bytearray()
    while n>=128:
        out.append((n&127)|128)
        n>>=7
    out.append(n)
    return bytes(out)

def b(i,data): return v(i*8+2)+v(len(data))+data
def n(i,x): return v(i*8)+v(x)

def packet(result, ads, *, order=True, digest=None):
    data=result+ads
    entries=[n(1,0)+n(2,len(result))+b(3,b"Result"),
             n(1,len(result))+n(2,len(ads))+b(3,b"Ads")+n(9,42)]
    if not order: entries.reverse()
    header=b(1,(digest or hashlib.md5(data).hexdigest()).encode())+b(2,b"range")+b(3,entries[0])+b(3,entries[1])+n(8,99)
    return struct.pack(">I",len(header))+header+data

def fixture(t, start=1, end=2):
    return b(1,t)+b(2,b"opaque")+n(4,start)+n(5,end)+n(19,42)

def test_baidu():
    code=pathlib.Path(__file__).with_name("startupads_baidu.js").read_text(encoding="utf-8")
    result=n(1,2)+n(9,88)
    ordinary=b(2,fixture(b"navigation"))
    ads=b(1,n(1,3))+ordinary+b(2,fixture(b"home_banner"))+b(2,fixture(b"splash_screen1040"))+n(15,8)
    expected=b(1,n(1,3))+ordinary+b(2,fixture(b"home_banner",1648746061,1648832461))+b(2,fixture(b"splash_screen1040",1648746061,1648832461))+n(15,8)
    original=packet(result,ads)
    target=packet(result,expected)
    fixtures=[
        (original,target),
        (packet(result,ordinary),None),
        (packet(result,ads,digest="0"*32),None),
        (original[:-1],None),
        (packet(result,ads,order=False),None),
        (b"\xff\xff\xff\xff"+original[4:],None),
        (packet(result,b(2,b(1,b"home_banner")+n(4,1))),None),
        (packet(result,b(2,fixture(b"home_banner")+n(4,3))),None),
        (packet(result,b"\x12\xff"),None),
        (b"",None),
        (target,target),
    ]
    data={"code":code,"fixtures":[[list(x),None if y is None else list(y)] for x,y in fixtures]}
    harness=r"""
const vm=require("vm"),assert=require("assert");
const data=JSON.parse(require("fs").readFileSync(0,"utf8"));
for(const [input,expected] of data.fixtures){
  let calls=[];
  // Also verify nonzero byte offset handling.
  const padded=new Uint8Array(input.length+2);padded.set(input,1);
  vm.runInNewContext(data.code,{Uint8Array,DataView,$response:{body:padded.subarray(1,-1)},$done:x=>calls.push(x)},{timeout:1000});
  assert.equal(calls.length,1);
  if(expected===null)assert.equal(Object.keys(calls[0]).length,0);
  else assert.deepEqual(Array.from(calls[0].body),expected);
}
console.log(data.fixtures.length);
"""
    out=subprocess.run(["node","-e",harness],input=json.dumps(data),text=True,capture_output=True,check=True,timeout=15)
    return code,int(out.stdout.strip())

if __name__=="__main__":
    print("BAIDU TESTS",test_baidu()[1])
