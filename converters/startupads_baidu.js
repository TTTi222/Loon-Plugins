// Loon binary ad-response adapter. Protocol fields inspected from app2smile/rules.
// Standalone implementation; no network, storage, eval or external library.
(function () {
  "use strict";
  function fail(){throw new Error("unsupported packet");}
  function join(parts){
    var size=parts.reduce(function(n,p){return n+p.length;},0);
    if(size>4000000)fail();
    var out=new Uint8Array(size),pos=0;
    parts.forEach(function(p){out.set(p,pos);pos+=p.length;});return out;
  }
  function ascii(s){return Uint8Array.from(s.split("").map(function(c){return c.charCodeAt(0);}));}
  function str(b){return Array.from(b,function(x){return String.fromCharCode(x);}).join("");}
  function v(n){if(!Number.isSafeInteger(n)||n<0||n>0xffffffff)fail();var a=[];do{a.push((n%128)|(n>=128?128:0));n=Math.floor(n/128);}while(n);return Uint8Array.from(a);}
  function fields(b){
    var a=[],i=0;
    function read(max){var start=i,n=0,m=1;for(var k=0;k<max;k++){if(i>=b.length)fail();var x=b[i++];n+=(x&127)*m;m*=128;if(!(x&128))return {n:n,raw:b.slice(start,i)};}fail();}
    while(i<b.length){
      if(a.length>=20000)fail();
      var start=i,t=read(5).n,id=Math.floor(t/8),w=t%8,f={id:id,w:w};
      if(!id||id>0x1fffffff)fail();
      if(w===0){var q=read(10);f.n=q.n;}
      else if(w===2){var l=read(5).n;if(l>b.length-i)fail();f.data=b.slice(i,i+l);i+=l;}
      else if(w===1||w===5){i+=w===1?8:4;if(i>b.length)fail();}
      else fail();
      f.raw=b.slice(start,i);a.push(f);
    }return a;
  }
  function one(a,id,w){var z=a.filter(function(f){return f.id===id;});if(z.length!==1||z[0].w!==w)fail();return z[0];}
  function bytes(id,b){return join([v(id*8+2),v(b.length),b]);}
  function number(id,n){return join([v(id*8),v(n)]);}
  function md5(b){
    var len=b.length,n=((len+9+63)>>6)<<6,p=new Uint8Array(n);p.set(b);p[len]=128;
    var dv=new DataView(p.buffer);dv.setUint32(n-8,len*8,true);
    var a0=0x67452301|0,b0=0xefcdab89|0,c0=0x98badcfe|0,d0=0x10325476|0;
    var shifts=[[7,12,17,22],[5,9,14,20],[4,11,16,23],[6,10,15,21]],k=[];
    for(var i=0;i<64;i++)k[i]=Math.floor(Math.abs(Math.sin(i+1))*4294967296)|0;
    for(var off=0;off<n;off+=64){
      var a=a0,c=c0,d=d0,x=b0;
      for(var j=0;j<64;j++){
        var f,g,round=j>>4;
        if(round===0){f=(x&c)|(~x&d);g=j;}
        else if(round===1){f=(d&x)|(~d&c);g=(5*j+1)%16;}
        else if(round===2){f=x^c^d;g=(3*j+5)%16;}
        else{f=c^(x|~d);g=(7*j)%16;}
        var t=(a+f+k[j]+dv.getInt32(off+4*g,true))|0,s=shifts[round][j%4];
        var next=(x+((t<<s)|(t>>>(32-s))))|0;a=d;d=c;c=x;x=next;
      }
      a0=(a0+a)|0;b0=(b0+x)|0;c0=(c0+c)|0;d0=(d0+d)|0;
    }
    var out=new Uint8Array(16),o=new DataView(out.buffer);
    [a0,b0,c0,d0].forEach(function(x,i){o.setInt32(i*4,x,true);});
    return Array.from(out,function(x){return ("0"+x.toString(16)).slice(-2);}).join("");
  }
  function transform(input){
    if(!(input instanceof Uint8Array)||input.length<5||input.length>2000000)fail();
    var len=new DataView(input.buffer,input.byteOffset,input.byteLength).getUint32(0,false);
    if(!len||len>input.length-4)fail();
    var head=fields(input.slice(4,4+len)),payload=input.slice(4+len);
    var hash=one(head,1,2);
    if(str(hash.data).toLowerCase()!==md5(payload))fail();
    var entries=head.filter(function(f){return f.id===3;});
    if(entries.length!==2||entries.some(function(f){return f.w!==2;}))fail();
    var h=entries.map(function(f){
      var a=fields(f.data);
      return {entry:f,fields:a,offset:one(a,1,0).n,length:one(a,2,0).n,name:str(one(a,3,2).data)};
    });
    if(h[0].name!=="Result"||h[1].name!=="Ads"||h[0].offset!==0||
       h[1].offset!==h[0].length||h[0].length+h[1].length!==payload.length)fail();
    var result=payload.slice(0,h[0].length),ads=fields(payload.slice(h[1].offset)),changed=false;
    var newAds=join(ads.map(function(f){
      if(f.id!==2)return f.raw;if(f.w!==2)fail();
      var c=fields(f.data),type=str(one(c,1,2).data);
      if(type.indexOf("_banner")<0&&type.indexOf("splash_screen1040")<0)return f.raw;
      var start=c.filter(function(x){return x.id===4;}),end=c.filter(function(x){return x.id===5;});
      if(!start.length||!end.length)return f.raw;
      if(start.length!==1||end.length!==1||start[0].w!==0||end[0].w!==0)fail();
      changed=true;
      return bytes(2,join(c.map(function(x){return x.id===4?number(4,1648746061):x.id===5?number(5,1648832461):x.raw;})));
    }));
    if(!changed)return null;
    var updated=join([result,newAds]),newHead=join(head.map(function(f){
      if(f===hash)return bytes(1,ascii(md5(updated)));
      if(f===h[1].entry)return bytes(3,join(h[1].fields.map(function(x){return x.id===2?number(2,newAds.length):x.raw;})));
      return f.raw;
    }));
    var prefix=new Uint8Array(4);new DataView(prefix.buffer).setUint32(0,newHead.length,false);
    return join([prefix,newHead,updated]);
  }
  try {
    var body=transform($response.body);
    $done(body?{body:body}:{});
  } catch (_) {$done({});}
})();
