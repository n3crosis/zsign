// Test the existing CLI in a real browser Worker; no libraries or real credentials.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import {spawn,spawnSync} from 'node:child_process';
import {createRequire} from 'node:module';
import {createHash,webcrypto as crypto} from 'node:crypto';
import {tmpdir} from 'node:os';
import path from 'node:path';
async function verifySignature(bytes) {
 const v=new DataView(bytes.buffer,bytes.byteOffset,bytes.length),le=o=>v.getUint32(o,true),be=o=>v.getUint32(o,false);
 if(le(0)!==0xfeedfacf)throw Error();
 let command=32,signature=0,signatureSize=0;
 for(let i=0;i<le(16);i++){const size=le(command+4);if(size<8||command+size>32+le(20)||command+size>bytes.length)throw Error();if(le(command)===0x1d){signature=le(command+8);signatureSize=le(command+12)}command+=size;}
 if(!signature||signature+signatureSize>bytes.length||be(signature)!==0xfade0cc0)throw Error();
 const length=be(signature+4),count=be(signature+8);
 if(length>signatureSize||count>32||12+count*8>length)throw Error();
 let directories=0,pages=0;
 for(let i=0;i<count;i++){
  const offset=be(signature+16+i*8);if(offset<12+count*8||offset+8>length)throw Error();const cd=signature+offset;
  if(be(cd)!==0xfade0c02)continue;
  const size=be(cd+4),hashOffset=be(cd+16),slots=be(cd+28),limit=be(cd+32),hashSize=v.getUint8(cd+36),hashType=v.getUint8(cd+37),pageLog=v.getUint8(cd+39);
  if(size<44||offset+size>length||!(be(cd+12)&2)||pageLog>20||limit!==signature)throw Error();
  const pageSize=2**pageLog,algorithm=hashType===1?'SHA-1':(hashType===2||hashType===3)?'SHA-256':null;
  if(!algorithm||hashSize!==(hashType===2?32:20)||slots!==Math.ceil(limit/pageSize)||hashOffset<44||hashOffset+slots*hashSize>size)throw Error();
  for(let page=0;page<slots;page++){
   const digest=new Uint8Array(await crypto.subtle.digest(algorithm,bytes.subarray(page*pageSize,Math.min(limit,(page+1)*pageSize))));
   const expected=bytes.subarray(cd+hashOffset+page*hashSize,cd+hashOffset+(page+1)*hashSize);
   if(!expected.every((b,i)=>b===digest[i]))throw Error();pages++;
  }directories++;
 }
 if(!directories||!pages)throw Error();

 return {directories,pages};
}
const assets=new Map();
for(const [url,file,type] of [
 ['/zsign.mjs','bin/zsign.mjs','text/javascript'],
 ['/zsign.wasm','bin/zsign.wasm','application/wasm'],
 ['/fixture','test/dylib/bin/demo1.dylib','application/octet-stream']
])assets.set(url,[type,await fs.readFile(file)]);
// The same generated files run in Node; do not build another WASM for this check.
const {mapArguments}=createRequire(import.meta.url)('./node-cli.cjs');
const mapped=mapArguments(['-qfk/identity with spaces.p12','-p','/password/not/a/path','--bundle_id=/literal','--prov=/profile','-o','/output with spaces.ipa','--','/input with spaces.ipa'],p=>p.startsWith('/')?'/host'+p:p);
assert.deepEqual(mapped,['-qfk/host/identity with spaces.p12','-p','/password/not/a/path','--bundle_id=/literal','--prov=/host/profile','-o','/host/output with spaces.ipa','--','/host/input with spaces.ipa']);
assert.deepEqual(mapArguments(['--password=/unchanged','-p/also-unchanged','--bundle_version','/unchanged','-k','relative.p12','relative.app'],p=>p.startsWith('/')?'/host'+p:p),['--password=/unchanged','-p/also-unchanged','--bundle_version','/unchanged','-k','relative.p12','relative.app']);
const nodeDir=await fs.mkdtemp(path.join(tmpdir(),'zsign shared smoke '));
let nodeChecks=0;
try {
 for(const absolute of [false,true]) {
  const name=absolute?'absolute fixture.dylib':'relative fixture.dylib',file=path.join(nodeDir,name);
  await fs.copyFile('test/dylib/bin/demo1.dylib',file);
  const result=spawnSync(process.execPath,[path.resolve('bin/zsign.js'),'-qaf','--',absolute?file:name],{cwd:nodeDir,encoding:'utf8',timeout:60000});
  assert.equal(result.status,0,'Node shared-module CLI failed');await verifySignature(new Uint8Array(await fs.readFile(file)));nodeChecks++;
 }
 const traversal=path.join(nodeDir,'parent traversal.dylib');await fs.copyFile('test/dylib/bin/demo1.dylib',traversal);
 const traversed=spawnSync(process.execPath,[path.resolve('bin/zsign.js'),'-qaf','--','../../'+traversal.slice(1)],{cwd:'/',encoding:'utf8',timeout:60000});
 assert.equal(traversed.status,0,'Node relative host-root traversal failed');await verifySignature(new Uint8Array(await fs.readFile(traversal)));nodeChecks++;
 const app=path.join(nodeDir,'bundle source','Payload','Smoke app.app');await fs.mkdir(app,{recursive:true});
 await fs.copyFile('test/dylib/bin/demo1.dylib',path.join(app,'Smoke'));
 await fs.writeFile(path.join(app,'Info.plist'),'<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.example.smoke</string><key>CFBundleExecutable</key><string>Smoke</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleVersion</key><string>1</string></dict></plist>');
 const output=path.join(nodeDir,'signed output.ipa');
 const result=spawnSync(process.execPath,[path.resolve('bin/zsign.js'),'-qaf','--output='+output,'--',app],{cwd:nodeDir,encoding:'utf8',timeout:60000});
 assert.equal(result.status,0,'Node shared-module output path failed');
 const zip=await fs.readFile(output);assert.equal(zip.readUInt32LE(),0x04034b50);await verifySignature(new Uint8Array(await fs.readFile(path.join(app,'Smoke'))));nodeChecks++;
} finally {await fs.rm(nodeDir,{recursive:true,force:true});}
const worker=`import create from '/zsign.mjs';
${verifySignature.toString()}
let module,stage='loading';
try {
 const wasmBinary=new Uint8Array(await(await fetch('/zsign.wasm')).arrayBuffer());
 const before=new Uint8Array(await(await fetch('/fixture')).arrayBuffer());
 for(const name of ['fetch','XMLHttpRequest','WebSocket','EventSource','importScripts']) self[name]=()=>{throw Error('network disabled')};
 stage='initialize';module=await create({wasmBinary,noInitialRun:true,noExitRuntime:true,print(){},printErr(){},stdin:()=>null});
 stage='CLI';module.FS.writeFile('/fixture.dylib',before);
 if(module.callMain(['-q','-a','-f','/fixture.dylib'])!==0)throw Error();
 const bytes=module.FS.readFile('/fixture.dylib');
 if(bytes.length===before.length&&bytes.every((b,i)=>b===before[i]))throw Error();
 stage='signature';const {directories,pages}=await verifySignature(bytes);
 postMessage({ok:true,adHocCodeDirectories:directories,verifiedCodePages:pages,p12SigningVerified:false,deviceInstallVerified:false});
} catch {postMessage({ok:false,stage});} finally {module?.HEAPU8?.fill(0);close();}`;
assets.set('/worker.mjs',['text/javascript',worker]);
assets.set('/',['text/html',`<!doctype html><script>const w=new Worker('/worker.mjs',{type:'module'});w.onmessage=e=>{w.terminate();fetch('/result',{method:'POST',body:JSON.stringify(e.data)})};w.onerror=()=>{w.terminate();fetch('/result',{method:'POST',body:'{"ok":false,"stage":"worker"}'})};</script>`]);
let done;const result=new Promise(resolve=>done=resolve);
const server=http.createServer(async(req,res)=>{
 if(req.url==='/result'&&req.method==='POST'){let data='';for await(const b of req){data+=b;if(data.length>4096){res.writeHead(413).end();done({ok:false});return}}try{done(JSON.parse(data))}catch{done({ok:false})}res.end('ok');return}
 const entry=assets.get(req.url);if(!entry){res.writeHead(404).end();return}res.writeHead(200,{'Content-Type':entry[0],'Cache-Control':'no-store'}).end(entry[1]);
});
await new Promise(r=>server.listen(0,'127.0.0.1',r));
const profile=await fs.mkdtemp(path.join(tmpdir(),'zsign-browser-'));
const chrome=spawn(process.env.CHROME_BIN??'google-chrome',['--headless','--no-sandbox','--disable-gpu','--disable-background-networking','--disable-extensions','--no-first-run','--user-data-dir='+profile,`http://127.0.0.1:${server.address().port}/`],{stdio:'ignore'});
let exited=false;const chromeExit=new Promise(resolve=>{chrome.on('error',()=>{exited=true;done({ok:false});resolve()});chrome.on('exit',()=>{exited=true;done({ok:false});resolve()})});
const timer=setTimeout(()=>done({ok:false,stage:'timeout'}),60000);
try{
 const value=await result;assert.equal(value.ok,true,JSON.stringify(value));
 const runtimeFiles=Object.fromEntries(['/zsign.mjs','/zsign.wasm'].map(name=>{const bytes=assets.get(name)[1];return[name.slice(1),{bytes:bytes.length,sha256:createHash('sha256').update(bytes).digest('hex')}]}));
 await fs.writeFile('bin/browser-smoke.json',JSON.stringify({...value,nodeChecks,sameRuntimeTestedInNodeAndBrowser:true,sourceRevision:process.env.GITHUB_SHA,runtimeFiles},null,2)+'\n');
 console.log('Same module/WASM signed repository demo1 ad-hoc in Node and Chromium; CodeDirectory page hashes verified. Not P12 or device verification.');
}finally{clearTimeout(timer);if(!exited)chrome.kill('SIGKILL');await chromeExit;server.closeAllConnections();await new Promise(r=>server.close(r));await fs.rm(profile,{recursive:true,force:true,maxRetries:3});}
