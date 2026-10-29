// Host-filesystem CLI for the same module/WASM used by browsers. Node built-ins only.
const path = require('node:path');
const pathOptions = new Set('ckmoeIltx');
const valueOptions = new Set('ckmopebnzlDtrxMI');
const options = { debug:'d',force:'f',version:'v',adhoc:'a',cert:'c',pkey:'k',prov:'m',password:'p',bundle_id:'b',bundle_name:'n',bundle_version:'r',entitlements:'e',icon:'I',output:'o',zip_level:'z',dylib:'l',rm_dylib:'D',weak:'w',temp_folder:'t',sha256_only:'2',legacy_sha1:'L',install:'i',check:'C',quiet:'q',metadata:'x',rm_provision:'R',enable_docs:'S',min_version:'M',rm_extensions:'E',rm_watch:'W',rm_uisd:'U',inject_extensions:'P',help:'h' };
function mapArguments(args, mapPath) {
  const output=[];let positional=false;
  for(let i=0;i<args.length;i++) {
    const arg=args[i];
    if(positional||!arg.startsWith('-')||arg==='-'){output.push(mapPath(arg));continue;}
    if(arg==='--'){positional=true;output.push(arg);continue;}
    if(arg.startsWith('--')) {
      const equal=arg.indexOf('='),name=arg.slice(2,equal<0?undefined:equal);
      const matches=Object.keys(options).filter(k=>k.startsWith(name));
      const option=options[name]??(matches.length===1?options[matches[0]]:undefined);
      if(!valueOptions.has(option)){output.push(arg);continue;}
      if(equal>=0) output.push(arg.slice(0,equal+1)+(pathOptions.has(option)?mapPath(arg.slice(equal+1)):arg.slice(equal+1)));
      else {output.push(arg);if(i+1<args.length){const value=args[++i];output.push(pathOptions.has(option)?mapPath(value):value);}}
      continue;
    }
    let rewritten=arg;
    for(let j=1;j<arg.length;j++)if(valueOptions.has(arg[j])) {
      if(j+1<arg.length)rewritten=arg.slice(0,j+1)+(pathOptions.has(arg[j])?mapPath(arg.slice(j+1)):arg.slice(j+1));
      else if(i+1<args.length){output.push(arg);const value=args[++i];rewritten=pathOptions.has(arg[j])?mapPath(value):value;}
      break;
    }
    output.push(rewritten);
  }
  return output;
}
exports.mapArguments=mapArguments;
if(require.main===module)(async()=>{
  const fs=require('node:fs'),{pathToFileURL}=require('node:url');
  const {default:create}=await import(pathToFileURL(path.join(__dirname,'zsign.mjs')).href);
  const module=await create({wasmBinary:fs.readFileSync(path.join(__dirname,'zsign.wasm')),noInitialRun:true,noExitRuntime:true});
  const roots=new Map();
  const hostPath=value=>{
    if(value===''||value==='-')return value;
    // Resolve at the host boundary so excess '..' cannot escape the mounted root.
    value=path.resolve(value);
    const root=path.parse(value).root;
    if(!roots.has(root)){const mount='/host'+(roots.size||'');module.FS.mkdir(mount);module.FS.mount(module.NODEFS,{root},mount);roots.set(root,mount);}
    return roots.get(root)+'/'+value.slice(root.length).split(path.sep).join('/');
  };
  module.FS.chdir(hostPath(process.cwd()));
  const args=['-t',hostPath(process.platform==='win32'?require('node:os').tmpdir():'/tmp'),...mapArguments(process.argv.slice(2),hostPath)];
  try {process.exitCode=module.callMain(args)&255;} finally {args.fill('');module.HEAPU8.fill(0);}
})().catch(()=>{console.error('zsign: unable to run shared WASM CLI');process.exitCode=1;});
