// High-detail Atlas integration. This module never calls a CA or handles key data.
import * as THREE from 'three';
import { GLTFLoader } from 'three/addons/loaders/GLTFLoader.js';
import { makeLabel, setLabelText } from './world.js';
import { STATIONS, GATES } from './lesson.js';

export const ATLAS_IDS = Object.freeze(Array.from({length: 40}, (_, i) => `A${String(i+1).padStart(2,'0')}`));

export async function buildAtlasWorld(scene, { lod = 1, renderer, onProgress = () => {} } = {}) {
  if (![0,1].includes(lod)) throw new Error('Unsupported Atlas LOD');
  THREE.Cache.enabled = true;
  const loader = new GLTFLoader();
  const source = new Map(), materials = new Map();
  let loaded = 0;
  async function load(id) {
    const gltf = await loader.loadAsync(`assets/atlas/models/lod${lod}/${id}.glb`);
    // GLTF parsers have separate material objects. Reuse the one shared PBR atlas
    // rather than allocating 40 copies of three 4K textures on the GPU.
    gltf.scene.traverse(o => {
      if (!o.isMesh) return;
      const adopt = m => {
        if (!materials.has(m.name)) {
          for (const key of ['map','normalMap','roughnessMap','metalnessMap','aoMap']) {
            if (m[key]) m[key].anisotropy = Math.min(8, renderer.capabilities.getMaxAnisotropy());
          }
          if (m.name === 'ExhibitGlass') { m.depthWrite = false; m.opacity = .13; }
          materials.set(m.name, m);
        }
        const shared = materials.get(m.name);
        if (shared !== m) m.dispose();
        return shared;
      };
      o.material = Array.isArray(o.material) ? o.material.map(adopt) : adopt(o.material);
      o.castShadow = o.material?.name !== 'ExhibitGlass';
      o.receiveShadow = true;
    });
    source.set(id, gltf);
    onProgress(++loaded, ATLAS_IDS.length);
  }
  // Resolve the common images before issuing the remaining loads concurrently.
  await load('A01');
  for (let i = 1; i < ATLAS_IDS.length; i += 4) await Promise.all(ATLAS_IDS.slice(i,i+4).map(load));

  const root = new THREE.Group(); root.name = 'Atlas_R4';
  const used = new Set();
  const get = id => { used.add(id); return source.get(id).scene.clone(true); };
  function put(id, pos, scale = 1, ry = 0, parent = root) {
    const o = get(id); o.position.set(...pos); o.rotation.y = ry;
    if (Array.isArray(scale)) o.scale.set(...scale); else o.scale.setScalar(scale);
    parent.add(o); return o;
  }
  function batch(id, positions, scale = 1, ry = 0) {
    const src = get(id); src.updateMatrixWorld(true);
    src.traverse(m => {
      if (!m.isMesh) return;
      const inst = new THREE.InstancedMesh(m.geometry, m.material, positions.length);
      const helper = new THREE.Object3D(); helper.scale.setScalar(scale); helper.rotation.y = ry;
      positions.forEach((p,i) => { helper.position.set(...p); helper.updateMatrix();
        inst.setMatrixAt(i, helper.matrix.clone().multiply(m.matrixWorld)); });
      inst.castShadow = id !== 'A02'; inst.receiveShadow = true; root.add(inst);
    });
  }
  const labels = [];
  function label(text, pos, size=.19, parent=root) {
    const l=makeLabel(text,{size, bg:'rgba(15,25,36,0.9)'}); l.position.set(...pos); parent.add(l); labels.push(l); return l;
  }
  const foundation = put('A01',[0,0,0]);
  foundation.traverse(o => {o.castShadow=false;});
  const tilePos=[]; for(let x=-13;x<=13;x+=2) for(let z=-9;z<=9;z+=2) tilePos.push([x,-.10,z]);
  batch('A02',tilePos);
  batch('A03',Array.from({length:14},(_,i)=>[-13+i*2,0,-9.65]));
  batch('A06',[-11,-5,2,9].map(x=>[x,3.36,-6.8]));
  for(const x of [-8.1,-1.6,5.5]) batch('A04',[-8,-6,-4].map(z=>[x,0,z]),1,Math.PI/2);
  batch('A04',[[-13.8,0,-8],[-13.8,0,-6],[-13.8,0,-4]],1,Math.PI/2);
  put('A05',[0,0,9.6],1.12);
  label('信頼のアトリエ',[0,3.86,9.6],.25);
  batch('A07',Array.from({length:9},(_,i)=>[3.4+i*1.25,0,7.1]));
  batch('A07',Array.from({length:9},(_,i)=>[3.4+i*1.25,0,2.9]));
  // The offline root enclosure deliberately has no cable tray connection.
  batch('A39',Array.from({length:9},(_,i)=>[-5.8+i*2,.02,-2.7]));
  batch('A38',[[-4,0,8.5],[5,0,8.5]]);

  const vault=put('A09',[-11,0,-6.4],.9);
  const door=put('A10',[-11,0,-5.52],.9).getObjectByName('hinge');
  put('A11',[-11,.76,-6.01],.7);
  put('A23',[-12.8,0,-3.5],.85);
  const signing=put('A12',[-5,0,-6.5],.82);
  put('A11',[-6.7,0,-5.2],.62);
  const audit=put('A22',[-2.5,0,-8.1],.9);
  put('A16',[2.4,0,-7],1);
  put('A08',[1.05,0,-5.6],.9);
  put('A14',[1.05,.49,-5.72],.65);
  put('A15',[1.05,.50,-5.14],.6);
  put('A11',[3.3,0,-5.7],.7);
  put('A13',[-8,0,4.0],.9);
  put('A14',[-8.8,1.02,3.75],.56);
  put('A15',[-8.8,1.03,4.34],.6);
  const raLamp=new THREE.PointLight(0x5be7cb,0,3);raLamp.position.set(-8,1.5,4.5);root.add(raLamp);
  put('A08',[.8,0,5.15],[1.05,1.35,.80]);
  put('A14',[.8,.74,5.02],.72); put('A15',[.8,.75,5.6],.65);
  const trust=put('A17',[-1.6,0,6.5],.68,.15);
  const trustLabel=label('',[-1.6,1.62,6.5],.14);
  const targetLabel=label('',[.8,2.2,5],.15);
  const crlCab=put('A20',[9,0,-6.65],1);
  put('A21',[12.35,0,.3],.90,-.5);
  put('A31',[12.35,1.75,.40],.48,-.5);
  label('OCSP 比較展示\ngood ≠ 全検証の成功',[12.35,2.40,.3],.14);
  put('A19',[3.15,0,3.0],.84,.5);
  const clock=put('A35',[7.4,2.1,5.0],.5);
  const tls=put('A33',[11.6,2.5,5],.4);tls.visible=false;
  // A separate public-chain exhibit, not a set of private keys.
  for (const [i,id] of ['A29','A28','A27'].entries()) {
    put('A40',[-2.6+i*1.55,0,.5],.82);
    put(id,[-2.6+i*1.55,.32,.5],.49);
  }
  put('A32',[-1.82,.70,.55],.39); put('A32',[-.27,.70,.55],.39);
  label('公開証明書のチェーン：ルート → 中間 → サーバー',[-.9,1.80,.5],.14);

  const keys={};
  for (const [name,pos,s] of [['root',[-11,1.22,-5.93],.40],['issuer',[-6.7,.32,-5.10],.33],['server',[3.3,.36,-5.60],.36]]) {
    const k=put('A24',pos,s); const localMat=materials.get('SurfaceAtlas').clone();
    k.traverse(o=>{if(o.isMesh) o.material=localMat;});k.userData.material=localMat;keys[name]=k;
  }
  // All key root transforms remain constant; only a material highlight changes.
  const privateTransforms=Object.fromEntries(Object.entries(keys).map(([k,o])=>[k,o.position.toArray()]));

  // Dynamic, readable, scenario-bound faces on the real GLB frames.
  function card(id, accent, scale=.49) {
    const wrap=new THREE.Group();const model=get(id);wrap.add(model);root.add(wrap);
    const crl=id==='A30';const h=crl?1.92:1.76; model.position.y=-h/2;
    const canvas=document.createElement('canvas');canvas.width=768;canvas.height=1024;
    const ctx=canvas.getContext('2d');const tex=new THREE.CanvasTexture(canvas);tex.colorSpace=THREE.SRGBColorSpace;
    const mat=new THREE.MeshStandardMaterial({map:tex,roughness:.88,metalness:0,emissive:0x000000});
    const face=new THREE.Mesh(new THREE.PlaneGeometry(crl?1.20:1.15,crl?1.63:1.47),mat);
    face.position.set(0,h/2,.14); model.add(face);wrap.scale.setScalar(scale);
    let content={title:'',rows:[]};
    function setContent(c) {
      content=structuredClone(c);ctx.fillStyle='#f3f2ec';ctx.fillRect(0,0,768,1024);
      ctx.fillStyle=accent;ctx.fillRect(0,0,768,172);ctx.fillStyle='#fff';
      ctx.font='700 47px "Noto Sans CJK JP",sans-serif';ctx.fillText(c.title,40,102,690);
      ctx.fillStyle='#243341';ctx.font='500 32px "Noto Sans CJK JP",monospace';
      (c.rows??[]).forEach((r,i)=>ctx.fillText(r,38,255+i*111,692));
      ctx.strokeStyle=accent;ctx.lineWidth=4;ctx.strokeRect(34,193,700,780);tex.needsUpdate=true;
    }
    wrap.userData={face, setContent, content:()=>content};return wrap;
  }
  const tokens={
    intCert:card('A28','#6c7882'),rootCertCopy:card('A29','#856430'),
    leaf:card('A27','#305c79'),chainCopy:card('A28','#6c7882'),
    crlFetch:card('A30','#675582',.45),crlNew:card('A30','#675582',.45),
  };
  function token(id,s,center) {const g=new THREE.Group();const o=get(id);o.position.y=-center;g.add(o);g.scale.setScalar(s);root.add(g);return g;}
  tokens.pubKey=token('A25',.55,.63);tokens.csr=token('A26',.6,.69);tokens.approval=token('A34',.54,.38);
  for(const t of Object.values(tokens)) t.visible=false;
  const link=put('A32',[0,0,0],.13);link.visible=false;
  const crlBoard=card('A30','#675582',.48);crlBoard.position.set(9,1.3,-5.84);

  const gates=GATES.map((info,i)=>{
    const o=put('A18',[STATIONS[`gate${i}`][0],0,5],[.84,.93,.84],Math.PI/2);
    const lampMat=new THREE.MeshStandardMaterial({color:0x607584,emissive:0x000000});
    const lamp=new THREE.Mesh(new THREE.SphereGeometry(.10,16,12),lampMat);
    lamp.position.set(STATIONS[`gate${i}`][0],2.69,5);root.add(lamp);
    label(`${i+1} ${info.label}`,[STATIONS[`gate${i}`][0],2.99,5],.105);
    const panel=put('A36',[STATIONS[`gate${i}`][0]-.10,.32,5],.62,Math.PI/2);panel.visible=false;
    const panelMat=materials.get('SurfaceAtlas').clone();panel.traverse(n=>{if(n.isMesh)n.material=panelMat;});
    return {group:o,left:o.getObjectByName('shutter_L'),right:o.getObjectByName('shutter_R'),lampMat,panel,panelMat};
  });
  label('利用者端末の内部を拡大した展示／順序は説明用',[8.1,3.50,5],.16);
  const robots=[[-12.8,0,-4.2],[-6.8,0,-4.5],[-9.8,0,4.25],[2.2,0,6.8]].map(p=>put('A37',p,.77));
  ['ルート管理','発行担当','RA 審査','利用者'].forEach((text,i)=>label(text,[robots[i].position.x,1.75,robots[i].position.z],.12));
  for (const [k,text] of [['rootVault','ルートCA／通常は隔離'],['intermediate','中間CA／発行'],['server','HTTPS サーバー'],['crl','失効情報の配布'],['ra','申請窓口 RA']])
    label(text,[STATIONS[k][0],3.15,STATIONS[k][2]],.23);
  scene.add(root);
  let currentView=null;
  const statusColors={idle:0x667784,checking:0xe1ac32,pass:0x37b784,fail:0xea455c,indeterminate:0xeaa23f,skipped:0x394958};
  const scratch=new THREE.Vector3();
  return {
    root,tokens,keys,robots,gates,privateTransforms,
    parts:{vault,signing,audit,crlCab,trust},
    quality:lod===0?'hero':'balanced',assetCount:source.size,usedAssetIds:[...used].sort(),
    setScenarioView(view) {
      currentView=structuredClone(view);
      for(const [name,c] of Object.entries({leaf:view.leaf,chainCopy:view.inter,intCert:view.inter,rootCertCopy:view.root,crlFetch:view.crlFetch,crlNew:view.crlNew??view.crlFetch})) tokens[name].userData.setContent(c);
      crlBoard.userData.setContent(view.crlFetch);
      setLabelText(trustLabel,view.trust);setLabelText(targetLabel,`接続先: https://${view.target}:8443/`);
    },
    describe() {return {leaf:tokens.leaf.userData.content(),chain:tokens.chainCopy.userData.content(),crlFetch:tokens.crlFetch.userData.content(),crlNew:tokens.crlNew.userData.content(),trust:trustLabel.userData.text,target:targetLabel.userData.text};},
    apply(st,time,camera) {
      for(const [name,o] of Object.entries(tokens)) {
        const v=st.tokens[name];o.visible=!!v;if(!v)continue;
        o.position.set(...v.p);scratch.copy(camera.position);scratch.y=o.position.y;o.lookAt(scratch);
      }
      if(tokens.csr.visible)tokens.csr.getObjectByName('cover').rotation.y=st.t>=57&&st.t<70?-2.5:0;
      const a=st.tokens.leaf,b=st.tokens.chainCopy;link.visible=!!(a&&b);
      if(a&&b)link.position.set(...a.p).lerp(new THREE.Vector3(...b.p),.5);
      for(const [name,who] of [['leaf','leaf'],['chainCopy','intermediate']]) {
        const m=tokens[name].userData.face.material;
        m.color.setHex(st.blame===who?0xffa3aa:0xffffff);m.emissive.setHex(st.blame===who?0x52101a:0x000000);
      }
      gates.forEach((g,i)=>{
        const s=st.gates[i];g.left.position.x=-.59*s.open;g.right.position.x=.59*s.open;
        g.lampMat.color.setHex(statusColors[s.state]);g.lampMat.emissive.setHex(statusColors[s.state]);g.lampMat.emissiveIntensity=s.state==='idle'?.04:.5;
        g.panel.visible=['fail','indeterminate'].includes(s.state);
        g.panelMat.color.setHex(s.state==='indeterminate'?0xffc875:0xffffff);
      });
      door.rotation.y=-st.parts.vaultDoor;
      signing.getObjectByName('press').position.y=-.30*st.parts.press;
      trust.getObjectByName('drawer_0').position.z=st.parts.drawer;
      keys.server.userData.material.emissive.setHex(0x514025);keys.server.userData.material.emissiveIntensity=.10*st.parts.serverKeyGlow;
      raLamp.intensity=st.parts.raCheck*.7;tls.visible=st.parts.tlsSpark>.01;
      // One source of truth for the CRL held in the cabinet and travelling card.
      const content=st.revokedReplay&&st.t>=163?(currentView?.crlNew??currentView?.crlFetch):currentView?.crlFetch;
      if(content && JSON.stringify(crlBoard.userData.content())!==JSON.stringify(content))crlBoard.userData.setContent(content);
      robots.forEach((r,i)=>{
        r.getObjectByName('head').rotation.y=.17*Math.sin(time*.5+i);
        r.getObjectByName('arm_R').rotation.x=i===3&&st.result?-1.1:.08*Math.sin(time+i);
      });
    },
  };
}
