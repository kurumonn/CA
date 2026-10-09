import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';
import { RoomEnvironment } from 'three/addons/environments/RoomEnvironment.js';
import { GLTFLoader } from 'three/addons/loaders/GLTFLoader.js';

const $=id=>document.getElementById(id);
const params=new URLSearchParams(location.search);
const renderer=new THREE.WebGLRenderer({canvas:$('modelCanvas'),antialias:true});
renderer.setPixelRatio(Math.min(devicePixelRatio,2));renderer.toneMapping=THREE.ACESFilmicToneMapping;
renderer.shadowMap.enabled=true;renderer.shadowMap.type=THREE.PCFSoftShadowMap;
const scene=new THREE.Scene();scene.background=new THREE.Color(0x17232e);
const pmrem=new THREE.PMREMGenerator(renderer);const env=pmrem.fromScene(new RoomEnvironment(),.035);
scene.environment=env.texture;
scene.add(new THREE.HemisphereLight(0xecf4ff,0x39414b,1.0));
const key=new THREE.DirectionalLight(0xfff2db,3);key.position.set(-4,7,5);scene.add(key);
const fill=new THREE.DirectionalLight(0xc6ddff,1.3);fill.position.set(4,3,-3);scene.add(fill);
const camera=new THREE.PerspectiveCamera(35,1,.01,400);
const controls=new OrbitControls(camera,renderer.domElement);controls.enableDamping=true;
const loader=new GLTFLoader();const clock=new THREE.Clock();
let current=null,mixer=null,action=null,helper=null,epoch=0,clips=[],record=null,loaded=false;
const meta=await (await fetch('assets/atlas/catalog.json')).json();
for(const a of meta){const o=document.createElement('option');o.value=a.id;o.textContent=`${a.id} ${a.name}`;$('asset').append(o);}
$('asset').value=meta.some(a=>a.id===params.get('id'))?params.get('id'):'A12';
$('lod').value=params.get('lod')==='1'?'1':'0';
$('animate').checked=false;
function dispose(root){const gs=new Set(),ms=new Set(),ts=new Set();root.traverse(o=>{
 if(o.geometry)gs.add(o.geometry);for(const m of (Array.isArray(o.material)?o.material:[o.material]).filter(Boolean)){
 ms.add(m);for(const k of ['map','normalMap','roughnessMap','metalnessMap','aoMap','emissiveMap'])if(m[k])ts.add(m[k]);}});
 gs.forEach(g=>g.dispose());ms.forEach(m=>m.dispose());ts.forEach(t=>t.dispose());}
function setClip(){if(action)action.stop();action=null;if(mixer&&clips.length){action=mixer.clipAction(clips[Number($('clip').value)]);action.play();action.paused=!$('animate').checked;}}
async function load(){
 const turn=++epoch;loaded=false;$('modelStatus').textContent='GLBとPBR材質を読み込み中…';
 const id=$('asset').value,lod=Number($('lod').value);record=meta.find(a=>a.id===id);
 try{
  const g=await loader.loadAsync(`assets/atlas/models/lod${lod}/${id}.glb`);
  if(turn!==epoch){dispose(g.scene);return;}
  if(mixer){mixer.stopAllAction();mixer.uncacheRoot(current);}
  if(current){scene.remove(current);dispose(current);}
  if(helper){scene.remove(helper);helper.dispose();}
  current=g.scene;scene.add(current);current.traverse(o=>{if(o.isMesh){o.castShadow=true;o.receiveShadow=true;
   const mats=Array.isArray(o.material)?o.material:[o.material];for(const m of mats){m.wireframe=$('wire').checked;if(m.name==='ExhibitGlass')m.depthWrite=false;}}});
  const box=new THREE.Box3().setFromObject(current),size=box.getSize(new THREE.Vector3()),center=box.getCenter(new THREE.Vector3());
  const radius=size.length()/2;const distance=Math.max(.6,radius/Math.sin(THREE.MathUtils.degToRad(camera.fov/2))*1.15);
  camera.position.copy(center).add(new THREE.Vector3(.85,.6,1.35).normalize().multiplyScalar(distance));controls.target.copy(center);controls.update();
  helper=new THREE.Box3Helper(box,0xcea860);helper.visible=$('bounds').checked;scene.add(helper);
  clips=g.animations;mixer=new THREE.AnimationMixer(current);$('clip').replaceChildren();
  for(const [i,c] of clips.entries()){const o=document.createElement('option');o.value=String(i);o.textContent=`${c.name} (${c.duration.toFixed(1)}秒)`;$('clip').append(o);}
  if(!clips.length){const o=document.createElement('option');o.textContent='固定モデル';$('clip').append(o);}
  $('clip').disabled=!clips.length;$('animate').disabled=!clips.length;setClip();
  $('modelMeta').replaceChildren();
  for(const [k,v] of Object.entries({'寸法':record.dimensions.map(v=>v.toFixed(3)).join(' × ')+' m','三角形':record[`lod${lod}`].mesh_triangles.toLocaleString(),'材質':lod===0?'共有4K Base Color / Normal / ORM':'共有2K Base Color / Normal / ORM','ファイル':`${id}.glb`})){
   const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=k;dd.textContent=v;$('modelMeta').append(dt,dd);}
  loaded=true;$('modelStatus').textContent=`${id}｜${record.name}｜LOD${lod}`;
 }catch(e){$('modelStatus').textContent=`読込失敗: ${e.message}`;console.error(e);}
}
$('asset').addEventListener('change',load);$('lod').addEventListener('change',load);$('clip').addEventListener('change',setClip);
$('animate').addEventListener('change',()=>{if(action)action.paused=!$('animate').checked;});
$('bounds').addEventListener('change',()=>{if(helper)helper.visible=$('bounds').checked;});
$('wire').addEventListener('change',()=>{current?.traverse(o=>{for(const m of (Array.isArray(o.material)?o.material:[o.material]).filter(Boolean))m.wireframe=$('wire').checked;});});
function frame(){const dt=Math.min(clock.getDelta(),.1);const c=renderer.domElement,w=c.clientWidth,h=c.clientHeight;
 if(c.width!==Math.floor(w*renderer.getPixelRatio())||c.height!==Math.floor(h*renderer.getPixelRatio())){renderer.setSize(w,h,false);camera.aspect=w/h;camera.updateProjectionMatrix();}
 if(mixer)mixer.update(dt);controls.update();renderer.render(scene,camera);requestAnimationFrame(frame);}
window.__modelViewer={renderer,scene,camera,inspect:()=>({loaded,id:$('asset').value,lod:Number($('lod').value),clips:clips.map(c=>c.name),dimensions:record?.dimensions,drawCalls:renderer.info.render.calls,triangles:renderer.info.render.triangles}),load};
await load();requestAnimationFrame(frame);
