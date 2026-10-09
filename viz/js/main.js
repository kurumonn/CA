// three.js の描画・カメラ・UI。教材の状態は lesson.js が決め、ここでは反映だけを行う。
import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';
import { RoomEnvironment } from 'three/addons/environments/RoomEnvironment.js';
import {
  DURATION, SCENES, SCENARIOS, STATIONS, lessonState, parseEvents, sceneIndexAt, scenarioView, captionFor, MAX_EVENTS_BYTES,
  REVOCATION_OBSERVATIONS,
} from './lesson.js';
import { buildWorld, CATALOG } from './world.js';

const params = new URLSearchParams(location.search);
const $ = (id) => document.getElementById(id);

// ---------------------------------------------------------------------------
// レンダラー
// ---------------------------------------------------------------------------
const canvas = $('scene');
let renderer;
try {
  renderer = new THREE.WebGLRenderer({ canvas, antialias: true, preserveDrawingBuffer: params.has('capture') });
} catch (e) {
  $('fallback').hidden = false;
  throw e;
}
renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
renderer.shadowMap.enabled = true;
renderer.shadowMap.type = THREE.PCFSoftShadowMap;
renderer.toneMapping = THREE.ACESFilmicToneMapping;
renderer.toneMappingExposure = 1.0;

const scene = new THREE.Scene();
scene.background = new THREE.Color(0x0e131c);
scene.fog = new THREE.Fog(0x0e131c, 30, 60);
const pmrem = new THREE.PMREMGenerator(renderer);
scene.environment = pmrem.fromScene(new RoomEnvironment(), 0.04).texture;

const camera = new THREE.PerspectiveCamera(42, 1, 0.1, 200);
camera.position.set(0, 17, 22);
const controls = new OrbitControls(camera, canvas);
controls.enableDamping = true;
controls.maxPolarAngle = Math.PI * 0.48;
controls.minDistance = 2.5;
controls.maxDistance = 45;
controls.target.set(0, 0.8, 0);

scene.add(new THREE.HemisphereLight(0xdfe9ff, 0x1a1f29, 0.55));
const sun = new THREE.DirectionalLight(0xfff1dc, 2.2);
sun.position.set(-8, 18, 10);
sun.castShadow = true;
sun.shadow.mapSize.set(2048, 2048);
Object.assign(sun.shadow.camera, { left: -17, right: 17, top: 13, bottom: -13, near: 1, far: 50 });
sun.shadow.bias = -0.0004;
sun.shadow.normalBias = 0.02;
scene.add(sun);

const quality = ['hero', 'balanced'].includes(params.get('quality')) ? params.get('quality') : 'lite';
const status = document.getElementById('qualityStatus');
let world;
try {
  if (quality === 'lite') world = buildWorld(scene);
  else {
    status.textContent = 'GLBと共有PBR材質を読み込み中…';
    const { buildAtlasWorld } = await import('./atlas-world.js');
    world = await buildAtlasWorld(scene, { lod: quality === 'hero' ? 0 : 1, renderer,
      onProgress: (n,total) => { status.textContent = `GLB ${n}/${total} 読み込み`; } });
  }
  status.textContent = quality === 'lite' ? '軽量・コード生成版' : `分割GLB 40種／${quality === 'hero' ? 'LOD0・4K' : 'LOD1・2K'}／美術仕上げは継続中`;
} catch (error) {
  document.getElementById('fallback').hidden = false;
  status.textContent = `読込失敗（成功扱いにしません）: ${error.message}`;
  throw error;
}
const qualitySelect = document.getElementById('quality');
qualitySelect.value = quality;
qualitySelect.addEventListener('change', e => {
  const u = new URL(location.href); u.searchParams.set('quality', e.target.value);
  u.searchParams.set('t', String(ui.t)); u.searchParams.set('scenario', ui.scenario);
  u.searchParams.set('autoplay', '0'); location.assign(u);
});

// ---------------------------------------------------------------------------
// カメラ
// ---------------------------------------------------------------------------
const CAMS = {
  overview: { target: [0, 0.5, 0], offset: quality === 'lite' ? [0, 17, 21] : [1, 22, 30] },
  root: { target: [-8, 1.2, -6], offset: [2.5, 5, 9] },
  trust: { target: [-5, 1.2, 0], offset: [4, 9, 12] },
  server: { target: STATIONS.server, offset: [1.5, 2.5, 5.5] },
  ra: { target: [-6.5, 1.2, 0], offset: [3, 7, 10] },
  intermediate: { target: STATIONS.intermediate, offset: [1.5, 2.6, 5.5] },
  client: { target: [1.2, 1.6, -0.5], offset: [2.5, 5, 8.5] },
  crl: { target: [8.5, 1.5, -1], offset: [0, 8, 12] },
  ocsp: { target: STATIONS.ocsp, offset: [-2.5, 2.5, 5] },
  audit: { target: STATIONS.audit, offset: [1, 2.5, 5] },
  trustStore: { target: STATIONS.trust, offset: [1, 2.2, 4] },
  rootVault: { target: STATIONS.rootVault, offset: [1.5, 2.5, 5.5] },
  gates: { target: [8, 1.2, 5], offset: [-2, 5, 8] },
};
for (let i = 0; i < 6; i++) {
  const g = STATIONS[`gate${i}`];
  CAMS[`gate${i}`] = { target: [g[0], 1.1, g[2]], offset: [-1.8, 2.4, 4.6] };
}
const camGoal = { pos: new THREE.Vector3(), target: new THREE.Vector3(), active: false };
function flyTo(key) {
  const c = CAMS[key] ?? CAMS.overview;
  camGoal.target.set(...c.target);
  camGoal.pos.set(c.target[0] + c.offset[0], c.target[1] + c.offset[1], c.target[2] + c.offset[2]);
  camGoal.active = true;
}
controls.addEventListener('start', () => { camGoal.active = false; });

// ---------------------------------------------------------------------------
// 状態
// ---------------------------------------------------------------------------
const ui = {
  t: Number(params.get('t') ?? 0),
  playing: params.get('autoplay') !== '0' && !matchMedia('(prefers-reduced-motion: reduce)').matches,
  speed: 1,
  scenario: SCENARIOS[params.get('scenario')] ? params.get('scenario') : 'lesson',
  autoCam: params.get('autocam') !== '0' && !matchMedia('(prefers-reduced-motion: reduce)').matches,
  lastScene: -1,
  events: [],
};
if (params.has('embed')) document.body.classList.add('embed');

// シナリオ選択肢
for (const [k, sc] of Object.entries(SCENARIOS)) {
  const o = document.createElement('option');
  o.value = k; o.textContent = sc.label;
  $('scenario').append(o);
}
$('scenario').value = ui.scenario;
world.setScenarioView(scenarioView(ui.scenario));
$('scenario').addEventListener('change', (e) => {
  ui.scenario = e.target.value;
  world.setScenarioView(scenarioView(ui.scenario));
  // 比較条件は、証明書が提示される場面（検証ゲートの手前）から再生する
  ui.t = ui.scenario === 'lesson' ? 0 : 90;
  ui.playing = true;
  ui.lastScene = -1;
});

// 章リスト
SCENES.forEach((s, i) => {
  const li = document.createElement('li');
  li.innerHTML = `<button type="button"><span class="time">${fmt(s.t)}</span><span class="name"></span><span class="dot" hidden>実測</span></button>`;
  li.querySelector('.name').textContent = s.title;
  li.querySelector('button').addEventListener('click', () => { ui.t = s.t + 0.01; ui.lastScene = -1; });
  $('chapters').append(li);
});

// モデル一覧
for (const item of CATALOG) {
  const li = document.createElement('li');
  li.innerHTML = '<button type="button"><b></b><span></span><small></small></button>';
  li.querySelector('b').textContent = item.id;
  li.querySelector('span').textContent = item.name;
  li.querySelector('small').textContent = item.desc;
  li.querySelector('button').addEventListener('click', () => {
    ui.autoCam = false; $('autocam').checked = false;
    flyTo(CAMS[item.station] ? item.station : (item.station === 'overview' ? 'overview' : item.station));
  });
  $('catalog').append(li);
}

// 操作
$('play').addEventListener('click', () => { ui.playing = !ui.playing; if (ui.t >= DURATION) ui.t = 0; });
$('restart').addEventListener('click', () => { ui.t = 0; ui.playing = true; ui.lastScene = -1; });
$('seek').addEventListener('input', (e) => { ui.t = Number(e.target.value); ui.lastScene = -1; });
$('speed').addEventListener('change', (e) => { ui.speed = Number(e.target.value); });
$('autocam').checked = ui.autoCam;
$('autocam').addEventListener('change', (e) => { ui.autoCam = e.target.checked; ui.lastScene = -1; });
document.querySelectorAll('[data-cam]').forEach((b) => b.addEventListener('click', () => {
  ui.autoCam = false; $('autocam').checked = false; flyTo(b.dataset.cam);
}));
$('detailToggle').addEventListener('click', () => {
  const d = $('detail'); d.hidden = !d.hidden;
  $('detailToggle').textContent = d.hidden ? '詳しく' : '閉じる';
});
window.addEventListener('keydown', (e) => {
  if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT') return;
  if (e.code === 'Space') { e.preventDefault(); $('play').click(); }
  if (e.code === 'ArrowRight') { ui.t = Math.min(DURATION, SCENES[Math.min(17, sceneIndexAt(ui.t) + 1)].t + 0.01); ui.lastScene = -1; }
  if (e.code === 'ArrowLeft') { ui.t = SCENES[Math.max(0, sceneIndexAt(ui.t) - 1)].t + 0.01; ui.lastScene = -1; }
});

// 実測イベントの読込（pkilab export-events の出力）
function loadEventsDoc(text, source) {
  try {
    ui.events = parseEvents(JSON.parse(text), text.length);
  } catch (err) {
    $('eventsStatus').textContent = `読み込めません: ${err.message}`;
    return;
  }
  const measured = ui.events.filter((e) => e.measured).length;
  // 実測の申告を区別して表示する。ファイルの真正性（本当にラボで生成されたか）はこの画面では確認していない。
  $('eventsStatus').textContent = measured === ui.events.length && measured > 0
    ? `${source}: ${ui.events.length} 件 — 実測として提供された記録（真正性はこの画面では未検証）`
    : `${source}: ${ui.events.length} 件 — うち実測 ${measured} 件（measured が true でない記録は実測扱いしません）`;
  const list = $('events'); list.replaceChildren();
  const measuredScenes = new Set();
  for (const e of ui.events) {
    const li = document.createElement('li');
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = /REJECT|REVOKED|FAILED|QUARANTINED/.test(e.type) || ['reject', 'indeterminate'].includes(e.result) ? 'bad' : '';
    const notes = [];
    if (e.details?.code) notes.push(e.details.code);
    if (e.revocationObservation) notes.push(REVOCATION_OBSERVATIONS[e.revocationObservation]);
    if (e.aggregate) notes.push('処理全体の結果');
    if (!e.measured) notes.push('実測ではない');
    btn.textContent = `#${e.seq} ${e.type}${notes.length ? ' · ' + notes.join(' · ') : ''}`;
    btn.title = `${e.ts} / role=${e.role}`;
    if (e.scene !== null) {
      if (e.measured) measuredScenes.add(e.scene);
      btn.addEventListener('click', () => { ui.t = SCENES[e.scene].t + 0.01; ui.lastScene = -1; ui.playing = false; });
    }
    li.append(btn);
    list.append(li);
  }
  document.querySelectorAll('#chapters li').forEach((li, i) => { li.querySelector('.dot').hidden = !measuredScenes.has(i); });
}
$('eventsFile').addEventListener('change', async (e) => {
  const f = e.target.files[0];
  if (!f) return;
  if (f.size > MAX_EVENTS_BYTES) { $('eventsStatus').textContent = '読み込めません: ファイルが大きすぎます'; return; }
  loadEventsDoc(await f.text(), f.name);
});
$('eventsSample').addEventListener('click', async () => {
  try {
    const r = await fetch('data/sample-events.json');
    loadEventsDoc(await r.text(), 'サンプル（ラボの実行結果）');
  } catch (err) { $('eventsStatus').textContent = `読み込めません: ${err.message}`; }
});

// ---------------------------------------------------------------------------
// 状態を3Dへ反映
// ---------------------------------------------------------------------------
const GATE_COLORS = {
  idle: [0x2a2f38, 0x000000, 0], checking: [0xffc23d, 0xffa000, 1.8], pass: [0x3bf08a, 0x14c25a, 1.6],
  fail: [0xff3b4e, 0xd0101f, 2.2], indeterminate: [0xff9a1f, 0xd06a00, 2.0], skipped: [0x1a1d22, 0x000000, 0],
};
const tmp = new THREE.Vector3();

function apply(st, time) {
  if (world.apply) { world.apply(st, time, camera); return; }
  // トークン
  for (const [name, obj] of Object.entries(world.tokens)) {
    const v = st.tokens[name];
    obj.visible = !!v;
    if (!v) continue;
    obj.position.set(...v.p);
    // カードはカメラの方を向きつつ、移動中は少し揺らす
    tmp.copy(camera.position); tmp.y = obj.position.y;
    obj.lookAt(tmp);
    if (v.moving) obj.rotation.z = Math.sin(time * 6) * 0.08;
    if (name === 'pubKey') obj.rotation.y = time * 2;
  }
  // 葉と中間の間のチェーン環
  const a = st.tokens.leaf, b = st.tokens.chainCopy;
  world.link.visible = !!(a && b);
  if (a && b) world.link.position.set((a.p[0] + b.p[0]) / 2, (a.p[1] + b.p[1]) / 2, (a.p[2] + b.p[2]) / 2);

  // 原因の強調（赤く光る）
  const blameLeaf = st.blame === 'leaf', blameInt = st.blame === 'intermediate';
  world.tokens.leaf.userData.face.material.emissive.setHex(blameLeaf ? 0xff2030 : 0x000000);
  world.tokens.leaf.userData.face.material.emissiveIntensity = blameLeaf ? 0.45 + 0.2 * Math.sin(time * 6) : 0;
  world.tokens.chainCopy.userData.face.material.emissive.setHex(blameInt ? 0xff2030 : 0x000000);
  world.tokens.chainCopy.userData.face.material.emissiveIntensity = blameInt ? 0.45 + 0.2 * Math.sin(time * 6) : 0;
  // 明るい面では発光だけだと見分けにくいので、面の色も赤く染める
  world.tokens.leaf.userData.face.material.color.setHex(blameLeaf ? 0xff8a95 : 0xffffff);
  world.tokens.chainCopy.userData.face.material.color.setHex(blameInt ? 0xff8a95 : 0xffffff);

  // ゲート
  st.gates.forEach((g, i) => {
    const w = world.gates[i];
    let [color, emissive, intensity] = GATE_COLORS[g.state];
    if (g.state === 'checking') intensity *= 0.6 + 0.4 * Math.sin(time * 10);
    w.lampMat.color.setHex(color); w.lampMat.emissive.setHex(emissive); w.lampMat.emissiveIntensity = intensity;
    w.pointLight.color.setHex(color); w.pointLight.intensity = intensity * 1.2;
    w.leftPivot.rotation.y = -g.open * 1.4;
    w.rightPivot.rotation.y = g.open * 1.4;
    w.panel.visible = g.state === 'fail' || g.state === 'indeterminate';
    if (w.panel.visible) {
      const c = g.state === 'fail' ? 0xd92b3a : 0xff9a1f;
      w.panel.userData.mat.color.setHex(c); w.panel.userData.mat.emissive.setHex(c);
      w.panel.userData.mat.opacity = 0.6 + 0.25 * Math.sin(time * 5);
    }
  });

  // 可動部
  const p = st.parts;
  world.parts.vault.userData.door.rotation.y = -p.vaultDoor;
  world.parts.vault.userData.glow.intensity = p.vaultDoor * 2.5;
  world.parts.trust.userData.drawer.position.z = p.drawer;
  world.parts.signing.userData.head.position.y = 1.75 - p.press * 0.42;
  world.parts.signing.userData.light.intensity = p.signingGlow * 6;
  world.parts.audit.userData.light.intensity = p.auditGlow * 4;
  world.parts.crlCab.userData.light.intensity = p.crlUpdate * 5;
  world.parts.crlCab.userData.boardNew.visible = st.revokedReplay && st.t >= 163;
  world.parts.crlCab.userData.board.visible = !world.parts.crlCab.userData.boardNew.visible;
  const lamp = world.parts.ra.userData.lamp.material;
  lamp.emissive.setHex(p.raCheck > 0 ? 0x1fe0c4 : 0x000000); lamp.emissiveIntensity = p.raCheck * 2.5;
  world.keys.server.userData.material.emissiveIntensity = 0.4 + p.serverKeyGlow * 1.5;
  world.tls.visible = p.tlsSpark > 0.01;
  world.tls.scale.setScalar(0.6 + 0.4 * p.tlsSpark);
  // 期限切れシナリオでは時計の針が大きく進む
  const hand = world.clock.userData.hand;
  hand.rotation.z = -(st.scenario.outcome === 'CERT_EXPIRED' && st.t > 120 ? (st.t - 120) * 1.2 : time * 0.2);

  // 区画名の大きなラベルは、近づいたら薄くして手前の物を隠さない
  for (const l of world.fadeLabels) {
    const o = Math.max(0, Math.min(1, (camera.position.distanceTo(l.position) - 6) / 5));
    l.material.opacity = o; l.visible = o > 0.02;
  }

  // ロボットの待機動作
  world.robots.forEach((r, i) => {
    r.userData.head.rotation.y = Math.sin(time * 0.7 + i) * 0.4;
    r.userData.armR.rotation.x = Math.sin(time * 1.3 + i * 2) * 0.25;
    r.position.y = Math.abs(Math.sin(time * 2 + i)) * 0.02;
  });
  // 案内（利用者ロボット）は結果が出たらゲートを指す
  if (st.result) world.robots[3].userData.armR.rotation.x = -1.2;
}

function updateUI(st) {
  const s = st.scene;
  $('seek').value = String(st.t);
  $('time').textContent = `${fmt(st.t)} / ${fmt(DURATION)}`;
  $('play').textContent = ui.playing ? '一時停止' : '再生';
  if (st.sceneIndex !== ui.lastScene) {
    ui.lastScene = st.sceneIndex;
    $('sceneNo').textContent = `場面 ${st.sceneIndex + 1} / ${SCENES.length}`;
    const { title, short, detail } = captionFor(st.sceneIndex, ui.scenario);
    $('sceneTitle').textContent = title;
    $('sceneShort').textContent = short;
    $('detail').textContent = detail;
    document.querySelectorAll('#chapters li').forEach((li, i) => li.classList.toggle('active', i === st.sceneIndex));
    if (ui.autoCam) flyTo(s.cam);
  }
  const r = st.result;
  const banner = $('result');
  if (r) {
    banner.hidden = false;
    banner.dataset.verdict = r.verdict;
    const word = { ACCEPT: '接続許可', REJECT: '拒否', INDETERMINATE: '判定不能 → 接続しない' }[r.verdict];
    banner.textContent = `${word}：${r.code}${r.note ? '（' + r.note + '）' : ''}`;
  } else banner.hidden = true;
}

function fmt(t) { const s = Math.floor(t); return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`; }

// ---------------------------------------------------------------------------
// ループ
// ---------------------------------------------------------------------------
function resize() {
  const w = canvas.clientWidth, h = canvas.clientHeight;
  if (canvas.width !== Math.floor(w * renderer.getPixelRatio()) || canvas.height !== Math.floor(h * renderer.getPixelRatio())) {
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  }
}

const clock = new THREE.Clock();
let elapsed = 0;
function frame() {
  const dt = Math.min(clock.getDelta(), 0.1);
  elapsed += dt;
  if (ui.playing) {
    ui.t += dt * ui.speed;
    if (ui.t >= DURATION) { ui.t = DURATION; ui.playing = false; }
  }
  const st = lessonState(ui.t, ui.scenario);
  resize();
  updateUI(st);
  apply(st, ui.playing ? elapsed : st.t);
  if (camGoal.active) {
    const k = 1 - Math.pow(0.02, dt);
    camera.position.lerp(camGoal.pos, k);
    controls.target.lerp(camGoal.target, k);
    if (camera.position.distanceTo(camGoal.pos) < 0.02) camGoal.active = false;
  }
  controls.update();
  renderer.render(scene, camera);
  requestAnimationFrame(frame);
}

// 撮影・試験用の固定フレーム（?capture=1&t=..）：カメラを即座に目的地へ
if (params.has('capture')) {
  ui.playing = false;
  const st = lessonState(ui.t, ui.scenario);
  const c = CAMS[params.get('cam') ?? st.scene.cam] ?? CAMS.overview;
  controls.target.set(...c.target);
  camera.position.set(c.target[0] + c.offset[0], c.target[1] + c.offset[1], c.target[2] + c.offset[2]);
  ui.autoCam = false;
}
window.__atelier = { ui, lessonState, world, renderer, scene, camera, quality, describe: () => world.describe(), loadEventsDoc };
requestAnimationFrame(frame);
document.body.classList.add('ready');
