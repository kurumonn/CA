// 教材ロジックの試験: node --test viz/tests/
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DURATION, SCENES, SCENARIOS, GATES, STATIONS, lessonState, buildTracks, parseEvents, sample, EVENT_TO_SCENE,
  scenarioView, captionFor, eventScene,
} from '../js/lesson.js';

const times = (step = 0.25) => Array.from({ length: DURATION / step + 1 }, (_, i) => i * step);

test('18場面が0〜180秒を隙間なく覆う', () => {
  assert.equal(SCENES.length, 18);
  SCENES.forEach((s, i) => assert.equal(s.t, i * 10));
  for (const s of SCENES) {
    assert.ok(s.title && s.short && s.detail, s.title);
  }
});

test('全シナリオが結果コードと説明を持つ', () => {
  for (const [k, sc] of Object.entries(SCENARIOS)) {
    assert.ok(sc.label && sc.outcome && sc.verdict && sc.summary, k);
    const end = lessonState(DURATION, k);
    assert.deepEqual([end.result.verdict, end.result.code], [sc.verdict, sc.outcome], k);
  }
});

test('秘密鍵は軌跡を持たない（移動しない）', () => {
  for (const k of Object.keys(SCENARIOS)) {
    const names = Object.keys(buildTracks(k));
    assert.ok(!names.some((n) => /key/i.test(n) && n !== 'pubKey'), names.join(','));
  }
});

test('ルート証明書はサーバーから届かない（利用者が別経路で受け取る）', () => {
  const tr = buildTracks('lesson').rootCertCopy;
  const near = (p, station) => Math.hypot(p[0] - STATIONS[station][0], p[2] - STATIONS[station][2]) < 1.2;
  assert.ok(near(tr[0].at, 'rootVault'));
  assert.ok(near(tr[tr.length - 1].at, 'trust'));
  for (const kf of tr) if (kf.at) assert.ok(!near(kf.at, 'server'));
  // サーバーから送られるのは葉と中間CAのコピーだけ
  assert.ok(near(buildTracks('lesson').chainCopy[0].at, 'server'));
});

test('失敗シナリオは指定ゲートで止まり、以降のゲートは評価しない', () => {
  for (const [k, sc] of Object.entries(SCENARIOS)) {
    if (sc.failAt === null) continue;
    const end = lessonState(DURATION, k);
    const g = end.gates[sc.failAt];
    assert.equal(g.state, sc.verdict === 'INDETERMINATE' ? 'indeterminate' : 'fail', k);
    for (let i = sc.failAt + 1; i < GATES.length; i++) assert.equal(end.gates[i].state, 'skipped', k);
    for (let i = 0; i < sc.failAt; i++) assert.equal(end.gates[i].state, 'pass', k);
    const leaf = end.tokens.leaf.p;
    assert.ok(Math.abs(leaf[0] - (STATIONS[`gate${sc.failAt}`][0] - 0.55)) < 1e-9, k);
    assert.ok(end.tokens.chainCopy.p[1] - leaf[1] >= 0.55, '葉と中間のカードが重ならない');
  }
});

test('CRL が古い場合は「失効」ではなく「判定不能」', () => {
  const end = lessonState(DURATION, 'crlExpired');
  assert.equal(end.result.verdict, 'INDETERMINATE');
  assert.notEqual(end.result.code, 'LEAF_REVOKED');
});

test('本編：最初の接続は成功し、失効後の新規接続だけ拒否', () => {
  const mid = lessonState(165, 'lesson');
  assert.deepEqual([mid.result.verdict, mid.result.code], ['ACCEPT', 'OK']);
  assert.ok(mid.gates.every((g) => g.state === 'pass'));
  const end = lessonState(DURATION, 'lesson');
  assert.equal(end.gates[4].state, 'fail');
  assert.equal(end.gates[5].state, 'idle');
  assert.equal(end.result.code, 'LEAF_REVOKED');
  assert.ok(end.tokens.crlNew, '新しい CRL が配布される');
});

test('正常シナリオは全ゲート通過・TLS成立', () => {
  const end = lessonState(DURATION, 'normal');
  assert.ok(end.gates.every((g) => g.state === 'pass'));
  assert.equal(end.result.verdict, 'ACCEPT');
});

test('トークン位置は常に有限値で、床の範囲内', () => {
  for (const k of Object.keys(SCENARIOS)) {
    for (const t of times(0.5)) {
      const st = lessonState(t, k);
      for (const [name, v] of Object.entries(st.tokens)) {
        if (!v) continue;
        assert.ok(v.p.every(Number.isFinite), `${k} ${name} ${t}`);
        assert.ok(Math.abs(v.p[0]) <= 14 && Math.abs(v.p[2]) <= 10 && v.p[1] > 0 && v.p[1] < 8, `${k} ${name} ${t} ${v.p}`);
      }
      for (const val of Object.values(st.parts)) assert.ok(val >= 0 && val <= 1.6 + 1e-9);
    }
  }
});

test('sample: 非表示と補間', () => {
  const tr = [{ t: 0, at: [0, 0, 0] }, { t: 2, at: [2, 0, 0], move: true, arc: 0 }, { t: 3, at: null, hide: true }];
  assert.equal(sample(tr, -1), null);
  assert.deepEqual(sample(tr, 1).p, [1, 0, 0]);
  assert.equal(sample(tr, 3.5), null);
});

test('実測イベントの読込：schema 2・秘密情報の拒否', () => {
  const doc = { schema: 'pkilab-events/2', measured: true,
    events: [{ seq: 1, type: 'CERT_ISSUED', ts: 'x', role: 'issuer', result: 'ok', origin: 'measured' }] };
  const ev = parseEvents(doc);
  assert.equal(ev[0].scene, EVENT_TO_SCENE.CERT_ISSUED);
  assert.equal(ev[0].measured, true);
  assert.throws(() => parseEvents({ schema: 'pkilab-events/1', events: [] }));
  assert.throws(() => parseEvents({ ...doc, events: [{ type: '-----BEGIN PRIVATE KEY-----' }] }));
  assert.throws(() => parseEvents(doc, 3 * 1024 * 1024));
});

test('F08: measured が true（真偽値）でない記録は実測扱いしない', () => {
  const ev = { seq: 1, type: 'CERT_ISSUED', origin: 'measured' };
  for (const measured of [false, undefined, 'true', 1]) {
    const out = parseEvents({ schema: 'pkilab-events/2', measured, events: [ev] });
    assert.equal(out[0].measured, false, String(measured));
  }
  const synthetic = parseEvents({ schema: 'pkilab-events/2', measured: true, events: [{ ...ev, origin: 'simulated' }] });
  assert.equal(synthetic[0].measured, false);
});

test('F07: 集約された検証イベントは、結果コードの確認場面に対応し、失効確認なしを保持する', () => {
  const doc = { schema: 'pkilab-events/2', measured: true, events: [
    { seq: 1, type: 'CERT_VERIFICATION_COMPLETED', origin: 'measured', observation: 'aggregate',
      result: 'accept', details: { code: 'OK', revocation_requested: false, revocation_observation: 'not_requested', stages: 'not_observed' } },
    { seq: 2, type: 'CERT_VERIFICATION_COMPLETED', origin: 'measured', observation: 'aggregate',
      result: 'reject', details: { code: 'SAN_MISMATCH', revocation_requested: true, revocation_observation: 'not_executed', stopped_at: 'san_check' } },
  ] };
  const [a, b] = parseEvents(doc);
  assert.equal(a.revocationRequested, false);
  assert.equal(a.revocationObservation, 'not_requested');
  // NR05: 要求していても、名前の確認で止まれば「実行されていない」
  assert.equal(b.revocationRequested, true);
  assert.equal(b.revocationObservation, 'not_executed');
  // 不明な値は表示に使わない
  const [c] = parseEvents({ schema: 'pkilab-events/2', measured: true, events: [
    { seq: 3, type: 'CERT_VERIFICATION_COMPLETED', origin: 'measured', details: { revocation_observation: 'checked' } }] });
  assert.equal(c.revocationObservation, null);
  assert.equal(a.aggregate, true);
  assert.equal(b.scene, 11);
  assert.equal(eventScene({ type: 'TLS_HANDSHAKE_FAILED', details: { code: 'REVOKED' } }), 17);
  for (const old of ['PATH_VALIDATED', 'SAN_CHECKED', 'REVOCATION_CHECKED']) assert.equal(EVENT_TO_SCENE[old], undefined);
});

test('F15: 条件とカード・CRL・信頼ストアの表示が一致する', () => {
  const join = (c) => `${c.title}\n${c.rows.join('\n')}`;
  const v = (k) => scenarioView(k);
  assert.match(join(v('wrongEku').leaf), /clientAuth/);
  assert.doesNotMatch(join(v('wrongEku').leaf), /serverAuth/);
  assert.match(join(v('normal').leaf), /serverAuth/);
  assert.match(join(v('leafRevoked').crlFetch), /失効 1件[\s\S]*サーバー証明書/);
  assert.match(join(v('intermediateRevoked').crlFetch), /ルートCA[\s\S]*中間CA証明書/);
  assert.match(join(v('crlExpired').crlFetch), /2日前[\s\S]*期限切れ/);
  assert.match(join(v('normal').crlFetch), /失効 0件/);
  assert.match(join(v('lesson').crlNew), /失効 1件/);
  assert.match(join(v('expired').leaf), /15日前/);
  assert.equal(v('sanMismatch').target, 'example.com');
  assert.match(v('untrusted').trust, /PKI Lab Root CA なし/);
  // 未信頼の条件では、ルートを信頼ストアへ運ぶ演出をしない
  assert.equal(buildTracks('untrusted').rootCertCopy, undefined);
  assert.ok(buildTracks('normal').rootCertCopy);
  assert.match(captionFor(2, 'untrusted').short, /入れていません/);
});

test('説明文：止まるゲートで結果コードを示し、以降は評価しない', () => {
  for (const [k, sc] of Object.entries(SCENARIOS)) {
    if (sc.failAt === null) continue;
    const scene = SCENES.findIndex((s) => s.gate === sc.failAt);
    assert.match(captionFor(scene, k).short, new RegExp(sc.outcome), k);
    if (sc.failAt < 5) assert.match(captionFor(scene + 1, k).short, /行いません/, k);
    assert.match(captionFor(17, k).title, /ふりかえり/, k);
  }
  assert.equal(captionFor(17, 'lesson').title, SCENES[17].title);
});
