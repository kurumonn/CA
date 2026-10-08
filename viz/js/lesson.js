// 教材のシナリオと時間軸（描画に依存しない純粋なロジック）。
// three.js 側は lessonState(t, scenario) の結果を3D空間へ反映するだけにする。
// Node からも import してテストできる（viz/tests/lesson.test.mjs）。

export const DURATION = 180;

// 区画（ステーション）の位置。単位はメートル。床は 28m × 20m。
export const STATIONS = {
  rootVault: [-11, 1.35, -6],
  intermediate: [-5, 1.45, -6],
  audit: [-2.2, 1.3, -8.4],
  server: [2, 1.55, -6],
  crl: [9, 1.4, -6],
  ra: [-8, 1.35, 4.5],
  client: [0.8, 1.25, 5],
  trust: [-1.6, 1.05, 6.6],
  ocsp: [12.4, 1.3, 0.5],
  gate0: [4.6, 1.15, 5],
  gate1: [6.0, 1.15, 5],
  gate2: [7.4, 1.15, 5],
  gate3: [8.8, 1.15, 5],
  gate4: [10.2, 1.15, 5],
  gate5: [11.6, 1.15, 5],
  exit: [13.2, 1.15, 5],
};

// 検証ゲート。並び順は説明用であり、実ブラウザ内部の固定された実行順ではない。
export const GATES = [
  { id: 'TRUST', label: '信頼の経路', short: '署名の連鎖が、自分の信頼ストアのルートまでつながるか' },
  { id: 'SAN', label: '接続先名 (SAN)', short: '接続したい名前が SAN に含まれるか（CN は見ない）' },
  { id: 'VALIDITY', label: '有効期限', short: '今が notBefore〜notAfter の範囲内か' },
  { id: 'EKU', label: '用途 (EKU)', short: 'サーバー認証 (serverAuth) 用の証明書か' },
  { id: 'REVOCATION', label: '失効確認 (CRL)', short: '葉と中間CAが、新しい CRL に載っていないか' },
  { id: 'TLS_AUTH', label: 'TLS 本人確認', short: 'サーバーが秘密鍵で CertificateVerify に署名できたか' },
];

// 比較できる条件。failAt はゲート番号、outcome は教材の結果コード。
export const SCENARIOS = {
  lesson: {
    label: '本編：発行 → 接続 → 失効',
    failAt: null, revokeAtEnd: true,
    outcome: 'LEAF_REVOKED', verdict: 'REJECT',
    summary: '最初の接続は成功。失効後の新しい接続は、新しい CRL を確認して拒否されます。',
  },
  normal: {
    label: '正常な証明書', failAt: null, outcome: 'OK', verdict: 'ACCEPT',
    summary: 'すべての確認を通過し、TLS 接続が成立します。',
  },
  untrusted: {
    label: '信頼していないルート', failAt: 0, outcome: 'UNTRUSTED_ANCHOR', verdict: 'REJECT',
    summary: '証明書の署名は正しくても、利用者の信頼ストアにルートがないため拒否されます。',
  },
  sanMismatch: {
    label: '接続先の名前が違う', failAt: 1, outcome: 'SAN_MISMATCH', verdict: 'REJECT',
    summary: 'example.com に接続したのに、証明書の SAN は localhost / 127.0.0.1 だけです。',
  },
  expired: {
    label: '証明書の期限切れ', failAt: 2, outcome: 'CERT_EXPIRED', verdict: 'REJECT',
    summary: '有効期間（30日）を過ぎた証明書は拒否されます。OS の時計を戻して試すのはやめましょう。',
  },
  wrongEku: {
    label: 'サーバー用途ではない', failAt: 3, outcome: 'WRONG_EKU', verdict: 'REJECT',
    summary: 'clientAuth だけの証明書は、サーバー証明書として使えません。',
  },
  leafRevoked: {
    label: 'サーバー証明書が失効', failAt: 4, outcome: 'LEAF_REVOKED', verdict: 'REJECT',
    summary: '中間CA の CRL に葉証明書のシリアルが載っているため拒否されます。',
  },
  intermediateRevoked: {
    label: '中間CAが失効', failAt: 4, outcome: 'INTERMEDIATE_REVOKED', verdict: 'REJECT', blame: 'intermediate',
    summary: 'ルートCA の CRL に中間CA が載っています。その配下の証明書はすべて拒否されます。',
  },
  crlExpired: {
    label: 'CRL が古く確認できない', failAt: 4, outcome: 'CRL_EXPIRED', verdict: 'INDETERMINATE',
    summary: '「失効している」のではなく「失効状態を確認できない」状態です。ラボ方針として接続は許可しません。',
  },
};

// 18場面 × 10秒。kind はカメラと強調表示に使う。
export const SCENES = [
  { t: 0, cam: 'overview', title: '信頼のアトリエへようこそ',
    short: '左が「発行する側」、右下が「信頼する側」。2つは別の場所です。',
    detail: '証明書を発行することと、その証明書が信頼されることは別の判断です。信頼の起点（トラストアンカー）は、検証する側が自分で持ちます（RFC 5280）。' },
  { t: 10, cam: 'root', title: 'ルートCAが中間CAに権限を委任',
    short: 'ルート鍵は金庫から出さず、中間CA証明書にだけ署名します。',
    detail: 'ルートCAは普段オフライン。中間CA証明書（CA:TRUE, pathlen:0）に署名して、日常の発行を任せます。金色の鍵（秘密鍵）は一度も移動しません。' },
  { t: 20, cam: 'trust', title: '利用者が信頼の起点を選ぶ',
    short: 'ルート証明書は、利用者が「別の経路」で事前に受け取ります。',
    detail: 'サーバーからルートを受け取って自動登録はしません。今回のラボでは OS の信頼ストアは書き換えず、検証時だけ指定（--cacert / -trusted）します。' },
  { t: 30, cam: 'server', title: 'サーバーで鍵ペアを作る',
    short: '秘密鍵（金）はサーバーに残り、公開鍵（青）だけを使います。',
    detail: 'サーバー秘密鍵を CA に送ることはありません。CA が鍵を作って配る設計にすると、CA が全員の秘密鍵を知ってしまいます。' },
  { t: 40, cam: 'server', title: 'CSR（署名付きの申込書）を作る',
    short: '公開鍵と希望する名前を書き、秘密鍵で申込書に署名します。',
    detail: 'CSR の署名で分かるのは「この公開鍵の秘密鍵を持っている」ことだけ。その名前を使う権利があるかは、次の窓口で別に確認します。' },
  { t: 50, cam: 'ra', title: '申請窓口（RA）へ提出',
    short: 'CSR は公開情報なので、運んでも秘密は漏れません。',
    detail: '受付ではサイズ、形式、CSR 署名、鍵の種類（EC P-256）、要求された名前と用途を検査します。' },
  { t: 60, cam: 'ra', title: 'RA が審査・承認する',
    short: '許可された名前だけ。CA 権限の要求は拒否します。',
    detail: 'SAN は localhost / 127.0.0.1 の完全一致のみ。承認は CSR のハッシュ・プロファイル・SAN・期間・承認者・期限に結び付け、後から変わったら再承認です。' },
  { t: 70, cam: 'intermediate', title: '中間CAが署名する',
    short: '押印は電子署名のたとえ。証明書を「暗号化」するわけではありません。',
    detail: '発行する拡張は CSR からコピーせず（copy_extensions = none）、CA 側の固定プロファイルから作ります。CA:FALSE / serverAuth / SAN。' },
  { t: 80, cam: 'intermediate', title: '発行後検査・台帳・配置',
    short: '検査に通った証明書だけを台帳に記録し、サーバーへ渡します。',
    detail: '構造、鍵の一致、用途、期間、チェーンを検査。監査ログはハッシュ連鎖で記録し、最新ハッシュは別媒体にも保存します。' },
  { t: 90, cam: 'client', title: 'TLS 接続で証明書を提示',
    short: 'サーバーは「葉＋中間CA」を送ります。ルートは送りません。',
    detail: 'ルートは利用者が事前に持っている前提なので、送信チェーンから省略できます。届いたルートを信じる仕組みではありません。' },
  { t: 100, cam: 'gate0', gate: 0, title: '確認①：信頼の経路',
    short: '中間CA → ルートと署名をたどり、信頼ストアのルートに着くか。',
    detail: '-trusted に信頼するルート、-untrusted に経路を組み立てる中間CA を渡します。中間CA を信頼の起点にはしません。' },
  { t: 110, cam: 'gate1', gate: 1, title: '確認②：接続先名（SAN）',
    short: '「CA の署名が正しい」と「接続先が正しい」は別の確認です。',
    detail: 'DNS 名と IP アドレスは別の種類として照合します。CN だけ一致する証明書は受け入れません（RFC 9525）。' },
  { t: 120, cam: 'gate2', gate: 2, title: '確認③：有効期限',
    short: '今の時刻が有効期間の中にあるか。',
    detail: '葉は30日。親CA より長生きしないよう、発行時に「notAfter ≤ 親の notAfter − 24時間」を確認しています。' },
  { t: 130, cam: 'gate3', gate: 3, title: '確認④：用途（EKU）',
    short: 'サーバー認証用（serverAuth）の証明書か。',
    detail: 'CA 権限（keyCertSign）やクライアント認証の用途は持たせていません。' },
  { t: 140, cam: 'gate4', gate: 4, title: '確認⑤：失効確認（CRL）',
    short: '葉は中間CA の CRL、中間CA はルートの CRL で確認します。',
    detail: 'CRL が取れない・期限切れ・署名不正なら「判定不能」。失効とは別の結果として記録し、接続は許可しません。' },
  { t: 150, cam: 'gate5', gate: 5, title: '確認⑥：TLS の本人確認',
    short: 'サーバーが自分の秘密鍵で CertificateVerify に署名できたか。',
    detail: '証明書は誰でもコピーできます。秘密鍵を持つ本人だけがこの署名を作れます。通信の暗号鍵はクライアントとサーバーの間で作られ、CA は関与しません。' },
  { t: 160, cam: 'crl', title: '失効の登録と CRL の更新',
    short: '中間CA が失効を登録し、新しい CRL を配布します。',
    detail: '失効は「登録」「配布」「利用側の確認」の3つがそろって働きます。CRL を更新しても、既存の接続がその場で必ず切れるわけではありません。' },
  { t: 170, cam: 'gate4', title: '新しい接続で拒否される',
    short: '新規の接続で新しい CRL を確認し、失効した証明書を止めます。',
    detail: '前回の実験の要点：失効確認をしないクライアント（curl の既定など）は、失効済みでも接続できてしまいます。' },
];

export function sceneIndexAt(t) {
  let idx = 0;
  for (let i = 0; i < SCENES.length; i++) if (t >= SCENES[i].t) idx = i;
  return idx;
}

// ---- 補助 ----------------------------------------------------------------
const clamp01 = (x) => Math.max(0, Math.min(1, x));
const ease = (x) => { x = clamp01(x); return x < 0.5 ? 4 * x * x * x : 1 - Math.pow(-2 * x + 2, 3) / 2; };
const lerp = (a, b, k) => a + (b - a) * k;

function pos(name, offset = [0, 0, 0]) {
  const p = Array.isArray(name) ? name : STATIONS[name];
  if (!p) throw new Error(`unknown station ${name}`);
  return [p[0] + offset[0], p[1] + offset[1], p[2] + offset[2]];
}

// keyframes: [{t, at, hide?}] → 時刻 t の位置。移動区間は放物線で持ち上げる。
export function sample(track, t) {
  if (!track.length || t < track[0].t) return null;
  let i = 0;
  while (i + 1 < track.length && track[i + 1].t <= t) i++;
  const a = track[i];
  if (a.hide) return null;
  const b = track[i + 1];
  if (!b || b.hide || !b.move) return { p: a.at, moving: false };
  const k = ease((t - a.t) / (b.t - a.t));
  const p = [0, 1, 2].map((j) => lerp(a.at[j], b.at[j], k));
  p[1] += Math.sin(Math.PI * k) * (b.arc ?? 1.2);
  return { p, moving: k > 0 && k < 1 };
}

// ---- シナリオごとのトークン軌跡 --------------------------------------------
export function buildTracks(scenarioKey) {
  const sc = SCENARIOS[scenarioKey] ?? SCENARIOS.lesson;
  const kf = (t, at, extra = {}) => ({ t, at, ...extra });
  const tracks = {};

  // 中間CA証明書：ルートで署名され、中間CA室へ（委任）
  tracks.intCert = [
    kf(10, pos('rootVault', [0, 0.6, 0.6])),
    kf(13, pos('rootVault', [0, 0.6, 0.6])),
    kf(18, pos('intermediate', [-0.9, 0.9, 0.4]), { move: true, arc: 1.6 }),
  ];
  // ルート証明書（公開情報）：別経路で信頼ストアへ
  tracks.rootCertCopy = [
    kf(20, pos('rootVault', [0.4, 0.6, 0.8])),
    kf(21, pos('rootVault', [0.4, 0.6, 0.8])),
    kf(28, pos('trust', [0, 0.75, 0]), { move: true, arc: 3.2 }),
  ];
  // 公開鍵：サーバーの鍵ペアから取り出され、CSR に入る
  tracks.pubKey = [
    kf(31, pos('server', [-0.7, 0.5, 0.9])),
    kf(36, pos('server', [-0.7, 0.9, 1.2]), { move: true, arc: 0.3 }),
    kf(41, pos('server', [0.3, 0.9, 1.3]), { move: true, arc: 0.3 }),
    kf(44, null, { hide: true }),
  ];
  // CSR：サーバー → RA → 中間CA
  tracks.csr = [
    kf(40, pos('server', [0.3, 0.9, 1.3])),
    kf(50, pos('server', [0.3, 0.9, 1.3])),
    kf(57, pos('ra', [0, 0.35, 0]), { move: true, arc: 2.4 }),
    kf(70, pos('ra', [0, 0.35, 0])),
    kf(74, pos('intermediate', [0, 0.25, 0.9]), { move: true, arc: 2.6 }),
    kf(78, null, { hide: true }),
  ];
  // 承認バッジ
  tracks.approval = [
    kf(64, pos('ra', [0.35, 0.55, 0.1])),
    kf(70, pos('ra', [0.35, 0.55, 0.1])),
    kf(74, pos('intermediate', [0.35, 0.45, 0.9]), { move: true, arc: 2.6 }),
    kf(80, null, { hide: true }),
  ];

  // 葉証明書（サーバー証明書）
  const leaf = [
    kf(76.5, pos('intermediate', [0, 0.35, 0.9])),
    kf(83, pos('intermediate', [0, 0.35, 0.9])),
    kf(88, pos('server', [0, 0.9, 1.0]), { move: true, arc: 1.4 }),
    kf(91, pos('server', [0, 0.9, 1.0])),
    kf(98, pos('client', [-0.45, 0.9, 0]), { move: true, arc: 3.0 }),
  ];
  // 中間CA証明書のコピー（チェーンとして一緒に届く）
  const chain = [
    kf(90, pos('server', [0.5, 0.9, 1.0])),
    kf(91, pos('server', [0.5, 0.9, 1.0])),
    kf(98, pos('client', [0.45, 0.9, 0]), { move: true, arc: 3.0 }),
  ];

  const stop = sc.failAt;
  for (let g = 0; g < GATES.length; g++) {
    const s = 100 + g * 10;
    if (stop !== null && g > stop) break;
    leaf.push(kf(s, leaf[leaf.length - 1].at), kf(s + 3, pos(`gate${g}`, [-0.55, 0.45, 0]), { move: true, arc: 0.5 }));
    chain.push(kf(s, chain[chain.length - 1].at), kf(s + 3, pos(`gate${g}`, [-0.55, 1.05, 0]), { move: true, arc: 0.5 }));
    if (stop === g) break;
    leaf.push(kf(s + 7, leaf[leaf.length - 1].at), kf(s + 9.5, pos(`gate${g}`, [0.55, 0.45, 0]), { move: true, arc: 0.2 }));
    chain.push(kf(s + 7, chain[chain.length - 1].at), kf(s + 9.5, pos(`gate${g}`, [0.55, 1.05, 0]), { move: true, arc: 0.2 }));
  }
  if (stop === null) {
    leaf.push(kf(160, leaf[leaf.length - 1].at), kf(162, pos('exit', [0, 0.45, 0]), { move: true, arc: 0.3 }));
    chain.push(kf(160, chain[chain.length - 1].at), kf(162, pos('exit', [0, 1.05, 0]), { move: true, arc: 0.3 }));
    if (sc.revokeAtEnd) {
      // 最初の接続は成功済み。新規接続のために証明書が再び提示される
      leaf.push(kf(166, null, { hide: true }), kf(170, pos('client', [-0.45, 0.9, 0])),
        kf(171, pos('client', [-0.45, 0.9, 0])), kf(175, pos('gate4', [-0.55, 0.45, 0]), { move: true, arc: 1.0 }));
      chain.push(kf(166, null, { hide: true }), kf(170, pos('client', [0.45, 0.9, 0])),
        kf(171, pos('client', [0.45, 0.9, 0])), kf(175, pos('gate4', [-0.55, 1.05, 0]), { move: true, arc: 1.0 }));
    }
  }
  tracks.leaf = leaf;
  tracks.chainCopy = chain;

  // 失効確認で参照する CRL（ゲート⑤の場面で配布区画から取り寄せる）
  if (stop === null || stop >= 4) {
    tracks.crlFetch = [
      kf(140, pos('crl', [0, 1.1, 0.6])),
      kf(141, pos('crl', [0, 1.1, 0.6])),
      kf(145, pos('gate4', [0.7, 1.6, -1.0]), { move: true, arc: 2.5 }),
    ];
  }
  if (sc.revokeAtEnd) {
    tracks.crlNew = [
      kf(163, pos('crl', [0, 1.1, 0.6])),
      kf(164, pos('crl', [0, 1.1, 0.6])),
      kf(169, pos('gate4', [0.7, 1.6, -1.0]), { move: true, arc: 2.5 }),
    ];
    tracks.crlFetch?.push(kf(163, null, { hide: true }));
  }
  return tracks;
}

// ---- 時刻 t の状態 ---------------------------------------------------------
export function lessonState(t, scenarioKey = 'lesson') {
  const sc = SCENARIOS[scenarioKey] ?? SCENARIOS.lesson;
  t = Math.max(0, Math.min(DURATION, t));
  const sceneIndex = sceneIndexAt(t);
  const scene = SCENES[sceneIndex];
  const tracks = buildTracks(scenarioKey);
  const tokens = {};
  for (const [name, track] of Object.entries(tracks)) tokens[name] = sample(track, t);

  // ゲートの状態
  const gates = GATES.map((g, i) => {
    const s = 100 + i * 10;
    let state = 'idle';
    if (sc.failAt !== null && i > sc.failAt) state = t >= s ? 'skipped' : 'idle';
    else if (t >= s + 3 && t < s + 6.5) state = 'checking';
    else if (t >= s + 6.5) {
      if (sc.failAt === i) state = sc.verdict === 'INDETERMINATE' ? 'indeterminate' : 'fail';
      else state = 'pass';
    }
    return { ...g, state, open: state === 'pass' ? ease((t - s - 6.5) / 1.5) : 0 };
  });

  let revokedReplay = false;
  if (sc.revokeAtEnd && t >= 160) {
    revokedReplay = true;
    // 新規接続：失効ゲートだけ「拒否」に変わる
    for (const g of gates) { if (g.state === 'pass' && t >= 170) g.open = 1; }
    if (t >= 170) { gates[5].state = 'idle'; gates[5].open = 0; } // 新規接続はここまで届かない
    if (t >= 175) { gates[4].state = t >= 176.5 ? 'fail' : 'checking'; gates[4].open = 0; }
  }

  // 可動部
  const vaultDoor = Math.max(win(t, 10, 13, 17, 19), win(t, 20, 21, 23, 25)) * 1.6; // rad
  const drawer = Math.max(win(t, 26, 27, 29, 30), win(t, 100, 101, 108, 109)) * 0.45; // m
  const press = win(t, 74.5, 75.3, 75.8, 76.6); // 0..1
  const signingGlow = win(t, 74.5, 75.3, 76.5, 78);
  const serverKeyGlow = win(t, 30, 31, 44, 46);
  const auditGlow = win(t, 80, 81, 86, 88);
  const raCheck = win(t, 58, 60, 68, 70);
  const crlUpdate = win(t, 160, 161, 166, 168);
  const tlsSpark = sc.failAt === null ? win(t, 153, 154, 158, 160) : 0;

  let result = null;
  const done = sc.revokeAtEnd ? t >= 176.5 : (sc.failAt === null ? t >= 160 : t >= 106.5 + sc.failAt * 10);
  if (done) {
    result = { verdict: sc.verdict, code: sc.outcome };
  } else if (sc.revokeAtEnd && t >= 162 && t < 170) {
    result = { verdict: 'ACCEPT', code: 'OK', note: '最初の接続は成功' };
  }

  return {
    t, sceneIndex, scene, scenario: sc, tokens, gates,
    parts: { vaultDoor, drawer, press, signingGlow, serverKeyGlow, auditGlow, raCheck, crlUpdate, tlsSpark },
    revokedReplay, result,
    blame: done && sc.failAt !== null ? (sc.blame ?? 'leaf') : (done && sc.revokeAtEnd ? 'leaf' : null),
  };
}

// 立ち上がり a→b、維持、立ち下がり c→d の窓関数（0..1）
function win(t, a, b, c, d) {
  if (t <= a || t >= d) return 0;
  if (t < b) return ease((t - a) / (b - a));
  if (t <= c) return 1;
  return 1 - ease((t - c) / (d - c));
}

// ---- ラボの実測イベント（pkilab export-events）との対応 ---------------------
export const EVENT_TO_SCENE = {
  ROOT_CREATED: 0, INTERMEDIATE_DELEGATED: 1, CSR_CREATED: 4, CSR_SIGNATURE_CHECKED: 5,
  REQUEST_AUTHORIZED: 6, REQUEST_REJECTED: 6, CERT_ISSUED: 7, CERT_DEPLOYED: 8,
  TRUST_ANCHOR_SELECTED: 10, PATH_VALIDATED: 10, SAN_CHECKED: 11, REVOCATION_CHECKED: 14,
  VERIFY_ACCEPTED: 15, VERIFY_REJECTED: 17, TLS_HANDSHAKE_COMPLETED: 15, TLS_HANDSHAKE_REJECTED: 17,
  CERT_REVOKED: 16, INTERMEDIATE_REVOKED: 16, CRL_PUBLISHED: 16,
};

export function parseEvents(doc) {
  if (!doc || doc.schema !== 'pkilab-events/1' || !Array.isArray(doc.events)) {
    throw new Error('pkilab-events/1 形式の JSON ではありません');
  }
  const text = JSON.stringify(doc);
  if (/PRIVATE KEY|BEGIN /.test(text)) throw new Error('秘密情報らしき文字列を含むため読み込みません');
  return doc.events.map((e) => ({
    ...e,
    scene: EVENT_TO_SCENE[e.type] ?? null,
    measured: doc.measured === true,
  }));
}
