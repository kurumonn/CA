# 自分だけの認証局（CA）— 学習用 PKI ラボと3D教材

ルートCA → 中間CA → localhost 用サーバー証明書の3階層を自分で構築し、
**発行・審査・失効・検証・監査・復旧**までを試せる学習用の私設CAと、
その流れを three.js の3Dアニメーションで見られる教材「信頼のアトリエ」です。

> 学習用です。公開認証局として運用できるものではありません。
> 本人確認、HSM、独立監査、CRL の継続配布、OCSP などは対象外です。

![信頼のアトリエ](articles/images/atelier-01-overview.png)

## 構成

| ディレクトリ | 内容 |
|---|---|
| [`lab/`](lab/) | CA を操作する CLI `pkilab.py`（Python 標準ライブラリ＋OpenSSL）、OpenSSL 設定、デモ、自動テスト |
| [`viz/`](viz/) | three.js の3D学習空間（three.js r169 同梱・CDN 不要） |
| [`docs/`](docs/) | 要件定義・基本設計・詳細設計・受入試験・3D空間設計 |
| [`articles/`](articles/) | ブログ記事の原稿（解説2本・日記1本）と画像 |

## すぐ試す

必要なもの: Python 3.9 以上、OpenSSL 3.x（Linux / WSL2 / macOS）

```bash
bash lab/scripts/demo.sh
```

CA 構築 → 申請 → RA 審査 → 発行 → 検証 → HTTPS 接続 → 失効 → 失効確認あり／なしの比較 → 監査・照合 → 3D 用イベント出力 までを順に実行します。作業ディレクトリ `lab/work/`（秘密鍵が作られる。Git 管理外）をやり直すときは削除してください。

### 1つずつ操作する

```bash
cd lab
python3 pkilab.py init                         # ルートCA・中間CA・初期CRL
python3 pkilab.py request                      # [server-admin] 鍵とCSRを作って申請
python3 pkilab.py approve <REQ-ID>             # [ra] 審査・承認
python3 pkilab.py issue <REQ-ID>               # [issuer] 発行（冪等）
python3 pkilab.py verify --request <REQ-ID>    # [verifier] 証明書検証（CRL込み）
python3 pkilab.py serve-https <REQ-ID>         # [server-admin] 127.0.0.1:8443
python3 pkilab.py client                       # [verifier] 厳格な TLS 1.3 クライアント
python3 pkilab.py revoke <REQ-ID> --reason keyCompromise   # 失効＋CRL再発行
python3 pkilab.py revoke-intermediate          # [root-admin] 中間CAの失効
python3 pkilab.py audit-verify                 # 監査ログのハッシュ連鎖
python3 pkilab.py check                        # 承認・台帳・証明書・CRL の照合
python3 pkilab.py backup / restore <file> <dir>
python3 pkilab.py export-events                # 3D 教材向け（秘密情報なし）
```

`--role` を省略するとコマンドごとの標準の役割で実行されます。許可されていない役割では `ROLE_DENIED` になります。

### 結果コード

| コード | 意味 |
|---|---|
| `OK` | すべての確認に合格 |
| `UNTRUSTED_ANCHOR` | 信頼するルートまでたどれない |
| `SAN_MISMATCH` | 接続先名が SAN にない |
| `CERT_EXPIRED` | 期限切れ |
| `WRONG_EKU` | 用途が違う |
| `LEAF_REVOKED` / `INTERMEDIATE_REVOKED` | 葉／中間CAが失効 |
| `NAME_CONSTRAINT_VIOLATION` | 中間CAの名前制約の外 |
| `CRL_MISSING` / `CRL_EXPIRED` | 失効状態を確認できない（判定不能。接続はしない） |

## 3D 教材を開く

```bash
cd viz
python3 -m http.server 8765 --bind 127.0.0.1
# http://127.0.0.1:8765/ を開く
```

180秒・18場面のアニメーションと、9つの条件（正常・信頼していないルート・名前違い・期限切れ・用途違い・葉の失効・中間CAの失効・CRL期限切れ・本編）を切り替えられます。「実測イベント」から `lab/work/exports/events.json` を読み込むと、ラボで実際に起きた処理の場面に印が付きます。

ブログへの埋め込み: `viz/` を静的ファイルとして置き、`?embed=1&autoplay=0` を付けて iframe で表示します。

## テスト

```bash
python3 -m unittest discover -s lab/tests -v     # CA ラボ 37件
(cd viz && npm test)                              # 3D 教材のロジック 11件
```

実ブラウザでの描画確認（Playwright が必要）:

```bash
python3 -m http.server 8765 --bind 127.0.0.1 --directory viz &
node viz/tests/render-check.mjs http://127.0.0.1:8765/ screenshots
```

## ライセンス・同梱物

- `viz/vendor/three/` は three.js（MIT License、`viz/vendor/three/LICENSE`）
- 秘密鍵・パスフレーズはリポジトリに含めていません
