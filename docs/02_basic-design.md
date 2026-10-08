# 02 基本設計 — 学習用私設CA「PKI Lab」

## 1. 全体構成

```
┌──────────────────────────────────┐
│ Root 領域（本来は Root VM：ネットワークなし・通常停止）│
│   root/private/root.key.pem（暗号化 PKCS#8）           │
│   ├─ 中間CA証明書に署名（sign-intermediate）         │
│   └─ ルート CRL に署名（crl-root）                   │
└───────────────┬──────────────────┘
        持ち込み: 中間CAの CSR    持ち出し: 公開証明書・CRL だけ
                ▼
┌──────────────────────────────────┐
│ Lab 領域（外部非公開）                                  │
│   server-admin → ra → issuer                          │
│                    ├─ サーバー証明書                   │
│                    └─ 中間CA CRL                       │
│   HTTPS サーバー（server/private の鍵）                 │
│   public/ → verifier（verify / client）                │
│   audit/ → export-events → viz/（3D 教材）             │
└──────────────────────────────────┘
```

このリポジトリの実装は1台の中でディレクトリと役割を分けた**論理分離**である。オフラインルートの安全性を再現したとは扱わない。本格的に試す場合は `root/` と `secrets/root.pass` を別 VM に置き、`PKILAB_ROOT_PASS_FILE` で参照する。

## 2. 証明書を発行する流れ

1. サーバー側で EC P-256 の秘密鍵を作る（CA に渡さない）
2. 公開鍵と SAN を入れた CSR を作り、秘密鍵で署名（`request`）
3. RA が CSR 署名・鍵種別・SAN・要求用途を審査（`approve`）
4. 承認を CSR ハッシュ・プロファイルハッシュ・SAN・期間・承認者・期限に結び付けて記録
5. 中間CAが固定プロファイルで署名（`issue`）
6. 発行後検査 → 台帳照合 → 監査記録
7. 葉＋中間CAのチェーンをサーバーへ配置
8. 実 TLS 接続で確認（`serve-https` ＋ `client`）

CSR の署名で分かるのは「その公開鍵の秘密鍵を持っている」ことだけ。名前を使う権限の確認は RA の工程で別に行う。

## 3. 証明書プロファイル

| 項目 | ルートCA | 中間CA | TLS サーバー |
|---|---|---|---|
| 鍵 / 署名 | EC P-256 / ECDSA-SHA256 | 同左 | 同左 |
| 有効期間 | 1,825日 | 365日 | 30日 |
| Basic Constraints | critical, CA:TRUE, pathlen:1 | critical, CA:TRUE, pathlen:0 | critical, CA:FALSE |
| Key Usage | critical, keyCertSign, cRLSign | critical, keyCertSign, cRLSign | critical, digitalSignature |
| EKU | なし | serverAuth | serverAuth |
| SAN | なし | なし | DNS:localhost, IP:127.0.0.1 |
| Name Constraints | なし | critical, permitted DNS:localhost, IP:127.0.0.1/32 | なし |
| CRL 配布点 | なし | ルート CRL | 中間CA CRL |

設定: `lab/config/root.cnf`、`lab/config/intermediate.cnf`、`lab/config/profiles/server_localhost.ext`。

- `pathlen:0` は「さらに下位の CA を経由する経路」を制限するもので、署名処理を物理的に止める機能ではない。発行審査と検証側の深さ制限（`-verify_depth 1`）を併用する。
- DNS の名前制約は配下（`sub.localhost`）も許すため、発行審査では完全一致の許可リストを使う。
- 接続先名は SAN で検証し、CN へのフォールバックは使わない（RFC 9525）。

## 4. 鍵管理

| 鍵 | 保管先 | 保護 |
|---|---|---|
| ルート秘密鍵 | `root/private/` | PKCS#8 / PBES2 / AES-256-CBC / PBKDF2-HMAC-SHA256、反復回数は `PKILAB_KDF_ITER`（既定 200,000） |
| 中間CA秘密鍵 | `issuer/private/` | 同上 |
| サーバー秘密鍵 | `server/private/` | 0600 の非暗号化 PEM（ローカル非対話デモのための**例外**） |
| バックアップ | `backups/` | CA 鍵とは別のパスフレーズで AES-256-CBC + PBKDF2 |

- 平文の CA 鍵はパイプで受け渡し、ディスクに書かない。
- パスフレーズは `-passin file:` で渡し、コマンド引数・ログに残さない。
- 学習のため `secrets/` にランダム生成したパスフレーズを置く。本番相当の運用では各担当者だけが知る場所に分ける。

## 5. 失効

| 失効する対象 | 主体 | 利用側が確認する情報 |
|---|---|---|
| サーバー証明書 | 中間CA | 中間CA CRL |
| 中間CA証明書 | ルートCA | ルート CRL |
| ルート（信頼アンカー） | 検証側の管理者 | 信頼設定から削除 |

検証では `-crl_check -crl_check_all`（Python は `VERIFY_CRL_CHECK_CHAIN`）でチェーン全体を確認する。

| 項目 | ルート CRL | 中間CA CRL |
|---|---|---|
| 有効期間 | 30日 | 24時間 |
| 失効発生時 | 直ちに再発行・配布 | 直ちに再発行・配布（`revoke` が自動実行） |
| 初期状態 | 失効0件で生成 | 失効0件で生成 |

「失効している（REJECT）」と「失効状態を確認できない（INDETERMINATE）」は別の結果として記録し、どちらも接続は許可しない。

## 6. 公開CAとの違い

| 観点 | PKI Lab | 公開 Web PKI の CA |
|---|---|---|
| 信頼する利用者 | 自分が明示した検証環境 | ルートプログラムに組み込まれた多数の利用者 |
| 審査 | ローカル資産と操作権限 | 規定に沿ったドメイン・IP 管理権限の確認 |
| 規程・監査 | 学習用の独自ルール・自己点検 | CA/Browser Forum 要件・独立監査 |
| 失効情報 | 実験中だけ提供 | 規程に沿って継続提供 |
| 鍵保護 | 暗号化ファイル＋論理分離 | HSM など要件に沿った保護 |
