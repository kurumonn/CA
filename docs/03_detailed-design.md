# 03 詳細設計 — 学習用私設CA「PKI Lab」

実装: `lab/pkilab.py`（Python 標準ライブラリ＋OpenSSL 3.x CLI）

## 1. ファイル配置（`PKILAB_HOME`、既定 `lab/work/`）

```
root/{private,certs,db,newcerts,crl}     ルートCA（本来は Root VM）
issuer/{private,certs,db,newcerts,crl,lock}  中間CA
requests/REQ-*/{request.csr.pem,state.json,cert.json}
approvals/REQ-*.json      承認記録
journal/OP-*.json         未完了操作の記録
audit/audit.jsonl         監査ログ（ハッシュ連鎖）
anchor/anchor.json        最新の連番とハッシュ（別媒体の代用）
server/{private,certs}    サーバー鍵・証明書・フルチェーン
public/{certs,crl}        配布してよい公開情報だけ
verifier/{bundle,cache}   検証用バンドル・CRL キャッシュ
exports/events.json       3D 教材用イベント
secrets/                  学習用パスフレーズ（0600）
backups/                  暗号化バックアップ
```

`serve-public` は `public/` だけを配信し、PUT/POST/DELETE を 405 で拒否する。

## 2. 申請の状態遷移

```
RECEIVED → VALIDATED → APPROVED → SIGNING → ISSUED → PUBLISHED
例外: REJECTED / APPROVAL_EXPIRED / NEEDS_RECOVERY / QUARANTINED
```

許可される遷移は `TRANSITIONS` で定義し、それ以外は `BAD_TRANSITION` で拒否する。

## 3. CSR 受付検査（`inspect_csr`）

| 検査 | 拒否コード |
|---|---|
| 64 KiB 超 | `CSR_TOO_LARGE` |
| PEM でない | `CSR_BAD_FORMAT` |
| CSR 自己署名の不一致 | `CSR_BAD_SIGNATURE` |
| EC P-256 以外 | `CSR_BAD_KEY` |
| CA:TRUE / keyCertSign / cRLSign / clientAuth / codeSigning の要求 | `CSR_FORBIDDEN_EXTENSION` |
| SAN なし | `SAN_REQUIRED` |
| 許可リスト外の SAN | `SAN_NOT_ALLOWED` |

発行時は `copy_extensions = none` とし、拡張は `server_localhost.ext` から CA 側で生成する。

## 4. 承認記録

```json
{ "approval_id", "request", "csr_sha256", "pubkey_sha256",
  "profile", "profile_sha256", "san", "days",
  "approver", "approved_at", "expires_at", "note" }
```

発行時に CSR ハッシュ・プロファイルハッシュ・期限を再確認し、違えば `APPROVAL_MISMATCH` / `APPROVAL_EXPIRED`。

## 5. 期間制御

```
notBefore = max(現在 − 300秒, 発行元CAの notBefore)
notAfter  = 現在 + 30日
必須: notAfter ≤ 発行元CAの notAfter − 24時間  （満たさなければ ISSUER_RENEWAL_REQUIRED）
```

`openssl ca -startdate/-enddate` で明示する。期限切れの再現は OS 時刻を変えず `verify --attime` で行う。

## 6. 発行処理（`cmd_issue`）

1. `issuer/lock/ca.lock` を `flock`（`PKILAB_LOCK_TIMEOUT` 秒で `LOCK_BUSY`）
2. 状態確認：ISSUED/PUBLISHED なら同じ証明書を返す（冪等）。SIGNING/NEEDS_RECOVERY なら `NEEDS_RECOVERY` で停止
3. 承認・CSR・プロファイル・中間CAの残存期間を再確認
4. `journal/OP-*.json` に開始を記録 → 状態を SIGNING に
5. `openssl ca -batch -notext -subj ... -extfile ... -startdate ... -enddate ...` で非公開領域に生成
6. 発行後検査：CA:FALSE、SAN 一致、公開鍵一致、EKU=serverAuth のみ、親より長くない、チェーン検証、台帳と newcerts の存在
7. 不合格なら失効させて QUARANTINED（`POST_ISSUE_CHECK_FAILED`）
8. `cert.json` 記録 → ISSUED → 監査 → サーバーとpublicへ配置 → PUBLISHED → 操作完了記録 → ロック解放

## 7. 復旧（`cmd_recover`）

SIGNING / NEEDS_RECOVERY の申請について、`issuer/db/index.txt` の各シリアルの発行物の公開鍵ハッシュを承認の公開鍵ハッシュと照合する。

- 一致あり → その証明書を採用（`adopted_existing_certificate`、二重発行しない）
- 一致なし → APPROVED に戻す（`returned_to_approved`）

## 8. 検証（`cmd_verify`）

```
openssl verify -show_chain -x509_strict -auth_level 2 -verify_depth 1 \
  -purpose sslserver -verify_hostname localhost (IP の場合 -verify_ip) \
  -trusted root.cert.pem -untrusted intermediate.cert.pem \
  -CRLfile crls.pem -crl_check -crl_check_all  server.cert.pem
```

事前に SAN の有無を構造検査し、無ければ `SAN_REQUIRED`（CN フォールバックを許さない）。

| OpenSSL エラー | 結果コード | 判定 |
|---|---|---|
| 2, 19, 20, 21 | `UNTRUSTED_ANCHOR` | REJECT |
| 62, 64 | `SAN_MISMATCH` | REJECT |
| 10 / 9 | `CERT_EXPIRED` / `NOT_YET_VALID` | REJECT |
| 26 | `WRONG_EKU` | REJECT |
| 23（深さ0 / 1） | `LEAF_REVOKED` / `INTERMEDIATE_REVOKED` | REJECT |
| 47, 48 | `NAME_CONSTRAINT_VIOLATION` | REJECT |
| 3 / 12 / 11 / 8 | `CRL_MISSING` / `CRL_EXPIRED` / … | INDETERMINATE |

## 9. 実 TLS 接続（`strict_client_context`）

- `PROTOCOL_TLS_CLIENT`（証明書必須・ホスト名検証）、TLS 1.3 以上
- `hostname_checks_common_name = False`
- `verify_flags = VERIFY_X509_STRICT | VERIFY_CRL_CHECK_CHAIN`（`PARTIAL_CHAIN` を外し中間CAを信頼の起点にしない）
- 信頼するのはルート1つだけ。CRL は PEM で読み込む
- 失効（23）の場合、Python の例外は深さを持たないため、検証なしの別接続で葉のシリアルだけを読み、中間CA CRL と照合して葉／中間を判別する

サーバーは「葉＋中間CA」を送り、ルートは送らない。

## 10. 監査ログ

各行: `seq, ts, actor, role, op, result, target, details, prev, hash`。`hash = SHA-256(正規化 JSON（hash を除く）)`、`prev` は直前の hash。最新の `seq/hash` を `anchor/anchor.json`（別媒体の代用）に書き、`audit-verify` で改ざん（`AUDIT_TAMPERED`）と末尾削除・再計算（`AUDIT_TRUNCATED_OR_REWRITTEN`）を検出する。秘密鍵・パスフレーズ・セッション鍵は記録しない。

## 11. 照合（`cmd_check`）

承認 ⇔ 申請状態 ⇔ `index.txt` ⇔ `newcerts/` ⇔ 公開 CRL ⇔ 監査ログ を照合し、不一致を列挙する（台帳にあるが発行物がない／申請に紐づかない有効な証明書／CRL 未反映の失効／CRL の期限切れ など）。

## 12. バックアップと復旧

`backup` は root・issuer・requests・approvals・journal・audit・public・anchor を tar.gz にし、別パスフレーズで暗号化する。`restore` は**空の隔離ディレクトリ**にだけ展開し（パス逸脱・リンクは拒否）、監査ログ検証と照合が通った場合に `ready: true` を返す。

台帳が壊れたときに空の `index.txt` を作って旧 CA 鍵で発行を再開することは禁止する（失効状態が消え、失効済み証明書が有効に戻るため）。状態を確定できない場合は旧 CA を廃止し、新しい世代に移行する。

## 13. 鍵漏えい時の手順

| 漏えい | 手順 |
|---|---|
| サーバー鍵 | 停止 → `revoke REQ --reason keyCompromise`（CRL 自動更新）→ 新しい申請で再発行 |
| 中間CA鍵 | 発行停止 → `revoke-intermediate --reason CACompromise` → 新しい中間CAへ移行 |
| ルート鍵 | 旧階層停止 → 検証側で旧ルートの信頼を削除 → 新ルートを別経路で配布 |

## 14. 教材イベント出力（`export-events`）

監査ログから `pkilab-events/1` 形式を作る。`target` は SHA-256 の先頭12桁に置き換え、`details` は許可したキーだけを残す。出力に `PRIVATE KEY` / `BEGIN` が含まれたら破棄する。対応表は `viz/js/lesson.js` の `EVENT_TO_SCENE`。
