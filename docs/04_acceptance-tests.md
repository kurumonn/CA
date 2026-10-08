# 04 受入試験

自動試験: `python3 -m unittest discover -s lab/tests -v`（37件）
3D ロジック: `cd viz && npm test`（11件）
実ブラウザ描画: `viz/tests/render-check.mjs`（Playwright / Chromium、12構図）

## PKI Lab（`lab/tests/test_pkilab.py`）

| 区分 | 試験 | 期待結果 |
|---|---|---|
| 鍵 | `test_keys_separated_and_encrypted` | ルート・中間鍵が暗号化PKCS#8・0600、issuer/ にルート鍵なし、public/ に秘密鍵なし |
| 鍵 | `test_profiles` | 中間 pathlen:0＋名前制約、ルート pathlen:1・P-256 |
| 権限 | `test_role_separation` | RA 役割での発行は `ROLE_DENIED` |
| 発行 | `test_issue_and_verify_ok` | DNS/IP どちらでも OK、CA:FALSE・serverAuth のみ |
| 発行 | `test_idempotent_issue` | 再実行で同じ証明書、台帳は1件 |
| 審査 | `test_reject_disallowed_san` | example.com / sub.localhost / *.localhost / 10.0.0.1 を拒否 |
| 審査 | `test_reject_ca_request_in_csr` | CA:TRUE 要求を拒否 |
| 審査 | `test_reject_client_auth_request` | clientAuth 要求を拒否 |
| 審査 | `test_reject_rsa_key` | RSA 鍵を拒否 |
| 審査 | `test_reject_missing_san` | SAN なしを拒否 |
| 審査 | `test_reject_oversized_csr` | 64KiB 超を拒否 |
| 審査 | `test_reject_tampered_csr_signature` | 署名改ざんを拒否 |
| 承認 | `test_issue_without_approval` | `NOT_APPROVED` |
| 承認 | `test_csr_changed_after_approval` | `APPROVAL_MISMATCH` |
| 承認 | `test_approval_expired` | `APPROVAL_EXPIRED` |
| 排他 | `test_lock_busy` | ロック保持中は `LOCK_BUSY`、解放後は成功 |
| 復旧 | `test_crash_and_recover_without_double_issue` | 署名前停止 → `NEEDS_RECOVERY` → APPROVED に戻して発行 |
| 復旧 | `test_recover_adopts_already_signed_certificate` | 署名後停止 → 既存証明書を採用、二重発行なし |
| 検証 | `test_untrusted_anchor` | 別ルートを信頼 → `UNTRUSTED_ANCHOR` |
| 検証 | `test_hostname_mismatch` | example.com / 127.0.0.2 → `SAN_MISMATCH` |
| 検証 | `test_wrong_purpose` | sslclient 用途 → `WRONG_EKU` |
| 検証 | `test_expired` | 45日後評価 → `CERT_EXPIRED` |
| 検証 | `test_crl_expired_is_indeterminate` | 2日後評価 → `INDETERMINATE / CRL_EXPIRED` |
| 検証 | `test_crl_missing_is_indeterminate` | ルート CRL なし → `INDETERMINATE / CRL_MISSING` |
| 失効 | `test_leaf_revoked` | `LEAF_REVOKED`、失効確認なしだと OK になってしまう |
| 失効 | `test_intermediate_revoked` | `INTERMEDIATE_REVOKED` |
| 制約 | `test_name_constraints_block_misissuance` | 審査を迂回した example.com 証明書も `NAME_CONSTRAINT_VIOLATION` |
| 制約 | `test_cn_only_certificate_rejected` | CN だけの証明書は `SAN_REQUIRED` |
| TLS | `test_tls_accept_then_reject_after_revocation` | TLS1.3 成功 → 失効後 `LEAF_REVOKED`、確認なしなら接続できる |
| TLS | `test_tls_intermediate_revoked` | `INTERMEDIATE_REVOKED` |
| TLS | `test_tls_wrong_host` | `SAN_MISMATCH` |
| TLS | `test_curl_does_not_check_revocation_by_default` | curl は既定で成功、`--crlfile` で失敗 |
| 監査 | `test_audit_chain_ok_and_tamper_detected` | 1行改ざん → `AUDIT_TAMPERED` |
| 監査 | `test_audit_truncation_detected_by_anchor` | 末尾削除 → `AUDIT_TRUNCATED_OR_REWRITTEN` |
| 照合 | `test_consistency_check` | 正常時 OK、発行物消失を検出 |
| 復旧 | `test_backup_and_restore` | 暗号化バックアップに平文鍵なし、隔離先で `ready: true` |
| 教材 | `test_export_events_has_no_secrets` | 必要なイベント種別があり、秘密情報・シリアルを含まない |

## 未実装・対象外（試験で代替したと扱わないもの）

- 物理的に分離した Root VM・HSM・独立した二者承認
- HTTP 以外での CRL 配布、OCSP レスポンダー、ACME
- 長時間運用（CRL の定期再発行を自動で回す仕組み）
