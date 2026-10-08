#!/usr/bin/env bash
# PKI Lab の一連の流れを実行するデモ。
#   CA 構築 → 申請 → 審査・承認 → 発行 → 検証 → HTTPS 接続
#   → 失効 → 失効確認あり/なしの比較 → 監査・照合 → 3D 用イベント出力
#
# 使い方: bash lab/scripts/demo.sh [作業ディレクトリ]
# 既定の作業ディレクトリは lab/work（.gitignore 済み）。秘密鍵はここに作られる。
set -euo pipefail

LAB="$(cd "$(dirname "$0")/.." && pwd)"
HOME_DIR="${1:-$LAB/work}"
PORT="${PKILAB_DEMO_PORT:-8443}"
pk() { python3 "$LAB/pkilab.py" --home "$HOME_DIR" "$@"; }
step() { printf '\n\033[1;33m== %s ==\033[0m\n' "$*"; }
field() { python3 -c "import json,sys; print(json.load(sys.stdin)['$1'])"; }

if [ -e "$HOME_DIR/root/certs/root.cert.pem" ]; then
  echo "既に $HOME_DIR に CA があります。消してやり直す場合: rm -rf '$HOME_DIR'" >&2
  exit 1
fi

step "1. ルートCA・中間CAを作成（ルート鍵は root/ 、中間CA鍵は issuer/ に分離）"
pk init >/dev/null
openssl x509 -in "$HOME_DIR/issuer/certs/intermediate.cert.pem" -noout -subject -issuer -ext basicConstraints,nameConstraints

step "2. サーバー管理者が鍵と CSR を作って申請"
REQ=$(pk request | field request)
echo "申請ID: $REQ"

step "3. RA が審査・承認（許可外の名前は拒否される例も確認）"
BAD=$(pk request --san DNS:example.com | field request)
pk approve "$BAD" || true
pk approve "$REQ" | head -12

step "4. 中間CAが発行（発行後検査・台帳・監査まで）"
pk issue "$REQ"

step "5. 証明書ファイルを検証（信頼・SAN・用途・期限・チェーン全体の CRL）"
pk verify --request "$REQ"
pk verify --request "$REQ" --host example.com || true

step "6. HTTPS サーバーを起動し、厳格なクライアントで接続"
python3 "$LAB/pkilab.py" --home "$HOME_DIR" serve-https "$REQ" --port "$PORT" 2>/dev/null &
SERVER=$!
trap 'kill $SERVER 2>/dev/null || true' EXIT
for _ in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null && break; sleep 0.1; done
pk client --port "$PORT"
if command -v curl >/dev/null; then
  echo "curl（ルートCAをこの場だけ信頼）:"
  curl -sS --noproxy '*' --cacert "$HOME_DIR/public/certs/root.cert.pem" "https://localhost:$PORT/"
fi

step "7. 証明書を失効させ、CRL を更新"
pk revoke "$REQ" --reason keyCompromise

step "8. 失効確認あり → 拒否 / 失効確認なし → 接続できてしまう"
pk client --port "$PORT" || true
pk client --port "$PORT" --no-crl || true
if command -v curl >/dev/null; then
  echo "curl（既定では失効確認しない）:"
  curl -sS --noproxy '*' --cacert "$HOME_DIR/public/certs/root.cert.pem" "https://localhost:$PORT/" || true
  echo "curl --crlfile（失効確認する）:"
  curl -sS --noproxy '*' --cacert "$HOME_DIR/public/certs/root.cert.pem" \
       --crlfile "$HOME_DIR/public/crl/intermediate.crl.pem" "https://localhost:$PORT/" || echo "→ 拒否されました（期待どおり）"
fi

step "9. 監査ログのハッシュ連鎖と、台帳・CRL の照合"
pk audit-verify
pk check

step "10. 3D 教材用のイベント JSON を出力（秘密情報なし）"
pk export-events
echo
echo "完了。viz/ を開いて「実測イベント」から $HOME_DIR/exports/events.json を読み込めます。"
