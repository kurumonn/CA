#!/usr/bin/env python3
"""PKI Lab: 学習用の私設認証局 CLI。

ルートCA → 中間CA → localhost 用 TLS サーバー証明書 の3階層を、
「申請 → 審査 → 承認 → 発行 → 配置 → 検証 → 失効 → 監査 → 復旧」の
流れで操作できるようにする。証明書処理は OpenSSL に任せ、このスクリプトは
業務ルール（審査・承認の結び付け・排他・状態遷移・監査・照合）を受け持つ。

公開認証局として運用できるものではない。設計の詳細は docs/ を参照。
標準ライブラリだけで動作する（Python 3.9 以上 / OpenSSL 3.x）。
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import errno
import fcntl
import hashlib
import http.server
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

LAB_DIR = Path(__file__).resolve().parent
CONFIG_DIR = LAB_DIR / "config"
ROOT_CNF = CONFIG_DIR / "root.cnf"
ISSUER_CNF = CONFIG_DIR / "intermediate.cnf"
SERVER_PROFILE = CONFIG_DIR / "profiles" / "server_localhost.ext"

# --- 設計値（docs/02_basic-design.md の証明書プロファイル） -----------------
ROOT_DAYS = 1825
ISSUER_DAYS = 365
LEAF_DAYS = 30
BACKDATE_SECONDS = 300
ISSUER_MARGIN = dt.timedelta(hours=24)
APPROVAL_TTL = dt.timedelta(hours=24)
MAX_CSR_BYTES = 64 * 1024
MAX_CRL_BYTES = 1024 * 1024
ALLOWED_SAN = {"DNS:localhost", "IP:127.0.0.1"}
KDF_ITER = int(os.environ.get("PKILAB_KDF_ITER", "200000"))
LOCK_TIMEOUT = float(os.environ.get("PKILAB_LOCK_TIMEOUT", "5"))

# 役割ごとに許可する操作（1人で切り替える学習用の役割分離）
ROLE_OPS = {
    "root-admin": {"init-root", "sign-intermediate", "revoke-intermediate", "crl-root"},
    "issuer": {"init-issuer", "issue", "revoke", "crl-issuer", "recover"},
    "ra": {"approve", "reject"},
    "server-admin": {"request", "serve-https"},
    "verifier": {"verify", "client", "bundle"},
    "auditor": {"audit-verify", "check", "export-events"},
    "operator": {"backup", "restore", "serve-public", "status"},
}

# 申請の状態遷移
TRANSITIONS = {
    "RECEIVED": {"VALIDATED", "REJECTED"},
    "VALIDATED": {"APPROVED", "REJECTED"},
    "APPROVED": {"SIGNING", "APPROVAL_EXPIRED"},
    "SIGNING": {"ISSUED", "NEEDS_RECOVERY", "QUARANTINED"},
    "NEEDS_RECOVERY": {"ISSUED", "APPROVED", "QUARANTINED"},
    "ISSUED": {"PUBLISHED", "QUARANTINED"},
    "PUBLISHED": set(),
    "REJECTED": set(),
    "APPROVAL_EXPIRED": set(),
    "QUARANTINED": set(),
}


class LabError(Exception):
    """業務上の拒否・失敗。code は機械判定用、message は人向け。"""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# =============================================================================
# 共通ユーティリティ
# =============================================================================

def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s: str) -> dt.datetime:
    return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def asn1_time(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime("%Y%m%d%H%M%SZ")


def parse_openssl_date(s: str) -> dt.datetime:
    # 例: "Oct  8 18:40:00 2026 GMT"
    return dt.datetime.strptime(" ".join(s.split()), "%b %d %H:%M:%S %Y GMT").replace(
        tzinfo=dt.timezone.utc)


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_file(p: Path) -> str:
    return sha256_bytes(p.read_bytes())


def write_private(path: Path, data: bytes | str) -> None:
    """所有者だけが読み書きできるファイルとして書く（0600）。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        data = data.encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.chmod(path, 0o600)


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n")
    os.replace(tmp, path)  # 途中で止まっても半端なJSONを残さない


def read_json(path: Path):
    return json.loads(path.read_text())


def canonical(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


class Lab:
    """PKILAB_HOME 配下のファイル配置（docs/03_detailed-design.md 4.1）。"""

    def __init__(self, home: Path, actor: str, role: str):
        self.home = home.resolve()
        self.actor = actor
        self.role = role
        self.env = dict(os.environ, PKILAB_HOME=str(self.home))

    # --- パス ---------------------------------------------------------------
    def p(self, *parts) -> Path:
        return self.home.joinpath(*parts)

    @property
    def root_cert(self) -> Path:
        return self.p("root", "certs", "root.cert.pem")

    @property
    def root_key(self) -> Path:
        return self.p("root", "private", "root.key.pem")

    @property
    def issuer_cert(self) -> Path:
        return self.p("issuer", "certs", "intermediate.cert.pem")

    @property
    def issuer_key(self) -> Path:
        return self.p("issuer", "private", "intermediate.key.pem")

    @property
    def root_pass(self) -> Path:
        # 本番ではルートのパスフレーズは Root VM の管理者だけが知る。
        return Path(os.environ.get("PKILAB_ROOT_PASS_FILE", self.p("secrets", "root.pass")))

    @property
    def issuer_pass(self) -> Path:
        return Path(os.environ.get("PKILAB_ISSUER_PASS_FILE", self.p("secrets", "issuer.pass")))

    def layout(self) -> None:
        dirs = [
            "root/private", "root/certs", "root/db", "root/newcerts", "root/crl",
            "issuer/private", "issuer/certs", "issuer/db", "issuer/newcerts", "issuer/crl",
            "issuer/lock", "requests", "approvals", "journal", "audit", "anchor",
            "server/private", "server/certs", "public/certs", "public/crl",
            "verifier/trust", "verifier/cache", "exports", "secrets", "backups",
        ]
        for d in dirs:
            self.p(d).mkdir(parents=True, exist_ok=True)
        for d in ["root/private", "issuer/private", "server/private", "secrets"]:
            os.chmod(self.p(d), 0o700)

    # --- 権限 ---------------------------------------------------------------
    def require(self, op: str) -> None:
        allowed = ROLE_OPS.get(self.role, set())
        if op not in allowed:
            raise LabError("ROLE_DENIED",
                           f"役割 '{self.role}' は操作 '{op}' を実行できません"
                           f"（--role {role_for(op)} で実行してください）")

    # --- OpenSSL 呼び出し -----------------------------------------------------
    def openssl(self, *args, input: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess:
        cmd = ["openssl", *[str(a) for a in args]]
        cp = subprocess.run(cmd, input=input, capture_output=True, env=self.env)
        if check and cp.returncode != 0:
            raise LabError("OPENSSL_FAILED",
                           f"{' '.join(cmd[:3])} ...: {cp.stderr.decode(errors='replace').strip()}")
        return cp

    # --- 監査ログ（ハッシュ連鎖） -----------------------------------------------
    def audit(self, op: str, result: str, target: str = "", **details) -> dict:
        log = self.p("audit", "audit.jsonl")
        log.parent.mkdir(parents=True, exist_ok=True)
        prev_hash, seq = "0" * 64, 0
        if log.exists():
            lines = [ln for ln in log.read_text().splitlines() if ln.strip()]
            if lines:
                last = json.loads(lines[-1])
                prev_hash, seq = last["hash"], last["seq"]
        entry = {
            "seq": seq + 1,
            "ts": iso(utcnow()),
            "actor": self.actor,
            "role": self.role,
            "op": op,
            "result": result,
            "target": target,
            "details": details,
            "prev": prev_hash,
        }
        entry["hash"] = sha256_bytes(canonical(entry))
        with log.open("a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())
        # 末尾の削除やログ全体の再計算を検出するため、最新の連番とハッシュを
        # 「別媒体」（ここでは anchor/ ディレクトリで代用）にも保存する。
        write_json(self.p("anchor", "anchor.json"), {"seq": entry["seq"], "hash": entry["hash"]})
        return entry

    # --- 排他制御 -------------------------------------------------------------
    @contextlib.contextmanager
    def ca_lock(self, which: str = "issuer"):
        lock_path = self.p(which, "lock", "ca.lock") if which == "issuer" else self.p("root", "db", "ca.lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        deadline = time.monotonic() + LOCK_TIMEOUT
        try:
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError as e:
                    if e.errno not in (errno.EAGAIN, errno.EACCES):
                        raise
                    if time.monotonic() > deadline:
                        raise LabError("LOCK_BUSY", f"{which} CA は別の処理が使用中です")
                    time.sleep(0.1)
            yield
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    # --- 申請の状態 -------------------------------------------------------------
    def req_dir(self, req_id: str) -> Path:
        if not re.fullmatch(r"REQ-[0-9]{8}-[0-9a-f]{8}", req_id):
            raise LabError("BAD_REQUEST_ID", f"不正な申請IDです: {req_id}")
        d = self.p("requests", req_id)
        if not d.exists():
            raise LabError("UNKNOWN_REQUEST", f"申請が見つかりません: {req_id}")
        return d

    def state(self, req_id: str) -> dict:
        return read_json(self.req_dir(req_id) / "state.json")

    def set_state(self, req_id: str, new: str, **extra) -> dict:
        path = self.req_dir(req_id) / "state.json"
        st = read_json(path)
        old = st["status"]
        if new != old and new not in TRANSITIONS[old]:
            raise LabError("BAD_TRANSITION", f"{old} → {new} への遷移は許可されていません")
        st["status"] = new
        st.setdefault("history", []).append({"status": new, "ts": iso(utcnow()), "by": self.actor})
        st.update(extra)
        write_json(path, st)
        return st


def role_for(op: str) -> str:
    for role, ops in ROLE_OPS.items():
        if op in ops:
            return role
    return "?"


# =============================================================================
# 証明書・CSR の解析
# =============================================================================

def cert_info(lab: Lab, cert: Path) -> dict:
    cp = lab.openssl("x509", "-in", cert, "-noout", "-serial", "-subject", "-issuer",
                     "-startdate", "-enddate", "-ext",
                     "subjectAltName,basicConstraints,keyUsage,extendedKeyUsage")
    text = cp.stdout.decode()
    info: dict = {"san": [], "ca": None, "eku": [], "ku": []}
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.startswith("serial="):
            info["serial"] = line.split("=", 1)[1].strip().upper()
        elif line.startswith("subject="):
            info["subject"] = line.split("=", 1)[1].strip()
        elif line.startswith("issuer="):
            info["issuer"] = line.split("=", 1)[1].strip()
        elif line.startswith("notBefore="):
            info["not_before"] = iso(parse_openssl_date(line.split("=", 1)[1]))
        elif line.startswith("notAfter="):
            info["not_after"] = iso(parse_openssl_date(line.split("=", 1)[1]))
        elif "Subject Alternative Name" in line and i + 1 < len(lines):
            info["san"] = normalize_san(lines[i + 1])
        elif "Basic Constraints" in line and i + 1 < len(lines):
            info["ca"] = "CA:TRUE" in lines[i + 1]
        elif "Extended Key Usage" in line and i + 1 < len(lines):
            info["eku"] = [x.strip() for x in lines[i + 1].split(",")]
        elif re.search(r"X509v3 Key Usage", line) and i + 1 < len(lines):
            info["ku"] = [x.strip() for x in lines[i + 1].split(",")]
    pub = lab.openssl("x509", "-in", cert, "-noout", "-pubkey").stdout
    info["pubkey_sha256"] = sha256_bytes(pub)
    info["sha256"] = sha256_file(cert)
    return info


def normalize_san(line: str) -> list[str]:
    out = []
    for item in line.split(","):
        item = item.strip()
        if not item:
            continue
        if item.startswith("IP Address:"):
            out.append("IP:" + item.split(":", 1)[1])
        else:
            out.append(item)
    return sorted(out)


def inspect_csr(lab: Lab, csr: Path) -> dict:
    """CSR の受付検査（docs/03_detailed-design.md 4.4）。"""
    data = csr.read_bytes()
    if len(data) > MAX_CSR_BYTES:
        raise LabError("CSR_TOO_LARGE", f"CSR が上限 {MAX_CSR_BYTES} バイトを超えています")
    if b"-----BEGIN CERTIFICATE REQUEST-----" not in data:
        raise LabError("CSR_BAD_FORMAT", "PEM 形式の CSR ではありません")
    # CSR の自己署名 = 「この公開鍵の秘密鍵を持っている」ことの確認だけ。
    # 名前を使う権限の確認は RA の承認で別に行う。
    cp = lab.openssl("req", "-in", csr, "-noout", "-verify", check=False)
    if cp.returncode != 0 or b"verify failure" in cp.stderr.lower() + cp.stdout.lower():
        raise LabError("CSR_BAD_SIGNATURE", "CSR の署名を検証できません")
    text = lab.openssl("req", "-in", csr, "-noout", "-text").stdout.decode()
    if "id-ecPublicKey" not in text or not ("prime256v1" in text or "P-256" in text):
        raise LabError("CSR_BAD_KEY", "許可されていない鍵です（EC P-256 のみ受け付けます）")

    requested = ""
    m = re.search(r"Requested Extensions:(.*?)(?:\n\s*Signature Algorithm:|\Z)", text, re.S)
    if m:
        requested = m.group(1)
    forbidden = {
        "CA:TRUE": "CA 権限（CA:TRUE）",
        "Certificate Sign": "keyCertSign",
        "CRL Sign": "cRLSign",
        "TLS Web Client Authentication": "clientAuth",
        "Code Signing": "codeSigning",
    }
    for needle, label in forbidden.items():
        if needle in requested:
            raise LabError("CSR_FORBIDDEN_EXTENSION", f"サーバー証明書に不要な権限を要求しています: {label}")

    san: list[str] = []
    lines = requested.splitlines()
    for i, line in enumerate(lines):
        if "Subject Alternative Name" in line and i + 1 < len(lines):
            san = normalize_san(lines[i + 1])
    pub = lab.openssl("req", "-in", csr, "-noout", "-pubkey").stdout
    return {"csr_sha256": sha256_bytes(data), "pubkey_sha256": sha256_bytes(pub), "san": san}


def check_san_policy(san: list[str]) -> None:
    if not san:
        raise LabError("SAN_REQUIRED", "SAN（接続先名）がありません。CN だけの証明書は発行しません")
    bad = [s for s in san if s not in ALLOWED_SAN]
    if bad:
        # DNS の名前制約は配下（sub.localhost 等）も許してしまうため、
        # 発行審査では完全一致の許可リストで確認する。
        raise LabError("SAN_NOT_ALLOWED", f"許可されていない名前です: {', '.join(bad)}")


def profile_hash() -> str:
    return sha256_bytes(SERVER_PROFILE.read_bytes() + f"\ndays={LEAF_DAYS}".encode())


# =============================================================================
# CA の初期化
# =============================================================================

def gen_encrypted_key(lab: Lab, out: Path, pass_file: Path) -> None:
    """EC P-256 の鍵を作り、PKCS#8(PBES2 / AES-256-CBC / PBKDF2-HMAC-SHA256)で暗号化して保存。
    平文の鍵はパイプで受け渡し、ディスクに書かない。パスフレーズは file: で渡し、
    コマンド引数やログに残さない。"""
    raw = lab.openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256").stdout
    enc = lab.openssl("pkcs8", "-topk8", "-v2", "aes-256-cbc", "-v2prf", "hmacWithSHA256",
                      "-iter", KDF_ITER, "-passout", f"file:{pass_file}", input=raw).stdout
    write_private(out, enc)


def ensure_passphrase(path: Path) -> None:
    if not path.exists():
        write_private(path, secrets.token_urlsafe(32) + "\n")


def init_ca_db(base: Path) -> None:
    (base / "db" / "index.txt").touch()
    crlnum = base / "db" / "crlnumber"
    if not crlnum.exists():
        crlnum.write_text("1000\n")


def cmd_init_root(lab: Lab, args) -> dict:
    lab.require("init-root")
    lab.layout()
    if lab.root_cert.exists():
        raise LabError("ALREADY_INITIALIZED", "ルートCAは作成済みです")
    with lab.ca_lock("root"):
        ensure_passphrase(lab.root_pass)
        init_ca_db(lab.p("root"))
        gen_encrypted_key(lab, lab.root_key, lab.root_pass)
        lab.openssl("req", "-config", ROOT_CNF, "-new", "-x509", "-key", lab.root_key,
                    "-passin", f"file:{lab.root_pass}", "-sha256", "-days", ROOT_DAYS,
                    "-extensions", "v3_root", "-set_serial", "0x" + secrets.token_hex(16),
                    "-out", lab.root_cert)
        shutil.copy(lab.root_cert, lab.p("public", "certs", "root.cert.pem"))
        info = cert_info(lab, lab.root_cert)
        lab.audit("init-root", "ok", info["serial"], not_after=info["not_after"],
                  cert_sha256=info["sha256"])
    return {"root": str(lab.root_cert), "serial": info["serial"], "not_after": info["not_after"]}


def cmd_init_issuer(lab: Lab, args) -> dict:
    """中間CAの鍵と CSR を Lab 側で作る。署名はルート側（sign-intermediate）で行う。"""
    lab.require("init-issuer")
    lab.layout()
    if lab.issuer_key.exists():
        raise LabError("ALREADY_INITIALIZED", "中間CAの鍵は作成済みです")
    with lab.ca_lock("issuer"):
        ensure_passphrase(lab.issuer_pass)
        init_ca_db(lab.p("issuer"))
        gen_encrypted_key(lab, lab.issuer_key, lab.issuer_pass)
        csr = lab.p("issuer", "certs", "intermediate.csr.pem")
        lab.openssl("req", "-config", ISSUER_CNF, "-new", "-key", lab.issuer_key,
                    "-passin", f"file:{lab.issuer_pass}", "-sha256", "-out", csr)
        lab.audit("init-issuer", "ok", "intermediate", csr_sha256=sha256_file(csr))
    return {"csr": str(csr)}


def cmd_sign_intermediate(lab: Lab, args) -> dict:
    lab.require("sign-intermediate")
    csr = lab.p("issuer", "certs", "intermediate.csr.pem")
    if not csr.exists():
        raise LabError("NO_CSR", "中間CAの CSR がありません（init-issuer を先に実行）")
    root = cert_info(lab, lab.root_cert)
    now = utcnow()
    not_after = now + dt.timedelta(days=ISSUER_DAYS)
    if not_after > parse_iso(root["not_after"]) - ISSUER_MARGIN:
        raise LabError("ISSUER_RENEWAL_REQUIRED", "ルートCAの残り期間が足りません")
    with lab.ca_lock("root"):
        out = lab.p("issuer", "certs", "intermediate.cert.pem.new")
        lab.openssl("ca", "-config", ROOT_CNF, "-batch", "-notext", "-in", csr, "-out", out,
                    "-passin", f"file:{lab.root_pass}", "-extensions", "v3_intermediate",
                    "-subj", "/CN=PKI Lab Issuing CA 1",
                    "-startdate", asn1_time(now - dt.timedelta(seconds=BACKDATE_SECONDS)),
                    "-enddate", asn1_time(not_after))
        os.replace(out, lab.issuer_cert)
        shutil.copy(lab.issuer_cert, lab.p("public", "certs", "intermediate.cert.pem"))
        info = cert_info(lab, lab.issuer_cert)
        lab.audit("sign-intermediate", "ok", info["serial"], not_after=info["not_after"],
                  cert_sha256=info["sha256"])
    return {"intermediate": str(lab.issuer_cert), "serial": info["serial"]}


def cmd_init(lab: Lab, args) -> dict:
    """学習用の一括初期化（役割を順に切り替えて実行する）。"""
    out = {}
    lab.layout()
    for role, fn in [("root-admin", cmd_init_root), ("issuer", cmd_init_issuer),
                     ("root-admin", cmd_sign_intermediate), ("root-admin", cmd_crl_root),
                     ("issuer", cmd_crl_issuer)]:
        lab.role = role
        out[fn.__name__.replace("cmd_", "")] = fn(lab, args)
    return out


# =============================================================================
# 申請 → 審査・承認 → 発行
# =============================================================================

def new_request_id() -> str:
    return f"REQ-{utcnow():%Y%m%d}-{secrets.token_hex(4)}"


def cmd_request(lab: Lab, args) -> dict:
    """サーバー管理者が鍵と CSR を作って申請する。秘密鍵は server/private から出さない。"""
    lab.require("request")
    lab.layout()
    req_id = new_request_id()
    d = lab.p("requests", req_id)
    d.mkdir(parents=True)
    csr = d / "request.csr.pem"
    if args.csr:
        src = Path(args.csr)
        if src.stat().st_size > MAX_CSR_BYTES:
            shutil.rmtree(d)
            raise LabError("CSR_TOO_LARGE", f"CSR が上限 {MAX_CSR_BYTES} バイトを超えています")
        shutil.copy(src, csr)
        key_path = None
    else:
        san = args.san or ["DNS:localhost", "IP:127.0.0.1"]
        key_path = lab.p("server", "private", f"{req_id}.key.pem")
        raw = lab.openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256").stdout
        # ローカルの非対話 TLS デモのための例外として、サーバー鍵だけ非暗号化 PEM(0600)。
        write_private(key_path, raw)
        lab.openssl("req", "-new", "-key", key_path, "-sha256", "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=" + ",".join(san), "-out", csr)
    st = {"id": req_id, "status": "RECEIVED", "requester": lab.actor,
          "asset": args.asset, "created": iso(utcnow()),
          "server_key": str(key_path.relative_to(lab.home)) if key_path else None,
          "history": [{"status": "RECEIVED", "ts": iso(utcnow()), "by": lab.actor}]}
    write_json(d / "state.json", st)
    lab.audit("request", "ok", req_id, csr_sha256=sha256_file(csr), asset=args.asset)
    return {"request": req_id, "csr": str(csr)}


def cmd_approve(lab: Lab, args) -> dict:
    """RA の審査と承認。承認は CSR・プロファイル・SAN・期間・承認者・期限に結び付ける。"""
    lab.require("approve")
    req_id = args.request
    d = lab.req_dir(req_id)
    st = lab.state(req_id)
    if st["status"] != "RECEIVED":
        raise LabError("BAD_STATE", f"この申請は審査できる状態ではありません（{st['status']}）")
    try:
        csr = inspect_csr(lab, d / "request.csr.pem")
        check_san_policy(csr["san"])
        if args.asset_owner and args.asset_owner != st.get("asset"):
            raise LabError("ASSET_MISMATCH", "申請された資産と、管理権限を確認した資産が一致しません")
    except LabError as e:
        lab.set_state(req_id, "REJECTED", reject_code=e.code)
        lab.audit("approve", "rejected", req_id, code=e.code, reason=e.message)
        raise
    lab.set_state(req_id, "VALIDATED")
    lab.audit("validate", "ok", req_id, csr_sha256=csr["csr_sha256"], san=csr["san"])
    if lab.actor == st.get("requester"):
        # 1人で役割を切り替える学習環境なので拒否はしないが、記録に残す。
        note = "requester_and_approver_same_actor"
    else:
        note = ""
    approval = {
        "approval_id": "APR-" + secrets.token_hex(6),
        "request": req_id,
        "csr_sha256": csr["csr_sha256"],
        "pubkey_sha256": csr["pubkey_sha256"],
        "profile": "server_localhost",
        "profile_sha256": profile_hash(),
        "san": csr["san"],
        "days": LEAF_DAYS,
        "approver": lab.actor,
        "approved_at": iso(utcnow()),
        "expires_at": iso(utcnow() + APPROVAL_TTL),
        "note": note,
    }
    write_json(lab.p("approvals", f"{req_id}.json"), approval)
    lab.set_state(req_id, "APPROVED", approval_id=approval["approval_id"])
    lab.audit("approve", "ok", req_id, approval_id=approval["approval_id"], san=csr["san"],
              note=note)
    return approval


def cmd_reject(lab: Lab, args) -> dict:
    lab.require("reject")
    lab.set_state(args.request, "REJECTED", reject_code="RA_REJECTED")
    lab.audit("reject", "ok", args.request, reason=args.reason)
    return {"request": args.request, "status": "REJECTED"}


def _journal(lab: Lab, op_id: str, **data) -> Path:
    path = lab.p("journal", f"{op_id}.json")
    cur = read_json(path) if path.exists() else {"op_id": op_id}
    cur.update(data)
    write_json(path, cur)
    return path


def cmd_issue(lab: Lab, args) -> dict:
    """中間CAによる発行（docs/03_detailed-design.md 4.6 の手順どおり）。"""
    lab.require("issue")
    req_id = args.request
    d = lab.req_dir(req_id)
    with lab.ca_lock("issuer"):
        st = lab.state(req_id)
        # 冪等性：完了済みなら同じ証明書を返す。新しい証明書には新しい申請が必要。
        if st["status"] in ("ISSUED", "PUBLISHED"):
            return {"request": req_id, "serial": st["serial"], "cert": st["cert"], "reused": True}
        if st["status"] in ("SIGNING", "NEEDS_RECOVERY"):
            if st["status"] == "SIGNING":
                lab.set_state(req_id, "NEEDS_RECOVERY")
            lab.audit("issue", "refused", req_id, code="NEEDS_RECOVERY")
            raise LabError("NEEDS_RECOVERY",
                           "前回の署名処理が完了していません。recover で照合してから再開してください")
        if st["status"] != "APPROVED":
            raise LabError("NOT_APPROVED", f"承認されていない申請です（{st['status']}）")

        # 承認・CSR・設定・CA状態の再確認
        apr_path = lab.p("approvals", f"{req_id}.json")
        if not apr_path.exists():
            raise LabError("NOT_APPROVED", "承認記録がありません")
        apr = read_json(apr_path)
        csr_path = d / "request.csr.pem"
        if utcnow() > parse_iso(apr["expires_at"]):
            lab.set_state(req_id, "APPROVAL_EXPIRED")
            lab.audit("issue", "refused", req_id, code="APPROVAL_EXPIRED")
            raise LabError("APPROVAL_EXPIRED", "承認の有効期限が切れています。再申請してください")
        if sha256_file(csr_path) != apr["csr_sha256"]:
            lab.audit("issue", "refused", req_id, code="APPROVAL_MISMATCH", what="csr")
            raise LabError("APPROVAL_MISMATCH", "承認後に CSR が変更されています。再承認が必要です")
        if profile_hash() != apr["profile_sha256"]:
            lab.audit("issue", "refused", req_id, code="APPROVAL_MISMATCH", what="profile")
            raise LabError("APPROVAL_MISMATCH", "承認後にプロファイルが変更されています。再承認が必要です")
        check_san_policy(apr["san"])

        issuer = cert_info(lab, lab.issuer_cert)
        now = utcnow()
        not_before = max(now - dt.timedelta(seconds=BACKDATE_SECONDS), parse_iso(issuer["not_before"]))
        not_after = now + dt.timedelta(days=apr["days"])
        if not_after > parse_iso(issuer["not_after"]) - ISSUER_MARGIN:
            lab.audit("issue", "refused", req_id, code="ISSUER_RENEWAL_REQUIRED")
            raise LabError("ISSUER_RENEWAL_REQUIRED",
                           "中間CAの残り期間が足りません。短い証明書を黙って出さずに停止します")

        # 操作開始を永続化してから署名する
        op_id = "OP-" + secrets.token_hex(6)
        _journal(lab, op_id, op="issue", request=req_id, started=iso(now), finished=None,
                 csr_sha256=apr["csr_sha256"])
        lab.set_state(req_id, "SIGNING", op_id=op_id)
        if os.environ.get("PKILAB_CRASH_AFTER_JOURNAL"):  # 障害試験用
            raise LabError("SIMULATED_CRASH", "試験用：署名直前で停止しました")

        ext = Path(tempfile.mkstemp(prefix="ext-", dir=lab.p("journal"))[1])
        staging = lab.p("journal", f"{op_id}.cert.pem")
        try:
            ext.write_text(SERVER_PROFILE.read_text().replace("{SAN}", ",".join(apr["san"])))
            lab.openssl("ca", "-config", ISSUER_CNF, "-batch", "-notext",
                        "-in", csr_path, "-out", staging, "-passin", f"file:{lab.issuer_pass}",
                        "-extfile", ext, "-extensions", "server_cert",
                        "-subj", "/CN=" + apr["san"][0].split(":", 1)[1],
                        "-startdate", asn1_time(not_before), "-enddate", asn1_time(not_after))
        finally:
            ext.unlink(missing_ok=True)

        # 発行後検査：構造・鍵一致・用途・期間・チェーン
        info = cert_info(lab, staging)
        problems = []
        if info["ca"] is not False:
            problems.append("basicConstraints")
        if info["san"] != sorted(apr["san"]):
            problems.append("san")
        if info["pubkey_sha256"] != apr["pubkey_sha256"]:
            problems.append("pubkey")
        if info["eku"] != ["TLS Web Server Authentication"]:
            problems.append("eku")
        if parse_iso(info["not_after"]) > parse_iso(issuer["not_after"]):
            problems.append("validity")
        chain_ok = lab.openssl("verify", "-x509_strict", "-purpose", "sslserver",
                               "-CAfile", lab.root_cert, "-untrusted", lab.issuer_cert,
                               staging, check=False).returncode == 0
        if not chain_ok:
            problems.append("chain")
        newcert = lab.p("issuer", "newcerts", f"{info['serial']}.pem")
        if not newcert.exists() or info["serial"] not in index_serials(lab, "issuer"):
            problems.append("ledger")
        if problems:
            lab.openssl("ca", "-config", ISSUER_CNF, "-revoke", newcert,
                        "-crl_reason", "cessationOfOperation",
                        "-passin", f"file:{lab.issuer_pass}", check=False)
            lab.set_state(req_id, "QUARANTINED", problems=problems, serial=info["serial"])
            _journal(lab, op_id, finished=iso(utcnow()), result="quarantined")
            lab.audit("issue", "quarantined", req_id, serial=info["serial"], problems=problems)
            raise LabError("POST_ISSUE_CHECK_FAILED", f"発行後検査で不合格: {problems}")

        rec = {"issuer": issuer["subject"], "serial": info["serial"], "request": req_id,
               "approval_id": apr["approval_id"], "cert_sha256": info["sha256"],
               "pubkey_sha256": info["pubkey_sha256"], "san": info["san"],
               "not_before": info["not_before"], "not_after": info["not_after"]}
        write_json(d / "cert.json", rec)
        lab.set_state(req_id, "ISSUED", serial=info["serial"])
        lab.audit("issue", "ok", req_id, serial=info["serial"], cert_sha256=info["sha256"],
                  san=info["san"], not_after=info["not_after"])

        # 公開領域へ切り替え（証明書＋中間CA証明書）
        leaf = lab.p("server", "certs", f"{req_id}.cert.pem")
        shutil.copy(staging, leaf)
        chain = lab.p("server", "certs", f"{req_id}.fullchain.pem")
        chain.write_bytes(staging.read_bytes() + lab.issuer_cert.read_bytes())
        shutil.copy(staging, lab.p("public", "certs", f"{info['serial']}.pem"))
        staging.unlink()
        lab.set_state(req_id, "PUBLISHED", cert=str(leaf.relative_to(lab.home)),
                      fullchain=str(chain.relative_to(lab.home)))
        _journal(lab, op_id, finished=iso(utcnow()), result="ok", serial=info["serial"])
        lab.audit("publish", "ok", req_id, serial=info["serial"])
    return {"request": req_id, "serial": info["serial"], "cert": str(leaf),
            "fullchain": str(chain), "not_after": info["not_after"], "reused": False}


def cmd_recover(lab: Lab, args) -> dict:
    """署名途中で止まった申請を、台帳・発行物・操作記録と照合して再開可否を判断する。"""
    lab.require("recover")
    req_id = args.request
    with lab.ca_lock("issuer"):
        st = lab.state(req_id)
        if st["status"] not in ("SIGNING", "NEEDS_RECOVERY"):
            return {"request": req_id, "status": st["status"], "action": "none"}
        if st["status"] == "SIGNING":
            st = lab.set_state(req_id, "NEEDS_RECOVERY")
        apr = read_json(lab.p("approvals", f"{req_id}.json"))
        # 同じ公開鍵で発行済みの証明書が台帳にあるか照合する
        found = None
        for serial in index_serials(lab, "issuer"):
            pem = lab.p("issuer", "newcerts", f"{serial}.pem")
            if pem.exists() and cert_info(lab, pem)["pubkey_sha256"] == apr["pubkey_sha256"]:
                found = serial
        if found:
            # 署名済みだった：二重発行せず、その証明書を採用する
            info = cert_info(lab, lab.p("issuer", "newcerts", f"{found}.pem"))
            lab.set_state(req_id, "ISSUED", serial=found)
            leaf = lab.p("server", "certs", f"{req_id}.cert.pem")
            shutil.copy(lab.p("issuer", "newcerts", f"{found}.pem"), leaf)
            chain = lab.p("server", "certs", f"{req_id}.fullchain.pem")
            chain.write_bytes(leaf.read_bytes() + lab.issuer_cert.read_bytes())
            write_json(lab.req_dir(req_id) / "cert.json",
                       {"issuer": info["issuer"], "serial": found, "request": req_id,
                        "approval_id": apr["approval_id"], "cert_sha256": info["sha256"],
                        "pubkey_sha256": info["pubkey_sha256"], "san": info["san"],
                        "not_before": info["not_before"], "not_after": info["not_after"]})
            lab.set_state(req_id, "PUBLISHED", cert=str(leaf.relative_to(lab.home)),
                          fullchain=str(chain.relative_to(lab.home)))
            action = "adopted_existing_certificate"
        else:
            lab.set_state(req_id, "APPROVED")
            action = "returned_to_approved"
        op_id = st.get("op_id")
        if op_id:
            _journal(lab, op_id, finished=iso(utcnow()), result=f"recovered:{action}")
        lab.audit("recover", "ok", req_id, action=action, serial=found or "")
    return {"request": req_id, "action": action, "serial": found}


def index_serials(lab: Lab, which: str) -> list[str]:
    return [row["serial"] for row in read_index(lab, which)]


def read_index(lab: Lab, which: str) -> list[dict]:
    rows = []
    path = lab.p(which, "db", "index.txt")
    if not path.exists():
        return rows
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        rows.append({"status": parts[0], "expires": parts[1], "revoked": parts[2],
                     "serial": parts[3].upper(), "subject": parts[5] if len(parts) > 5 else ""})
    return rows


# =============================================================================
# 失効・CRL
# =============================================================================

def _gen_crl(lab: Lab, which: str) -> Path:
    cnf = ROOT_CNF if which == "root" else ISSUER_CNF
    pw = lab.root_pass if which == "root" else lab.issuer_pass
    name = "root.crl.pem" if which == "root" else "intermediate.crl.pem"
    out = lab.p(which, "crl", name)
    tmp = out.with_suffix(".tmp")
    lab.openssl("ca", "-config", cnf, "-gencrl", "-passin", f"file:{pw}", "-out", tmp)
    if tmp.stat().st_size > MAX_CRL_BYTES:
        raise LabError("CRL_TOO_LARGE", "CRL が上限を超えています")
    os.replace(tmp, out)
    shutil.copy(out, lab.p("public", "crl", name))
    text = lab.openssl("crl", "-in", out, "-noout", "-crlnumber", "-lastupdate", "-nextupdate").stdout.decode()
    meta = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
    lab.audit(f"crl-{which}", "ok", name, crl_number=meta.get("crlNumber", "").strip(),
              next_update=iso(parse_openssl_date(meta["nextUpdate"])), crl_sha256=sha256_file(out))
    return out


def cmd_crl_root(lab: Lab, args) -> dict:
    lab.require("crl-root")
    with lab.ca_lock("root"):
        return {"crl": str(_gen_crl(lab, "root"))}


def cmd_crl_issuer(lab: Lab, args) -> dict:
    lab.require("crl-issuer")
    with lab.ca_lock("issuer"):
        return {"crl": str(_gen_crl(lab, "issuer"))}


REASONS = {"unspecified", "keyCompromise", "CACompromise", "affiliationChanged",
           "superseded", "cessationOfOperation", "certificateHold"}


def cmd_revoke(lab: Lab, args) -> dict:
    """サーバー証明書の失効。失効したら直ちに CRL を再発行・配布する。"""
    lab.require("revoke")
    if args.reason not in REASONS:
        raise LabError("BAD_REASON", f"失効理由は {sorted(REASONS)} のいずれか")
    serial = resolve_serial(lab, args.target)
    with lab.ca_lock("issuer"):
        pem = lab.p("issuer", "newcerts", f"{serial}.pem")
        if not pem.exists():
            raise LabError("UNKNOWN_SERIAL", f"中間CAが発行した証明書ではありません: {serial}")
        cp = lab.openssl("ca", "-config", ISSUER_CNF, "-revoke", pem, "-crl_reason", args.reason,
                         "-passin", f"file:{lab.issuer_pass}", check=False)
        if cp.returncode != 0 and b"Already revoked" not in cp.stderr + cp.stdout:
            raise LabError("OPENSSL_FAILED", cp.stderr.decode(errors="replace").strip())
        lab.audit("revoke", "ok", serial, reason=args.reason, incident=args.incident or "")
        crl = _gen_crl(lab, "issuer")
    return {"revoked": serial, "reason": args.reason, "crl": str(crl)}


def cmd_revoke_intermediate(lab: Lab, args) -> dict:
    lab.require("revoke-intermediate")
    info = cert_info(lab, lab.issuer_cert)
    with lab.ca_lock("root"):
        pem = lab.p("root", "newcerts", f"{info['serial']}.pem")
        cp = lab.openssl("ca", "-config", ROOT_CNF, "-revoke", pem, "-crl_reason", args.reason,
                         "-passin", f"file:{lab.root_pass}", check=False)
        if cp.returncode != 0 and b"Already revoked" not in cp.stderr + cp.stdout:
            raise LabError("OPENSSL_FAILED", cp.stderr.decode(errors="replace").strip())
        lab.audit("revoke-intermediate", "ok", info["serial"], reason=args.reason)
        crl = _gen_crl(lab, "root")
    return {"revoked": info["serial"], "crl": str(crl)}


def resolve_serial(lab: Lab, target: str) -> str:
    if target.startswith("REQ-"):
        st = lab.state(target)
        if "serial" not in st:
            raise LabError("NOT_ISSUED", "この申請には証明書が発行されていません")
        return st["serial"]
    return target.upper()


# =============================================================================
# 検証
# =============================================================================

def cmd_bundle(lab: Lab, args) -> dict:
    """公開情報だけを集めた検証用バンドルを作る。"""
    lab.require("bundle")
    out = Path(args.out) if args.out else lab.p("verifier", "bundle")
    out.mkdir(parents=True, exist_ok=True)
    shutil.copy(lab.p("public", "certs", "root.cert.pem"), out / "root.cert.pem")
    shutil.copy(lab.p("public", "certs", "intermediate.cert.pem"), out / "intermediate.cert.pem")
    crls = b""
    for name in ("root.crl.pem", "intermediate.crl.pem"):
        p = lab.p("public", "crl", name)
        if p.exists():
            crls += p.read_bytes()
    (out / "crls.pem").write_bytes(crls)
    if args.request:
        shutil.copy(lab.p(lab.state(args.request)["cert"]), out / "server.cert.pem")
    lab.audit("bundle", "ok", str(out))
    return {"bundle": str(out)}


# OpenSSL の検証エラー番号 → 教材の結果コード
VERIFY_CODES = {
    2: "UNTRUSTED_ANCHOR", 19: "UNTRUSTED_ANCHOR", 20: "UNTRUSTED_ANCHOR", 21: "UNTRUSTED_ANCHOR",
    9: "NOT_YET_VALID", 10: "CERT_EXPIRED",
    3: "CRL_MISSING", 11: "CRL_NOT_YET_VALID", 12: "CRL_EXPIRED", 8: "CRL_BAD_SIGNATURE",
    7: "BAD_SIGNATURE", 26: "WRONG_EKU", 24: "INVALID_CA", 25: "PATH_LENGTH_EXCEEDED",
    47: "NAME_CONSTRAINT_VIOLATION", 48: "NAME_CONSTRAINT_VIOLATION",
    62: "SAN_MISMATCH", 64: "SAN_MISMATCH", 22: "CHAIN_TOO_LONG",
}
INDETERMINATE = {"CRL_MISSING", "CRL_EXPIRED", "CRL_NOT_YET_VALID", "CRL_BAD_SIGNATURE"}


def classify_verify(code: int, depth: int) -> str:
    if code == 23:
        return "LEAF_REVOKED" if depth == 0 else "INTERMEDIATE_REVOKED"
    return VERIFY_CODES.get(code, f"VERIFY_ERROR_{code}")


def cmd_verify(lab: Lab, args) -> dict:
    """証明書ファイルの検証（docs/03_detailed-design.md 4.8）。"""
    lab.require("verify")
    cert = Path(args.cert) if args.cert else lab.p(lab.state(args.request)["cert"])
    trust = Path(args.trust) if args.trust else lab.p("public", "certs", "root.cert.pem")
    inter = Path(args.untrusted) if args.untrusted else lab.p("public", "certs", "intermediate.cert.pem")
    host = args.host

    checks = []
    # openssl verify -verify_hostname は SAN が無いと CN を見に行くため、
    # SAN の存在と内容は事前に構造検査する（CN フォールバックを許さない）。
    info = cert_info(lab, cert)
    if not info["san"]:
        result = {"result": "REJECT", "code": "SAN_REQUIRED", "checks": [("SAN_PRESENT", False)]}
        lab.audit("verify", "reject", info.get("serial", ""), code="SAN_REQUIRED")
        return result
    checks.append(("SAN_PRESENT", True))

    cmd = ["verify", "-show_chain", "-x509_strict", "-auth_level", "2", "-verify_depth", "1",
           "-purpose", args.purpose, "-trusted", trust, "-untrusted", inter]
    if host:
        if re.fullmatch(r"[0-9.]+", host):
            cmd += ["-verify_ip", host]
        else:
            cmd += ["-verify_hostname", host]
    crl_file = Path(args.crl) if args.crl else lab.p("verifier", "cache", "crls.pem")
    if not args.no_crl:
        if not args.crl:
            data = b"".join(lab.p("public", "crl", n).read_bytes()
                            for n in ("root.crl.pem", "intermediate.crl.pem")
                            if lab.p("public", "crl", n).exists())
            crl_file.parent.mkdir(parents=True, exist_ok=True)
            crl_file.write_bytes(data)
        if crl_file.exists() and crl_file.stat().st_size > 0:
            cmd += ["-CRLfile", crl_file]
        cmd += ["-crl_check", "-crl_check_all"]
    if args.attime:
        cmd += ["-attime", str(int(parse_iso(args.attime).timestamp()))]
    cmd.append(cert)
    cp = lab.openssl(*cmd, check=False)
    out = (cp.stdout + cp.stderr).decode(errors="replace")
    if cp.returncode == 0:
        code, verdict = "OK", "ACCEPT"
    else:
        m = re.search(r"error (\d+) at (\d+) depth", out)
        if m:
            code = classify_verify(int(m.group(1)), int(m.group(2)))
        else:
            code = "VERIFY_ERROR"
        # 「失効している」と「失効状態を確認できない」は別の結果として記録し、
        # どちらの場合もラボ方針として接続は許可しない。
        verdict = "INDETERMINATE" if code in INDETERMINATE else "REJECT"
    lab.audit("verify", verdict.lower(), info.get("serial", ""), code=code, host=host or "",
              purpose=args.purpose, crl_check=not args.no_crl, attime=args.attime or "")
    summary = [ln for ln in out.splitlines() if ln.startswith("error ") or ln.endswith(": OK")]
    return {"result": verdict, "code": code, "serial": info.get("serial"), "san": info["san"],
            "openssl": summary[0] if summary else ""}


# =============================================================================
# HTTPS サーバー・厳格な TLS クライアント
# =============================================================================

class _Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = b"Hello from PKI Lab over TLS\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *a):
        sys.stderr.write("[https] " + (fmt % a) + "\n")


def make_https_server(lab: Lab, req_id: str, host: str, port: int) -> http.server.HTTPServer:
    st = lab.state(req_id)
    if st["status"] != "PUBLISHED":
        raise LabError("NOT_PUBLISHED", "証明書が配置されていません")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    # サーバーは葉＋中間CAを送る。ルートは利用側が事前に持つ前提なので送らない。
    ctx.load_cert_chain(lab.p(st["fullchain"]), lab.p(st["server_key"]))
    srv = http.server.ThreadingHTTPServer((host, port), _Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


def cmd_serve_https(lab: Lab, args) -> dict:
    lab.require("serve-https")
    srv = make_https_server(lab, args.request, args.bind, args.port)
    print(f"PKI Lab HTTPS: https://localhost:{args.port}/  (Ctrl+C で停止)", flush=True)
    lab.audit("serve-https", "start", args.request, port=args.port)
    with contextlib.suppress(KeyboardInterrupt):
        srv.serve_forever()
    return {"stopped": True}


def cmd_serve_public(lab: Lab, args) -> dict:
    """public/ だけを読み取り専用で配布する（CA の作業領域は公開しない）。"""
    lab.require("serve-public")
    pub = str(lab.p("public"))

    class H(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=pub, **kw)

        def do_PUT(self):  # noqa: N802
            self.send_error(405)
        do_POST = do_DELETE = do_PUT  # noqa: N815

    srv = http.server.ThreadingHTTPServer((args.bind, args.port), H)
    print(f"PKI Lab public: http://{args.bind}:{args.port}/  (Ctrl+C で停止)", flush=True)
    with contextlib.suppress(KeyboardInterrupt):
        srv.serve_forever()
    return {"stopped": True}


def strict_client_context(trust: Path, crl: Path | None) -> ssl.SSLContext:
    """実TLS接続用の厳格な設定（docs/03_detailed-design.md 4.9）。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # CERT_REQUIRED + check_hostname が既定
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(cafile=str(trust))
    ctx.hostname_checks_common_name = False  # CN へのフォールバック禁止
    flags = ssl.VERIFY_X509_STRICT
    if crl is not None:
        ctx.load_verify_locations(cafile=str(crl))  # PEM の CRL も読み込める
        flags |= ssl.VERIFY_CRL_CHECK_CHAIN       # 葉だけでなくチェーン全体を確認
    ctx.verify_flags = flags  # PARTIAL_CHAIN を外し、中間CAを信頼の起点にしない
    return ctx


def tls_probe(trust: Path, crl: Path | None, host: str, port: int, connect_host: str = "127.0.0.1") -> dict:
    ctx = strict_client_context(trust, crl)
    try:
        with socket.create_connection((connect_host, port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                version = tls.version()
                tls.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
                body = b""
                while chunk := tls.recv(4096):
                    body += chunk
                return {"result": "ACCEPT", "code": "OK", "tls_version": version,
                        "status_line": body.split(b"\r\n", 1)[0].decode(errors="replace")}
    except ssl.SSLCertVerificationError as e:
        # Python の例外には失敗した深さが含まれないため、失効(23)は呼び出し側で
        # 葉か中間CAかを判別する。
        code = "REVOKED" if e.verify_code == 23 else classify_verify(e.verify_code, 0)
        verdict = "INDETERMINATE" if code in INDETERMINATE else "REJECT"
        return {"result": verdict, "code": code, "detail": e.verify_message}


def peer_leaf_serial(lab: Lab, host: str, port: int, connect_host: str = "127.0.0.1") -> str:
    """失効理由の分類のためだけに、検証なしで葉証明書を取得してシリアルを読む。
    この接続でデータは送受信しない。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((connect_host, port), timeout=5) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    out = lab.openssl("x509", "-inform", "DER", "-noout", "-serial", input=der).stdout.decode()
    return out.split("=", 1)[1].strip().upper()


def cmd_client(lab: Lab, args) -> dict:
    lab.require("client")
    trust = Path(args.trust) if args.trust else lab.p("public", "certs", "root.cert.pem")
    crl = None
    if not args.no_crl:
        crl = lab.p("verifier", "cache", "crls.pem")
        crl.parent.mkdir(parents=True, exist_ok=True)
        crl.write_bytes(b"".join(lab.p("public", "crl", n).read_bytes()
                                 for n in ("root.crl.pem", "intermediate.crl.pem")
                                 if lab.p("public", "crl", n).exists()))
    res = tls_probe(trust, crl, args.host, args.port)
    if res["code"] == "REVOKED":
        leaf_revoked = peer_leaf_serial(lab, args.host, args.port) in crl_revoked_serials(
            lab, lab.p("public", "crl", "intermediate.crl.pem"))
        res["code"] = "LEAF_REVOKED" if leaf_revoked else "INTERMEDIATE_REVOKED"
    lab.audit("tls-connect", res["result"].lower(), f"{args.host}:{args.port}",
              code=res["code"], crl_check=not args.no_crl)
    return res


# =============================================================================
# 監査・照合・バックアップ・復旧
# =============================================================================

def verify_audit_chain(home: Path) -> dict:
    log = home / "audit" / "audit.jsonl"
    anchor = home / "anchor" / "anchor.json"
    prev, seq, last_hash = "0" * 64, 0, None
    for n, line in enumerate(log.read_text().splitlines(), 1):
        if not line.strip():
            continue
        e = json.loads(line)
        h = e.pop("hash")
        if e["prev"] != prev or e["seq"] != seq + 1 or sha256_bytes(canonical(e)) != h:
            return {"ok": False, "code": "AUDIT_TAMPERED", "line": n}
        prev, seq, last_hash = h, e["seq"], h
    if anchor.exists():
        a = read_json(anchor)
        if a["seq"] != seq or a["hash"] != last_hash:
            return {"ok": False, "code": "AUDIT_TRUNCATED_OR_REWRITTEN", "anchor_seq": a["seq"], "log_seq": seq}
    else:
        return {"ok": False, "code": "ANCHOR_MISSING"}
    return {"ok": True, "entries": seq, "head": last_hash}


def cmd_audit_verify(lab: Lab, args) -> dict:
    lab.require("audit-verify")
    res = verify_audit_chain(lab.home)
    if not res["ok"]:
        raise LabError(res["code"], json.dumps(res, ensure_ascii=False))
    return res


def crl_revoked_serials(lab: Lab, crl: Path) -> set[str]:
    if not crl.exists():
        return set()
    text = lab.openssl("crl", "-in", crl, "-noout", "-text").stdout.decode()
    return {m.upper() for m in re.findall(r"Serial Number: ([0-9A-Fa-f]+)", text)}


def cmd_check(lab: Lab, args) -> dict:
    """承認 ⇔ 発行台帳 ⇔ 実際の証明書 ⇔ 失効記録 ⇔ 公開CRL の照合。"""
    lab.require("check")
    problems = []
    rows = {r["serial"]: r for r in read_index(lab, "issuer")}
    for serial, row in rows.items():
        if not lab.p("issuer", "newcerts", f"{serial}.pem").exists():
            problems.append(f"台帳にあるが発行物がない: {serial}")
    for pem in lab.p("issuer", "newcerts").glob("*.pem"):
        if pem.stem.upper() not in rows:
            problems.append(f"発行物があるが台帳にない: {pem.stem}")
    issued_by_request = {}
    for d in sorted(lab.p("requests").glob("REQ-*")):
        st = read_json(d / "state.json")
        if st["status"] in ("ISSUED", "PUBLISHED"):
            if not lab.p("approvals", f"{st['id']}.json").exists():
                problems.append(f"承認記録のない発行: {st['id']}")
            if st.get("serial") not in rows:
                problems.append(f"申請の証明書が台帳にない: {st['id']}")
            issued_by_request[st.get("serial")] = st["id"]
        if st["status"] in ("SIGNING", "NEEDS_RECOVERY"):
            problems.append(f"復旧が必要な申請: {st['id']}")
    for serial, row in rows.items():
        if serial not in issued_by_request and row["status"] != "R":
            problems.append(f"申請に紐づかない有効な証明書: {serial}")
    revoked = {s for s, r in rows.items() if r["status"] == "R"}
    in_crl = crl_revoked_serials(lab, lab.p("public", "crl", "intermediate.crl.pem"))
    if revoked - in_crl:
        problems.append(f"公開CRLに未反映の失効: {sorted(revoked - in_crl)}")
    if in_crl - revoked:
        problems.append(f"台帳にない失効がCRLにある: {sorted(in_crl - revoked)}")
    for name in ("root.crl.pem", "intermediate.crl.pem"):
        p = lab.p("public", "crl", name)
        if p.exists():
            nu = lab.openssl("crl", "-in", p, "-noout", "-nextupdate").stdout.decode().split("=", 1)[1]
            if parse_openssl_date(nu) < utcnow():
                problems.append(f"CRL の次回更新期限切れ: {name}")
    audit = verify_audit_chain(lab.home)
    if not audit["ok"]:
        problems.append(f"監査ログ: {audit['code']}")
    lab.audit("check", "ok" if not problems else "problems", "", count=len(problems))
    return {"ok": not problems, "problems": problems, "issued": len(rows), "revoked": len(revoked)}


BACKUP_ITEMS = ["root", "issuer", "requests", "approvals", "journal", "audit", "public"]


def cmd_backup(lab: Lab, args) -> dict:
    """CA 一式（鍵は暗号化済みのまま・台帳・発行物・失効・CRL番号・承認・監査）を
    バックアップ用パスフレーズで暗号化して保存する。秘密鍵だけでは復旧できない。"""
    lab.require("backup")
    pass_file = Path(args.pass_file) if args.pass_file else lab.p("secrets", "backup.pass")
    ensure_passphrase(pass_file)
    with lab.ca_lock("issuer"), lab.ca_lock("root"):
        stamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
        tmp_tar = Path(tempfile.mkstemp(suffix=".tar.gz", dir=lab.p("backups"))[1])
        with tarfile.open(tmp_tar, "w:gz") as tar:
            for item in BACKUP_ITEMS:
                if lab.p(item).exists():
                    tar.add(lab.p(item), arcname=item,
                            filter=lambda ti: None if ti.name.endswith("ca.lock") else ti)
            tar.add(lab.p("anchor"), arcname="anchor")
        out = lab.p("backups", f"pkilab-{stamp}.tar.gz.enc")
        lab.openssl("enc", "-aes-256-cbc", "-pbkdf2", "-iter", KDF_ITER, "-salt",
                    "-in", tmp_tar, "-out", out, "-pass", f"file:{pass_file}")
        tmp_tar.unlink()
        digest = sha256_file(out)
        lab.audit("backup", "ok", out.name, sha256=digest)
    return {"backup": str(out), "sha256": digest}


def cmd_restore(lab: Lab, args) -> dict:
    """隔離した別ディレクトリへ復元し、照合が通るまで署名・公開を再開しない。"""
    lab.require("restore")
    dest = Path(args.dest).resolve()
    if dest.exists() and any(dest.iterdir()):
        raise LabError("DEST_NOT_EMPTY", "復旧先は空の隔離ディレクトリにしてください")
    dest.mkdir(parents=True, exist_ok=True)
    pass_file = Path(args.pass_file) if args.pass_file else lab.p("secrets", "backup.pass")
    tmp_tar = dest / ".restore.tar.gz"
    lab.openssl("enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", KDF_ITER,
                "-in", args.backup, "-out", tmp_tar, "-pass", f"file:{pass_file}")
    with tarfile.open(tmp_tar) as tar:
        for m in tar.getmembers():  # パス逸脱の防止（古い Python 向けにも明示的に確認）
            if m.name.startswith("/") or ".." in Path(m.name).parts or m.issym() or m.islnk():
                raise LabError("BACKUP_UNSAFE", f"不正なパスを含むバックアップです: {m.name}")
        tar.extractall(dest, **({"filter": "data"} if hasattr(tarfile, "data_filter") else {}))
    tmp_tar.unlink()
    restored = Lab(dest, lab.actor, "auditor")
    restored.layout()
    audit = verify_audit_chain(dest)
    report = {"restored_to": str(dest), "audit": audit}
    if audit["ok"]:
        # 照合（秘密情報は使わない）
        report["check"] = cmd_check(restored, argparse.Namespace())
    report["ready"] = bool(audit["ok"] and report.get("check", {}).get("ok"))
    lab.audit("restore", "ok" if report["ready"] else "needs_review", str(dest))
    return report


# =============================================================================
# 3D 教材向けイベント出力（秘密情報を含めない）
# =============================================================================

EVENT_MAP = {
    ("init-root", "ok"): ["ROOT_CREATED"],
    ("sign-intermediate", "ok"): ["INTERMEDIATE_DELEGATED"],
    ("request", "ok"): ["CSR_CREATED"],
    ("validate", "ok"): ["CSR_SIGNATURE_CHECKED"],
    ("approve", "ok"): ["REQUEST_AUTHORIZED"],
    ("approve", "rejected"): ["REQUEST_REJECTED"],
    ("issue", "ok"): ["CERT_ISSUED"],
    ("publish", "ok"): ["CERT_DEPLOYED"],
    ("revoke", "ok"): ["CERT_REVOKED"],
    ("revoke-intermediate", "ok"): ["INTERMEDIATE_REVOKED"],
    ("crl-issuer", "ok"): ["CRL_PUBLISHED"],
    ("crl-root", "ok"): ["CRL_PUBLISHED"],
}
SAFE_DETAIL_KEYS = {"code", "san", "reason", "host", "purpose", "crl_check", "not_after",
                    "next_update", "crl_number", "action"}


def cmd_export_events(lab: Lab, args) -> dict:
    lab.require("export-events")
    events = []
    for line in lab.p("audit", "audit.jsonl").read_text().splitlines():
        e = json.loads(line)
        details = {k: v for k, v in e["details"].items() if k in SAFE_DETAIL_KEYS}
        types = EVENT_MAP.get((e["op"], e["result"]), [])
        if e["op"] == "verify":
            ok = e["result"] == "accept"
            types = ["TRUST_ANCHOR_SELECTED", "PATH_VALIDATED", "SAN_CHECKED",
                     "REVOCATION_CHECKED", "VERIFY_ACCEPTED" if ok else "VERIFY_REJECTED"]
        elif e["op"] == "tls-connect":
            types = ["TLS_HANDSHAKE_COMPLETED" if e["result"] == "accept" else "TLS_HANDSHAKE_REJECTED"]
        for t in types:
            events.append({"seq": e["seq"], "ts": e["ts"], "type": t, "role": e["role"],
                           # シリアルなどはそのまま出さず短いハッシュにする
                           "target": sha256_bytes(e["target"].encode())[:12] if e["target"] else "",
                           "result": e["result"], "details": details})
    doc = {"schema": "pkilab-events/1", "measured": True,
           "note": "PKI Lab の監査ログから生成。秘密鍵・パスフレーズ・証明書本体は含まない。",
           "generated": iso(utcnow()), "events": events}
    out = Path(args.out) if args.out else lab.p("exports", "events.json")
    write_json(out, doc)
    blob = out.read_text()
    if "PRIVATE KEY" in blob or "BEGIN" in blob:
        out.unlink()
        raise LabError("EXPORT_LEAK", "出力に秘密情報らしき文字列が含まれていたため破棄しました")
    lab.audit("export-events", "ok", out.name, count=len(events))
    return {"events": str(out), "count": len(events)}


def cmd_status(lab: Lab, args) -> dict:
    lab.require("status")
    out = {"home": str(lab.home), "requests": []}
    if lab.issuer_cert.exists():
        out["intermediate"] = cert_info(lab, lab.issuer_cert)["not_after"]
    for d in sorted(lab.p("requests").glob("REQ-*")):
        st = read_json(d / "state.json")
        out["requests"].append({"id": st["id"], "status": st["status"], "serial": st.get("serial")})
    return out


# =============================================================================
# CLI
# =============================================================================

COMMANDS = {
    "init": (cmd_init, None), "init-root": (cmd_init_root, "root-admin"),
    "init-issuer": (cmd_init_issuer, "issuer"), "sign-intermediate": (cmd_sign_intermediate, "root-admin"),
    "request": (cmd_request, "server-admin"), "approve": (cmd_approve, "ra"), "reject": (cmd_reject, "ra"),
    "issue": (cmd_issue, "issuer"), "recover": (cmd_recover, "issuer"),
    "revoke": (cmd_revoke, "issuer"), "revoke-intermediate": (cmd_revoke_intermediate, "root-admin"),
    "crl-root": (cmd_crl_root, "root-admin"), "crl-issuer": (cmd_crl_issuer, "issuer"),
    "bundle": (cmd_bundle, "verifier"), "verify": (cmd_verify, "verifier"), "client": (cmd_client, "verifier"),
    "serve-https": (cmd_serve_https, "server-admin"), "serve-public": (cmd_serve_public, "operator"),
    "audit-verify": (cmd_audit_verify, "auditor"), "check": (cmd_check, "auditor"),
    "export-events": (cmd_export_events, "auditor"), "backup": (cmd_backup, "operator"),
    "restore": (cmd_restore, "operator"), "status": (cmd_status, "operator"),
}


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="pkilab", description="学習用の私設認証局 CLI")
    ap.add_argument("--home", default=os.environ.get("PKILAB_HOME", str(LAB_DIR / "work")),
                    help="作業ディレクトリ（既定: lab/work）")
    ap.add_argument("--actor", default=os.environ.get("PKILAB_ACTOR", os.environ.get("USER", "learner")))
    ap.add_argument("--role", help="操作する役割（省略時はコマンドの標準の役割）")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in COMMANDS:
        sp = sub.add_parser(name)
        if name in ("approve", "reject", "issue", "recover", "serve-https"):
            sp.add_argument("request")
        if name == "approve":
            sp.add_argument("--asset-owner", help="管理権限を確認した資産ID")
        if name == "reject":
            sp.add_argument("--reason", default="")
        if name == "request":
            sp.add_argument("--san", action="append", help="例: DNS:localhost（複数可）")
            sp.add_argument("--csr", help="既存の CSR を申請する")
            sp.add_argument("--asset", default="lab-https-01")
        if name in ("revoke", "revoke-intermediate"):
            if name == "revoke":
                sp.add_argument("target", help="申請ID またはシリアル")
                sp.add_argument("--incident")
            sp.add_argument("--reason", default="keyCompromise")
        if name == "bundle":
            sp.add_argument("--out")
            sp.add_argument("--request")
        if name == "verify":
            g = sp.add_mutually_exclusive_group(required=True)
            g.add_argument("--request")
            g.add_argument("--cert")
            sp.add_argument("--host", default="localhost")
            sp.add_argument("--purpose", default="sslserver")
            sp.add_argument("--trust", help="信頼の起点にするルート証明書")
            sp.add_argument("--untrusted", help="経路構築用の中間CA証明書")
            sp.add_argument("--crl", help="CRL を含む PEM")
            sp.add_argument("--no-crl", action="store_true", help="失効確認をしない（比較実験用）")
            sp.add_argument("--attime", help="評価時刻 例: 2030-01-01T00:00:00Z")
        if name == "client":
            sp.add_argument("--host", default="localhost")
            sp.add_argument("--port", type=int, default=8443)
            sp.add_argument("--trust")
            sp.add_argument("--no-crl", action="store_true")
        if name in ("serve-https", "serve-public"):
            sp.add_argument("--bind", default="127.0.0.1")
            sp.add_argument("--port", type=int, default=8443 if name == "serve-https" else 8000)
        if name == "export-events":
            sp.add_argument("--out")
        if name in ("backup", "restore"):
            sp.add_argument("--pass-file")
        if name == "restore":
            sp.add_argument("backup")
            sp.add_argument("dest")
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    fn, default_role = COMMANDS[args.cmd]
    lab = Lab(Path(args.home), args.actor, args.role or default_role or "operator")
    try:
        result = fn(lab, args)
    except LabError as e:
        print(json.dumps({"error": e.code, "message": e.message}, ensure_ascii=False, indent=2))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    if isinstance(result, dict) and result.get("result") in ("REJECT", "INDETERMINATE"):
        return 1
    if isinstance(result, dict) and result.get("ok") is False:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
