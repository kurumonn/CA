#!/usr/bin/env python3
"""PKI Lab: 学習用の私設認証局 CLI。

ルートCA → 中間CA → localhost 用 TLS サーバー証明書 の3階層を、
「申請 → 審査 → 承認 → 発行 → 配置 → 検証 → 失効 → 監査 → 復旧」の
流れで操作できるようにする。証明書の署名は OpenSSL に任せ、このスクリプトは
業務ルール（審査・承認の結び付け・排他・状態遷移・監査・照合・復旧）を受け持つ。

公開認証局として運用できるものではない。設計の詳細は docs/ を参照。
標準ライブラリだけで動作する（Python 3.9 以上 / OpenSSL 3.x）。

終了コード: 0 = 成功/受理, 1 = 拒否・判定不能・照合異常・復旧準備未完了,
            2 = 業務上の拒否（LabError）, 3 = 環境エラー（想定外の例外）
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import errno
import fcntl
import hashlib
import hmac
import http.server
import ipaddress
import json
import os
import re
import secrets
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

# EC P-256 の SubjectPublicKeyInfo（非圧縮点）の先頭。鍵種はこの構造で判定する。
P256_SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")

# 役割ごとに許可する操作（1人で切り替える学習用の役割分離）
ROLE_OPS = {
    "root-admin": {"init-root", "sign-intermediate", "revoke-intermediate", "crl-root"},
    "issuer": {"init-issuer", "issue", "revoke", "crl-issuer", "recover"},
    "ra": {"approve", "reject"},
    "server-admin": {"request", "serve-https"},
    "verifier": {"verify", "client", "bundle"},
    "auditor": {"audit-verify", "audit-reanchor", "check", "export-events"},
    "operator": {"backup", "restore", "resume", "serve-public", "status"},
}

# 申請の状態遷移
TRANSITIONS = {
    "RECEIVED": {"VALIDATED", "REJECTED"},
    "VALIDATED": {"APPROVED", "REJECTED"},
    "APPROVED": {"SIGNING", "APPROVAL_EXPIRED"},
    "SIGNING": {"ISSUED", "NEEDS_RECOVERY", "QUARANTINED"},
    "NEEDS_RECOVERY": {"ISSUED", "APPROVED", "QUARANTINED"},
    "ISSUED": {"PUBLISHED", "QUARANTINED"},
    "PUBLISHED": {"QUARANTINED"},
    "REJECTED": set(),
    "APPROVAL_EXPIRED": set(),
    "QUARANTINED": set(),
}

# 中間CA（発行用CA）の運用状態
CA_STATES = {"PENDING", "ACTIVE", "SUSPENDED", "REVOKED", "RETIRED"}

# 監査ログが壊れていても実行できる操作（読み取り・管理された復旧のみ）
NO_AUDIT_PRECHECK = {"audit-verify", "audit-reanchor", "check", "status", "restore", "serve-public"}
# 復旧保留（restore 直後）の間は止める操作
HOLD_BLOCKED = {"init", "init-root", "init-issuer", "sign-intermediate", "request", "approve", "reject",
                "issue", "recover", "revoke", "revoke-intermediate", "crl-root", "crl-issuer", "backup"}


class LabError(Exception):
    """業務上の拒否・失敗。code は機械判定用、message は人向け。"""

    def __init__(self, code: str, message: str, **extra):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.extra = extra


# =============================================================================
# 時刻・ハッシュ
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


def canonical(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


# =============================================================================
# 永続化（一時ファイル → fsync → rename → ディレクトリ fsync）
# =============================================================================

def fsync_dir(d: Path) -> None:
    fd = os.open(d, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path: Path, data: bytes | str, mode: int = 0o644) -> None:
    """読み手が書きかけのファイルを見ないよう、同じディレクトリの一意な一時ファイルに
    書いて fsync してから置き換える。電源断後も旧版か新版のどちらかが残る。"""
    if isinstance(data, str):
        data = data.encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
        fsync_dir(path.parent)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def write_private(path: Path, data: bytes | str) -> None:
    atomic_write(path, data, 0o600)


def write_json(path: Path, obj) -> None:
    atomic_write(path, json.dumps(obj, ensure_ascii=False, indent=2) + "\n")


def read_json(path: Path):
    return json.loads(path.read_text())


def append_durable(path: Path, line: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        f.write(line + "\n")
        f.flush()
        os.fsync(f.fileno())


# =============================================================================
# 最小限の DER 解析（証明書・CSR の構造を文字列表示ではなく型で読む）
# =============================================================================

class DerError(ValueError):
    pass


def _tlv(buf: bytes, i: int):
    if i + 2 > len(buf):
        raise DerError("truncated")
    tag, ln = buf[i], buf[i + 1]
    j = i + 2
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4 or j + n > len(buf):
            raise DerError("bad length")
        ln = int.from_bytes(buf[j:j + n], "big")
        j += n
    if j + ln > len(buf):
        raise DerError("truncated value")
    return tag, buf[j:j + ln], buf[i:j + ln], j + ln


def der_children(content: bytes) -> list[tuple[int, bytes, bytes]]:
    out, i = [], 0
    while i < len(content):
        tag, val, raw, i = _tlv(content, i)
        out.append((tag, val, raw))
    return out


def der_oid(b: bytes) -> str:
    if not b:
        raise DerError("empty oid")
    first = b[0]
    parts = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    v = 0
    for byte in b[1:]:
        v = (v << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(v)
            v = 0
    return ".".join(map(str, parts))


OID_EXT_REQ = "1.2.840.113549.1.9.14"
OID_SAN, OID_BC, OID_KU, OID_EKU = "2.5.29.17", "2.5.29.19", "2.5.29.15", "2.5.29.37"
EKU_NAMES = {
    "1.3.6.1.5.5.7.3.1": "serverAuth", "1.3.6.1.5.5.7.3.2": "clientAuth",
    "1.3.6.1.5.5.7.3.3": "codeSigning", "1.3.6.1.5.5.7.3.4": "emailProtection",
    "1.3.6.1.5.5.7.3.8": "timeStamping", "1.3.6.1.5.5.7.3.9": "OCSPSigning",
    "2.5.29.37.0": "anyExtendedKeyUsage",
}
KU_BITS = ["digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment",
           "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"]


def parse_extensions(seq_content: bytes) -> dict:
    exts = {}
    for tag, val, _ in der_children(seq_content):
        if tag != 0x30:
            raise DerError("extension is not a SEQUENCE")
        parts = der_children(val)
        oid = der_oid(parts[0][1])
        critical = len(parts) == 3 and parts[1][0] == 0x01 and parts[1][1] != b"\x00"
        if oid in exts:
            raise DerError(f"duplicate extension {oid}")
        exts[oid] = (critical, parts[-1][1])
    return exts


def decode_general_names(content: bytes) -> list[str]:
    names = []
    for tag, val, _ in der_children(content):
        if tag == 0x82:
            names.append("DNS:" + val.decode("ascii", "replace").lower())
        elif tag == 0x87:
            try:
                names.append("IP:" + str(ipaddress.ip_address(val)))
            except ValueError:
                names.append("IP:invalid")
        elif tag == 0x81:
            names.append("EMAIL:" + val.decode("ascii", "replace"))
        elif tag == 0x86:
            names.append("URI:" + val.decode("ascii", "replace"))
        else:
            names.append(f"OTHER:{tag:02x}")
    return sorted(names)


def decode_ext_info(exts: dict) -> dict:
    info = {"san": [], "ca": None, "pathlen": None, "ku": [], "eku": [],
            "critical": sorted(o for o, (c, _) in exts.items() if c)}
    if OID_SAN in exts:
        _, seq = der_children(exts[OID_SAN][1])[0][:2]
        info["san"] = decode_general_names(seq)
    if OID_BC in exts:
        info["ca"] = False
        _, seq = der_children(exts[OID_BC][1])[0][:2]
        for tag, val, _ in der_children(seq):
            if tag == 0x01:
                info["ca"] = val != b"\x00"
            elif tag == 0x02:
                info["pathlen"] = int.from_bytes(val, "big")
    if OID_KU in exts:
        tag, val = der_children(exts[OID_KU][1])[0][:2]
        unused, bits = val[0], val[1:]
        total = len(bits) * 8 - unused
        info["ku"] = [KU_BITS[i] for i in range(min(total, len(KU_BITS)))
                      if bits[i // 8] & (0x80 >> (i % 8))]
    if OID_EKU in exts:
        _, seq = der_children(exts[OID_EKU][1])[0][:2]
        info["eku"] = [EKU_NAMES.get(der_oid(v), der_oid(v)) for t, v, _ in der_children(seq)]
    return info


def csr_structure(der: bytes) -> dict:
    (tag, top, _), = der_children(der)
    cri_tag, cri, _ = der_children(top)[0]
    parts = der_children(cri)
    spki_raw = parts[2][2]
    exts = {}
    for tag, val, _ in parts[3:]:
        if tag != 0xA0:
            continue
        for _t, attr, _r in der_children(val):
            a = der_children(attr)
            if der_oid(a[0][1]) == OID_EXT_REQ:
                (_st, seq, _sr), = der_children(a[1][1])[:1]
                exts = parse_extensions(seq)
    return {"spki": spki_raw, **decode_ext_info(exts)}


def cert_structure(der: bytes) -> dict:
    (tag, top, _), = der_children(der)
    tbs = der_children(der_children(top)[0][1])
    if tbs[0][0] == 0xA0:
        tbs = tbs[1:]
    spki_raw = tbs[5][2]
    exts = {}
    for tag, val, _ in tbs[6:]:
        if tag == 0xA3:
            exts = parse_extensions(der_children(val)[0][1])
    return {"spki": spki_raw, **decode_ext_info(exts)}


# =============================================================================
# ラボの作業領域
# =============================================================================

class Lab:
    """PKILAB_HOME 配下のファイル配置（docs/03_detailed-design.md 1章）。"""

    def __init__(self, home: Path, actor: str, role: str):
        self.home = home.resolve()
        self.actor = actor
        self.role = role
        self.env = dict(os.environ, PKILAB_HOME=str(self.home))
        self.lock_timeout = float(os.environ.get("PKILAB_LOCK_TIMEOUT", "5"))

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
        # 本番相当の運用ではルートのパスフレーズは Root VM の管理者だけが知る。
        return Path(os.environ.get("PKILAB_ROOT_PASS_FILE", self.p("secrets", "root.pass")))

    @property
    def issuer_pass(self) -> Path:
        return Path(os.environ.get("PKILAB_ISSUER_PASS_FILE", self.p("secrets", "issuer.pass")))

    def layout(self) -> None:
        dirs = [
            "root/private", "root/certs", "root/db", "root/newcerts", "root/crl",
            "issuer/private", "issuer/certs", "issuer/db", "issuer/newcerts", "issuer/crl",
            "issuer/lock", "requests", "approvals", "journal", "audit", "anchor", "incidents",
            "server/private", "server/certs", "public/certs", "public/crl",
            "verifier/trust", "verifier/cache", "exports", "secrets", "backups", "archive",
        ]
        for d in dirs:
            self.p(d).mkdir(parents=True, exist_ok=True)
        for d in ["root/private", "issuer/private", "server/private", "secrets"]:
            os.chmod(self.p(d), 0o700)

    # --- 権限 ---------------------------------------------------------------
    def require(self, op: str) -> None:
        if op not in ROLE_OPS.get(self.role, set()):
            raise LabError("ROLE_DENIED", f"役割 '{self.role}' は操作 '{op}' を実行できません"
                                          f"（--role {role_for(op)} で実行してください）")

    # --- OpenSSL --------------------------------------------------------------
    def openssl(self, *args, input: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess:
        cmd = ["openssl", *[str(a) for a in args]]
        cp = subprocess.run(cmd, input=input, capture_output=True, env=self.env)
        if check and cp.returncode != 0:
            raise LabError("OPENSSL_FAILED",
                           f"{' '.join(cmd[:3])} ...: {cp.stderr.decode(errors='replace').strip()}")
        return cp

    # --- 排他制御 -------------------------------------------------------------
    @contextlib.contextmanager
    def _flock(self, path: Path, name: str):
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        deadline = time.monotonic() + self.lock_timeout
        try:
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError as e:
                    if e.errno not in (errno.EAGAIN, errno.EACCES):
                        raise
                    if time.monotonic() > deadline:
                        raise LabError("LOCK_BUSY", f"{name} は別の処理が使用中です")
                    time.sleep(0.05)
            yield
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def ca_lock(self, which: str = "issuer"):
        # 取得順は常に issuer → root → audit（デッドロック防止）
        path = self.p("issuer", "lock", "ca.lock") if which == "issuer" else self.p("root", "db", "ca.lock")
        return self._flock(path, f"{which} CA")

    def audit_lock(self):
        return self._flock(self.p("audit", ".lock"), "監査ログ")

    # --- 監査ログ（ハッシュ連鎖・凍結） ------------------------------------------
    @property
    def frozen_marker(self) -> Path:
        return self.p("audit", "FROZEN.json")

    def is_frozen(self) -> bool:
        return self.frozen_marker.exists()

    def incident(self, code: str, **details) -> None:
        """監査ログとは別の障害ログ。監査ログや基準ハッシュは変更しない。"""
        append_durable(self.p("incidents", "incidents.jsonl"), json.dumps(
            {"ts": iso(utcnow()), "actor": self.actor, "role": self.role, "code": code, "details": details},
            ensure_ascii=False))

    def freeze(self, code: str, detail: dict) -> None:
        if not self.is_frozen():
            write_json(self.frozen_marker, {"since": iso(utcnow()), "code": code, "detail": detail})
        self.incident(code, audit=detail)

    def ensure_audit_ok(self) -> None:
        """監査ログの連鎖と基準ハッシュを確認する。異常なら CA を凍結し、何も追記しない。"""
        if self.is_frozen():
            raise LabError("AUDIT_FROZEN", "監査ログの異常により凍結中です。audit-verify で確認し、"
                                           "audit-reanchor（管理された再アンカー）か restore で復旧してください",
                           frozen=read_json(self.frozen_marker))
        with self.audit_lock():
            res = verify_audit_chain(self.home)
        if not res["ok"]:
            self.freeze(res["code"], res)
            raise LabError("AUDIT_FROZEN", f"監査ログの異常を検出したため凍結しました（{res['code']}）", audit=res)

    def audit(self, op: str, result: str, target: str = "", **details) -> dict:
        log = self.p("audit", "audit.jsonl")
        with self.audit_lock():
            if self.is_frozen():
                raise LabError("AUDIT_FROZEN", "監査ログは凍結中のため記録できません")
            # 末尾が基準ハッシュと一致していることを確認してから追記する
            tail = audit_tail(self.home)
            if not tail["ok"]:
                self.freeze(tail["code"], tail)
                raise LabError("AUDIT_FROZEN", f"監査ログの末尾が基準と一致しません（{tail['code']}）", audit=tail)
            entry = {
                "seq": tail["seq"] + 1, "ts": iso(utcnow()), "actor": self.actor, "role": self.role,
                "op": op, "result": result, "target": target, "details": details, "prev": tail["hash"],
            }
            entry["hash"] = sha256_bytes(canonical(entry))
            append_durable(log, json.dumps(entry, ensure_ascii=False))
            # 末尾削除・再計算の検出用に、最新の連番とハッシュを「別媒体」（anchor/ で代用）へ
            write_json(self.p("anchor", "anchor.json"), {"seq": entry["seq"], "hash": entry["hash"]})
        return entry

    def audit_if_possible(self, op: str, result: str, target: str = "", **details) -> None:
        """照合・復元などの報告用。凍結中は監査ログに書かず障害ログだけに残す。"""
        try:
            self.audit(op, result, target, **details)
        except LabError:
            self.incident(f"{op}:{result}", target=target, details=details)

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

    # --- 中間CAの運用状態・世代 ---------------------------------------------------
    def ca_state(self) -> dict:
        path = self.p("issuer", "state.json")
        if path.exists():
            return read_json(path)
        return {"status": "ACTIVE" if self.issuer_cert.exists() else "PENDING", "generation": 1, "history": []}

    def set_ca_state(self, status: str, reason: str, **extra) -> dict:
        assert status in CA_STATES
        st = self.ca_state()
        st["status"] = status
        st.setdefault("history", []).append({"status": status, "ts": iso(utcnow()), "by": self.actor,
                                             "reason": reason})
        st.update(extra)
        write_json(self.p("issuer", "state.json"), st)
        return st

    def issuer_base(self, generation: int | None = None) -> Path:
        cur = self.ca_state()["generation"]
        if generation is None or generation == cur:
            return self.p("issuer")
        return self.p("archive", f"issuer-gen{generation}")

    # --- 復旧保留 ---------------------------------------------------------------
    @property
    def hold_marker(self) -> Path:
        return self.p("recovery", "hold.json")

    def on_hold(self) -> bool:
        return self.hold_marker.exists()


def role_for(op: str) -> str:
    for role, ops in ROLE_OPS.items():
        if op in ops:
            return role
    return "?"


# =============================================================================
# 監査ログの検証
# =============================================================================

def _audit_lines(home: Path) -> list[str]:
    log = home / "audit" / "audit.jsonl"
    if not log.exists():
        return []
    return [ln for ln in log.read_text().splitlines() if ln.strip()]


def audit_tail(home: Path) -> dict:
    """末尾の1行と基準ハッシュの一致だけを確認する（追記前の軽い確認）。"""
    lines = _audit_lines(home)
    anchor_path = home / "anchor" / "anchor.json"
    anchor = read_json(anchor_path) if anchor_path.exists() else None
    if not lines:
        if anchor is None:
            return {"ok": True, "seq": 0, "hash": "0" * 64}
        return {"ok": False, "code": "AUDIT_TRUNCATED_OR_REWRITTEN", "anchor_seq": anchor["seq"], "log_seq": 0}
    try:
        last = json.loads(lines[-1])
    except json.JSONDecodeError:
        return {"ok": False, "code": "AUDIT_TAMPERED", "line": len(lines)}
    if anchor is None:
        return {"ok": False, "code": "ANCHOR_MISSING"}
    if anchor["seq"] != last.get("seq") or anchor["hash"] != last.get("hash"):
        return {"ok": False, "code": "AUDIT_TRUNCATED_OR_REWRITTEN", "anchor_seq": anchor["seq"],
                "log_seq": last.get("seq")}
    return {"ok": True, "seq": last["seq"], "hash": last["hash"]}


def verify_audit_chain(home: Path) -> dict:
    """全行の連鎖（prev・hash・連番）と、基準ハッシュとの一致を検証する。"""
    prev, seq, head = "0" * 64, 0, "0" * 64
    for n, line in enumerate(_audit_lines(home), 1):
        try:
            e = json.loads(line)
            h = e.pop("hash")
        except (json.JSONDecodeError, KeyError):
            return {"ok": False, "internal_ok": False, "code": "AUDIT_TAMPERED", "line": n}
        if e.get("prev") != prev or e.get("seq") != seq + 1 or sha256_bytes(canonical(e)) != h:
            return {"ok": False, "internal_ok": False, "code": "AUDIT_TAMPERED", "line": n}
        prev, seq, head = h, e["seq"], h
    anchor_path = home / "anchor" / "anchor.json"
    if not anchor_path.exists():
        if seq == 0:
            return {"ok": True, "internal_ok": True, "entries": 0, "head": head}
        return {"ok": False, "internal_ok": True, "code": "ANCHOR_MISSING", "entries": seq, "head": head}
    a = read_json(anchor_path)
    if a["seq"] != seq or a["hash"] != head:
        return {"ok": False, "internal_ok": True, "code": "AUDIT_TRUNCATED_OR_REWRITTEN",
                "anchor_seq": a["seq"], "log_seq": seq, "head": head}
    return {"ok": True, "internal_ok": True, "entries": seq, "head": head}


# =============================================================================
# 証明書・CSR の解析
# =============================================================================

def cert_info(lab: Lab, cert: Path) -> dict:
    cp = lab.openssl("x509", "-in", cert, "-noout", "-serial", "-subject", "-issuer",
                     "-startdate", "-enddate", "-nameopt", "RFC2253", check=False)
    der_cp = lab.openssl("x509", "-in", cert, "-outform", "DER", check=False)
    if cp.returncode != 0 or der_cp.returncode != 0 or not der_cp.stdout:
        raise LabError("CERT_PARSE_ERROR", f"証明書として解析できません: {cert}")
    info: dict = {}
    for line in cp.stdout.decode().splitlines():
        key, _, val = line.partition("=")
        if key == "serial":
            info["serial"] = val.strip().upper()
        elif key == "subject":
            info["subject"] = val.strip()
        elif key == "issuer":
            info["issuer"] = val.strip()
        elif key == "notBefore":
            info["not_before"] = iso(parse_openssl_date(val))
        elif key == "notAfter":
            info["not_after"] = iso(parse_openssl_date(val))
    try:
        st = cert_structure(der_cp.stdout)
    except (DerError, IndexError, ValueError) as e:
        raise LabError("CERT_PARSE_ERROR", f"証明書の構造を解析できません: {e}")
    info.update({k: st[k] for k in ("san", "ca", "pathlen", "ku", "eku", "critical")})
    info["pubkey_sha256"] = sha256_bytes(st["spki"])
    info["cert_sha256"] = sha256_bytes(der_cp.stdout)  # 証明書の識別には DER のハッシュを使う
    return info


def inspect_csr(lab: Lab, csr: Path) -> dict:
    """CSR の受付検査（docs/03_detailed-design.md 3章）。表示テキストではなく構造で判定する。"""
    data = csr.read_bytes()
    if len(data) > MAX_CSR_BYTES:
        raise LabError("CSR_TOO_LARGE", f"CSR が上限 {MAX_CSR_BYTES} バイトを超えています")
    if b"-----BEGIN CERTIFICATE REQUEST-----" not in data:
        raise LabError("CSR_BAD_FORMAT", "PEM 形式の CSR ではありません")
    # CSR の自己署名 = 「この公開鍵の秘密鍵を持っている」ことの確認だけ。
    # 名前を使う権限の確認は RA の承認で別に行う。
    cp = lab.openssl("req", "-in", csr, "-noout", "-verify", check=False)
    if cp.returncode != 0 or b"verify failure" in (cp.stderr + cp.stdout).lower():
        raise LabError("CSR_BAD_SIGNATURE", "CSR の署名を検証できません")
    der = lab.openssl("req", "-in", csr, "-outform", "DER").stdout
    try:
        st = csr_structure(der)
    except (DerError, IndexError, ValueError) as e:
        raise LabError("CSR_BAD_FORMAT", f"CSR の構造を解析できません: {e}")
    if not (len(st["spki"]) == 91 and st["spki"].startswith(P256_SPKI_PREFIX)):
        raise LabError("CSR_BAD_KEY", "許可されていない鍵です（EC P-256 のみ受け付けます）")
    forbidden = []
    if st["ca"]:
        forbidden.append("CA 権限（CA:TRUE）")
    forbidden += [k for k in st["ku"] if k in ("keyCertSign", "cRLSign")]
    forbidden += [k for k in st["eku"] if k != "serverAuth"]
    if forbidden:
        raise LabError("CSR_FORBIDDEN_EXTENSION", f"サーバー証明書に不要な権限を要求しています: {', '.join(forbidden)}")
    return {"csr_sha256": sha256_bytes(data), "pubkey_sha256": sha256_bytes(st["spki"]), "san": st["san"]}


def check_san_policy(san: list[str]) -> None:
    if not san:
        raise LabError("SAN_REQUIRED", "SAN（接続先名）がありません。CN だけの証明書は発行しません")
    bad = [s for s in san if s not in ALLOWED_SAN]
    if bad:
        # DNS の名前制約は配下（sub.localhost 等）も許してしまうため、
        # 発行審査では完全一致の許可リストで確認する。
        raise LabError("SAN_NOT_ALLOWED", f"許可されていない名前です: {', '.join(bad)}")


def host_identity(host: str) -> str:
    """接続先を型付きの SAN 表記にする（DNS 名と IP アドレスは別の種類）。"""
    try:
        return "IP:" + str(ipaddress.ip_address(host))
    except ValueError:
        return "DNS:" + host.lower().rstrip(".")


def profile_hash() -> str:
    return sha256_bytes(SERVER_PROFILE.read_bytes() + f"\ndays={LEAF_DAYS}".encode())


def read_index(base: Path) -> list[dict]:
    rows = []
    path = base / "db" / "index.txt"
    if not path.exists():
        return rows
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        rows.append({"status": parts[0], "expires": parts[1], "revoked": parts[2],
                     "serial": parts[3].upper(), "subject": parts[5] if len(parts) > 5 else ""})
    return rows


def crl_meta(lab: Lab, crl: Path, ca_cert: Path) -> dict:
    """CRL の署名・発行者・番号・期限・失効シリアルを読む。"""
    if not crl.exists():
        return {"present": False}
    if crl.stat().st_size > MAX_CRL_BYTES:
        return {"present": True, "sig_ok": False, "error": "too large"}
    sig = lab.openssl("crl", "-in", crl, "-CAfile", ca_cert, "-noout", check=False)
    sig_ok = sig.returncode == 0 and b"verify OK" in (sig.stderr + sig.stdout)
    cp = lab.openssl("crl", "-in", crl, "-noout", "-issuer", "-crlnumber", "-lastupdate", "-nextupdate",
                     "-nameopt", "RFC2253", check=False)
    if cp.returncode != 0:
        return {"present": True, "sig_ok": False, "error": "unparseable"}
    meta = dict(line.split("=", 1) for line in cp.stdout.decode().splitlines() if "=" in line)
    text = lab.openssl("crl", "-in", crl, "-noout", "-text").stdout.decode()
    num = meta.get("crlNumber", "").strip()
    return {
        "present": True, "sig_ok": sig_ok, "issuer": meta.get("issuer", "").strip(),
        "number": int(num, 16) if num.lower().startswith("0x") else int(num or -1),
        "last_update": iso(parse_openssl_date(meta["lastUpdate"])),
        "next_update": iso(parse_openssl_date(meta["nextUpdate"])),
        "revoked": {m.upper() for m in re.findall(r"Serial Number: ([0-9A-Fa-f]+)", text)},
        "sha256": sha256_file(crl),
    }


# =============================================================================
# CA の初期化・世代
# =============================================================================

def gen_encrypted_key(lab: Lab, out: Path, pass_file: Path) -> None:
    """EC P-256 の鍵を作り、PKCS#8(PBES2 / AES-256-CBC / PBKDF2-HMAC-SHA256)で暗号化して保存。
    平文の鍵はパイプで受け渡し、ディスクに書かない。パスフレーズは file: で渡す。"""
    raw = lab.openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256").stdout
    enc = lab.openssl("pkcs8", "-topk8", "-v2", "aes-256-cbc", "-v2prf", "hmacWithSHA256",
                      "-iter", KDF_ITER, "-passout", f"file:{pass_file}", input=raw).stdout
    write_private(out, enc)


def ensure_passphrase(path: Path) -> None:
    if not path.exists():
        write_private(path, secrets.token_urlsafe(32) + "\n")


def init_ca_db(base: Path) -> None:
    (base / "db").mkdir(parents=True, exist_ok=True)
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
        tmp = lab.p("root", "certs", ".root.cert.pem.new")
        lab.openssl("req", "-config", ROOT_CNF, "-new", "-x509", "-key", lab.root_key,
                    "-passin", f"file:{lab.root_pass}", "-sha256", "-days", ROOT_DAYS,
                    "-extensions", "v3_root", "-set_serial", "0x" + secrets.token_hex(16), "-out", tmp)
        os.replace(tmp, lab.root_cert)
        atomic_write(lab.p("public", "certs", "root.cert.pem"), lab.root_cert.read_bytes())
        info = cert_info(lab, lab.root_cert)
        lab.audit("init-root", "ok", info["serial"], not_after=info["not_after"], cert_sha256=info["cert_sha256"])
    return {"root": str(lab.root_cert), "serial": info["serial"], "not_after": info["not_after"]}


def cmd_init_issuer(lab: Lab, args) -> dict:
    """中間CAの鍵と CSR を作る。署名はルート側（sign-intermediate）で行う。
    --new-generation：失効・廃止した中間CAを archive/ へ移し、新しい鍵で次の世代を作る。"""
    lab.require("init-issuer")
    lab.layout()
    with lab.ca_lock("issuer"):
        st = lab.ca_state()
        generation = st["generation"]
        if lab.issuer_key.exists():
            if not getattr(args, "new_generation", False):
                raise LabError("ALREADY_INITIALIZED", "中間CAの鍵は作成済みです")
            if st["status"] not in ("REVOKED", "RETIRED"):
                raise LabError("CA_STILL_ACTIVE", "新しい世代へ移るには、現在の中間CAを失効または廃止してください")
            archive = lab.p("archive", f"issuer-gen{generation}")
            if archive.exists():
                raise LabError("ARCHIVE_EXISTS", f"{archive} が既にあります")
            # 旧世代は秘密鍵ごと保管庫へ（署名には二度と使わない）
            os.rename(lab.p("issuer"), archive)
            fsync_dir(lab.p("archive"))
            lab.layout()
            generation += 1
        ensure_passphrase(lab.issuer_pass)
        init_ca_db(lab.p("issuer"))
        gen_encrypted_key(lab, lab.issuer_key, lab.issuer_pass)
        csr = lab.p("issuer", "certs", "intermediate.csr.pem")
        lab.openssl("req", "-config", ISSUER_CNF, "-new", "-key", lab.issuer_key,
                    "-passin", f"file:{lab.issuer_pass}", "-sha256",
                    "-subj", f"/CN=PKI Lab Issuing CA {generation}", "-out", csr)
        write_json(lab.p("issuer", "state.json"), {"status": "PENDING", "generation": generation, "history": [
            {"status": "PENDING", "ts": iso(utcnow()), "by": lab.actor, "reason": "init-issuer"}]})
        lab.audit("init-issuer", "ok", f"generation-{generation}", csr_sha256=sha256_file(csr),
                  generation=generation)
    return {"csr": str(csr), "generation": generation}


def cmd_sign_intermediate(lab: Lab, args) -> dict:
    lab.require("sign-intermediate")
    csr = lab.p("issuer", "certs", "intermediate.csr.pem")
    if not csr.exists():
        raise LabError("NO_CSR", "中間CAの CSR がありません（init-issuer を先に実行）")
    with lab.ca_lock("issuer"), lab.ca_lock("root"):
        st = lab.ca_state()
        if st["status"] != "PENDING":
            raise LabError("ALREADY_SIGNED", f"中間CAは {st['status']} 状態です。署名し直しは"
                                             "新しい世代（init-issuer --new-generation）でのみ行います")
        csr_spki = sha256_bytes(csr_structure(lab.openssl("req", "-in", csr, "-outform", "DER").stdout)["spki"])
        # 失効させた鍵を同じまま再署名して復帰させない
        for row in read_index(lab.p("root")):
            pem = lab.p("root", "newcerts", f"{row['serial']}.pem")
            if pem.exists() and cert_info(lab, pem)["pubkey_sha256"] == csr_spki:
                raise LabError("KEY_REUSE", "過去にルートが署名した中間CAと同じ鍵です。新しい鍵を作ってください")
        root = cert_info(lab, lab.root_cert)
        now = utcnow()
        not_after = now + dt.timedelta(days=ISSUER_DAYS)
        if not_after > parse_iso(root["not_after"]) - ISSUER_MARGIN:
            raise LabError("ISSUER_RENEWAL_REQUIRED", "ルートCAの残り期間が足りません")
        out = lab.p("issuer", "certs", ".intermediate.cert.pem.new")
        lab.openssl("ca", "-config", ROOT_CNF, "-batch", "-notext", "-in", csr, "-out", out,
                    "-passin", f"file:{lab.root_pass}", "-extensions", "v3_intermediate",
                    "-subj", f"/CN=PKI Lab Issuing CA {st['generation']}",
                    "-startdate", asn1_time(now - dt.timedelta(seconds=BACKDATE_SECONDS)),
                    "-enddate", asn1_time(not_after))
        os.replace(out, lab.issuer_cert)
        atomic_write(lab.p("public", "certs", "intermediate.cert.pem"), lab.issuer_cert.read_bytes())
        info = cert_info(lab, lab.issuer_cert)
        lab.set_ca_state("ACTIVE", "sign-intermediate", serial=info["serial"])
        lab.audit("sign-intermediate", "ok", info["serial"], not_after=info["not_after"],
                  cert_sha256=info["cert_sha256"], generation=st["generation"])
    return {"intermediate": str(lab.issuer_cert), "serial": info["serial"], "generation": st["generation"]}


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
# 申請 → 審査・承認
# =============================================================================

def new_request_id() -> str:
    return f"REQ-{utcnow():%Y%m%d}-{secrets.token_hex(4)}"


def cmd_request(lab: Lab, args) -> dict:
    """サーバー管理者が鍵と CSR を作って申請する。秘密鍵は server/private から出さない。"""
    lab.require("request")
    lab.layout()
    req_id = new_request_id()
    d = lab.p("requests", req_id)
    csr = d / "request.csr.pem"
    key_path = None
    if args.csr:
        src = Path(args.csr)
        if src.stat().st_size > MAX_CSR_BYTES:
            raise LabError("CSR_TOO_LARGE", f"CSR が上限 {MAX_CSR_BYTES} バイトを超えています")
        d.mkdir(parents=True)
        atomic_write(csr, src.read_bytes())
    else:
        d.mkdir(parents=True)
        san = args.san or ["DNS:localhost", "IP:127.0.0.1"]
        if args.key:
            key_path = Path(args.key).resolve()  # 同じ鍵で再申請する場合（鍵更新しない更新）
        else:
            key_path = lab.p("server", "private", f"{req_id}.key.pem")
            raw = lab.openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256").stdout
            # ローカルの非対話 TLS デモのための例外として、サーバー鍵だけ非暗号化 PEM(0600)。
            write_private(key_path, raw)
        lab.openssl("req", "-new", "-key", key_path, "-sha256", "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=" + ",".join(san), "-out", csr)
    rel_key = None
    if key_path:
        rel_key = str(key_path.relative_to(lab.home)) if key_path.is_relative_to(lab.home) else str(key_path)
    st = {"id": req_id, "status": "RECEIVED", "requester": lab.actor, "asset": args.asset,
          "created": iso(utcnow()), "server_key": rel_key,
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
    # 1人で役割を切り替える学習環境なので拒否はしないが、記録に残す。
    note = "requester_and_approver_same_actor" if lab.actor == st.get("requester") else ""
    approval = {
        "approval_id": "APR-" + secrets.token_hex(6), "request": req_id,
        "csr_sha256": csr["csr_sha256"], "pubkey_sha256": csr["pubkey_sha256"],
        "profile": "server_localhost", "profile_sha256": profile_hash(),
        "san": csr["san"], "eku": ["serverAuth"], "days": LEAF_DAYS,
        "approver": lab.actor, "approved_at": iso(utcnow()),
        "expires_at": iso(utcnow() + APPROVAL_TTL), "note": note,
    }
    write_json(lab.p("approvals", f"{req_id}.json"), approval)
    lab.set_state(req_id, "APPROVED", approval_id=approval["approval_id"])
    lab.audit("approve", "ok", req_id, approval_id=approval["approval_id"], san=csr["san"], note=note)
    return approval


def cmd_reject(lab: Lab, args) -> dict:
    lab.require("reject")
    lab.set_state(args.request, "REJECTED", reject_code="RA_REJECTED")
    lab.audit("reject", "ok", args.request, reason=args.reason)
    return {"request": args.request, "status": "REJECTED"}


# =============================================================================
# 発行・配置・復旧
# =============================================================================

def _journal(lab: Lab, op_id: str, **data) -> dict:
    path = lab.p("journal", f"{op_id}.json")
    cur = read_json(path) if path.exists() else {"op_id": op_id}
    cur.update(data)
    write_json(path, cur)
    return cur


def _crash_point(name: str) -> None:
    """障害注入（試験用）。PKILAB_CRASH_AT=<name> の箇所で処理を止める。"""
    if os.environ.get("PKILAB_CRASH_AT") == name:
        raise LabError("SIMULATED_CRASH", f"試験用：{name} で停止しました")


def require_issuer_active(lab: Lab) -> dict:
    """署名前に、中間CAの運用状態と、ルート CRL 上で失効していないことを確認する。"""
    st = lab.ca_state()
    if st["status"] != "ACTIVE":
        raise LabError("CA_NOT_ACTIVE", f"中間CAは {st['status']} 状態のため発行できません", ca_state=st["status"])
    issuer = cert_info(lab, lab.issuer_cert)
    meta = crl_meta(lab, lab.p("public", "crl", "root.crl.pem"), lab.root_cert)
    if not meta["present"] or not meta.get("sig_ok"):
        raise LabError("ROOT_CRL_UNAVAILABLE", "ルート CRL が無いか署名を検証できないため、中間CAの状態を確認できません")
    if parse_iso(meta["next_update"]) < utcnow():
        raise LabError("ROOT_CRL_UNAVAILABLE", "ルート CRL の期限が切れています（crl-root で更新）")
    if issuer["serial"] in meta["revoked"]:
        lab.set_ca_state("REVOKED", "found in root CRL")
        raise LabError("CA_NOT_ACTIVE", "中間CAはルート CRL で失効しています", ca_state="REVOKED")
    return issuer


def validate_issued(lab: Lab, rec: dict, apr: dict) -> list[str]:
    """署名済み証明書が、台帳・承認・プロファイルと一致するかを確認する。"""
    base = lab.issuer_base(rec.get("generation"))
    pem = base / "newcerts" / f"{rec['serial']}.pem"
    if not pem.exists():
        return ["newcert_missing"]
    try:
        info = cert_info(lab, pem)
    except LabError:
        return ["newcert_unparseable"]
    problems = []
    if info["cert_sha256"] != rec["cert_sha256"]:
        problems.append("cert_hash")
    if info["serial"] != rec["serial"]:
        problems.append("serial")
    rows = {r["serial"]: r for r in read_index(base)}
    if rec["serial"] not in rows:
        problems.append("not_in_ledger")
    elif rows[rec["serial"]]["status"] != "V":
        problems.append(f"ledger_status_{rows[rec['serial']]['status']}")
    if info["san"] != sorted(apr["san"]):
        problems.append("san")
    if info["pubkey_sha256"] != apr["pubkey_sha256"]:
        problems.append("pubkey")
    if info["ca"] is not False:
        problems.append("basicConstraints")
    if info["eku"] != ["serverAuth"]:
        problems.append("eku")
    if info["ku"] != ["digitalSignature"]:
        problems.append("keyUsage")
    issuer_cert = base / "certs" / "intermediate.cert.pem"
    if issuer_cert.exists() and info["issuer"] != cert_info(lab, issuer_cert)["subject"]:
        problems.append("issuer")
    return problems


def _quarantine(lab: Lab, req_id: str, op_id: str | None, serial: str | None, problems: list[str]) -> dict:
    """発行後検査に不合格の証明書を失効させ、CRL を公開してから隔離する。
    失効か CRL 公開に失敗したら、中間CAを SUSPENDED にして未完了の失効を記録する。"""
    pem = lab.p("issuer", "newcerts", f"{serial}.pem") if serial else None
    rows = {r["serial"]: r for r in read_index(lab.p("issuer"))}
    if pem and pem.exists() and rows.get(serial, {}).get("status") == "V":
        cp = lab.openssl("ca", "-config", ISSUER_CNF, "-revoke", pem, "-crl_reason", "cessationOfOperation",
                         "-passin", f"file:{lab.issuer_pass}", check=False)
        ok = cp.returncode == 0
        if ok:
            try:
                _gen_crl(lab, "issuer")
            except LabError:
                ok = False
        if not ok:
            lab.set_ca_state("SUSPENDED", "pending revocation of quarantined certificate", pending_revocation=serial)
            if op_id:
                _journal(lab, op_id, pending_revocation=serial)
            lab.audit("quarantine", "revocation_pending", req_id, serial=serial, problems=problems)
            lab.set_state(req_id, "QUARANTINED", problems=problems, serial=serial)
            return {"request": req_id, "action": "quarantined", "revocation": "pending", "problems": problems}
    lab.set_state(req_id, "QUARANTINED", problems=problems, serial=serial)
    if op_id:
        _journal(lab, op_id, finished=iso(utcnow()), result="quarantined")
    lab.audit("quarantine", "ok", req_id, serial=serial or "", problems=problems)
    return {"request": req_id, "action": "quarantined", "revocation": "done" if serial else "none",
            "problems": problems}


def _publish(lab: Lab, req_id: str, republish: bool = False) -> dict:
    """署名済み（ISSUED）の証明書を、再署名せずにサーバーと公開領域へ配置する。"""
    st = lab.state(req_id)
    d = lab.req_dir(req_id)
    rec = read_json(d / "cert.json")
    apr = read_json(lab.p("approvals", f"{req_id}.json"))
    problems = validate_issued(lab, rec, apr)
    if problems:
        res = _quarantine(lab, req_id, st.get("op_id"), rec["serial"], problems)
        raise LabError("POST_ISSUE_CHECK_FAILED", f"配置前の検査で不合格: {problems}", **res)
    base = lab.issuer_base(rec.get("generation"))
    data = (base / "newcerts" / f"{rec['serial']}.pem").read_bytes()
    leaf = lab.p("server", "certs", f"{req_id}.cert.pem")
    chain = lab.p("server", "certs", f"{req_id}.fullchain.pem")
    atomic_write(leaf, data)
    atomic_write(chain, data + (base / "certs" / "intermediate.cert.pem").read_bytes())
    atomic_write(lab.p("public", "certs", f"{rec['serial']}.pem"), data)
    lab.set_state(req_id, "PUBLISHED", cert=str(leaf.relative_to(lab.home)),
                  fullchain=str(chain.relative_to(lab.home)))
    if st.get("op_id"):
        _journal(lab, st["op_id"], finished=iso(utcnow()), result="ok", serial=rec["serial"])
    lab.audit("republish" if republish else "publish", "ok", req_id, serial=rec["serial"])
    return {"request": req_id, "serial": rec["serial"], "cert": str(leaf), "fullchain": str(chain),
            "not_after": rec["not_after"]}


def _ensure_published(lab: Lab, req_id: str) -> dict:
    """PUBLISHED でも、配置物が台帳の証明書と一致しているかを確かめてから返す。"""
    st = lab.state(req_id)
    rec = read_json(lab.req_dir(req_id) / "cert.json")
    leaf = lab.p(st["cert"])
    ok = leaf.exists()
    if ok:
        try:
            ok = cert_info(lab, leaf)["cert_sha256"] == rec["cert_sha256"]
        except LabError:
            ok = False
    if not ok:
        return {**_publish(lab, req_id, republish=True), "reused": True, "republished": True}
    return {"request": req_id, "serial": rec["serial"], "cert": str(leaf), "fullchain": str(lab.p(st["fullchain"])),
            "not_after": rec["not_after"], "reused": True}


def _record_issued(lab: Lab, req_id: str, apr: dict, info: dict, op_id: str | None) -> dict:
    rec = {"issuer": info["issuer"], "serial": info["serial"], "request": req_id,
           "approval_id": apr["approval_id"], "op_id": op_id, "generation": lab.ca_state()["generation"],
           "cert_sha256": info["cert_sha256"], "pubkey_sha256": info["pubkey_sha256"], "san": info["san"],
           "not_before": info["not_before"], "not_after": info["not_after"]}
    write_json(lab.req_dir(req_id) / "cert.json", rec)
    lab.set_state(req_id, "ISSUED", serial=info["serial"], cert_sha256=info["cert_sha256"])
    return rec


def cmd_issue(lab: Lab, args) -> dict:
    """中間CAによる発行（docs/03_detailed-design.md 6章の手順どおり）。"""
    lab.require("issue")
    req_id = args.request
    d = lab.req_dir(req_id)
    with lab.ca_lock("issuer"):
        st = lab.state(req_id)
        # 冪等性：完了済みなら同じ証明書を返す。署名済み・未配置なら配置だけを再開する。
        if st["status"] == "PUBLISHED":
            return _ensure_published(lab, req_id)
        if st["status"] == "ISSUED":
            return {**_publish(lab, req_id), "reused": True, "resumed": "publish"}
        if st["status"] in ("SIGNING", "NEEDS_RECOVERY"):
            if st["status"] == "SIGNING":
                lab.set_state(req_id, "NEEDS_RECOVERY")
            lab.audit("issue", "refused", req_id, code="NEEDS_RECOVERY")
            raise LabError("NEEDS_RECOVERY", "前回の署名処理が完了していません。recover で照合してから再開してください")
        if st["status"] != "APPROVED":
            raise LabError("NOT_APPROVED", f"承認されていない申請です（{st['status']}）")

        issuer = require_issuer_active(lab)
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

        now = utcnow()
        not_before = max(now - dt.timedelta(seconds=BACKDATE_SECONDS), parse_iso(issuer["not_before"]))
        not_after = now + dt.timedelta(days=apr["days"])
        if not_after > parse_iso(issuer["not_after"]) - ISSUER_MARGIN:
            lab.audit("issue", "refused", req_id, code="ISSUER_RENEWAL_REQUIRED")
            raise LabError("ISSUER_RENEWAL_REQUIRED", "中間CAの残り期間が足りません。短い証明書を黙って出さずに停止します")

        # 署名前に「どこまで台帳があったか」を含めて操作開始を永続化する
        op_id = "OP-" + secrets.token_hex(6)
        rows_before = len(read_index(lab.p("issuer")))
        _journal(lab, op_id, op="issue", request=req_id, started=iso(now), finished=None,
                 csr_sha256=apr["csr_sha256"], approval_id=apr["approval_id"],
                 index_rows_before=rows_before, signed=False)
        lab.set_state(req_id, "SIGNING", op_id=op_id)
        _crash_point("before-sign")

        staging = lab.p("journal", f"{op_id}.cert.pem")
        with tempfile.NamedTemporaryFile("w", prefix="ext-", suffix=".cnf", dir=lab.p("journal"),
                                         delete=False) as f:
            f.write(SERVER_PROFILE.read_text().replace("{SAN}", ",".join(apr["san"])))
            ext = Path(f.name)
        try:
            lab.openssl("ca", "-config", ISSUER_CNF, "-batch", "-notext",
                        "-in", csr_path, "-out", staging, "-passin", f"file:{lab.issuer_pass}",
                        "-extfile", ext, "-extensions", "server_cert",
                        "-subj", "/CN=" + apr["san"][0].split(":", 1)[1],
                        "-startdate", asn1_time(not_before), "-enddate", asn1_time(not_after))
        finally:
            ext.unlink(missing_ok=True)

        # 台帳に追加された行が1つだけで、ステージングの証明書と同じであることを確認
        new_rows = read_index(lab.p("issuer"))[rows_before:]
        if len(new_rows) != 1:
            lab.set_state(req_id, "NEEDS_RECOVERY")
            lab.audit("issue", "anomaly", req_id, code="LEDGER_ANOMALY", new_rows=len(new_rows))
            raise LabError("LEDGER_ANOMALY", f"署名後の台帳に {len(new_rows)} 行が追加されました。recover で照合してください")
        serial = new_rows[0]["serial"]
        info = cert_info(lab, lab.p("issuer", "newcerts", f"{serial}.pem"))
        if staging.exists() and cert_info(lab, staging)["cert_sha256"] != info["cert_sha256"]:
            lab.set_state(req_id, "NEEDS_RECOVERY")
            raise LabError("LEDGER_ANOMALY", "ステージングと台帳の証明書が一致しません")
        staging.unlink(missing_ok=True)
        _journal(lab, op_id, signed=True, serial=serial, cert_sha256=info["cert_sha256"])
        _crash_point("after-sign")

        rec_probe = {"serial": serial, "cert_sha256": info["cert_sha256"], "generation": lab.ca_state()["generation"]}
        problems = validate_issued(lab, rec_probe, apr)
        if parse_iso(info["not_after"]) > parse_iso(issuer["not_after"]):
            problems.append("validity")
        if os.environ.get("PKILAB_FORCE_POSTCHECK_FAIL"):  # 試験用
            problems.append("forced")
        if problems:
            res = _quarantine(lab, req_id, op_id, serial, problems)
            raise LabError("POST_ISSUE_CHECK_FAILED", f"発行後検査で不合格: {problems}", **res)

        _record_issued(lab, req_id, apr, info, op_id)
        lab.audit("issue", "ok", req_id, serial=serial, cert_sha256=info["cert_sha256"], san=info["san"],
                  not_after=info["not_after"], op_id=op_id)
        _crash_point("after-issued")
        out = _publish(lab, req_id)
    return {**out, "reused": False}


def cmd_recover(lab: Lab, args) -> dict:
    """止まった発行を、操作記録・台帳・承認と照合して再開する（再署名はしない）。"""
    lab.require("recover")
    req_id = args.request
    with lab.ca_lock("issuer"):
        st = lab.state(req_id)
        if st["status"] == "PUBLISHED":
            return {**_ensure_published(lab, req_id), "action": "verified_published"}
        if st["status"] == "ISSUED":
            return {**_publish(lab, req_id), "action": "completed_publish"}
        if st["status"] not in ("SIGNING", "NEEDS_RECOVERY"):
            return {"request": req_id, "status": st["status"], "action": "none"}
        if st["status"] == "SIGNING":
            st = lab.set_state(req_id, "NEEDS_RECOVERY")
        apr = read_json(lab.p("approvals", f"{req_id}.json"))
        op_id = st.get("op_id")
        j = read_json(lab.p("journal", f"{op_id}.json")) if op_id and lab.p("journal", f"{op_id}.json").exists() else {}
        if not j or j.get("request") != req_id or j.get("csr_sha256") != apr["csr_sha256"]:
            res = _quarantine(lab, req_id, op_id, None, ["journal_missing_or_mismatch"])
            return {**res, "action": "quarantined"}

        if j.get("serial"):
            candidates = [j["serial"]]
        else:
            # 操作開始後に台帳へ追加された行のうち、他の申請に結び付いておらず、
            # この申請の公開鍵と承認 SAN を持つものだけを候補にする
            claimed = set()
            for c in lab.p("requests").glob("REQ-*/cert.json"):
                if c.parent.name != req_id:
                    claimed.add(read_json(c)["serial"])
            candidates = []
            for row in read_index(lab.p("issuer"))[j.get("index_rows_before", 0):]:
                if row["serial"] in claimed:
                    continue
                pem = lab.p("issuer", "newcerts", f"{row['serial']}.pem")
                try:
                    info = cert_info(lab, pem)
                except LabError:
                    continue
                if info["pubkey_sha256"] == apr["pubkey_sha256"] and info["san"] == sorted(apr["san"]):
                    candidates.append(row["serial"])

        if not candidates:
            lab.set_state(req_id, "APPROVED")
            _journal(lab, op_id, finished=iso(utcnow()), result="recovered:not_signed")
            lab.audit("recover", "ok", req_id, action="returned_to_approved")
            return {"request": req_id, "action": "returned_to_approved", "serial": None}
        if len(candidates) > 1:
            # どれが今回の署名か一意に決められない：自動選択せず隔離して止める
            lab.set_state(req_id, "QUARANTINED", problems=["ambiguous_candidates"], candidates=candidates)
            _journal(lab, op_id, finished=iso(utcnow()), result="quarantined:ambiguous", candidates=candidates)
            lab.audit("recover", "quarantined", req_id, code="AMBIGUOUS", candidates=candidates)
            return {"request": req_id, "action": "quarantined", "candidates": candidates}

        serial = candidates[0]
        pem = lab.p("issuer", "newcerts", f"{serial}.pem")
        try:
            info = cert_info(lab, pem)
        except LabError:
            res = _quarantine(lab, req_id, op_id, None, ["newcert_unparseable"])
            return {**res, "action": "quarantined"}
        if j.get("cert_sha256") and j["cert_sha256"] != info["cert_sha256"]:
            res = _quarantine(lab, req_id, op_id, serial, ["cert_hash_differs_from_journal"])
            return {**res, "action": "quarantined"}
        problems = validate_issued(lab, {"serial": serial, "cert_sha256": info["cert_sha256"],
                                         "generation": lab.ca_state()["generation"]}, apr)
        if problems:
            res = _quarantine(lab, req_id, op_id, serial, problems)
            return {**res, "action": "quarantined"}
        _record_issued(lab, req_id, apr, info, op_id)
        lab.audit("recover", "ok", req_id, action="adopted_signed_certificate", serial=serial)
        out = _publish(lab, req_id)
    return {**out, "action": "adopted_signed_certificate"}


# =============================================================================
# 失効・CRL
# =============================================================================

def _gen_crl(lab: Lab, which: str) -> Path:
    cnf = ROOT_CNF if which == "root" else ISSUER_CNF
    pw = lab.root_pass if which == "root" else lab.issuer_pass
    ca_cert = lab.root_cert if which == "root" else lab.issuer_cert
    name = "root.crl.pem" if which == "root" else "intermediate.crl.pem"
    out = lab.p(which, "crl", name)
    tmp = lab.p(which, "crl", f".{name}.new")
    lab.openssl("ca", "-config", cnf, "-gencrl", "-passin", f"file:{pw}", "-out", tmp)
    if tmp.stat().st_size > MAX_CRL_BYTES:
        tmp.unlink()
        raise LabError("CRL_TOO_LARGE", "CRL が上限を超えています")
    meta = crl_meta(lab, tmp, ca_cert)
    if not meta.get("sig_ok"):
        tmp.unlink()
        raise LabError("CRL_SIGNATURE_FAILED", "生成した CRL の署名を検証できません")
    data = tmp.read_bytes()
    tmp.unlink()
    atomic_write(out, data)
    atomic_write(lab.p("public", "crl", name), data)
    # 公開した CRL の番号とハッシュを記録（照合でロールバックや差し替えを検出する）
    write_json(lab.p(which, "db", "crl_published.json"),
               {"number": meta["number"], "sha256": meta["sha256"], "next_update": meta["next_update"]})
    lab.audit(f"crl-{which}", "ok", name, crl_number=meta["number"], next_update=meta["next_update"],
              crl_sha256=meta["sha256"], revoked=len(meta["revoked"]))
    return out


def cmd_crl_root(lab: Lab, args) -> dict:
    lab.require("crl-root")
    with lab.ca_lock("root"):
        return {"crl": str(_gen_crl(lab, "root"))}


def cmd_crl_issuer(lab: Lab, args) -> dict:
    lab.require("crl-issuer")
    with lab.ca_lock("issuer"):
        if lab.ca_state()["status"] in ("REVOKED", "RETIRED"):
            raise LabError("CA_NOT_ACTIVE", "失効・廃止した中間CAで CRL は作りません")
        return {"crl": str(_gen_crl(lab, "issuer"))}


REASONS = {"unspecified", "keyCompromise", "CACompromise", "affiliationChanged",
           "superseded", "cessationOfOperation", "certificateHold"}


def _revoke_in(lab: Lab, cnf: Path, pem: Path, reason: str, pw: Path) -> None:
    cp = lab.openssl("ca", "-config", cnf, "-revoke", pem, "-crl_reason", reason, "-passin", f"file:{pw}",
                     check=False)
    if cp.returncode != 0 and b"Already revoked" not in cp.stderr + cp.stdout:
        raise LabError("REVOKE_FAILED", cp.stderr.decode(errors="replace").strip())


def cmd_revoke(lab: Lab, args) -> dict:
    """サーバー証明書の失効。失効したら直ちに CRL を再発行・配布する。"""
    lab.require("revoke")
    if args.reason not in REASONS:
        raise LabError("BAD_REASON", f"失効理由は {sorted(REASONS)} のいずれか")
    serial = resolve_serial(lab, args.target)
    with lab.ca_lock("issuer"):
        pem = lab.p("issuer", "newcerts", f"{serial}.pem")
        if not pem.exists():
            raise LabError("UNKNOWN_SERIAL", f"現在の中間CAが発行した証明書ではありません: {serial}")
        _revoke_in(lab, ISSUER_CNF, pem, args.reason, lab.issuer_pass)
        lab.audit("revoke", "ok", serial, reason=args.reason, incident=args.incident or "")
        crl = _gen_crl(lab, "issuer")
    return {"revoked": serial, "reason": args.reason, "crl": str(crl)}


def cmd_revoke_intermediate(lab: Lab, args) -> dict:
    """中間CAの失効。ルート CRL に載せ、中間CAの運用状態を REVOKED にして発行を止める。"""
    lab.require("revoke-intermediate")
    with lab.ca_lock("issuer"), lab.ca_lock("root"):
        info = cert_info(lab, lab.issuer_cert)
        pem = lab.p("root", "newcerts", f"{info['serial']}.pem")
        _revoke_in(lab, ROOT_CNF, pem, args.reason, lab.root_pass)
        lab.set_ca_state("REVOKED", args.reason)
        lab.audit("revoke-intermediate", "ok", info["serial"], reason=args.reason)
        crl = _gen_crl(lab, "root")
    return {"revoked": info["serial"], "ca_state": "REVOKED", "crl": str(crl)}


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
    atomic_write(out / "root.cert.pem", lab.p("public", "certs", "root.cert.pem").read_bytes())
    atomic_write(out / "intermediate.cert.pem", lab.p("public", "certs", "intermediate.cert.pem").read_bytes())
    atomic_write(out / "crls.pem", collect_crls(lab))
    if args.request:
        atomic_write(out / "server.cert.pem", lab.p(lab.state(args.request)["cert"]).read_bytes())
    lab.audit("bundle", "ok", str(out))
    return {"bundle": str(out)}


def collect_crls(lab: Lab) -> bytes:
    # 注意：ここでは public/ を直接読む。HTTP 配布（serve-public）経由の取得・伝播は検証していない。
    return b"".join(lab.p("public", "crl", n).read_bytes() for n in ("root.crl.pem", "intermediate.crl.pem")
                    if lab.p("public", "crl", n).exists())


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
    """証明書ファイルの検証（docs/03_detailed-design.md 8章）。"""
    lab.require("verify")
    cert = Path(args.cert) if args.cert else lab.p(lab.state(args.request)["cert"])
    trust = Path(args.trust) if args.trust else lab.p("public", "certs", "root.cert.pem")
    inter = Path(args.untrusted) if args.untrusted else lab.p("public", "certs", "intermediate.cert.pem")
    host = args.host
    info = cert_info(lab, cert)
    base = {"serial": info.get("serial"), "san": info["san"], "crl_check": not args.no_crl}

    def done(verdict: str, code: str, **extra) -> dict:
        lab.audit("verify", verdict.lower(), info.get("serial", ""), code=code, host=host or "",
                  purpose=args.purpose, crl_check=not args.no_crl, attime=args.attime or "")
        return {"result": verdict, "code": code, **base, **extra}

    # 名前は型付きで照合する。DNS 接続には dNSName、IP 接続には iPAddress の完全一致が必要。
    # （openssl verify -verify_hostname は該当する型の SAN が無いと CN を見に行くため、
    #   CN フォールバックを許さないよう、ここで先に判定する）
    if not info["san"]:
        return done("REJECT", "SAN_REQUIRED")
    if host:
        want = host_identity(host)
        if want not in info["san"]:
            kind = want.split(":")[0]
            has_kind = any(s.startswith(kind + ":") for s in info["san"])
            return done("REJECT", "SAN_MISMATCH", expected=want,
                        detail="一致する SAN がありません" if has_kind else f"{kind} 型の SAN がありません（CN は見ません）")

    cmd = ["verify", "-show_chain", "-x509_strict", "-auth_level", "2", "-verify_depth", "1",
           "-purpose", args.purpose, "-trusted", trust, "-untrusted", inter]
    if host:
        cmd += ["-verify_ip", host] if host_identity(host).startswith("IP:") else ["-verify_hostname", host]
    if not args.no_crl:
        crl_file = Path(args.crl) if args.crl else lab.p("verifier", "cache", "crls.pem")
        if not args.crl:
            atomic_write(crl_file, collect_crls(lab))
        if crl_file.exists() and crl_file.stat().st_size > 0:
            cmd += ["-CRLfile", crl_file]
        cmd += ["-crl_check", "-crl_check_all"]
    if args.attime:
        cmd += ["-attime", str(int(parse_iso(args.attime).timestamp()))]
    cmd.append(cert)
    cp = lab.openssl(*cmd, check=False)
    out = (cp.stdout + cp.stderr).decode(errors="replace")
    summary = [ln for ln in out.splitlines() if ln.startswith("error ") or ln.endswith(": OK")]
    if cp.returncode == 0:
        return done("ACCEPT", "OK", openssl=summary[0] if summary else "")
    m = re.search(r"error (\d+) at (\d+) depth", out)
    code = classify_verify(int(m.group(1)), int(m.group(2))) if m else "VERIFY_ERROR"
    # 「失効している」と「失効状態を確認できない」は別の結果として記録し、
    # どちらの場合もラボ方針として接続は許可しない。
    verdict = "INDETERMINATE" if code in INDETERMINATE else "REJECT"
    return done(verdict, code, openssl=summary[0] if summary else "")


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
    key = Path(st["server_key"])
    ctx.load_cert_chain(lab.p(st["fullchain"]), key if key.is_absolute() else lab.p(st["server_key"]))
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
    """実TLS接続用の厳格な設定（docs/03_detailed-design.md 9章）。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # CERT_REQUIRED + check_hostname が既定
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(cafile=str(trust))
    ctx.hostname_checks_common_name = False  # CN へのフォールバック禁止
    flags = ssl.VERIFY_X509_STRICT
    if crl is not None:
        ctx.load_verify_locations(cafile=str(crl))
        flags |= ssl.VERIFY_CRL_CHECK_CHAIN  # 葉だけでなくチェーン全体を確認
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
        # Python の例外は、どの深さの証明書が失効したかを返さない。
        # 同じハンドシェイクで確定できない情報は REVOKED（部位不明）として返す。
        code = "REVOKED" if e.verify_code == 23 else classify_verify(e.verify_code, 0)
        verdict = "INDETERMINATE" if code in INDETERMINATE else "REJECT"
        return {"result": verdict, "code": code, "detail": e.verify_message}


def unverified_leaf_serial(lab: Lab, host: str, port: int, connect_host: str = "127.0.0.1") -> str:
    """診断用：検証なしの別接続で葉のシリアルを読む（データの送受信はしない）。"""
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
        atomic_write(crl, collect_crls(lab))
    res = tls_probe(trust, crl, args.host, args.port)
    if res["code"] == "REVOKED":
        # 参考情報：別の未検証接続と現在の CRL から推定した部位（同じ接続の観測ではない）
        try:
            serial = unverified_leaf_serial(lab, args.host, args.port)
            leaf = serial in crl_meta(lab, lab.p("public", "crl", "intermediate.crl.pem"), lab.issuer_cert).get("revoked", set())
            res["diagnostic"] = {"probable": "LEAF_REVOKED" if leaf else "INTERMEDIATE_REVOKED",
                                 "method": "separate_unverified_connection", "verified": False,
                                 "observed_at": iso(utcnow())}
        except (OSError, LabError) as e:
            res["diagnostic"] = {"probable": "UNKNOWN", "error": str(e), "verified": False}
    lab.audit("tls-connect", res["result"].lower(), f"{args.host}:{args.port}",
              code=res["code"], crl_check=not args.no_crl)
    return res


# =============================================================================
# 監査・照合
# =============================================================================

def cmd_audit_verify(lab: Lab, args) -> dict:
    """読み取りのみ。監査ログにも基準ハッシュにも書き込まない。"""
    lab.require("audit-verify")
    res = verify_audit_chain(lab.home)
    if lab.is_frozen():
        res["frozen"] = read_json(lab.frozen_marker)
    if not res["ok"]:
        raise LabError(res["code"], "監査ログの検証に失敗しました", audit=res)
    return res


def cmd_audit_reanchor(lab: Lab, args) -> dict:
    """管理された再アンカー。内部の連鎖が正しいログについて、失われた履歴を受け入れる判断を
    明示的に記録してから基準ハッシュを付け替える。連鎖自体が壊れたログは restore で戻す。"""
    lab.require("audit-reanchor")
    with lab.audit_lock():
        res = verify_audit_chain(lab.home)
        if res["ok"] and not lab.is_frozen():
            return {"action": "none", "audit": res}
        if not res.get("internal_ok"):
            raise LabError("AUDIT_TAMPERED", "連鎖が壊れたログは再アンカーできません。restore で復旧してください", audit=res)
        if args.confirm_head != res["head"]:
            raise LabError("CONFIRMATION_REQUIRED", "--confirm-head に現在のログ先頭ハッシュを指定してください",
                           head=res["head"], entries=res.get("entries", res.get("log_seq")))
        if not args.reason:
            raise LabError("REASON_REQUIRED", "--reason を指定してください")
        seq = res.get("entries", res.get("log_seq", 0))
        lab.incident("AUDIT_REANCHOR", reason=args.reason, previous=res, new_seq=seq, new_head=res["head"])
        write_json(lab.p("anchor", "anchor.json"), {"seq": seq, "hash": res["head"]})
        lab.frozen_marker.unlink(missing_ok=True)
    lab.audit("audit-reanchor", "ok", "", reason=args.reason, previous_code=res.get("code", "FROZEN"))
    return {"action": "reanchored", "seq": seq, "head": res["head"]}


def _check_ca(lab: Lab, base: Path, ca_cert: Path, label: str, problems: list[str],
              expect_issuer: str | None) -> dict[str, dict]:
    """台帳の各行について、発行物を解析し、シリアル・発行者・ファイルを照合する。"""
    rows = {r["serial"]: r for r in read_index(base)}
    certs = {}
    for serial in rows:
        pem = base / "newcerts" / f"{serial}.pem"
        if not pem.exists():
            problems.append(f"[{label}] 台帳にあるが発行物がない: {serial}")
            continue
        try:
            info = cert_info(lab, pem)
        except LabError:
            problems.append(f"[{label}] 発行物を証明書として解析できない: {serial}")
            continue
        if info["serial"] != serial:
            problems.append(f"[{label}] 発行物のシリアルが台帳と違う: {serial}")
        if expect_issuer and info["issuer"] != expect_issuer:
            problems.append(f"[{label}] 発行者が違う: {serial}")
        certs[serial] = info
    for pem in (base / "newcerts").glob("*.pem"):
        if pem.stem.upper() not in rows:
            problems.append(f"[{label}] 発行物があるが台帳にない: {pem.stem}")
    return {s: {"row": rows[s], "info": certs.get(s)} for s in rows}


def _check_crl(lab: Lab, which: str, ca_cert: Path, ledger: dict, problems: list[str], now: dt.datetime) -> None:
    name = "root.crl.pem" if which == "root" else "intermediate.crl.pem"
    meta = crl_meta(lab, lab.p("public", "crl", name), ca_cert)
    if not meta["present"]:
        problems.append(f"公開 CRL がない: {name}")
        return
    if not meta.get("sig_ok"):
        problems.append(f"CRL の署名を {which} CA で検証できない: {name}")
        return
    if meta["issuer"] != cert_info(lab, ca_cert)["subject"]:
        problems.append(f"CRL の発行者が違う: {name}")
    if parse_iso(meta["next_update"]) < now:
        problems.append(f"CRL の次回更新期限切れ: {name}")
    rec_path = lab.p(which, "db", "crl_published.json")
    if rec_path.exists():
        rec = read_json(rec_path)
        if meta["number"] < rec["number"]:
            problems.append(f"CRL 番号が後退している（ロールバックの疑い）: {name}")
        elif meta["sha256"] != rec["sha256"]:
            problems.append(f"公開 CRL が最後に生成したものと違う: {name}")
    revoked = {s for s, v in ledger.items() if v["row"]["status"] == "R"}
    if revoked - meta["revoked"]:
        problems.append(f"公開 CRL に未反映の失効: {sorted(revoked - meta['revoked'])}")
    if meta["revoked"] - revoked:
        problems.append(f"台帳にない失効が CRL にある: {sorted(meta['revoked'] - revoked)}")


def run_check(lab: Lab) -> dict:
    """承認 ⇔ 申請 ⇔ 台帳 ⇔ 発行物（中身） ⇔ 配置物 ⇔ 公開 CRL ⇔ 監査ログ を照合する。"""
    problems: list[str] = []
    now = utcnow()
    for label, path in [("ルート証明書", lab.root_cert), ("中間CA証明書", lab.issuer_cert),
                        ("ルート台帳", lab.p("root", "db", "index.txt")),
                        ("中間CA台帳", lab.p("issuer", "db", "index.txt"))]:
        if not path.exists():
            problems.append(f"必須ファイルがない: {label}")
    if problems:
        return {"ok": False, "problems": problems}

    root_subject = cert_info(lab, lab.root_cert)["subject"]
    issuer_info = cert_info(lab, lab.issuer_cert)
    root_ledger = _check_ca(lab, lab.p("root"), lab.root_cert, "root", problems, root_subject)
    if issuer_info["serial"] not in root_ledger:
        problems.append("中間CA証明書がルートの台帳にない")
    elif (root_ledger[issuer_info["serial"]]["info"] or {}).get("cert_sha256") != issuer_info["cert_sha256"]:
        problems.append("中間CA証明書がルートの発行物と一致しない")
    _check_crl(lab, "root", lab.root_cert, root_ledger, problems, now)

    ca = lab.ca_state()
    if ca.get("pending_revocation"):
        problems.append(f"未完了の失効がある: {ca['pending_revocation']}")
    if ca["status"] == "ACTIVE" and issuer_info["serial"] in {s for s, v in root_ledger.items() if v["row"]["status"] == "R"}:
        problems.append("ルートで失効した中間CAが ACTIVE のまま")

    ledgers = {ca["generation"]: _check_ca(lab, lab.p("issuer"), lab.issuer_cert, "issuer",
                                           problems, issuer_info["subject"])}
    if ca["status"] not in ("REVOKED", "RETIRED"):
        _check_crl(lab, "issuer", lab.issuer_cert, ledgers[ca["generation"]], problems, now)

    claimed: dict[tuple[int, str], str] = {}
    for d in sorted(lab.p("requests").glob("REQ-*")):
        st = read_json(d / "state.json")
        rid = st["id"]
        if st["status"] in ("SIGNING", "NEEDS_RECOVERY"):
            problems.append(f"復旧が必要な申請: {rid}")
        if st["status"] not in ("ISSUED", "PUBLISHED"):
            continue
        apr_path = lab.p("approvals", f"{rid}.json")
        cert_json = d / "cert.json"
        if not apr_path.exists() or not cert_json.exists():
            problems.append(f"承認記録または発行記録のない発行: {rid}")
            continue
        rec, apr = read_json(cert_json), read_json(apr_path)
        gen = rec.get("generation", ca["generation"])
        if gen not in ledgers:
            base = lab.issuer_base(gen)
            if not (base / "db" / "index.txt").exists():
                problems.append(f"世代 {gen} の台帳がない: {rid}")
                continue
            ledgers[gen] = _check_ca(lab, base, base / "certs" / "intermediate.cert.pem", f"issuer-gen{gen}",
                                     problems, None)
        entry = ledgers[gen].get(rec["serial"])
        if entry is None:
            problems.append(f"申請の証明書が台帳にない: {rid}")
            continue
        claimed[(gen, rec["serial"])] = rid
        info = entry["info"]
        if info is None:
            continue  # 解析できない旨は台帳側で報告済み
        if info["cert_sha256"] != rec["cert_sha256"]:
            problems.append(f"発行物が発行記録と一致しない: {rid}")
        if info["san"] != sorted(apr["san"]) or info["pubkey_sha256"] != apr["pubkey_sha256"]:
            problems.append(f"発行物が承認内容（SAN・公開鍵）と一致しない: {rid}")
        if info["eku"] != ["serverAuth"] or info["ca"] is not False:
            problems.append(f"発行物がプロファイル（用途・CA:FALSE）と一致しない: {rid}")
        if st["status"] == "PUBLISHED":
            leaf = lab.p(st["cert"])
            try:
                if cert_info(lab, leaf)["cert_sha256"] != rec["cert_sha256"]:
                    problems.append(f"配置された証明書が発行記録と違う: {rid}")
            except LabError:
                problems.append(f"配置された証明書がない、または解析できない: {rid}")
    for gen, ledger in ledgers.items():
        for serial, v in ledger.items():
            if (gen, serial) not in claimed and v["row"]["status"] == "V":
                problems.append(f"申請に紐づかない有効な証明書: gen{gen} {serial}")

    audit = verify_audit_chain(lab.home)
    if not audit["ok"]:
        problems.append(f"監査ログ: {audit['code']}")
    if lab.is_frozen():
        problems.append("監査ログの異常により凍結中")
    return {"ok": not problems, "problems": problems, "ca_state": ca["status"], "generation": ca["generation"]}


def cmd_check(lab: Lab, args) -> dict:
    lab.require("check")
    res = run_check(lab)
    # 監査ログが正常なときだけ結果を追記する（異常時は障害ログへ。基準ハッシュは動かさない）
    lab.audit_if_possible("check", "ok" if res["ok"] else "problems", "", count=len(res["problems"]))
    return res


# =============================================================================
# バックアップ・復旧
# =============================================================================

# server/certs は公開情報（配置済みの証明書）なので含める。server/private と secrets/ は含めない。
BACKUP_ITEMS = ["root", "issuer", "archive", "requests", "approvals", "journal", "audit", "anchor",
                "incidents", "public", "server/certs"]


def _mac_key(pass_file: Path, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", pass_file.read_bytes().strip(), b"pkilab-backup-mac" + salt, KDF_ITER)


def cmd_backup(lab: Lab, args) -> dict:
    """CA 一式（鍵は暗号化済みのまま・台帳・発行物・失効・CRL番号・承認・監査）を暗号化し、
    改ざん検出用の HMAC（暗号化後のデータに対して）を付けて保存する。
    パスフレーズ（secrets/）とサーバー鍵は含めない（別経路で保管する前提）。"""
    lab.require("backup")
    pass_file = Path(args.pass_file) if args.pass_file else lab.p("secrets", "backup.pass")
    ensure_passphrase(pass_file)
    with lab.ca_lock("issuer"), lab.ca_lock("root"), lab.audit_lock():
        stamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
        tail = audit_tail(lab.home)
        fd, tmp_name = tempfile.mkstemp(suffix=".tar.gz", dir=lab.p("backups"))
        os.close(fd)
        tmp_tar = Path(tmp_name)
        try:
            with tarfile.open(tmp_tar, "w:gz") as tar:
                for item in BACKUP_ITEMS:
                    if lab.p(item).exists():
                        tar.add(lab.p(item), arcname=item,
                                filter=lambda ti: None if ti.name.endswith((".lock", "ca.lock")) else ti)
            out = lab.p("backups", f"pkilab-{stamp}.tar.gz.enc")
            lab.openssl("enc", "-aes-256-cbc", "-pbkdf2", "-iter", KDF_ITER, "-salt",
                        "-in", tmp_tar, "-out", out, "-pass", f"file:{pass_file}")
        finally:
            tmp_tar.unlink(missing_ok=True)
        salt = secrets.token_bytes(16)
        blob = out.read_bytes()
        manifest = {"file": out.name, "sha256": sha256_bytes(blob), "hmac_salt": salt.hex(), "kdf_iter": KDF_ITER,
                    "hmac": hmac.new(_mac_key(pass_file, salt), blob, hashlib.sha256).hexdigest(),
                    "created": iso(utcnow()), "audit_seq": tail.get("seq"), "audit_head": tail.get("hash"),
                    "excluded": ["secrets/", "server/private/", "lab/config/（リポジトリで管理）"]}
        write_json(out.with_name(out.name + ".manifest.json"), manifest)
    lab.audit("backup", "ok", out.name, sha256=manifest["sha256"], audit_seq=manifest["audit_seq"])
    return {"backup": str(out), "manifest": str(out.with_name(out.name + ".manifest.json")),
            "sha256": manifest["sha256"]}


# 証明書・CRL・台帳の状態を変えない操作（バックアップ後に記録されても巻き戻りにならない）
READONLY_OPS = {"verify", "tls-connect", "check", "restore", "backup", "bundle", "export-events", "serve-https"}


def check_freshness(lab: Lab, dest: Path, checkpoint: Path | None) -> dict:
    """復元したログが、最新のチェックポイントまでの状態変更をすべて含むかを確認する。"""
    restored = _audit_lines(dest)
    head = json.loads(restored[-1])["hash"] if restored else "0" * 64
    cp_path = checkpoint or lab.p("anchor", "anchor.json")
    if not cp_path.exists():
        return {"freshness_confirmed": False, "freshness_detail": "比較するチェックポイントがありません（--checkpoint）"}
    cp = read_json(cp_path)
    if 0 < cp["seq"] <= len(restored):
        ok = json.loads(restored[cp["seq"] - 1]).get("hash") == cp["hash"]
        return {"freshness_confirmed": ok,
                **({} if ok else {"freshness_detail": "チェックポイントと復元したログが分岐しています"})}
    # チェックポイントの方が新しい：元のログが読めれば、差分が読み取り専用の操作だけか確かめる
    live = _audit_lines(lab.home) if checkpoint is None else []
    if live and len(live) >= cp["seq"] and len(restored) > 0 and \
            json.loads(live[len(restored) - 1]).get("hash") == head:
        later = [json.loads(x) for x in live[len(restored):cp["seq"]]]
        changing = [f"{e['seq']}:{e['op']}" for e in later if e["op"] not in READONLY_OPS]
        if not changing:
            return {"freshness_confirmed": True,
                    "freshness_detail": f"バックアップ後の {len(later)} 件は読み取り専用の操作のみ"}
        return {"freshness_confirmed": False, "lost_changes": changing,
                "freshness_detail": "バックアップ後の状態変更（失効など）が含まれていません。復元すると巻き戻ります"}
    return {"freshness_confirmed": False,
            "freshness_detail": f"チェックポイント seq={cp['seq']} がバックアップ（最終 seq={len(restored)}）に含まれていません"}


def _key_access(lab: Lab, key: Path, pass_file: Path | None) -> bool:
    if not key.exists() or not pass_file or not pass_file.exists():
        return False
    return lab.openssl("pkey", "-in", key, "-passin", f"file:{pass_file}", "-noout", check=False).returncode == 0


def cmd_restore(lab: Lab, args) -> dict:
    """空の隔離ディレクトリへ復元し、準備状況を項目ごとに判定する。
    復元先は「復旧保留」状態になり、resume で再開を承認するまで署名・CRL 公開をしない。"""
    lab.require("restore")
    dest = Path(args.dest).resolve()
    if dest.exists() and any(dest.iterdir()):
        raise LabError("DEST_NOT_EMPTY", "復旧先は空の隔離ディレクトリにしてください")
    backup = Path(args.backup)
    pass_file = Path(args.pass_file) if args.pass_file else lab.p("secrets", "backup.pass")
    report: dict = {"restored_to": str(dest), "archive_integrity_ok": False, "state_consistent": False,
                    "freshness_confirmed": False, "key_access_ready": False, "resume_authorized": False}

    # 1. 暗号化後のデータの HMAC を、復号する前に検証する
    man_path = backup.with_name(backup.name + ".manifest.json")
    if man_path.exists() and pass_file.exists():
        man = read_json(man_path)
        blob = backup.read_bytes()
        mac = hmac.new(_mac_key(pass_file, bytes.fromhex(man["hmac_salt"])), blob, hashlib.sha256).hexdigest()
        report["archive_integrity_ok"] = hmac.compare_digest(mac, man["hmac"])
    if not report["archive_integrity_ok"]:
        report["reason"] = "バックアップの改ざん検出用 HMAC を確認できません（マニフェスト欠落・パスフレーズ違い・改ざん）"
        lab.audit_if_possible("restore", "rejected", str(dest), reason="integrity")
        report["ready"] = False
        return report

    dest.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(suffix=".tar.gz", dir=dest)
    os.close(fd)
    tmp_tar = Path(tmp_name)
    try:
        lab.openssl("enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", man["kdf_iter"],
                    "-in", backup, "-out", tmp_tar, "-pass", f"file:{pass_file}")
        with tarfile.open(tmp_tar) as tar:
            for m in tar.getmembers():  # パス逸脱・リンクを拒否
                if m.name.startswith("/") or ".." in Path(m.name).parts or m.issym() or m.islnk():
                    raise LabError("BACKUP_UNSAFE", f"不正なパスを含むバックアップです: {m.name}")
            tar.extractall(dest, **({"filter": "data"} if hasattr(tarfile, "data_filter") else {}))
    finally:
        tmp_tar.unlink(missing_ok=True)

    restored = Lab(dest, lab.actor, "auditor")
    restored.layout()
    # 2. 状態の整合（監査ログ連鎖・台帳・発行物・CRL の照合。復元先には書き込まない）
    chk = run_check(restored)
    report["check"] = chk
    report["state_consistent"] = chk["ok"]

    # 3. 新しさ：別に保管した最新のチェックポイントと比べ、バックアップ後の状態変更が失われないか
    report.update(check_freshness(lab, dest, Path(args.checkpoint) if args.checkpoint else None))

    # 4. 別保管のパスフレーズで CA 鍵を開けるか
    root_pass = Path(args.root_pass_file) if args.root_pass_file else lab.root_pass
    issuer_pass = Path(args.issuer_pass_file) if args.issuer_pass_file else lab.issuer_pass
    report["key_access_ready"] = (_key_access(lab, restored.root_key, root_pass)
                                  and _key_access(lab, restored.issuer_key, issuer_pass))

    # 5. 再開は人が承認するまで保留（resume）
    write_json(restored.hold_marker, {"since": iso(utcnow()), "from": backup.name,
                                      **{k: report[k] for k in ("archive_integrity_ok", "state_consistent",
                                                                 "freshness_confirmed", "key_access_ready")}})
    report["ready"] = all(report[k] for k in ("archive_integrity_ok", "state_consistent",
                                              "freshness_confirmed", "key_access_ready"))
    lab.audit_if_possible("restore", "ready" if report["ready"] else "needs_review", str(dest),
                          **{k: report[k] for k in ("archive_integrity_ok", "state_consistent",
                                                     "freshness_confirmed", "key_access_ready")})
    return report


def cmd_resume(lab: Lab, args) -> dict:
    """復旧保留を解除する。照合・鍵の確認をやり直し、--confirm があるときだけ再開する。"""
    lab.require("resume")
    if not lab.on_hold():
        return {"action": "none", "reason": "復旧保留ではありません"}
    hold = read_json(lab.hold_marker)
    for src, dst in ((args.root_pass_file, lab.p("secrets", "root.pass")),
                     (args.issuer_pass_file, lab.p("secrets", "issuer.pass"))):
        if src:
            write_private(dst, Path(src).read_bytes())  # 別経路で保管していた鍵解除情報を戻す
    chk = run_check(lab)
    keys = _key_access(lab, lab.root_key, lab.root_pass) and _key_access(lab, lab.issuer_key, lab.issuer_pass)
    blockers = []
    if not chk["ok"]:
        blockers.append("state_consistent")
    if not keys:
        blockers.append("key_access_ready")
    if not hold.get("freshness_confirmed") and not args.accept_stale:
        blockers.append("freshness_confirmed（--accept-stale で失われた履歴を受け入れる判断を明示）")
    if blockers or not args.confirm:
        return {"action": "held", "blockers": blockers, "confirm_required": not args.confirm, "check": chk}
    lab.hold_marker.unlink()
    lab.audit("resume", "ok", "", accepted_stale=bool(args.accept_stale))
    return {"action": "resumed"}


# =============================================================================
# 3D 教材向けイベント出力（観測できた粒度のまま・秘密情報なし）
# =============================================================================

EVENT_MAP = {
    ("init-root", "ok"): "ROOT_CREATED",
    ("sign-intermediate", "ok"): "INTERMEDIATE_DELEGATED",
    ("request", "ok"): "CSR_CREATED",
    ("validate", "ok"): "CSR_SIGNATURE_CHECKED",
    ("approve", "ok"): "REQUEST_AUTHORIZED",
    ("approve", "rejected"): "REQUEST_REJECTED",
    ("issue", "ok"): "CERT_ISSUED",
    ("publish", "ok"): "CERT_DEPLOYED",
    ("quarantine", "ok"): "CERT_QUARANTINED",
    ("revoke", "ok"): "CERT_REVOKED",
    ("revoke-intermediate", "ok"): "INTERMEDIATE_REVOKED",
    ("crl-issuer", "ok"): "CRL_PUBLISHED",
    ("crl-root", "ok"): "CRL_PUBLISHED",
}
SAFE_DETAIL_KEYS = {"code", "san", "reason", "host", "purpose", "crl_check", "not_after",
                    "next_update", "crl_number", "action", "revoked"}


def cmd_export_events(lab: Lab, args) -> dict:
    lab.require("export-events")
    res = verify_audit_chain(lab.home)
    if not res["ok"]:
        raise LabError(res["code"], "監査ログを検証できないため出力しません", audit=res)
    events = []
    for line in _audit_lines(lab.home):
        e = json.loads(line)
        details = {k: v for k, v in e["details"].items() if k in SAFE_DETAIL_KEYS}
        t = EVENT_MAP.get((e["op"], e["result"]))
        observation = "operation"
        if e["op"] == "verify":
            # 検証は1回の処理として記録しているので、まとめた結果だけを出す。
            # 段階（経路・名前・失効…）は個別に計測していない：stages = not_observed
            t = "CERT_VERIFICATION_COMPLETED"
            observation = "aggregate"
            details["revocation"] = "checked" if e["details"].get("crl_check") else "skipped"
            details["stages"] = "not_observed"
        elif e["op"] == "tls-connect":
            t = "TLS_HANDSHAKE_COMPLETED" if e["result"] == "accept" else "TLS_HANDSHAKE_FAILED"
            observation = "aggregate"
            details["revocation"] = "checked" if e["details"].get("crl_check") else "skipped"
        if not t:
            continue
        events.append({"seq": e["seq"], "ts": e["ts"], "type": t, "role": e["role"],
                       "origin": "measured", "observation": observation,
                       # シリアル等はそのまま出さず短いハッシュにする
                       "target": sha256_bytes(e["target"].encode())[:12] if e["target"] else "",
                       "result": e["result"], "details": details})
    doc = {"schema": "pkilab-events/2", "measured": True,
           "note": "PKI Lab の監査ログ（ハッシュ連鎖を検証済み）から生成。秘密鍵・パスフレーズ・証明書本体は含まない。"
                   "検証・TLS は処理全体の結果のみで、内部の段階は観測していない。",
           "audit_head": res["head"], "generated": iso(utcnow()), "events": events}
    blob = json.dumps(doc, ensure_ascii=False, indent=2) + "\n"
    if "PRIVATE KEY" in blob or "-----BEGIN" in blob:
        raise LabError("EXPORT_LEAK", "出力に秘密情報らしき文字列が含まれていたため出力しません")
    out = Path(args.out) if args.out else lab.p("exports", "events.json")
    atomic_write(out, blob)
    lab.audit("export-events", "ok", out.name, count=len(events))
    return {"events": str(out), "count": len(events)}


def cmd_status(lab: Lab, args) -> dict:
    lab.require("status")
    out = {"home": str(lab.home), "frozen": lab.is_frozen(), "recovery_hold": lab.on_hold(),
           "ca": lab.ca_state() if lab.p("issuer").exists() else None, "requests": []}
    if lab.issuer_cert.exists():
        out["intermediate_not_after"] = cert_info(lab, lab.issuer_cert)["not_after"]
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
    "audit-verify": (cmd_audit_verify, "auditor"), "audit-reanchor": (cmd_audit_reanchor, "auditor"),
    "check": (cmd_check, "auditor"), "export-events": (cmd_export_events, "auditor"),
    "backup": (cmd_backup, "operator"), "restore": (cmd_restore, "operator"), "resume": (cmd_resume, "operator"),
    "status": (cmd_status, "operator"),
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
        if name == "init-issuer":
            sp.add_argument("--new-generation", action="store_true",
                            help="失効・廃止した中間CAを保管し、新しい鍵で次の世代を作る")
        if name == "request":
            sp.add_argument("--san", action="append", help="例: DNS:localhost（複数可）")
            sp.add_argument("--csr", help="既存の CSR を申請する")
            sp.add_argument("--key", help="既存のサーバー鍵で CSR を作る")
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
        if name == "audit-reanchor":
            sp.add_argument("--confirm-head", default="")
            sp.add_argument("--reason", default="")
        if name in ("backup", "restore"):
            sp.add_argument("--pass-file")
        if name == "restore":
            sp.add_argument("backup")
            sp.add_argument("dest")
            sp.add_argument("--checkpoint", help="別に保管した最新の anchor.json（既定: 元の作業領域の anchor）")
        if name in ("restore", "resume"):
            sp.add_argument("--root-pass-file")
            sp.add_argument("--issuer-pass-file")
        if name == "resume":
            sp.add_argument("--confirm", action="store_true")
            sp.add_argument("--accept-stale", action="store_true")
    return ap


def run(lab: Lab, cmd: str, args) -> dict:
    fn, _ = COMMANDS[cmd]
    if cmd not in NO_AUDIT_PRECHECK:
        lab.ensure_audit_ok()
    if cmd in HOLD_BLOCKED and lab.on_hold():
        raise LabError("RECOVERY_HOLD", "復旧保留中です。照合と鍵の準備を確認し、resume --confirm で再開してください")
    return fn(lab, args)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    _, default_role = COMMANDS[args.cmd]
    lab = Lab(Path(args.home), args.actor, args.role or default_role or "operator")
    try:
        result = run(lab, args.cmd, args)
    except LabError as e:
        print(json.dumps({"error": e.code, "message": e.message, **e.extra}, ensure_ascii=False, indent=2,
                         default=str))
        return 2
    except Exception as e:  # noqa: BLE001  環境エラーも結果 JSON で返す
        print(json.dumps({"error": "ENV_ERROR", "type": type(e).__name__, "message": str(e)},
                         ensure_ascii=False, indent=2))
        return 3
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    if isinstance(result, dict):
        if result.get("result") in ("REJECT", "INDETERMINATE") or result.get("ok") is False:
            return 1
        if result.get("ready") is False or result.get("action") == "held":
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
