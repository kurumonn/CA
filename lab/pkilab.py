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
import base64
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
# 状態を変える操作。復旧保留中・置き換え済み（superseded）・世代交代の途中は止める
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
    # PKILAB_TEST_NOW は試験専用の時刻差し替え（OS の時計は変えない）。運用では設定しない。
    fake = os.environ.get("PKILAB_TEST_NOW")
    if fake:
        return dt.datetime.strptime(fake, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
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


def _fault(name: str) -> None:
    """I/O 障害の注入（試験用）。PKILAB_FAULT=<name> の箇所で容量不足の OSError を起こす。"""
    if os.environ.get("PKILAB_FAULT") == name:
        raise OSError(errno.ENOSPC, f"試験用の I/O 障害: {name}")


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
            "locks", "requests", "approvals", "journal", "audit", "anchor", "incidents",
            "server/private", "server/certs", "public/certs", "public/crl",
            "verifier/trust", "verifier/cache", "exports", "secrets", "backups", "archive",
        ]
        for d in dirs:
            self.p(d).mkdir(parents=True, exist_ok=True)
        for d in ["root/private", "issuer/private", "server/private", "secrets"]:
            os.chmod(self.p(d), 0o700)
        self.instance_id(create=True)

    # --- 権限 ---------------------------------------------------------------
    def require(self, op: str) -> None:
        if op not in ROLE_OPS.get(self.role, set()):
            raise LabError("ROLE_DENIED", f"役割 '{self.role}' は操作 '{op}' を実行できません"
                                          f"（--role {role_for(op)} で実行してください）")

    # --- OpenSSL --------------------------------------------------------------
    def openssl(self, *args, input: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess:
        cmd = ["openssl", *[str(a) for a in args]]
        # 入力が無いときは標準入力を閉じる（パスフレーズの入力待ちでロックを持ったまま止まらない）
        cp = subprocess.run(cmd, input=input, capture_output=True, env=self.env,
                            **({} if input is not None else {"stdin": subprocess.DEVNULL}))
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

    @contextlib.contextmanager
    def ca_lock(self, which: str = "issuer", allow_rotation: bool = False, fence_check: bool = True):
        # ロックは世代で入れ替わる issuer/ の外（locks/）に固定する。世代交代で issuer/ を
        # 移動しても、同じ inode のロックで全区間を保護できる。
        # 取得順は issuer → root → requests → audit（デッドロック防止）。
        with self._flock(self.p("locks", f"{which}.lock"), f"{which} CA"):
            # 待っている間に状態が変わっていないかを、ロックを取った後にもう一度確かめる
            if fence_check:
                self._fence_check()
            if which == "issuer" and not allow_rotation and self.rotation_marker.exists():
                raise LabError("ROTATION_IN_PROGRESS", "中間CAの世代交代が途中です（init-issuer --new-generation で再開）")
            yield

    @contextlib.contextmanager
    def req_lock(self, fence_check: bool = True):
        """申請の作成・審査・却下を直列化する（置き換え後に申請状態が変わらないように）。"""
        with self._flock(self.p("locks", "requests.lock"), "申請"):
            if fence_check:
                self._fence_check()
            yield

    def _fence_check(self) -> None:
        if self.superseded():
            raise LabError("SUPERSEDED", "この作業領域は復元先に置き換えられたため、状態を変更できません",
                           superseded=read_json(self.superseded_marker))
        if self.on_hold():
            raise LabError("RECOVERY_HOLD", "復旧保留中のため、状態を変更できません")

    def audit_lock(self):
        return self._flock(self.p("locks", "audit.lock"), "監査ログ")

    # --- この作業領域の識別子（復元先の取り違えを防ぐ。バックアップには含めない） ---------
    def instance_id(self, create: bool = False) -> str | None:
        path = self.p("instance.json")
        if path.exists():
            try:
                val = read_json(path).get("id")
                return val if isinstance(val, str) else None
            except (ValueError, OSError):
                return None
        if not create:
            return None
        ident = secrets.token_hex(16)
        write_json(path, {"id": ident, "created": iso(utcnow())})
        return ident

    # --- 置き換え済み・世代交代中 ------------------------------------------------
    @property
    def superseded_marker(self) -> Path:
        return self.p("recovery", "superseded.json")

    def superseded(self) -> bool:
        return self.superseded_marker.exists()

    @property
    def rotation_marker(self) -> Path:
        return self.p("rotation", "issuer.json")

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
        if self.on_hold():
            # 復旧保留中の復元先では監査ログを伸ばさない（バックアップ時点のログのまま比較するため）。
            # 読み取り操作の記録は recovery/held-ops.jsonl に残す。
            rec = {"ts": iso(utcnow()), "actor": self.actor, "role": self.role, "op": op, "result": result,
                   "target": target, "details": details, "held": True}
            append_durable(self.p("recovery", "held-ops.jsonl"), json.dumps(rec, ensure_ascii=False))
            return rec
        with self.audit_lock():
            if self.is_frozen():
                raise LabError("AUDIT_FROZEN", "監査ログは凍結中のため記録できません")
            if self.superseded():
                raise LabError("SUPERSEDED", "この作業領域は復元先に置き換えられたため、記録できません")
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
        path = self.req_dir(req_id) / "state.json"
        try:
            return read_json(path)
        except (OSError, ValueError):
            raise LabError("BROKEN_REQUEST", f"申請の状態ファイルを読めません: {req_id}")

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


def _read_anchor(home: Path) -> tuple[dict | None, str | None]:
    """anchor.json を読む。壊れていればエラーコードを返す（例外にしない）。"""
    path = home / "anchor" / "anchor.json"
    if not path.exists():
        return None, None
    try:
        a = read_json(path)
    except (ValueError, OSError):
        return None, "ANCHOR_CORRUPT"
    if not isinstance(a, dict) or not isinstance(a.get("seq"), int) or not isinstance(a.get("hash"), str):
        return None, "ANCHOR_CORRUPT"
    return a, None


def _parse_entry(line: str) -> dict | None:
    try:
        e = json.loads(line)
    except ValueError:
        return None
    if not isinstance(e, dict) or not isinstance(e.get("seq"), int) or not isinstance(e.get("hash"), str):
        return None
    return e


def audit_tail(home: Path) -> dict:
    """末尾の1行と基準ハッシュの一致だけを確認する（追記前の軽い確認）。"""
    lines = _audit_lines(home)
    anchor, err = _read_anchor(home)
    if err:
        return {"ok": False, "code": err}
    if not lines:
        if anchor is None:
            return {"ok": True, "seq": 0, "hash": "0" * 64}
        return {"ok": False, "code": "AUDIT_TRUNCATED_OR_REWRITTEN", "anchor_seq": anchor["seq"], "log_seq": 0}
    last = _parse_entry(lines[-1])
    if last is None:
        return {"ok": False, "code": "AUDIT_TAMPERED", "line": len(lines)}
    if anchor is None:
        return {"ok": False, "code": "ANCHOR_MISSING"}
    if anchor["seq"] != last["seq"] or anchor["hash"] != last["hash"]:
        return {"ok": False, "code": "AUDIT_TRUNCATED_OR_REWRITTEN", "anchor_seq": anchor["seq"],
                "log_seq": last["seq"]}
    return {"ok": True, "seq": last["seq"], "hash": last["hash"]}


def verify_audit_chain(home: Path) -> dict:
    """全行の連鎖（prev・hash・連番）と、基準ハッシュとの一致を検証する。壊れた入力でも例外にしない。"""
    prev, seq, head = "0" * 64, 0, "0" * 64
    try:
        lines = _audit_lines(home)
    except (OSError, UnicodeDecodeError):
        return {"ok": False, "internal_ok": False, "code": "AUDIT_UNREADABLE"}
    for n, line in enumerate(lines, 1):
        e = _parse_entry(line)
        if e is None:
            return {"ok": False, "internal_ok": False, "code": "AUDIT_TAMPERED", "line": n}
        h = e.pop("hash")
        if e.get("prev") != prev or e.get("seq") != seq + 1 or sha256_bytes(canonical(e)) != h:
            return {"ok": False, "internal_ok": False, "code": "AUDIT_TAMPERED", "line": n}
        prev, seq, head = h, e["seq"], h
    a, err = _read_anchor(home)
    if err:
        return {"ok": False, "internal_ok": True, "code": err, "entries": seq, "head": head}
    if a is None:
        if seq == 0:
            return {"ok": True, "internal_ok": True, "entries": 0, "head": head}
        return {"ok": False, "internal_ok": True, "code": "ANCHOR_MISSING", "entries": seq, "head": head}
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


def subject_cn(san: list[str]) -> str:
    """Subject の CN。DNS 型の SAN があればそれを使う。IP だけの場合は、ホスト名に見えない CN にする
    （DNS 型の SAN が無い証明書では、OpenSSL がホスト名らしい CN を名前制約の DNS 名として検査するため、
    CN=127.0.0.1 だと中間CAの permitted;DNS:localhost に反して検証で拒否される）。"""
    dns = [x.split(":", 1)[1] for x in san if x.startswith("DNS:")]
    return dns[0] if dns else "PKI Lab TLS server"


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
        atomic_write(crlnum, "1000\n")


def cmd_init_root(lab: Lab, args) -> dict:
    lab.require("init-root")
    lab.layout()
    with lab.ca_lock("root"):
        # 存在確認はロックの中で（同時に2つ作って最初のルート鍵を上書きしない）
        if lab.root_cert.exists() or lab.root_key.exists():
            raise LabError("ALREADY_INITIALIZED", "ルートCAは作成済みです")
        ensure_passphrase(lab.root_pass)
        init_ca_db(lab.p("root"))
        gen_encrypted_key(lab, lab.root_key, lab.root_pass)
        tmp = lab.p("root", "certs", ".root.cert.pem.new")
        lab.openssl("req", "-config", ROOT_CNF, "-new", "-x509", "-key", lab.root_key,
                    "-passin", f"file:{lab.root_pass}", "-sha256", "-days", ROOT_DAYS,
                    "-extensions", "v3_root", "-set_serial", "0x" + secrets.token_hex(16), "-out", tmp)
        atomic_write(lab.root_cert, tmp.read_bytes())
        tmp.unlink()
        atomic_write(lab.p("public", "certs", "root.cert.pem"), lab.root_cert.read_bytes())
        info = cert_info(lab, lab.root_cert)
        lab.audit("init-root", "ok", info["serial"], not_after=info["not_after"], cert_sha256=info["cert_sha256"])
    return {"root": str(lab.root_cert), "serial": info["serial"], "not_after": info["not_after"]}


def cmd_init_issuer(lab: Lab, args) -> dict:
    """中間CAの鍵と CSR を作る。署名はルート側（sign-intermediate）で行う。
    --new-generation：失効・廃止した中間CAを archive/ へ移し、新しい鍵で次の世代を作る。
    世代交代は rotation/issuer.json に段階（archiving → archived）を記録し、途中で止まっても
    同じコマンドで続きから再開する（旧世代を再び使ったり、二重に世代を作ったりしない）。"""
    lab.require("init-issuer")
    with lab.ca_lock("issuer", allow_rotation=True):
        rot = read_json(lab.rotation_marker) if lab.rotation_marker.exists() else None
        if rot is None:
            st = lab.ca_state()
            # 状態ファイル・証明書・鍵のどれかがあれば初期化済み（鍵を消しただけで同じ世代を作り直さない）
            existing = (lab.p("issuer", "state.json").exists() or lab.issuer_cert.exists() or lab.issuer_key.exists())
            partial_init = (st["status"] == "PENDING" and not lab.issuer_cert.exists() and not lab.issuer_key.exists())
            if existing and not getattr(args, "new_generation", False):
                if not partial_init:
                    hint = "" if lab.issuer_key.exists() else \
                        "（鍵が失われた場合は revoke-intermediate --reason keyCompromise の後に --new-generation）"
                    raise LabError("ALREADY_INITIALIZED", f"中間CAは初期化済みです（{st['status']}）{hint}")
            elif existing:
                if st["status"] not in ("REVOKED", "RETIRED"):
                    raise LabError("CA_STILL_ACTIVE", "新しい世代へ移るには、現在の中間CAを失効または廃止してください")
                if lab.p("archive", f"issuer-gen{st['generation']}").exists():
                    raise LabError("ARCHIVE_EXISTS", f"archive/issuer-gen{st['generation']} が既にあります")
                rot = {"from": st["generation"], "to": st["generation"] + 1, "stage": "archiving",
                       "started": iso(utcnow()), "by": lab.actor}
                lab.audit("rotation", "started", f"generation-{rot['to']}", **{"from": rot["from"]})
                write_json(lab.rotation_marker, rot)
            generation = rot["to"] if rot else st["generation"]
        else:
            if not getattr(args, "new_generation", False):
                raise LabError("ROTATION_IN_PROGRESS", "前回の世代交代が途中です。init-issuer --new-generation で再開してください",
                               rotation=rot)
            generation = rot["to"]
        if rot:
            archive = lab.p("archive", f"issuer-gen{rot['from']}")
            if rot["stage"] == "archiving":
                if not archive.exists():
                    # 旧世代は秘密鍵ごと保管庫へ（署名には二度と使わない）
                    archive.parent.mkdir(parents=True, exist_ok=True)
                    os.rename(lab.p("issuer"), archive)
                    fsync_dir(archive.parent)
                    fsync_dir(lab.home)
                rot["stage"] = "archived"
                write_json(lab.rotation_marker, rot)
                _crash_point("rotation-after-archive")
            # archived 以降に issuer/ があれば、署名前の作りかけの新世代なので作り直す
            partial = lab.p("issuer")
            if partial.exists():
                if (partial / "certs" / "intermediate.cert.pem").exists():
                    raise LabError("ROTATION_CONFLICT", "作りかけのはずの新世代に署名済み証明書があります。手動で確認してください")
                shutil.rmtree(partial)
        lab.layout()
        ensure_passphrase(lab.issuer_pass)
        init_ca_db(lab.p("issuer"))
        gen_encrypted_key(lab, lab.issuer_key, lab.issuer_pass)
        csr = lab.p("issuer", "certs", "intermediate.csr.pem")
        lab.openssl("req", "-config", ISSUER_CNF, "-new", "-key", lab.issuer_key,
                    "-passin", f"file:{lab.issuer_pass}", "-sha256",
                    "-subj", f"/CN=PKI Lab Issuing CA {generation}", "-out", csr)
        write_json(lab.p("issuer", "state.json"), {"status": "PENDING", "generation": generation, "history": [
            {"status": "PENDING", "ts": iso(utcnow()), "by": lab.actor, "reason": "init-issuer"}]})
        if rot:
            lab.rotation_marker.unlink()
            fsync_dir(lab.rotation_marker.parent)
        lab.audit("init-issuer", "ok", f"generation-{generation}", csr_sha256=sha256_file(csr),
                  generation=generation, rotated_from=rot["from"] if rot else None)
    return {"csr": str(csr), "generation": generation}


def cmd_sign_intermediate(lab: Lab, args) -> dict:
    """ルートが中間CAに署名する。前回ルートが署名した直後に止まっていたら、署名し直さずにその証明書を採用する
    （同じ鍵の有効な中間CAを二重に作らない。失効済みの鍵は KEY_REUSE）。"""
    lab.require("sign-intermediate")
    csr = lab.p("issuer", "certs", "intermediate.csr.pem")
    if not csr.exists():
        raise LabError("NO_CSR", "中間CAの CSR がありません（init-issuer を先に実行）")
    with lab.ca_lock("issuer"), lab.ca_lock("root"):
        _finish_pending(lab, "root")  # ルートの未完了の失効を先に完了させる
        st = lab.ca_state()
        if st["status"] != "PENDING":
            raise LabError("ALREADY_SIGNED", f"中間CAは {st['status']} 状態です。署名し直しは"
                                             "新しい世代（init-issuer --new-generation）でのみ行います")
        csr_spki = sha256_bytes(csr_structure(lab.openssl("req", "-in", csr, "-outform", "DER").stdout)["spki"])
        expected_subject = f"CN=PKI Lab Issuing CA {st['generation']}"
        matches = []
        for row in read_index(lab.p("root")):
            pem = lab.p("root", "newcerts", f"{row['serial']}.pem")
            if pem.exists() and cert_info(lab, pem)["pubkey_sha256"] == csr_spki:
                matches.append((row, pem))
        if any(row["status"] != "V" for row, _ in matches):
            raise LabError("KEY_REUSE", "失効した中間CAと同じ鍵です。新しい鍵を作ってください")
        resumed = False
        if matches:
            row, pem = matches[-1]
            info = cert_info(lab, pem)
            if info["subject"] != expected_subject or parse_iso(info["not_after"]) < utcnow():
                raise LabError("KEY_REUSE", "ルートが過去に署名した、この世代のものではない中間CAと同じ鍵です")
            data = pem.read_bytes()
            resumed = True
        else:
            root = cert_info(lab, lab.root_cert)
            now = utcnow()
            not_after = now + dt.timedelta(days=ISSUER_DAYS)
            if not_after > parse_iso(root["not_after"]) - ISSUER_MARGIN:
                raise LabError("ISSUER_RENEWAL_REQUIRED", "ルートCAの残り期間が足りません")
            # 先行書き込み：ルートの台帳を変える前に監査ログへ
            lab.audit("sign-intermediate", "started", f"generation-{st['generation']}", csr_spki=csr_spki[:16])
            out = lab.p("issuer", "certs", ".intermediate.cert.pem.new")
            lab.openssl("ca", "-config", ROOT_CNF, "-batch", "-notext", "-in", csr, "-out", out,
                        "-passin", f"file:{lab.root_pass}", "-extensions", "v3_intermediate",
                        "-subj", f"/{expected_subject}",
                        "-startdate", asn1_time(now - dt.timedelta(seconds=BACKDATE_SECONDS)),
                        "-enddate", asn1_time(not_after))
            data = out.read_bytes()
            out.unlink()
            _crash_point("after-root-sign")
        atomic_write(lab.issuer_cert, data)
        atomic_write(lab.p("public", "certs", "intermediate.cert.pem"), data)
        info = cert_info(lab, lab.issuer_cert)
        lab.set_ca_state("ACTIVE", "sign-intermediate" + (" (resumed)" if resumed else ""), serial=info["serial"])
        lab.audit("sign-intermediate", "ok", info["serial"], not_after=info["not_after"],
                  cert_sha256=info["cert_sha256"], generation=st["generation"], resumed=resumed)
    return {"intermediate": str(lab.issuer_cert), "serial": info["serial"], "generation": st["generation"],
            "resumed": resumed}


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
    """サーバー管理者が鍵と CSR を作って申請する。秘密鍵は server/private から出さない。
    申請は一時ディレクトリで作り、状態ファイルまで書けてから名前を付け替える（途中で失敗しても壊れた申請を残さない）。"""
    lab.require("request")
    if args.csr and not Path(args.csr).is_file():
        raise LabError("FILE_NOT_FOUND", f"CSR がありません: {args.csr}")
    if args.key and not Path(args.key).is_file():
        raise LabError("FILE_NOT_FOUND", f"サーバー鍵がありません: {args.key}")
    lab.layout()
    with lab.req_lock():
        req_id = new_request_id()
        final = lab.p("requests", req_id)
        tmp = lab.p("requests", f".tmp-{req_id}")
        tmp.mkdir(parents=True)
        csr = tmp / "request.csr.pem"
        key_path, created_key = None, False
        try:
            if args.csr:
                src = Path(args.csr)
                if src.stat().st_size > MAX_CSR_BYTES:
                    raise LabError("CSR_TOO_LARGE", f"CSR が上限 {MAX_CSR_BYTES} バイトを超えています")
                atomic_write(csr, src.read_bytes())
            else:
                san = args.san or ["DNS:localhost", "IP:127.0.0.1"]
                if args.key:
                    key_path = Path(args.key).resolve()  # 同じ鍵で再申請する場合（鍵更新しない更新）
                else:
                    key_path = lab.p("server", "private", f"{req_id}.key.pem")
                    raw = lab.openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256").stdout
                    # ローカルの非対話 TLS デモのための例外として、サーバー鍵だけ非暗号化 PEM(0600)。
                    write_private(key_path, raw)
                    created_key = True
                cp = lab.openssl("req", "-new", "-key", key_path, "-sha256", "-subj", "/CN=localhost",
                                 "-addext", "subjectAltName=" + ",".join(san), "-out", csr, check=False)
                if cp.returncode != 0:
                    raise LabError("CSR_CREATE_FAILED", f"CSR を作れません（SAN の書き方を確認）: "
                                                        f"{cp.stderr.decode(errors='replace').strip()[:300]}")
            rel_key = None
            if key_path:
                rel_key = str(key_path.relative_to(lab.home)) if key_path.is_relative_to(lab.home) else str(key_path)
            st = {"id": req_id, "status": "RECEIVED", "requester": lab.actor, "asset": args.asset,
                  "created": iso(utcnow()), "server_key": rel_key,
                  "history": [{"status": "RECEIVED", "ts": iso(utcnow()), "by": lab.actor}]}
            write_json(tmp / "state.json", st)
            csr_sha = sha256_file(csr)
            os.rename(tmp, final)
            fsync_dir(final.parent)
        except BaseException:
            shutil.rmtree(tmp, ignore_errors=True)
            if created_key and key_path:
                key_path.unlink(missing_ok=True)
            raise
        lab.audit("request", "ok", req_id, csr_sha256=csr_sha, asset=args.asset)
    return {"request": req_id, "csr": str(final / "request.csr.pem")}


def cmd_approve(lab: Lab, args) -> dict:
    """RA の審査と承認。承認は CSR・プロファイル・SAN・期間・承認者・期限に結び付ける。"""
    lab.require("approve")
    with lab.req_lock():
        return _approve(lab, args)


def _approve(lab: Lab, args) -> dict:
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
    with lab.req_lock():
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


# 一時的な状態（CRL の更新待ち・未完了の失効・一時停止）。これだけが理由なら、署名済みの正しい
# 証明書を隔離・失効させず、状態を変えずに「後で再試行」とする。
TRANSIENT_PROBLEMS = {
    "issuer_revocation_pending", "root_revocation_pending", "root_crl_unavailable", "root_crl_expired",
    "issuer_crl_unavailable", "issuer_crl_expired", "issuer_ca_suspended",
    "chain_CRL_MISSING", "chain_CRL_EXPIRED", "chain_CRL_NOT_YET_VALID", "chain_CRL_BAD_SIGNATURE",
}


def split_problems(problems: list[str]) -> tuple[list[str], list[str]]:
    permanent = [p for p in problems if p not in TRANSIENT_PROBLEMS]
    return permanent, [p for p in problems if p in TRANSIENT_PROBLEMS]


def issuer_usability_problems(lab: Lab, generation: int | None = None) -> list[str]:
    """中間CA（指定世代）で今も発行・配置してよいかを確かめる。空なら使える。"""
    st = lab.ca_state()
    if generation is not None and generation != st["generation"]:
        return [f"issuer_generation_{generation}_retired"]
    problems = []
    if st["status"] != "ACTIVE":
        problems.append(f"issuer_ca_{st['status'].lower()}")
    if pending_revocations(lab, "issuer"):
        problems.append("issuer_revocation_pending")
    if pending_revocations(lab, "root"):
        problems.append("root_revocation_pending")
    meta = crl_meta(lab, lab.p("public", "crl", "root.crl.pem"), lab.root_cert)
    if not meta["present"] or not meta.get("sig_ok"):
        problems.append("root_crl_unavailable")
    else:
        if parse_iso(meta["next_update"]) < utcnow():
            problems.append("root_crl_expired")
        # 期限切れでも、載っている失効は失効として扱う
        if lab.issuer_cert.exists() and cert_info(lab, lab.issuer_cert)["serial"] in meta["revoked"]:
            problems.append("issuer_revoked_in_root_crl")
    if lab.issuer_cert.exists():
        imeta = crl_meta(lab, lab.p("public", "crl", "intermediate.crl.pem"), lab.issuer_cert)
        if not imeta["present"] or not imeta.get("sig_ok"):
            problems.append("issuer_crl_unavailable")
        elif parse_iso(imeta["next_update"]) < utcnow():
            problems.append("issuer_crl_expired")
    return problems


def require_issuer_active(lab: Lab) -> dict:
    """署名前に、中間CAの運用状態・未完了の失効・ルート CRL 上の失効・中間CA自身の CRL を確認する。
    （署名してから CRL の不備で隔離・失効させることがないよう、署名の前に止める）"""
    st = lab.ca_state()
    if st["status"] != "ACTIVE":
        raise LabError("CA_NOT_ACTIVE", f"中間CAは {st['status']} 状態のため発行できません", ca_state=st["status"])
    problems = issuer_usability_problems(lab)
    if "issuer_revoked_in_root_crl" in problems:
        lab.set_ca_state("REVOKED", "found in root CRL")
        lab.audit("ca-state", "revoked", "", reason="found_in_root_crl")
        raise LabError("CA_NOT_ACTIVE", "中間CAはルート CRL で失効しています", ca_state="REVOKED")
    if any(p.endswith("revocation_pending") for p in problems):
        raise LabError("REVOCATION_PENDING", "公開が完了していない失効があるため発行できません", problems=problems)
    if "root_crl_unavailable" in problems:
        raise LabError("ROOT_CRL_UNAVAILABLE", "ルート CRL が無いか署名を検証できないため、中間CAの状態を確認できません")
    if "root_crl_expired" in problems:
        raise LabError("ROOT_CRL_UNAVAILABLE", "ルート CRL の期限が切れています（crl-root で更新）")
    if "issuer_crl_unavailable" in problems or "issuer_crl_expired" in problems:
        raise LabError("ISSUER_CRL_UNAVAILABLE", "中間CAの CRL が無いか期限切れです（crl-issuer で更新してから発行）")
    return cert_info(lab, lab.issuer_cert)


def chain_problem(lab: Lab, pem: Path, base: Path) -> str | None:
    """発行元の鍵による署名・経路・用途・有効期間・失効を OpenSSL で検証する（名前の一致だけで判断しない）。"""
    with tempfile.NamedTemporaryFile("wb", prefix="crls-", suffix=".pem", dir=lab.p("journal"), delete=False) as f:
        f.write(collect_crls(lab))
        crls = Path(f.name)
    try:
        cp = lab.openssl("verify", "-x509_strict", "-purpose", "sslserver", "-trusted", lab.root_cert,
                         "-untrusted", base / "certs" / "intermediate.cert.pem", "-CRLfile", crls,
                         "-crl_check", "-crl_check_all", "-attime", str(int(utcnow().timestamp())), pem, check=False)
    finally:
        crls.unlink(missing_ok=True)
    if cp.returncode == 0:
        return None
    m = re.search(r"error (\d+) at (\d+) depth", (cp.stdout + cp.stderr).decode(errors="replace"))
    return classify_verify(int(m.group(1)), int(m.group(2))) if m else "VERIFY_ERROR"


def validate_issued(lab: Lab, rec: dict, apr: dict) -> list[str]:
    """署名済み証明書を採用・配置してよいかを確かめる（空なら合格）。
    1) 台帳・承認・プロファイルとの一致、2) 承認した期間・時刻との対応、
    3) 現在の有効期間、4) 発行元CAの世代と運用状態、5) 署名経路と失効。"""
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
    issuer_info = cert_info(lab, issuer_cert) if issuer_cert.exists() else None
    if issuer_info and info["issuer"] != issuer_info["subject"]:
        problems.append("issuer")
    if rec.get("approval_id") and rec["approval_id"] != apr["approval_id"]:
        problems.append("approval_id")
    # 承認した期間・時刻との対応（notBefore は署名時刻の300秒前。中間CAの開始で切り詰めた場合を除く）
    nb, na = parse_iso(info["not_before"]), parse_iso(info["not_after"])
    slack = dt.timedelta(seconds=120)
    if na - nb > dt.timedelta(days=apr["days"], seconds=BACKDATE_SECONDS) + slack:
        problems.append("validity_exceeds_approval")
    if issuer_info is None or nb > parse_iso(issuer_info["not_before"]):
        signed_at = nb + dt.timedelta(seconds=BACKDATE_SECONDS)
        if not (parse_iso(apr["approved_at"]) - slack <= signed_at <= parse_iso(apr["expires_at"]) + slack):
            problems.append("signed_outside_approval_window")
    # 現在の有効期間（台帳の V は期限切れを反映しない）
    now = utcnow()
    if now < nb:
        problems.append("not_yet_valid")
    if now > na:
        problems.append("expired")
    # 発行元CAの世代と運用状態
    problems += issuer_usability_problems(lab, rec.get("generation"))
    # 署名経路・失効（Issuer 名の一致は、その鍵で署名されたことの証明にならない）
    code = chain_problem(lab, pem, base)
    if code:
        problems.append(f"chain_{code}")
    return problems


def pem_cert_ders(data: bytes) -> list[bytes]:
    """PEM の並びから証明書の DER を順に取り出す。証明書以外（鍵など）が混ざっていれば拒否。"""
    blocks = re.findall(rb"-----BEGIN ([A-Z0-9 ]+)-----\s*(.*?)\s*-----END \1-----", data, re.S)
    if not blocks or any(label != b"CERTIFICATE" for label, _ in blocks):
        raise LabError("CHAIN_BAD_CONTENT", "証明書以外の PEM を含むか、証明書がありません")
    try:
        return [base64.b64decode(b"".join(body.split()), validate=True) for _, body in blocks]
    except ValueError:
        raise LabError("CHAIN_BAD_CONTENT", "PEM を復号できません")


def deployment_problems(lab: Lab, st: dict, rec: dict, require_key: bool = True) -> list[str]:
    """配置物（葉・fullchain・公開コピー・サーバー鍵）が発行記録と一致するかを確かめる。"""
    base = lab.issuer_base(rec.get("generation"))
    out = []

    def der_sha(path: Path | None) -> str | None:
        if path is None or not path.exists():
            return None
        try:
            return cert_info(lab, path)["cert_sha256"]
        except LabError:
            return None

    if der_sha(lab.p(st["cert"]) if st.get("cert") else None) != rec["cert_sha256"]:
        out.append("leaf")
    chain = lab.p(st["fullchain"]) if st.get("fullchain") else None
    if chain is None or not chain.exists():
        out.append("fullchain_missing")
    else:
        try:
            ders = pem_cert_ders(chain.read_bytes())
            inter = der_sha(base / "certs" / "intermediate.cert.pem")
            # 葉 → 中間CA の2枚だけ（ルートは送らない）
            if [sha256_bytes(d) for d in ders] != [rec["cert_sha256"], inter]:
                out.append("fullchain_mismatch")
        except LabError:
            out.append("fullchain_bad_content")
    if der_sha(lab.p("public", "certs", f"{rec['serial']}.pem")) != rec["cert_sha256"]:
        out.append("public_copy")
    key = st.get("server_key")
    if key:
        kp = Path(key) if Path(key).is_absolute() else lab.p(key)
        if not kp.exists():
            if require_key:
                out.append("server_key_missing")
        else:
            cp = lab.openssl("pkey", "-in", kp, "-pubout", "-outform", "DER", check=False)
            if cp.returncode != 0:
                out.append("server_key_unreadable")
            elif sha256_bytes(cp.stdout) != rec["pubkey_sha256"]:
                out.append("server_key_mismatch")
    return out


def _quarantine(lab: Lab, req_id: str, op_id: str | None, serial: str | None, problems: list[str],
                generation: int | None = None) -> dict:
    """不合格の証明書を隔離する。現在の中間CAの台帳にあれば失効させ、公開 CRL への反映まで確認する。
    失効の公開が完了しなければ revocation=pending（中間CAは SUSPENDED、署名前に必ず再試行・拒否）。"""
    ca = lab.ca_state()
    revocation = "none"
    if serial:
        if (generation not in (None, ca["generation"])) or ca["status"] in ("REVOKED", "RETIRED"):
            revocation = "not_needed_issuer_revoked"  # 発行元CAごと失効・廃止済み
        elif serial in {r["serial"] for r in read_index(lab.p("issuer"))}:
            try:
                _revoke_and_publish(lab, "issuer", serial, "cessationOfOperation")
                revocation = "done"
            except LabError:
                revocation = "pending"
    lab.set_state(req_id, "QUARANTINED", problems=problems, serial=serial, revocation=revocation,
                  generation=generation if generation is not None else ca["generation"])
    if op_id:
        _journal(lab, op_id, finished=iso(utcnow()), result=f"quarantined:{revocation}")
    lab.audit_if_possible("quarantine", "ok" if revocation != "pending" else "revocation_pending", req_id,
                          serial=serial or "", problems=problems, revocation=revocation)
    return {"request": req_id, "action": "quarantined", "revocation": revocation, "problems": problems}


def _not_ready(problems: list[str]) -> LabError:
    return LabError("ISSUER_NOT_READY", f"一時的な状態のため配置を見送りました（状態は変えていません）: {problems}。"
                                        "crl-issuer / crl-root などで解消してから、同じコマンドを再実行してください",
                    problems=problems)


def _publish(lab: Lab, req_id: str, republish: bool = False) -> dict:
    """署名済み（ISSUED）の証明書を、再署名せずにサーバーと公開領域へ配置する。
    配置の前に、未完了の失効を完了させ、採用条件（validate_issued）を毎回確認する。
    一時的な理由だけなら状態を変えずに ISSUER_NOT_READY、恒久的な理由なら隔離する。"""
    _finish_pending(lab, "issuer")
    st = lab.state(req_id)
    d = lab.req_dir(req_id)
    rec = read_json(d / "cert.json")
    apr = read_json(lab.p("approvals", f"{req_id}.json"))
    permanent, transient = split_problems(validate_issued(lab, rec, apr))
    if permanent:
        res = _quarantine(lab, req_id, st.get("op_id"), rec["serial"], permanent + transient, rec.get("generation"))
        raise LabError("POST_ISSUE_CHECK_FAILED", f"配置前の検査で不合格: {permanent + transient}", **res)
    if transient:
        raise _not_ready(transient)
    base = lab.issuer_base(rec.get("generation"))
    data = (base / "newcerts" / f"{rec['serial']}.pem").read_bytes()
    leaf = lab.p("server", "certs", f"{req_id}.cert.pem")
    chain = lab.p("server", "certs", f"{req_id}.fullchain.pem")
    atomic_write(leaf, data)
    atomic_write(chain, data + (base / "certs" / "intermediate.cert.pem").read_bytes())
    atomic_write(lab.p("public", "certs", f"{rec['serial']}.pem"), data)
    # 配置物を確かめてから PUBLISHED にする（不一致なら ISSUED のまま。再実行で配置をやり直す）
    preview = {**st, "cert": str(leaf.relative_to(lab.home)), "fullchain": str(chain.relative_to(lab.home))}
    left = [x for x in deployment_problems(lab, preview, rec, require_key=False) if not x.startswith("server_key")]
    if left:
        raise LabError("PUBLISH_INCOMPLETE", f"配置後の確認で不一致: {left}", problems=left)
    st = lab.set_state(req_id, "PUBLISHED", cert=preview["cert"], fullchain=preview["fullchain"])
    if st.get("op_id"):
        _journal(lab, st["op_id"], finished=iso(utcnow()), result="ok", serial=rec["serial"])
    lab.audit("republish" if republish else "publish", "ok", req_id, serial=rec["serial"])
    return {"request": req_id, "serial": rec["serial"], "cert": str(leaf), "fullchain": str(chain),
            "not_after": rec["not_after"]}


def _ensure_published(lab: Lab, req_id: str) -> dict:
    """PUBLISHED でも、証明書が今も使えること（期限・経路・CA状態）と、配置物（葉・fullchain・
    公開コピー・サーバー鍵）が正しいことを確かめてから返す。壊れた配置物は正本から配置し直す。"""
    st = lab.state(req_id)
    rec = read_json(lab.req_dir(req_id) / "cert.json")
    apr = read_json(lab.p("approvals", f"{req_id}.json"))
    _finish_pending(lab, "issuer")
    permanent, transient = split_problems(validate_issued(lab, rec, apr))
    if permanent:
        # 状態は変えない（期限切れ・CA失効などは、新しい申請で再発行する）
        raise LabError("CERT_NOT_USABLE", f"この証明書は現在使えません: {permanent + transient}",
                       problems=permanent + transient)
    if transient:
        raise _not_ready(transient)
    dep = deployment_problems(lab, st, rec)
    keys = [p for p in dep if p.startswith("server_key") and p != "server_key_encrypted"]
    if keys:
        raise LabError("SERVER_KEY_PROBLEM", f"サーバー鍵が証明書と対応しません: {keys}", problems=keys)
    if dep:
        return {**_publish(lab, req_id, republish=True), "reused": True, "republished": True, "repaired": dep}
    return {"request": req_id, "serial": rec["serial"], "cert": str(lab.p(st["cert"])),
            "fullchain": str(lab.p(st["fullchain"])), "not_after": rec["not_after"], "reused": True}


def _record_issued(lab: Lab, req_id: str, apr: dict, info: dict, op_id: str | None,
                   generation: int | None = None) -> dict:
    rec = {"issuer": info["issuer"], "serial": info["serial"], "request": req_id,
           "approval_id": apr["approval_id"], "op_id": op_id,
           "generation": generation if generation is not None else lab.ca_state()["generation"],
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

        _finish_pending(lab, "issuer")  # 未完了の失効があれば先に完了させる（できなければ拒否）
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
                 generation=lab.ca_state()["generation"], index_rows_before=rows_before, signed=False)
        # 先行書き込み：台帳を変える前に監査ログへ（ここで止まっても、復元時の新しさ判定が気付く）
        lab.audit("issue-sign", "started", req_id, op_id=op_id)
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
                        "-subj", "/CN=" + subject_cn(apr["san"]),
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
        permanent, transient = split_problems(problems)
        if permanent:
            res = _quarantine(lab, req_id, op_id, serial, problems)
            raise LabError("POST_ISSUE_CHECK_FAILED", f"発行後検査で不合格: {problems}", **res)

        # 署名済みの正しい証明書は記録する。一時的な理由があれば配置だけを後回しにする（ISSUED のまま）
        _record_issued(lab, req_id, apr, info, op_id)
        lab.audit("issue", "ok", req_id, serial=serial, cert_sha256=info["cert_sha256"], san=info["san"],
                  not_after=info["not_after"], op_id=op_id)
        if transient:
            raise _not_ready(transient)
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
        # 一時的な未完了の失効で、正しく署名された証明書を誤って隔離しないよう先に完了させる
        _finish_pending(lab, "issuer")
        apr = read_json(lab.p("approvals", f"{req_id}.json"))
        op_id = st.get("op_id")
        j = read_json(lab.p("journal", f"{op_id}.json")) if op_id and lab.p("journal", f"{op_id}.json").exists() else {}
        if not j or j.get("request") != req_id or j.get("csr_sha256") != apr["csr_sha256"]:
            res = _quarantine(lab, req_id, op_id, None, ["journal_missing_or_mismatch"])
            return {**res, "action": "quarantined"}
        # 署名した世代の台帳で探す（その後に世代交代していれば、採用前の検査で不合格になる）
        gen = j.get("generation", lab.ca_state()["generation"])
        base = lab.issuer_base(gen)

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
            for row in read_index(base)[j.get("index_rows_before", 0):]:
                if row["serial"] in claimed:
                    continue
                pem = base / "newcerts" / f"{row['serial']}.pem"
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
        pem = base / "newcerts" / f"{serial}.pem"
        try:
            info = cert_info(lab, pem)
        except LabError:
            res = _quarantine(lab, req_id, op_id, None, ["newcert_unparseable"], gen)
            return {**res, "action": "quarantined"}
        if j.get("cert_sha256") and j["cert_sha256"] != info["cert_sha256"]:
            res = _quarantine(lab, req_id, op_id, serial, ["cert_hash_differs_from_journal"], gen)
            return {**res, "action": "quarantined"}
        # 採用前に、期限・署名経路・失効・発行CAの世代と状態・承認との対応まで確認する
        problems = validate_issued(lab, {"serial": serial, "cert_sha256": info["cert_sha256"],
                                         "generation": gen, "approval_id": j.get("approval_id")}, apr)
        permanent, transient = split_problems(problems)
        if permanent:
            res = _quarantine(lab, req_id, op_id, serial, problems, gen)
            return {**res, "action": "quarantined"}
        # 一時的な理由だけなら、署名済みの証明書として記録し、配置は後で（_publish が ISSUER_NOT_READY）
        _record_issued(lab, req_id, apr, info, op_id, gen)
        lab.audit("recover", "ok", req_id, action="adopted_signed_certificate", serial=serial)
        out = _publish(lab, req_id)
    return {**out, "action": "adopted_signed_certificate"}


# =============================================================================
# 失効・CRL
# =============================================================================

def _gen_crl(lab: Lab, which: str) -> dict:
    """CRL を生成し、署名を確認してから CA 内部 → 公開領域の順に書き、公開物を読み戻して確認する。"""
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
    atomic_write(out, data)                       # CA 内部の CRL
    _fault("crl-publish")
    public = lab.p("public", "crl", name)
    atomic_write(public, data)                    # 公開 CRL
    pub = crl_meta(lab, public, ca_cert)
    if not pub.get("sig_ok") or pub.get("sha256") != meta["sha256"]:
        raise LabError("CRL_PUBLISH_INCOMPLETE", "公開した CRL を読み戻して確認できません")
    # 公開した CRL の番号とハッシュを記録（照合でロールバックや差し替えを検出する）
    write_json(lab.p(which, "db", "crl_published.json"),
               {"number": meta["number"], "sha256": meta["sha256"], "next_update": meta["next_update"]})
    lab.audit(f"crl-{which}", "ok", name, crl_number=meta["number"], next_update=meta["next_update"],
              crl_sha256=meta["sha256"], revoked=len(meta["revoked"]))
    return {**pub, "path": str(out)}


# --- 失効の状態機械 ------------------------------------------------------------
# 失効は「要求」→「台帳（ledger）」→「CRL 生成・公開・読み戻し確認」の順に進む。
# <ca>/db/revocation_pending.json に未完了の失効を、失効コマンドより先に書く。
# 途中で失敗・停止したら記録が残り、その CA での署名・配置の前に必ず再試行され、
# 完了できなければ拒否される（中間CAは SUSPENDED）。台帳が既に R でも、公開 CRL に
# 載ったことを確認するまでは完了にしない。

def _pending_path(lab: Lab, which: str) -> Path:
    return lab.p(which, "db", "revocation_pending.json")


def pending_revocations(lab: Lab, which: str) -> list[dict]:
    path = _pending_path(lab, which)
    return read_json(path)["entries"] if path.exists() else []


def _save_pending(lab: Lab, which: str, entries: list[dict]) -> None:
    path = _pending_path(lab, which)
    if entries:
        write_json(path, {"entries": entries})
    elif path.exists():
        path.unlink()
        fsync_dir(path.parent)


# 失効理由。certificateHold（保留）は取り消せる「保留」で失効ではないので扱わない。
REASONS = {"unspecified", "keyCompromise", "CACompromise", "affiliationChanged",
           "superseded", "cessationOfOperation"}


def _check_reason(reason: str) -> None:
    if reason not in REASONS:
        raise LabError("BAD_REASON", f"失効理由は {sorted(REASONS)} のいずれか")


def _ledger_reason(row: dict) -> str | None:
    # index.txt の失効欄は「失効日時,理由」
    parts = row.get("revoked", "").split(",", 1)
    return parts[1] if len(parts) == 2 else None


def _request_revocation(lab: Lab, which: str, serial: str, reason: str) -> None:
    """失効の要求を、台帳を変える前に監査ログと未完了リストへ書く（先行書き込み）。
    ここで止まっても、要求は記録され、復元時の新しさ判定や署名前の再試行で必ず扱われる。
    呼び出し側が該当 CA のロックを持っていること。"""
    _check_reason(reason)
    entries = pending_revocations(lab, which)
    if any(e["serial"] == serial for e in entries):
        return
    lab.audit("revoke-requested", "ok", serial, which=which, reason=reason)
    entries.append({"serial": serial, "reason": reason, "requested_at": iso(utcnow()),
                    "by": lab.actor, "stage": "requested"})
    _save_pending(lab, which, entries)


def _revoke_and_publish(lab: Lab, which: str, serial: str, reason: str) -> dict:
    """呼び出し側が該当 CA のロックを持っていること。"""
    _request_revocation(lab, which, serial, reason)
    return _finish_pending(lab, which)


def _mark_quarantine_revocations(lab: Lab, serials: set[str], value: str) -> None:
    """隔離した申請の revocation 欄を、失効の完了に合わせて更新する。"""
    for path in lab.p("requests").glob("REQ-*/state.json"):
        try:
            st = read_json(path)
        except (OSError, ValueError):
            continue
        if st.get("status") == "QUARANTINED" and st.get("revocation") == "pending" and st.get("serial") in serials:
            lab.set_state(st["id"], "QUARANTINED", revocation=value)


def _finish_pending(lab: Lab, which: str) -> dict:
    """未完了の失効を完了させる（台帳 → CRL 生成・公開・読み戻し確認）。
    完了できなければ REVOCATION_PENDING（中間CAは SUSPENDED）。完了したら失効ごとに監査ログへ記録する。"""
    entries = pending_revocations(lab, which)
    if not entries:
        if which == "issuer":
            st = lab.ca_state()
            if st["status"] == "SUSPENDED" and st.get("pending_revocation"):
                # 未完了リストは空なのに停止のまま（前回、ACTIVE に戻す直前で止まった）を直す
                lab.set_ca_state("ACTIVE", "pending revocation already completed", pending_revocation=None)
        return {"completed": []}
    cnf, pw = (ROOT_CNF, lab.root_pass) if which == "root" else (ISSUER_CNF, lab.issuer_pass)
    base = lab.p(which)
    try:
        rows = {r["serial"]: r for r in read_index(base)}
        kept = []
        for e in entries:
            row = rows.get(e["serial"])
            pem = base / "newcerts" / f"{e['serial']}.pem"
            if row is None and not pem.exists():
                # 台帳にも発行物にも無い：失効させる対象が存在しない要求は取り下げる（記録は残す）
                lab.incident("REVOCATION_DROPPED", which=which, serial=e["serial"], reason="no ledger row or newcert")
                lab.audit("revoke-dropped", "ok", e["serial"], which=which, reason="not_in_ledger")
                continue
            if row is None or row["status"] == "V":
                # 台帳に無い発行物（署名中の停止で残ったもの）も、openssl ca -revoke は台帳に追加して失効させる
                _revoke_in(lab, cnf, pem, e["reason"], pw)
            e["stage"] = "ledger"
            kept.append(e)
        entries = kept
        serials = [e["serial"] for e in entries]
        _save_pending(lab, which, entries)
        if not entries:
            return {"completed": []}
        meta = _gen_crl(lab, which)
        missing = set(serials) - meta["revoked"]
        if missing:
            raise LabError("CRL_PUBLISH_INCOMPLETE", f"公開 CRL に載っていません: {sorted(missing)}")
    except Exception as ex:  # noqa: BLE001  I/O 障害（OSError）も未完了として扱う
        serials = [e["serial"] for e in pending_revocations(lab, which)] if _pending_path(lab, which).exists() else []
        detail = f"{type(ex).__name__}: {ex}"
        if which == "issuer":
            with contextlib.suppress(Exception):
                if lab.ca_state()["status"] == "ACTIVE":
                    lab.set_ca_state("SUSPENDED", "revocation pending", pending_revocation=serials)
        with contextlib.suppress(Exception):
            lab.incident("REVOCATION_PENDING", which=which, serials=serials, error=detail)
        raise LabError("REVOCATION_PENDING",
                       f"失効の公開が完了していません（{detail}）。原因を取り除いて crl-{which} で再試行してください",
                       pending=serials, which=which) from ex
    # 先に ACTIVE に戻してから未完了リストを消す（間で止まっても、残ったリストを次回もう一度完了させるだけ）
    if which == "issuer":
        st = lab.ca_state()
        if st["status"] == "SUSPENDED" and st.get("pending_revocation"):
            lab.set_ca_state("ACTIVE", "pending revocation completed", pending_revocation=None)
    for e in entries:
        lab.audit("revoke-completed", "ok", e["serial"], which=which, reason=e["reason"], crl_number=meta["number"])
    _save_pending(lab, which, [])
    if which == "issuer":
        _mark_quarantine_revocations(lab, set(serials), "done")
    return {"completed": serials, "crl": meta["path"], "crl_number": meta["number"]}


def cmd_crl_root(lab: Lab, args) -> dict:
    lab.require("crl-root")
    with lab.ca_lock("root"):
        res = _finish_pending(lab, "root")
        crl = res["crl"] if res["completed"] else _gen_crl(lab, "root")["path"]
        return {"crl": crl, "completed_revocations": res["completed"]}


def cmd_crl_issuer(lab: Lab, args) -> dict:
    lab.require("crl-issuer")
    with lab.ca_lock("issuer"):
        status = lab.ca_state()["status"]
        if status in ("REVOKED", "RETIRED", "PENDING"):
            raise LabError("CA_NOT_ACTIVE", f"中間CAは {status} 状態のため CRL は作りません（失効・廃止・署名前）")
        res = _finish_pending(lab, "issuer")
        crl = res["crl"] if res["completed"] else _gen_crl(lab, "issuer")["path"]
        return {"crl": crl, "completed_revocations": res["completed"], "ca_state": lab.ca_state()["status"]}


def _revoke_in(lab: Lab, cnf: Path, pem: Path, reason: str, pw: Path) -> None:
    cp = lab.openssl("ca", "-config", cnf, "-revoke", pem, "-crl_reason", reason, "-passin", f"file:{pw}",
                     check=False)
    if cp.returncode != 0 and b"Already revoked" not in cp.stderr + cp.stdout:
        raise LabError("REVOKE_FAILED", cp.stderr.decode(errors="replace").strip())


def cmd_revoke(lab: Lab, args) -> dict:
    """サーバー証明書の失効。台帳 → CRL 生成 → 公開 CRL の確認まで完了させる。
    既に失効済みなら理由は変えず、公開 CRL に載っていることだけを確かめる（載っていなければ公開し直す）。"""
    lab.require("revoke")
    _check_reason(args.reason)
    serial = resolve_serial(lab, args.target)
    with lab.ca_lock("issuer"):
        status = lab.ca_state()["status"]
        if status in ("REVOKED", "RETIRED"):
            raise LabError("CA_NOT_ACTIVE", "中間CAごと失効・廃止済みです。配下の証明書を個別に失効させる必要はありません"
                                            "（失効した鍵で CRL に署名しません）")
        pem = lab.p("issuer", "newcerts", f"{serial}.pem")
        if not pem.exists():
            raise LabError("UNKNOWN_SERIAL", f"現在の中間CAが発行した証明書ではありません: {serial}")
        row = {r["serial"]: r for r in read_index(lab.p("issuer"))}.get(serial)
        if row and row["status"] == "R":
            existing = _ledger_reason(row) or "unspecified"
            public = crl_meta(lab, lab.p("public", "crl", "intermediate.crl.pem"), lab.issuer_cert)
            res = {"crl": str(lab.p("issuer", "crl", "intermediate.crl.pem"))}
            if not public.get("sig_ok") or serial not in public.get("revoked", set()):
                res = _revoke_and_publish(lab, "issuer", serial, existing)
            return {"revoked": serial, "already_revoked": True, "reason": existing,
                    "requested_reason": args.reason, "crl": res.get("crl")}
        res = _revoke_and_publish(lab, "issuer", serial, args.reason)
    return {"revoked": serial, "reason": args.reason, "crl": res.get("crl")}


def cmd_revoke_intermediate(lab: Lab, args) -> dict:
    """中間CAの失効。要求を先に記録し、中間CAを REVOKED にして発行を止めてから、ルート CRL の公開まで完了させる。
    --serial でルートの台帳にある別の中間CA（署名直後の停止で残ったもの等）も失効できる。"""
    lab.require("revoke-intermediate")
    _check_reason(args.reason)
    current = cert_info(lab, lab.issuer_cert)["serial"] if lab.issuer_cert.exists() else None
    serial = args.serial.upper() if getattr(args, "serial", None) else current
    if serial is None:
        raise LabError("NO_INTERMEDIATE", "現在の中間CA証明書がありません（--serial でルート台帳のシリアルを指定）")
    if serial not in {r["serial"] for r in read_index(lab.p("root"))} and \
            not lab.p("root", "newcerts", f"{serial}.pem").exists():
        raise LabError("UNKNOWN_SERIAL", f"ルートが署名した証明書ではありません: {serial}")
    is_current = serial == current
    with contextlib.ExitStack() as stack:
        if is_current:
            stack.enter_context(lab.ca_lock("issuer", allow_rotation=True))
        stack.enter_context(lab.ca_lock("root"))
        _request_revocation(lab, "root", serial, args.reason)
        if is_current:
            lab.set_ca_state("REVOKED", args.reason)
            _drop_moot_issuer_revocations(lab)
        res = _finish_pending(lab, "root")
    return {"revoked": serial, "ca_state": lab.ca_state()["status"] if is_current else None, "crl": res.get("crl")}


def _drop_moot_issuer_revocations(lab: Lab) -> None:
    """中間CAごと失効したら、配下の証明書の未完了の失効は不要になる（失効した鍵で CRL に署名しない）。"""
    entries = pending_revocations(lab, "issuer")
    if entries:
        serials = [e["serial"] for e in entries]
        lab.incident("ISSUER_REVOCATIONS_SUPERSEDED", serials=serials)
        lab.audit("revoke-superseded", "ok", "", which="issuer", serials=serials, reason="issuer_revoked")
        _save_pending(lab, "issuer", [])
        _mark_quarantine_revocations(lab, set(serials), "not_needed_issuer_revoked")
    st = lab.ca_state()
    if st.get("pending_revocation"):
        lab.set_ca_state(st["status"], "pending leaf revocations superseded by issuer revocation", pending_revocation=None)


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
# 失効確認の段階が結果を返したと分かるコード
REVOCATION_CODES = {"LEAF_REVOKED", "INTERMEDIATE_REVOKED", "REVOKED"} | INDETERMINATE


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

    def done(verdict: str, code: str, stopped_at: str, **extra) -> dict:
        # 「失効確認を要求した」と「失効確認が実行された」を分けて記録する。
        #   not_requested : --no-crl
        #   not_executed  : OpenSSL を呼ぶ前（名前の確認）で止まった
        #   reported      : OpenSSL が失効・CRL に関する結果を返した
        #   not_observed  : OpenSSL を呼んだが、内部で失効確認まで到達したかは観測していない
        if args.no_crl:
            observation = "not_requested"
        elif stopped_at != "openssl_verify":
            observation = "not_executed"
        elif code in REVOCATION_CODES:
            observation = "reported"
        else:
            observation = "not_observed"
        lab.audit("verify", verdict.lower(), info.get("serial", ""), code=code, host=host or "",
                  purpose=args.purpose, crl_check=not args.no_crl, attime=args.attime or "",
                  stopped_at=stopped_at, revocation_observation=observation)
        return {"result": verdict, "code": code, **base, "stopped_at": stopped_at,
                "revocation_observation": observation, **extra}

    # 名前は型付きで照合する。DNS 接続には dNSName、IP 接続には iPAddress の完全一致が必要。
    # （openssl verify -verify_hostname は該当する型の SAN が無いと CN を見に行くため、
    #   CN フォールバックを許さないよう、ここで先に判定する）
    if not info["san"]:
        return done("REJECT", "SAN_REQUIRED", "san_check")
    if host:
        want = host_identity(host)
        if want not in info["san"]:
            kind = want.split(":")[0]
            has_kind = any(s.startswith(kind + ":") for s in info["san"])
            return done("REJECT", "SAN_MISMATCH", "san_check", expected=want,
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
        return done("ACCEPT", "OK", "openssl_verify", openssl=summary[0] if summary else "")
    m = re.search(r"error (\d+) at (\d+) depth", out)
    code = classify_verify(int(m.group(1)), int(m.group(2))) if m else "VERIFY_ERROR"
    # 「失効している」と「失効状態を確認できない」は別の結果として記録し、
    # どちらの場合もラボ方針として接続は許可しない。
    verdict = "INDETERMINATE" if code in INDETERMINATE else "REJECT"
    return done(verdict, code, "openssl_verify", openssl=summary[0] if summary else "")


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
    observation = ("not_requested" if args.no_crl else
                   "reported" if res["code"] in REVOCATION_CODES else "not_observed")
    res["revocation_observation"] = observation
    lab.audit("tls-connect", res["result"].lower(), f"{args.host}:{args.port}",
              code=res["code"], crl_check=not args.no_crl, revocation_observation=observation)
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


def _check_crl(lab: Lab, which: str, ca_cert: Path, ledger: dict, problems: list[str], actions: list[str],
               now: dt.datetime) -> None:
    """CRL の照合。欠落・期限切れは crl-* で直せる（actions）。署名・発行者・後退・差し替え・台帳との不一致は
    改ざんや取り違えの疑いなので整合性の異常（problems）。"""
    name = "root.crl.pem" if which == "root" else "intermediate.crl.pem"
    meta = crl_meta(lab, lab.p("public", "crl", name), ca_cert)
    if not meta["present"]:
        actions.append(f"公開 CRL がない: {name} → crl-{which}")
        return
    if not meta.get("sig_ok"):
        problems.append(f"CRL の署名を {which} CA で検証できない: {name}")
        return
    if meta["issuer"] != cert_info(lab, ca_cert)["subject"]:
        problems.append(f"CRL の発行者が違う: {name}")
    if parse_iso(meta["next_update"]) < now:
        actions.append(f"CRL の次回更新期限切れ: {name} → crl-{which}")
    rec_path = lab.p(which, "db", "crl_published.json")
    if rec_path.exists():
        rec = read_json(rec_path)
        if meta["number"] < rec["number"]:
            problems.append(f"CRL 番号が後退している（ロールバックの疑い）: {name}")
        elif meta["sha256"] != rec["sha256"]:
            problems.append(f"公開 CRL が最後に生成したものと違う: {name}")
    revoked = {s for s, v in ledger.items() if v["row"]["status"] == "R"}
    pending = {e["serial"] for e in pending_revocations(lab, which)}
    unpublished = revoked - meta["revoked"]
    if unpublished - pending:
        problems.append(f"公開 CRL に未反映の失効: {sorted(unpublished - pending)}")
    if meta["revoked"] - revoked:
        problems.append(f"台帳にない失効が CRL にある: {sorted(meta['revoked'] - revoked)}")


def run_check(lab: Lab) -> dict:
    """承認 ⇔ 申請 ⇔ 台帳 ⇔ 発行物（中身） ⇔ 配置物 ⇔ 公開 CRL ⇔ 監査ログ を照合する。
    problems = 整合性の異常（改ざん・取り違え・欠落。復元後の再開を止める）
    actions  = 決まった操作で直せる状態（CRL の更新・未完了の失効・署名待ち・停止した発行の復旧など）"""
    problems: list[str] = []
    actions: list[str] = []
    warnings: list[str] = []
    now = utcnow()
    try:
        ca = lab.ca_state()
    except (OSError, ValueError):
        ca = {"status": "UNKNOWN", "generation": None}
        problems.append("中間CAの状態ファイルを読めない")

    def result() -> dict:
        return {"ok": not problems and not actions, "integrity_ok": not problems, "problems": problems,
                "actions": actions, "warnings": warnings, "ca_state": ca.get("status"),
                "generation": ca.get("generation")}

    rotating = lab.rotation_marker.exists()
    if rotating:
        actions.append("中間CAの世代交代が途中 → init-issuer --new-generation")
    if lab.superseded():
        warnings.append("この作業領域は復元先に置き換え済み（状態の変更はできません）")
    for label, path in [("ルート証明書", lab.root_cert), ("ルート台帳", lab.p("root", "db", "index.txt"))]:
        if not path.exists():
            problems.append(f"必須ファイルがない: {label}")
    if problems:
        return result()

    root_subject = cert_info(lab, lab.root_cert)["subject"]
    root_ledger = _check_ca(lab, lab.p("root"), lab.root_cert, "root", problems, root_subject)
    _check_crl(lab, "root", lab.root_cert, root_ledger, problems, actions, now)

    issuer_info = None
    if lab.issuer_cert.exists():
        issuer_info = cert_info(lab, lab.issuer_cert)
        if issuer_info["serial"] not in root_ledger:
            problems.append("中間CA証明書がルートの台帳にない")
        elif (root_ledger[issuer_info["serial"]]["info"] or {}).get("cert_sha256") != issuer_info["cert_sha256"]:
            problems.append("中間CA証明書がルートの発行物と一致しない")
        if ca["status"] == "ACTIVE" and root_ledger.get(issuer_info["serial"], {}).get("row", {}).get("status") == "R":
            problems.append("ルートで失効した中間CAが ACTIVE のまま")
    elif ca["status"] == "PENDING" or rotating:
        actions.append("中間CAが署名待ち → sign-intermediate")
    else:
        problems.append("必須ファイルがない: 中間CA証明書")

    # ルートが署名した有効な中間CAは、現在のもの1つだけのはず
    csr = lab.p("issuer", "certs", "intermediate.csr.pem")
    csr_spki = None
    if ca["status"] == "PENDING" and csr.exists():
        with contextlib.suppress(LabError, DerError, IndexError, ValueError):
            csr_spki = sha256_bytes(csr_structure(lab.openssl("req", "-in", csr, "-outform", "DER").stdout)["spki"])
    for serial, v in root_ledger.items():
        if v["row"]["status"] != "V" or (issuer_info and serial == issuer_info["serial"]):
            continue
        if csr_spki and v["info"] and v["info"]["pubkey_sha256"] == csr_spki:
            actions.append(f"ルートが署名済みの中間CA {serial} を採用する → sign-intermediate")
        else:
            problems.append(f"現在の中間CA以外に、ルートが署名した有効な中間CAがある: {serial}"
                            "（revoke-intermediate --serial で失効）")

    for which in ("root", "issuer"):
        pend = pending_revocations(lab, which)
        if pend:
            actions.append(f"[{which}] 公開まで完了していない失効: {[e['serial'] for e in pend]} → crl-{which}")
    if ca.get("pending_revocation") and not pending_revocations(lab, "issuer"):
        actions.append("未完了の失効の記録が残って中間CAが停止中 → crl-issuer")

    ledgers: dict = {}
    issuer_usable = ca["status"] not in ("REVOKED", "RETIRED")
    if lab.p("issuer", "db", "index.txt").exists():
        ledgers[ca["generation"]] = _check_ca(lab, lab.p("issuer"), lab.issuer_cert, "issuer", problems,
                                               issuer_info["subject"] if issuer_info else None)
        if issuer_info and ca["status"] in ("ACTIVE", "SUSPENDED"):
            _check_crl(lab, "issuer", lab.issuer_cert, ledgers[ca["generation"]], problems, actions, now)

    claimed: dict = {}
    for d in sorted(lab.p("requests").glob("REQ-*")):
        try:
            st = read_json(d / "state.json")
            rid = st["id"]
        except (OSError, ValueError, KeyError):
            problems.append(f"壊れた申請ディレクトリ（状態ファイルを読めない）: {d.name}")
            continue
        if st["status"] in ("SIGNING", "NEEDS_RECOVERY"):
            actions.append(f"停止した発行の照合が必要: {rid} → recover {rid}")
        if st["status"] == "ISSUED":
            actions.append(f"署名済み・未配置: {rid} → issue {rid}")
        if st["status"] == "QUARANTINED" and st.get("serial"):
            claimed[(st.get("generation", ca["generation"]), st["serial"])] = rid
            if st.get("revocation") == "pending" and not pending_revocations(lab, "issuer"):
                actions.append(f"隔離した証明書の失効が未完了: {rid} → revoke {st['serial']}")
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
            # 葉・fullchain（葉＋中間CA の2枚）・公開コピー・サーバー鍵との対応
            for d_problem in deployment_problems(lab, st, rec, require_key=False):
                if d_problem == "server_key_encrypted":
                    warnings.append(f"サーバー鍵が暗号化されているため対応を確認できない: {rid}")
                else:
                    problems.append(f"配置された証明書が発行記録と違う（{d_problem}）: {rid}")
            key = st.get("server_key")
            if key and not (Path(key) if Path(key).is_absolute() else lab.p(key)).exists():
                warnings.append(f"サーバー鍵がこの作業領域にない（バックアップには含めない）: {rid}")
    for gen, ledger in ledgers.items():
        if gen != ca["generation"] or not issuer_usable:
            continue  # 失効・保管済みの世代の証明書は、中間CAごと無効
        for serial, v in ledger.items():
            if (gen, serial) in claimed or v["row"]["status"] != "V":
                continue
            if any(e["serial"] == serial for e in pending_revocations(lab, "issuer")):
                continue
            problems.append(f"申請に紐づかない有効な証明書: gen{gen} {serial}")

    audit = verify_audit_chain(lab.home)
    if not audit["ok"]:
        problems.append(f"監査ログ: {audit['code']}")
    if lab.is_frozen():
        problems.append("監査ログの異常により凍結中")
    return result()


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
# 復元で受け付ける最上位（recovery/・locks/・secrets/・server/private はアーカイブから受け付けない）
RESTORE_ALLOWED_TOP = {"root", "issuer", "archive", "requests", "approvals", "journal", "audit", "anchor",
                       "incidents", "public", "server"}
BACKUP_FORMAT = "pkilab-backup/2"
KDF_ITER_MIN, KDF_ITER_MAX = 10_000, 5_000_000


def read_passphrase(path: Path) -> bytes:
    """パスフレーズファイルの1行目（改行を除く）。openssl の -pass file: と同じ読み方にそろえる。"""
    try:
        data = path.read_bytes()
    except OSError:
        raise LabError("FILE_NOT_FOUND", f"パスフレーズのファイルを読めません: {path}")
    line = data.split(b"\n", 1)[0].rstrip(b"\r")
    if not line:
        raise LabError("EMPTY_PASSPHRASE", f"パスフレーズが空です: {path}")
    return line


def _manifest_mac(pass_file: Path, header: dict, blob: bytes) -> str:
    """マニフェストの項目（形式・KDF 設定・監査の位置など）と暗号化データの両方を認証する。
    鍵導出には、現在の設定ではなくマニフェストに記録した保存時の反復回数を使う。"""
    key = hashlib.pbkdf2_hmac("sha256", read_passphrase(pass_file),
                              b"pkilab-backup-mac" + bytes.fromhex(header["hmac_salt"]), header["kdf_iter"])
    return hmac.new(key, canonical(header) + b"\n" + blob, hashlib.sha256).hexdigest()


def verify_backup(backup: Path, pass_file: Path) -> tuple[bool, dict | None, str]:
    man_path = backup.with_name(backup.name + ".manifest.json")
    if not backup.is_file():
        return False, None, f"バックアップがありません: {backup}"
    if not man_path.is_file():
        return False, None, "マニフェストがありません"
    if not pass_file.is_file():
        return False, None, "バックアップのパスフレーズがありません"
    try:
        man = read_json(man_path)
    except (ValueError, OSError):
        return False, None, "マニフェストを読めません"
    if not isinstance(man, dict) or "hmac" not in man:
        return False, None, "マニフェストの形式が不正です"
    mac = man.pop("hmac")
    if man.get("format") != BACKUP_FORMAT:
        return False, None, f"対応していない形式です: {man.get('format')}（{BACKUP_FORMAT} のみ）"
    iters = man.get("kdf_iter")
    if not isinstance(iters, int) or isinstance(iters, bool) or not KDF_ITER_MIN <= iters <= KDF_ITER_MAX:
        return False, None, f"KDF の反復回数が範囲外です: {iters}"
    if man.get("file") != backup.name or not isinstance(man.get("hmac_salt"), str):
        return False, None, "マニフェストとファイルが対応しません"
    try:
        expected = _manifest_mac(pass_file, man, backup.read_bytes())
    except ValueError:
        return False, None, "マニフェストを読めません"
    except LabError as e:
        return False, None, e.message
    if not isinstance(mac, str) or not hmac.compare_digest(expected, mac):
        return False, None, "HMAC が一致しません（改ざん・パスフレーズ違い）"
    return True, man, ""


def cmd_backup(lab: Lab, args) -> dict:
    """CA 一式（鍵は暗号化済みのまま・台帳・発行物・失効・CRL番号・承認・監査）を暗号化し、
    マニフェストと暗号化データの両方に HMAC を付けて保存する。
    パスフレーズ（secrets/）とサーバー鍵は含めない（別経路で保管する前提）。"""
    lab.require("backup")
    if not KDF_ITER_MIN <= KDF_ITER <= KDF_ITER_MAX:
        raise LabError("BAD_KDF_ITER", f"PKILAB_KDF_ITER は {KDF_ITER_MIN}〜{KDF_ITER_MAX} にしてください（復元できなくなるため）")
    pass_file = Path(args.pass_file) if args.pass_file else lab.p("secrets", "backup.pass")
    ensure_passphrase(pass_file)
    read_passphrase(pass_file)
    with lab.ca_lock("issuer"), lab.ca_lock("root"), lab.req_lock(), lab.audit_lock():
        stamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
        tail = audit_tail(lab.home)
        fd, tmp_name = tempfile.mkstemp(suffix=".tar.gz", dir=lab.p("backups"))
        os.close(fd)
        tmp_tar = Path(tmp_name)
        tmp_enc = tmp_tar.with_suffix(".enc.tmp")
        try:
            with tarfile.open(tmp_tar, "w:gz") as tar:
                for item in BACKUP_ITEMS:
                    if lab.p(item).exists():
                        tar.add(lab.p(item), arcname=item,
                                filter=lambda ti: None if ti.name.endswith(".lock") else ti)
            lab.openssl("enc", "-aes-256-cbc", "-pbkdf2", "-iter", KDF_ITER, "-salt",
                        "-in", tmp_tar, "-out", tmp_enc, "-pass", f"file:{pass_file}")
            # 同じ秒の2回目でも上書きしない（一意な名前に移す）
            while True:
                out = lab.p("backups", f"pkilab-{stamp}-{secrets.token_hex(3)}.tar.gz.enc")
                if not out.exists():
                    break
            os.replace(tmp_enc, out)
            fsync_dir(out.parent)
        finally:
            tmp_tar.unlink(missing_ok=True)
            tmp_enc.unlink(missing_ok=True)
        blob = out.read_bytes()
        header = {"format": BACKUP_FORMAT, "file": out.name, "sha256": sha256_bytes(blob),
                  "cipher": "aes-256-cbc", "kdf": "pbkdf2-hmac-sha256", "kdf_iter": KDF_ITER,
                  "hmac_salt": secrets.token_bytes(16).hex(), "created": iso(utcnow()),
                  "audit_seq": tail.get("seq"), "audit_head": tail.get("hash"),
                  "generation": lab.ca_state()["generation"],
                  "excluded": ["secrets/", "server/private/", "lab/config/（リポジトリで管理）"]}
        manifest = {**header, "hmac": _manifest_mac(pass_file, header, blob)}
        write_json(out.with_name(out.name + ".manifest.json"), manifest)
    lab.audit("backup", "ok", out.name, sha256=header["sha256"], audit_seq=header["audit_seq"])
    return {"backup": str(out), "manifest": str(out.with_name(out.name + ".manifest.json")),
            "sha256": header["sha256"]}


# 証明書・CRL・台帳の状態を変えない操作（バックアップ後に記録されても巻き戻りにならない）
READONLY_OPS = {"verify", "tls-connect", "check", "restore", "backup", "bundle", "export-events", "serve-https"}


def source_available(source: Path | None) -> bool:
    """初期化済みの作業領域か（存在しない・空のディレクトリは「元の作業領域なし」として扱う）。"""
    return source is not None and (source / "root" / "certs" / "root.cert.pem").exists()


def state_fingerprint(home: Path) -> dict:
    """監査ログに頼らずに比べられる永続状態の要約（台帳・未完了の失効・中間CAの状態・世代・申請の状態）。
    監査ログに書く前に止まった変更（署名直後や失効途中の停止）も、ここで差として現れる。"""
    def h(path: Path):
        try:
            return sha256_file(path) if path.exists() else None
        except OSError:
            return "unreadable"
    fp = {"root_ledger": h(home / "root" / "db" / "index.txt"),
          "issuer_ledger": h(home / "issuer" / "db" / "index.txt"),
          "root_pending": h(home / "root" / "db" / "revocation_pending.json"),
          "issuer_pending": h(home / "issuer" / "db" / "revocation_pending.json"),
          "intermediate_cert": h(home / "issuer" / "certs" / "intermediate.cert.pem"),
          "rotation": (home / "rotation" / "issuer.json").exists(),
          "archives": sorted(p.name for p in (home / "archive").glob("issuer-gen*")) if (home / "archive").exists() else [],
          "issuer_state": None, "requests": {}}
    try:
        st = read_json(home / "issuer" / "state.json")
        fp["issuer_state"] = [st.get("status"), st.get("generation")]
    except FileNotFoundError:
        pass
    except (OSError, ValueError, AttributeError):
        fp["issuer_state"] = "unreadable"
    if (home / "requests").exists():
        for d in sorted((home / "requests").glob("REQ-*")):
            try:
                fp["requests"][d.name] = read_json(d / "state.json").get("status")
            except (OSError, ValueError, AttributeError):
                fp["requests"][d.name] = "unreadable"
    return fp


def fingerprint_diff(a: dict, b: dict) -> list[str]:
    diffs = [k for k in a if k != "requests" and a[k] != b.get(k)]
    for rid in sorted(set(a["requests"]) | set(b["requests"])):
        if a["requests"].get(rid) != b["requests"].get(rid):
            diffs.append(f"request:{rid}")
    return diffs


def _load_checkpoint(path: Path) -> dict | None:
    try:
        cp = read_json(path)
    except (OSError, ValueError):
        return None
    if not isinstance(cp, dict) or not isinstance(cp.get("seq"), int) or isinstance(cp.get("seq"), bool) \
            or cp["seq"] < 0 or not isinstance(cp.get("hash"), str):
        return None
    return cp


def check_freshness(source: Path | None, dest: Path, checkpoint: Path | None) -> dict:
    """復元したログが、信頼できる最新のチェックポイントまでの状態変更をすべて含むかを確かめる。
    元の作業領域のログは、連鎖と基準ハッシュを検証でき、凍結・置き換え済みでないときだけ判断材料に使う。
    （ログと基準ハッシュの両方を書き換えられた場合は、別媒体のチェックポイントでしか検出できない）"""
    def no(detail: str, **kw) -> dict:
        return {"freshness_confirmed": False, "freshness_detail": detail, **kw}

    rres = verify_audit_chain(dest)
    if not rres.get("internal_ok"):
        return no("復元したログの連鎖を検証できません")
    restored = _audit_lines(dest)
    r_len, r_head = len(restored), rres["head"]

    def source_problem() -> dict | None:
        """元の作業領域のログ・基準を判断材料に使ってよいか（凍結・置き換え済み・連鎖異常なら使わない）。"""
        if not source_available(source):
            return no("元の作業領域のログを確認できないため、バックアップ後の変更の有無が分かりません",
                      source_unavailable=True)
        if (source / "recovery" / "superseded.json").exists():
            return no("元の作業領域は既に別の復元先に置き換え済みです", source_superseded=True)
        if (source / "audit" / "FROZEN.json").exists():
            return no("元の作業領域は監査異常で凍結中のため、そのログを判断材料に使いません", source_frozen=True)
        sres = verify_audit_chain(source)
        if not sres["ok"]:
            return no(f"元の作業領域のログを検証できません（{sres['code']}）", source_audit=sres["code"])
        return None

    if checkpoint is not None:
        cp = _load_checkpoint(checkpoint)
        if cp is None:
            return no(f"チェックポイントを読めないか形式が不正です: {checkpoint}")
        cp_source = "external"
    else:
        bad = source_problem()  # 元の基準を使うなら、元のログが検証できることが前提
        if bad:
            return bad
        cp, err = _read_anchor(source)
        if cp is None:
            return no(f"元の作業領域の基準ハッシュを読めません（{err or 'ANCHOR_MISSING'}）")
        cp_source = "source_anchor"
    base = {"checkpoint_seq": cp["seq"], "checkpoint_source": cp_source, "backup_seq": r_len}
    if cp["seq"] <= r_len:
        ok = (cp["hash"] == "0" * 64) if cp["seq"] == 0 else _parse_entry(restored[cp["seq"] - 1]) is not None \
            and _parse_entry(restored[cp["seq"] - 1])["hash"] == cp["hash"]
        return {"freshness_confirmed": ok, **base,
                **({} if ok else {"freshness_detail": "チェックポイントと復元したログが一致しません"})}
    # チェックポイントの方が新しい：差分を元のログで確かめる（検証できる場合だけ）
    bad = source_problem()
    if bad:
        return {**bad, **base}
    live = _audit_lines(source)
    entry = _parse_entry(live[cp["seq"] - 1]) if len(live) >= cp["seq"] else None
    if entry is None or entry["hash"] != cp["hash"]:
        return no("チェックポイントが、検証した元のログに含まれていません", **base)
    if r_len > 0 and (_parse_entry(live[r_len - 1]) or {}).get("hash") != r_head:
        return no("復元したログと元のログが分岐しています", **base)
    later = [_parse_entry(x) for x in live[r_len:cp["seq"]]]
    changing = [f"{e['seq']}:{e.get('op')}" for e in later if e.get("op") not in READONLY_OPS]
    if changing:
        return no("バックアップ後の状態変更（失効など）が含まれていません。復元すると巻き戻ります",
                  lost_changes=changing, **base)
    return {"freshness_confirmed": True, **base,
            "freshness_detail": f"バックアップ後の {len(later)} 件は、検証済みログ上の読み取り専用の操作のみ"}


def _freshness(source: Path | None, dest: Path, checkpoint: Path | None) -> dict:
    """使える基準のすべてで新しさを確かめる（どれか一つでも確認できなければ新しいとみなさない）。
    - state:    元の作業領域の台帳・CA状態・申請状態と、復元したものの比較（監査ログに頼らない）
    - source:   元の作業領域の検証済みログ（凍結・改ざんで信頼できず、別媒体の基準があるときは使わない）
    - external: 別媒体のチェックポイント（指定時）"""
    checks: dict = {}
    if source_available(source):
        diff = fingerprint_diff(state_fingerprint(source), state_fingerprint(dest))
        checks["state"] = {"freshness_confirmed": not diff, **({
            "state_differs": diff,
            "freshness_detail": "元の作業領域の台帳・CA状態・申請状態が、復元したものと違います（バックアップ後の変更が失われます）",
        } if diff else {})}
        src = check_freshness(source, dest, None)
        untrusted = src.get("source_frozen") or src.get("source_audit") or src.get("source_superseded")
        if not (untrusted and checkpoint is not None):
            checks["source"] = src
    if checkpoint is not None:
        checks["external"] = check_freshness(source if source_available(source) else None, dest, checkpoint)
    if not checks:
        return {"freshness_confirmed": False, "freshness_detail": "元の作業領域もチェックポイントもありません"}
    failing = [c for c in checks.values() if not c["freshness_confirmed"]]
    out = {**(failing[0] if failing else next(iter(checks.values()))),
           "freshness_confirmed": not failing, "checks": checks}
    lost = sorted({x for c in checks.values() for x in c.get("lost_changes", [])})
    if lost:
        out["lost_changes"] = lost
    return out


def _key_access(lab: Lab, key: Path, pass_file: Path | None) -> bool:
    if not key.exists() or not pass_file or not pass_file.exists():
        return False
    return lab.openssl("pkey", "-in", key, "-passin", f"file:{pass_file}", "-noout", check=False).returncode == 0


READY_KEYS = ("archive_integrity_ok", "state_consistent", "freshness_confirmed", "key_access_ready")


def cmd_restore(lab: Lab, args) -> dict:
    """空の隔離ディレクトリへ復元し、準備状況を項目ごとに判定する。
    最初に「復元中」の保留を永続化するので、途中で止まっても復元先では発行・CRL 公開・再開ができない。
    --home が初期化済みの作業領域でなければ「元の作業領域なし」として扱い、そこには何も書かない。"""
    lab.require("restore")
    dest = Path(args.dest).resolve()
    backup = Path(args.backup).resolve()
    if not backup.is_file():
        raise LabError("FILE_NOT_FOUND", f"バックアップがありません: {backup}")
    if dest.exists() and not dest.is_dir():
        raise LabError("BAD_DEST", "復旧先はディレクトリにしてください")
    if dest.exists() and any(dest.iterdir()):
        raise LabError("DEST_NOT_EMPTY", "復旧先は空の隔離ディレクトリにしてください")
    if dest == lab.home or lab.home in dest.parents:
        raise LabError("DEST_INSIDE_SOURCE", "復旧先は元の作業領域の外にしてください")
    src_ok = source_available(lab.home)
    pass_file = Path(args.pass_file) if args.pass_file else lab.p("secrets", "backup.pass")
    checkpoint = Path(args.checkpoint).resolve() if args.checkpoint else None
    if checkpoint is not None and not checkpoint.is_file():
        raise LabError("FILE_NOT_FOUND", f"チェックポイントがありません: {checkpoint}")
    dest.mkdir(parents=True, exist_ok=True)
    try:
        (dest / "recovery").mkdir()  # 同時に2つの復元が同じ場所を使わないよう、排他的に作る
    except FileExistsError:
        raise LabError("DEST_NOT_EMPTY", "復旧先が別の復元で使われています")
    restored = Lab(dest, lab.actor, "auditor")
    hold = {"status": "RESTORING", "since": iso(utcnow()), "from": backup.name,
            "source_home": str(lab.home) if src_ok else None,
            "source_instance": lab.instance_id() if src_ok else None,
            "checkpoint": str(checkpoint) if checkpoint else None}
    write_json(restored.hold_marker, hold)
    report: dict = {"restored_to": str(dest), **{k: False for k in READY_KEYS}, "resume_authorized": False,
                    "source_available": src_ok}

    def note(op_result: str, **details) -> None:
        if src_ok:
            lab.audit_if_possible("restore", op_result, str(dest), **details)

    # 1. マニフェストと暗号化データの HMAC を、復号する前に検証する
    ok, man, reason = verify_backup(backup, pass_file)
    report["archive_integrity_ok"] = ok
    if not ok:
        report.update(reason=reason, ready=False)
        write_json(restored.hold_marker, {**hold, "status": "REJECTED", "reason": reason})
        note("rejected", reason="integrity")
        return report

    fd, tmp_name = tempfile.mkstemp(suffix=".tar.gz", dir=dest)
    os.close(fd)
    tmp_tar = Path(tmp_name)
    try:
        lab.openssl("enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", man["kdf_iter"],
                    "-in", backup, "-out", tmp_tar, "-pass", f"file:{pass_file}")
        with tarfile.open(tmp_tar) as tar:
            for m in tar.getmembers():
                parts = Path(m.name).parts
                if (m.name.startswith("/") or ".." in parts or not parts
                        or not (m.isdir() or m.isfile())          # リンク・FIFO・デバイスは受け付けない
                        or parts[0] not in RESTORE_ALLOWED_TOP
                        or (len(parts) == 1 and not m.isdir())
                        or (parts[0] == "server" and len(parts) > 1 and parts[1] != "certs")):
                    raise LabError("BACKUP_UNSAFE", f"復元できないパスを含むバックアップです: {m.name}")
            tar.extractall(dest, **({"filter": "data"} if hasattr(tarfile, "data_filter") else {}))
    finally:
        tmp_tar.unlink(missing_ok=True)
    _crash_point("restore-after-extract")

    restored.layout()  # 復元先には新しい識別子が付く（元の作業領域とは別のもの）
    # 2. 状態の整合（監査ログ連鎖・台帳・発行物・CRL の照合。復元先には書き込まない）
    chk = run_check(restored)
    report["check"] = chk
    report["state_consistent"] = chk["integrity_ok"]
    # 3. 新しさ：元の作業領域の状態・検証できたログ・別媒体のチェックポイントと比べる
    if src_ok:
        with lab.audit_lock():
            report.update(_freshness(lab.home, dest, checkpoint))
    else:
        report.update(_freshness(None, dest, checkpoint))
    # 4. 別保管のパスフレーズで CA 鍵を開けるか
    root_pass = Path(args.root_pass_file) if args.root_pass_file else lab.root_pass
    issuer_pass = Path(args.issuer_pass_file) if args.issuer_pass_file else lab.issuer_pass
    report["key_access_ready"] = (_key_access(lab, restored.root_key, root_pass)
                                  and _key_access(lab, restored.issuer_key, issuer_pass))
    # 5. 保留（HELD）。resume で、その時点の状態をもう一度確かめてから再開する
    write_json(restored.hold_marker, {**hold, "status": "HELD", "checked_at": iso(utcnow()),
                                      "backup_audit_seq": man.get("audit_seq"),
                                      "backup_audit_head": man.get("audit_head"),
                                      "generation": man.get("generation"),
                                      **{k: report[k] for k in READY_KEYS}})
    report["ready"] = all(report[k] for k in READY_KEYS)
    report["actions_after_resume"] = chk["actions"]
    note("ready" if report["ready"] else "needs_review", **{k: report[k] for k in READY_KEYS})
    return report


def cmd_resume(lab: Lab, args) -> dict:
    """復旧保留を解除する。整合・鍵・新しさを「今」もう一度確かめ、元の作業領域の発行・失効・申請・記録を
    ロックで止めたまま新しさを判定し、その場で元の作業領域を置き換え済み（superseded）にする。
    元の作業領域は restore 時の識別子で確かめる（別のコピーを指定しても置き換えない）。"""
    lab.require("resume")
    if not lab.on_hold():
        return {"action": "none", "reason": "復旧保留ではありません"}
    hold = read_json(lab.hold_marker)
    if hold.get("status") != "HELD":
        return {"action": "held", "blockers": ["restore_incomplete（復元が完了していません。空のディレクトリへ restore をやり直してください）"],
                "hold": hold}
    for src in (args.root_pass_file, args.issuer_pass_file, args.checkpoint):
        if src and not Path(src).is_file():
            raise LabError("FILE_NOT_FOUND", f"ファイルがありません: {src}")
    for src, dst in ((args.root_pass_file, lab.p("secrets", "root.pass")),
                     (args.issuer_pass_file, lab.p("secrets", "issuer.pass"))):
        if src:
            write_private(dst, Path(src).read_bytes())  # 別経路で保管していた鍵解除情報を戻す
    source = Path(args.source).resolve() if args.source else \
        (Path(hold["source_home"]) if hold.get("source_home") else None)
    checkpoint = Path(args.checkpoint).resolve() if args.checkpoint else \
        (Path(hold["checkpoint"]) if hold.get("checkpoint") else None)
    src_lab, binding = None, None
    if source_available(source) and source != lab.home:
        cand = Lab(source, lab.actor, "operator")
        if hold.get("source_instance") and cand.instance_id() == hold["source_instance"]:
            src_lab = cand
        else:
            binding = "source_mismatch（指定した作業領域は、このバックアップの復元元ではありません）"
    elif args.source:
        binding = "source_unavailable（指定した作業領域が見つかりません。止めたことを確認できるなら --source を外して --source-stopped）"

    # 前回の resume が元を置き換えた直後に止まっていた場合は、保留の解除だけをやり直す
    if src_lab is not None and src_lab.superseded():
        sup = read_json(src_lab.superseded_marker)
        if sup.get("replaced_by_instance") and sup.get("replaced_by_instance") == lab.instance_id():
            if not args.confirm:
                return {"action": "held", "blockers": [], "confirm_required": True, "note": "元の作業領域は置き換え済み"}
            lab.hold_marker.unlink()
            fsync_dir(lab.hold_marker.parent)
            lab.audit("resume", "ok", "", resumed_after_interruption=True, source_fenced=True)
            return {"action": "resumed", "source_fenced": True, "resumed_after_interruption": True}

    chk = run_check(lab)
    keys = _key_access(lab, lab.root_key, lab.root_pass) and _key_access(lab, lab.issuer_key, lab.issuer_pass)
    with contextlib.ExitStack() as stack:
        if src_lab is not None:
            # 元の作業領域の発行・失効・申請・記録を止めた状態で判定する（判定直後の変更の取りこぼしを防ぐ）
            for cm in (src_lab.ca_lock("issuer", allow_rotation=True), src_lab.ca_lock("root"),
                       src_lab.req_lock(), src_lab.audit_lock()):
                stack.enter_context(cm)
        fresh = _freshness(source if src_lab else None, lab.home, checkpoint)
        blockers = []
        if not chk["integrity_ok"]:
            blockers.append("state_consistent")
        if not keys:
            blockers.append("key_access_ready")
        if binding:
            blockers.append(binding)
        if not fresh["freshness_confirmed"] and not args.accept_stale:
            blockers.append("freshness_confirmed（--accept-stale で失われた履歴を受け入れる判断を明示）")
        if src_lab is None and not args.source_stopped:
            blockers.append("source_not_fenced（元の作業領域に届かないため止められません。止めたことを確認して --source-stopped）")
        if blockers or not args.confirm:
            return {"action": "held", "blockers": blockers, "confirm_required": not args.confirm,
                    "freshness": fresh, "check": chk}
        if src_lab is not None:
            write_json(src_lab.superseded_marker, {
                "since": iso(utcnow()), "by": lab.actor, "replaced_by": str(lab.home),
                "replaced_by_instance": lab.instance_id(), "checkpoint_seq": fresh.get("checkpoint_seq")})
            with contextlib.suppress(Exception):
                src_lab.incident("SUPERSEDED_BY_RESTORE", replaced_by=str(lab.home))
            _crash_point("resume-after-fence")
        lab.hold_marker.unlink()
        fsync_dir(lab.hold_marker.parent)
    lab.audit("resume", "ok", "", accepted_stale=bool(args.accept_stale), source_fenced=src_lab is not None,
              freshness_confirmed=fresh["freshness_confirmed"])
    return {"action": "resumed", "source_fenced": src_lab is not None, "freshness": fresh,
            "actions_after_resume": chk["actions"]}


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
SAFE_DETAIL_KEYS = {"code", "san", "reason", "host", "purpose", "not_after", "next_update", "crl_number",
                    "action", "revoked", "stopped_at", "revocation_observation"}


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
            # 要求（設定）と観測を分ける。設定が有効でも、実行されたとは限らない
            details["revocation_requested"] = bool(e["details"].get("crl_check"))
            details.setdefault("revocation_observation", "not_observed")
            details["stages"] = "not_observed"
        elif e["op"] == "tls-connect":
            t = "TLS_HANDSHAKE_COMPLETED" if e["result"] == "accept" else "TLS_HANDSHAKE_FAILED"
            observation = "aggregate"
            details["revocation_requested"] = bool(e["details"].get("crl_check"))
            details.setdefault("revocation_observation", "not_observed")
            details["stages"] = "not_observed"
        if not t:
            continue
        events.append({"seq": e["seq"], "ts": e["ts"], "type": t, "role": e["role"],
                       "origin": "measured", "observation": observation,
                       # シリアル等はそのまま出さず短いハッシュにする
                       "target": sha256_bytes(e["target"].encode())[:12] if e["target"] else "",
                       "result": e["result"], "details": details})
    doc = {"schema": "pkilab-events/2", "measured": True,
           "note": "PKI Lab の監査ログ（ハッシュ連鎖を検証済み）から生成。秘密鍵・パスフレーズ・証明書本体は含まない。"
                   "検証・TLS は処理全体の結果のみで、内部の段階は観測していない。"
                   "revocation_requested は設定、revocation_observation は観測（not_requested / not_executed / "
                   "reported / not_observed）。",
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
           "superseded": lab.superseded(), "rotation_in_progress": lab.rotation_marker.exists(),
           "pending_revocations": {w: [e["serial"] for e in pending_revocations(lab, w)] for w in ("root", "issuer")
                                   if lab.p(w).exists()},
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
            else:
                sp.add_argument("--serial", help="ルート台帳の中間CAのシリアル（既定: 現在の中間CA）")
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
            sp.add_argument("--source", help="元の作業領域（既定: restore 時の記録）")
            sp.add_argument("--checkpoint", help="別に保管した最新の anchor.json")
            sp.add_argument("--source-stopped", action="store_true",
                            help="元の作業領域に届かない場合に、止めたことを確認済みと明示する")
    return ap


def run(lab: Lab, cmd: str, args) -> dict:
    fn, _ = COMMANDS[cmd]
    if cmd not in NO_AUDIT_PRECHECK:
        lab.ensure_audit_ok()
    if cmd in HOLD_BLOCKED:
        if lab.on_hold():
            hold = read_json(lab.hold_marker)
            raise LabError("RECOVERY_HOLD", "復旧保留中です（restore 未完了なら作り直し、完了済みなら resume --confirm）",
                           hold_status=hold.get("status"))
        if lab.superseded():
            raise LabError("SUPERSEDED", "この作業領域は復元先に置き換えられたため、状態を変更できません",
                           superseded=read_json(lab.superseded_marker))
        if lab.rotation_marker.exists() and cmd != "init-issuer":
            raise LabError("ROTATION_IN_PROGRESS", "中間CAの世代交代が途中です（init-issuer --new-generation で再開）")
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
