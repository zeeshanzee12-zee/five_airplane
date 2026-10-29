#!/usr/bin/env python3
"""
AI-Powered Cyber Forensic Triage Tool
=====================================
Rapidly scans a directory (e.g. a mounted disk image or collected evidence
folder), extracts forensic features from each file, scores each one with a
hybrid engine (explainable rules + ML anomaly detection) and outputs a
prioritised list of what an investigator should examine first.

READ-ONLY: files are opened in binary read mode only; nothing is modified.

Usage:
    python triage.py /path/to/evidence --out report --top 25
    python triage.py /path/to/evidence --known-bad hashes.txt --ai-summary

Outputs: report.json, report.html (and a ranked table in the terminal).
Dependencies: stdlib only. Optional: scikit-learn (IsolationForest),
anthropic (+ ANTHROPIC_API_KEY) for the natural-language summary.
"""
import argparse, hashlib, html, json, math, os, re, sys, time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

MAX_READ = 5 * 1024 * 1024  # read at most 5 MB per file for content analysis

# ---------- signatures & indicators ----------
MAGIC = [  # (header bytes, type)
    (b"MZ", "pe_executable"), (b"\x7fELF", "elf_executable"),
    (b"\xcf\xfa\xed\xfe", "macho_executable"), (b"PK\x03\x04", "zip_archive"),
    (b"%PDF", "pdf"), (b"\xff\xd8\xff", "jpeg"), (b"\x89PNG", "png"),
    (b"GIF8", "gif"), (b"Rar!", "rar_archive"), (b"7z\xbc\xaf", "7z_archive"),
    (b"SQLite format 3", "sqlite_db"), (b"\xd0\xcf\x11\xe0", "ole_office"),
    (b"#!", "script"),
]
EXT_TO_TYPE = {
    ".exe": "pe_executable", ".dll": "pe_executable", ".sys": "pe_executable",
    ".elf": "elf_executable", ".zip": "zip_archive", ".pdf": "pdf",
    ".jpg": "jpeg", ".jpeg": "jpeg", ".png": "png", ".gif": "gif",
    ".rar": "rar_archive", ".7z": "7z_archive", ".db": "sqlite_db",
    ".sqlite": "sqlite_db", ".doc": "ole_office", ".xls": "ole_office",
    ".sh": "script",
}
EXEC_TYPES = {"pe_executable", "elf_executable", "macho_executable"}
RISKY_EXT = {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
             ".jar", ".lnk", ".hta", ".msi", ".sh", ".py"}
DOC_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt"}
STAGING_DIRS = ("temp", "tmp", "downloads", "appdata", "public", "$recycle.bin",
                "/dev/shm", "programdata")

# (name, regex, weight) -- applied to file text content
IOC_PATTERNS = [
    ("powershell_encoded", re.compile(rb"powershell[^\n]{0,40}-e(nc|ncodedcommand)\b", re.I), 25),
    ("download_cradle", re.compile(rb"(Invoke-WebRequest|DownloadString|certutil\s+-urlcache|bitsadmin)", re.I), 20),
    ("credential_tool", re.compile(rb"(mimikatz|sekurlsa|lsass\.dmp|procdump\s+.*lsass)", re.I), 30),
    ("persistence", re.compile(rb"(schtasks\s+/create|CurrentVersion\\Run|crontab\s+-|/etc/rc\.local)", re.I), 18),
    ("shell_reverse", re.compile(rb"(/dev/tcp/|nc\s+-e|bash\s+-i\s+>&)", re.I), 28),
    ("ransom_note", re.compile(rb"(your files (have been|are) encrypted|bitcoin|decrypt your)", re.I), 25),
    ("anti_forensics", re.compile(rb"(wevtutil\s+cl|Clear-EventLog|shred\s|history\s+-c|vssadmin\s+delete)", re.I), 25),
    ("base64_blob", re.compile(rb"[A-Za-z0-9+/]{200,}={0,2}"), 8),
]
URL_RE = re.compile(rb"https?://[^\s\"'<>]{4,100}", re.I)
IP_RE = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
FAILED_LOGIN_RE = re.compile(rb"(failed password|authentication failure|logon failure|4625)", re.I)


# ---------- feature extraction ----------
def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def detect_type(head: bytes) -> str:
    for sig, name in MAGIC:
        if head.startswith(sig):
            return name
    return "text" if head and all(b in range(9, 127) or b > 127 for b in head[:512]) and b"\x00" not in head[:512] else "unknown_binary"


def hash_file(path: Path):
    sha, md5 = hashlib.sha256(), hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            sha.update(chunk); md5.update(chunk)
    return sha.hexdigest(), md5.hexdigest()


def iso(ts): return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")


def extract(path: Path, root: Path, known_bad: set) -> dict | None:
    try:
        st = path.stat()
        with open(path, "rb") as f:
            data = f.read(MAX_READ)
        sha, md5 = hash_file(path)
    except (OSError, PermissionError):
        return None
    ext = path.suffix.lower()
    ftype = detect_type(data[:16])
    lower_path = "/" + str(path.relative_to(root)).lower().replace("\\", "/")
    iocs = [(n, w) for n, rx, w in IOC_PATTERNS if rx.search(data)]
    parts = path.name.lower().split(".")
    return {
        "path": str(path.relative_to(root)), "size": st.st_size, "sha256": sha, "md5": md5,
        "modified": iso(st.st_mtime), "mtime": st.st_mtime, "ctime": st.st_ctime,
        "atime": st.st_atime, "ext": ext, "magic_type": ftype,
        "entropy": round(entropy(data), 3),
        "hidden": path.name.startswith("."),
        "in_staging_dir": any(s in lower_path for s in STAGING_DIRS),
        "double_ext": len(parts) > 2 and ("." + parts[-1]) in RISKY_EXT and ("." + parts[-2]) in DOC_EXT,
        "ext_mismatch": bool(ext in EXT_TO_TYPE and ftype not in (EXT_TO_TYPE[ext], "unknown_binary")
                             and not (ext in (".docx", ".xlsx") and ftype == "zip_archive")),
        "disguised_exec": ftype in EXEC_TYPES and ext not in RISKY_EXT,
        "known_bad": sha in known_bad,
        "iocs": [n for n, _ in iocs], "ioc_weight": sum(w for _, w in iocs),
        "urls": sorted({u.decode("latin1") for u in URL_RE.findall(data)})[:10],
        "ips": sorted({i.decode() for i in IP_RE.findall(data)})[:10],
        "failed_logins": len(FAILED_LOGIN_RE.findall(data)),
    }


# ---------- scoring ----------
def rule_score(r: dict, now: float) -> tuple[float, list]:
    s, why = 0.0, []
    def add(pts, msg): nonlocal s; s += pts; why.append(f"+{pts:g} {msg}")
    if r["known_bad"]: add(100, "hash matches known-bad list")
    if r["disguised_exec"]: add(35, f"executable ({r['magic_type']}) with non-executable extension '{r['ext']}'")
    if r["double_ext"]: add(30, "double extension (document-looking executable)")
    elif r["ext_mismatch"]: add(20, f"extension '{r['ext']}' does not match content ({r['magic_type']})")
    if r["magic_type"] in EXEC_TYPES and r["in_staging_dir"]: add(20, "executable in temp/download/staging directory")
    if r["entropy"] > 7.4 and r["magic_type"] in EXEC_TYPES | {"unknown_binary"}:
        add(18, f"very high entropy ({r['entropy']}) - possible packing/encryption")
    if r["ioc_weight"]: add(min(r["ioc_weight"], 60), "indicators: " + ", ".join(r["iocs"]))
    if r["hidden"] and r["magic_type"] != "text": add(8, "hidden non-text file")
    if r["failed_logins"] >= 10: add(min(r["failed_logins"] // 5 + 10, 30), f"{r['failed_logins']} failed-login entries (brute force?)")
    if r["ips"] and r["urls"]: add(5, "embeds network endpoints")
    if now - r["mtime"] < 3 * 86400 and s > 0: add(8, "modified within last 3 days")
    if r["mtime"] < r["ctime"] - 86400 * 365 and s > 0: add(7, "timestamp anomaly (mtime far older than ctime - possible timestomping)")
    return s, why


FEATURES = ["entropy", "size_log", "ioc_weight", "failed_logins", "in_staging_dir",
            "hidden", "ext_mismatch", "disguised_exec", "age_days_log"]


def vec(r: dict, now: float):
    return [r["entropy"], math.log10(r["size"] + 1), r["ioc_weight"], min(r["failed_logins"], 200),
            int(r["in_staging_dir"]), int(r["hidden"]), int(r["ext_mismatch"]),
            int(r["disguised_exec"]), math.log10(max(now - r["mtime"], 1) / 86400 + 1)]


def anomaly_scores(rows: list, now: float) -> list:
    """0..1 anomaly score per file. IsolationForest if available, else robust z-score."""
    X = [vec(r, now) for r in rows]
    if len(X) < 8:
        return [0.0] * len(X)
    try:
        from sklearn.ensemble import IsolationForest
        m = IsolationForest(n_estimators=200, contamination="auto", random_state=42).fit(X)
        raw = -m.score_samples(X)  # higher = more anomalous
        lo, hi = min(raw), max(raw)
        return [(v - lo) / (hi - lo + 1e-9) for v in raw]
    except ImportError:
        cols = list(zip(*X))
        med = [sorted(c)[len(c) // 2] for c in cols]
        mad = [sorted(abs(v - m) for v in c)[len(c) // 2] or 1e-6 for c, m in zip(cols, med)]
        z = [sum(min(abs(v - m) / (1.4826 * d), 10) for v, m, d in zip(row, med, mad)) for row in X]
        hi = max(z) or 1
        return [v / hi for v in z]


def triage(root: Path, known_bad: set, top: int):
    now = time.time()
    rows = []
    for dp, dn, fn in os.walk(root, followlinks=False):
        for name in fn:
            p = Path(dp) / name
            if p.is_symlink():
                continue
            r = extract(p, root, known_bad)
            if r: rows.append(r)
    anom = anomaly_scores(rows, now)
    for r, a in zip(rows, anom):
        rs, why = rule_score(r, now)
        r["rule_score"], r["anomaly"], r["reasons"] = round(rs, 1), round(a, 3), why
        # hybrid: rules dominate, anomaly can lift an otherwise unflagged file
        r["priority"] = round(min(100, rs + a * 25), 1)
        r["level"] = "CRITICAL" if r["priority"] >= 70 else "HIGH" if r["priority"] >= 45 else \
                     "MEDIUM" if r["priority"] >= 25 else "LOW"
        if a > 0.8 and rs == 0: r["reasons"].append(f"statistical outlier vs. rest of dataset (anomaly {a:.2f})")
    rows.sort(key=lambda r: r["priority"], reverse=True)
    return rows


# ---------- timeline ----------
def timeline(rows, n=15):
    ev = [(r["mtime"], r["path"], r["level"]) for r in rows if r["level"] in ("CRITICAL", "HIGH", "MEDIUM")]
    return [{"time": iso(t), "file": p, "level": l} for t, p, l in sorted(ev)[-n:]]


# ---------- AI summary (optional) ----------
def ai_summary(rows, top):
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return "AI summary skipped: ANTHROPIC_API_KEY not set."
    try:
        import anthropic
    except ImportError:
        return "AI summary skipped: `pip install anthropic`."
    brief = [{k: r[k] for k in ("path", "level", "priority", "reasons", "sha256", "modified")} for r in rows[:top]]
    msg = anthropic.Anthropic(api_key=key).messages.create(
        model="claude-sonnet-4-6", max_tokens=800,
        messages=[{"role": "user", "content":
                   "You are a DFIR analyst. Given these triaged files (JSON), write a concise incident "
                   "summary: likely attack narrative, top 3 files to examine first, and recommended next "
                   "steps. Be explicit about uncertainty; these are automated findings.\n" + json.dumps(brief)}])
    return msg.content[0].text


# ---------- reporting ----------
COLORS = {"CRITICAL": "#c0392b", "HIGH": "#e67e22", "MEDIUM": "#f1c40f", "LOW": "#7f8c8d"}


def write_html(path, root, rows, top, tl, summary):
    esc = html.escape
    lv = Counter(r["level"] for r in rows)
    body = "".join(
        f"<tr><td><b style='color:{COLORS[r['level']]}'>{r['level']}</b><br>{r['priority']}</td>"
        f"<td><code>{esc(r['path'])}</code><br><small>sha256 {r['sha256'][:24]}… | {r['size']} B | {r['modified']}</small></td>"
        f"<td><ul>{''.join(f'<li>{esc(x)}</li>' for x in r['reasons']) or '<li>-</li>'}</ul></td></tr>"
        for r in rows[:top])
    tlh = "".join(f"<li>{t['time']} — <code>{esc(t['file'])}</code> ({t['level']})</li>" for t in tl)
    path.write_text(f"""<!doctype html><meta charset=utf-8><title>Forensic Triage Report</title>
<style>body{{font-family:system-ui;margin:2rem;max-width:1100px}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ddd;padding:6px;vertical-align:top}}th{{background:#f4f4f4}}ul{{margin:0;padding-left:1.1rem}}</style>
<h1>Forensic Triage Report</h1><p>Source: <code>{esc(str(root))}</code> | Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}
| Files scanned: {len(rows)} | {' | '.join(f'{k}: {v}' for k, v in lv.items())}</p>
<h2>AI Analyst Summary</h2><pre style="white-space:pre-wrap">{esc(summary or 'Not requested (use --ai-summary).')}</pre>
<h2>Top {min(top, len(rows))} files by priority</h2><table><tr><th>Priority</th><th>File</th><th>Why flagged</th></tr>{body}</table>
<h2>Timeline of suspicious activity</h2><ul>{tlh}</ul>
<p><small>Automated triage aids prioritisation only; findings must be validated by a qualified examiner.</small></p>""", encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description="AI-powered forensic triage tool (read-only)")
    ap.add_argument("target", help="directory of evidence to scan")
    ap.add_argument("--out", default="triage_report", help="output basename")
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("--known-bad", help="file with one SHA-256 hash per line")
    ap.add_argument("--ai-summary", action="store_true", help="LLM narrative summary (needs API key)")
    a = ap.parse_args()
    root = Path(a.target).resolve()
    if not root.is_dir():
        sys.exit(f"Not a directory: {root}")
    kb = set()
    if a.known_bad:
        kb = {l.strip().lower() for l in open(a.known_bad) if l.strip() and not l.startswith("#")}
    rows = triage(root, kb, a.top)
    tl = timeline(rows)
    summary = ai_summary(rows, a.top) if a.ai_summary else None
    Path(a.out + ".json").write_text(json.dumps(
        {"source": str(root), "generated": datetime.now(timezone.utc).isoformat(), "summary": summary,
         "timeline": tl, "files": [{k: v for k, v in r.items() if k not in ("mtime", "ctime", "atime")} for r in rows]},
        indent=2))
    write_html(Path(a.out + ".html"), root, rows, a.top, tl, summary)
    print(f"\n{'PRIORITY':<9}{'LEVEL':<10}FILE / REASONS")
    for r in rows[:a.top]:
        print(f"{r['priority']:<9}{r['level']:<10}{r['path']}")
        for w in r["reasons"][:3]: print(f"{'':19}{w}")
    print(f"\nScanned {len(rows)} files -> {a.out}.json, {a.out}.html")
    if summary: print("\n--- AI summary ---\n" + summary)


if __name__ == "__main__":
    main()
