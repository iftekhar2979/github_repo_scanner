#!/usr/bin/env python3
"""
polinRyder.py  (v10.1)

Scan YOUR OWN GitHub repos (or git repos on this computer) for the PolinRider
injection - all branches, full history - show what is affected and, repo by repo,
only after explicit confirmation, rewrite history to remove it and force-push.

Runs on Windows, Linux and macOS.

Requirements: Python 3.8+, git 2.31+, and git-filter-repo   (pip install git-filter-repo)
Usage:  python polinRyder.py              -> shows the plan, asks ONE question (all / one-by-one)
        python polinRyder.py --all        -> clean everything, no questions at all
        python polinRyder.py --one-by-one -> yes/no before each repository
        python polinRyder.py --select 3,5-7 -> only these rows of the table, one by one
        --local [FOLDER] -> clean git repos on THIS PC (optionally force-push); --github -> GitHub only
        (local extras: --push / --no-push to skip the push question)
        add --fresh  -> delete existing local copies and clone new ones (no question)
        add --reuse  -> work on existing local copies (no question)
        add --orgs to include organization repos too
        (set env var GITHUB_TOKEN to skip the hidden token prompt)
Token: classic PAT with `repo` scope, or fine-grained PAT with
       Contents: Read & Write + Metadata: Read on all your repos.
The token is typed at a hidden prompt, never written to disk, never put in a URL
or on a command line, and only ever sent to https://github.com.

Extra indicators: put one literal string per line in `extra_iocs.txt`
next to this script (copy them from your reference document).
"""
import base64, getpass, json, os, re, shutil, stat, subprocess, sys, time, urllib.request, urllib.error
from pathlib import Path

VERSION = "v10.1"
API = "https://api.github.com"
WORK = Path.home() / "polinrider_work"
BACKUP = WORK / "backups"               # pristine bare clones of every GitHub repo (your safety net)
CLEAN = WORK / "clean"                  # scratch copies that get rewritten
LOCAL_BACKUP = WORK / "local_backups"   # backup of each LOCAL repo before it is changed
HELPER = WORK / "_filter_helper.py"     # generated filter-repo script (see FILTER_HELPER)

# Known PolinRider indicators (OpenSourceMalware reports). Extend via extra_iocs.txt
IOCS = ["_$_1e42", "global['!']", 'global["!"]', "global['_V']", 'global["_V"]',
        "rmcej%otb%", "Cot%3t=shtP"]
_extra = Path(__file__).resolve().with_name("extra_iocs.txt")
if _extra.exists():   # utf-8-sig: Windows Notepad adds a BOM that would corrupt the first IOC
    IOCS += [l.strip() for l in _extra.read_text(encoding="utf-8-sig").splitlines() if l.strip()]
IOCS = list(dict.fromkeys(IOCS))
IOC_BYTES = [i.encode("utf-8") for i in IOCS]
# Pattern indicators: (git ERE, Python regex). The 2026 variant hides an obfuscated payload
# AFTER hundreds of spaces - at the end of a real line (`};      global.i='A10-...';global.j=1;/*RS..*/...`)
# or on a line of its own - so it is invisible in an editor.
IOC_PATTERNS = [
    # global.i = 'A10-*1_1331';global.j=1;...   and   global.i="A10-*13310";const _0x4997=...
    (r"""global\.i *= *["'][^"']*["'] *;""", r"""global\.i *= *["'][^"']*["'] *;"""),
    # a long line of code hidden behind 200+ spaces (100+ chars after the spaces: a real payload is
    # thousands of chars; sloppy indentation followed by a short `}` is not flagged)
    (r"[[:blank:]]{200,}[^[:space:]].{100,}", r"[ \t]{200,}[^\s][^\r\n]{100,}"),
]
IOC_RES = [re.compile(py.encode()) for _, py in IOC_PATTERNS]


def ioc_hits(data):
    """Byte offsets where an indicator starts. Patterns are only applied to text files
    (images and other binaries contain random runs of spaces)."""
    hits = [x for x in (data.find(m) for m in IOC_BYTES) if x != -1]
    if b"\x00" not in data[:8192]:
        for rx in IOC_RES:
            m = rx.search(data)
            if m:
                hits.append(m.start())
    return hits

# "Fake font" variant: a file named *.woff2 / *.woff / *.ttf / *.otf / *.eot that is really JavaScript
# (payload hidden in e.g. public/fonts/fa-solid-400.woff2). Detected by IOC strings OR a wrong file header.
# Only the BAD VERSIONS of such a file are removed: if a real font was overwritten, the real one comes back.
FONT_EXTS = (".woff2", ".woff", ".ttf", ".otf", ".eot")
FONT_MAGIC = (b"wOF2", b"wOFF", b"\x00\x01\x00\x00", b"true", b"typ1", b"ttcf", b"OTTO")
LFS_POINTER = b"version https://git-lfs"   # fonts stored in Git LFS are pointers - not malicious

# package.json scripts calling  node init / node init.js / node api / node api.cjs ...
# (alone, or chained with && || ;  -> the call is removed, the rest of the script is kept)
# Written so it is valid for BOTH git's POSIX ERE (-G / grep -E) and Python's re.
NODE_RE = r'node +(\./)?(init|api)(\.[cm]?js)?([ ";&|]|$)'
HOOKS = []   # literal fallback for package.json files that are not valid JSON
for _c in ("node init", "node init.js", "node api", "node api.js",
           "node init.cjs", "node api.cjs", "node init.mjs", "node api.mjs"):
    HOOKS += [(f"{_c} && ", ""), (f"{_c}&& ", ""), (f' && {_c}"', '"'), (f'&& {_c}"', '"')]
SUSPECT_FILES = ("init.js", "api.js", "init", "api", "init.cjs", "api.cjs", "init.mjs", "api.mjs")
# ^ deleted from history when they sit next to a package.json that ever had a `node init|api` hook
REMOVE_VSCODE = True     # delete every .vscode/ folder (any depth) from the whole history
DROPPER = "temp_auto_push.bat"          # propagation script - deleted from history
SUSPECT_TASKS = ("vercel.app", "onrender.com")   # in tasks.json -> reported, NOT auto-removed
SKIP_DIRS = {"node_modules", ".venv", "venv", "__pycache__", "AppData", "$RECYCLE.BIN",
             "System Volume Information", ".cache", ".npm", ".Trash"}


# ---------- console ----------
def _init_console():
    for s in (sys.stdout, sys.stderr):   # never crash on a repo name the console code page can't show
        try:
            s.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return False
    if os.name == "nt":
        os.system("")   # enables ANSI colors in Windows consoles
    return True


R, G, Y, B, D, X = ("\033[31m", "\033[32m", "\033[33m", "\033[36m", "\033[2m", "\033[0m") \
    if _init_console() else ("",) * 6


def ask(prompt, choices):
    """Ask until one of `choices` is typed. Ctrl+D / closed stdin counts as 'q' (or the last choice)."""
    while True:
        try:
            a = input(prompt).strip().lower()
        except EOFError:
            a = "q" if "q" in choices else choices[-1]
        if a in choices:
            return a


def read_secret(prompt):
    """Hidden prompt. On Windows getpass reads the CONSOLE directly and ignores stdin, so a
    piped / non-interactive run would hang forever - read a plain line from stdin instead."""
    if sys.stdin is not None and sys.stdin.isatty():
        return getpass.getpass(prompt)
    print(prompt, end="", flush=True)
    line = sys.stdin.readline() if sys.stdin else ""
    if not line:
        raise EOFError
    return line


def long_path(p):
    """Windows: \\\\?\\ prefix so paths longer than 260 chars (deep git objects) still work."""
    p = str(Path(p).resolve())
    if os.name == "nt" and not p.startswith("\\\\?\\"):
        return "\\\\?\\UNC\\" + p[2:] if p.startswith("\\\\") else "\\\\?\\" + p
    return p


def safe_tag(name, full):
    """Short, unique folder name: readable part + hash of the full path/name (no collisions)."""
    import hashlib
    h = hashlib.sha1(str(full).encode("utf-8", "replace")).hexdigest()[:8]
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(name))[-40:] + "_" + h


def rmtree(path):
    """Remove a folder even if it contains read-only files (git objects on Windows)."""
    def _fix(func, p, *_):
        os.chmod(p, stat.S_IWRITE)
        func(p)
    if sys.version_info >= (3, 12):
        shutil.rmtree(long_path(path), onexc=_fix)
    else:
        shutil.rmtree(long_path(path), onerror=_fix)


def remove_path(p):
    p = Path(p)
    if p.is_dir() and not p.is_symlink():
        rmtree(p)
    else:
        try:
            os.chmod(p, stat.S_IWRITE)
        except OSError:
            pass
        p.unlink()


# ---------- helpers ----------
# core.quotepath=false: non-ASCII file names come out as real UTF-8 instead of "\303\244" escapes
GIT = ["git", "-c", "core.quotepath=false", "-c", "core.longpaths=true", "-c", "gc.auto=0"]


def _git_env(token):
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    if token:
        # Passed via GIT_CONFIG_* env vars (not -c) so the token never shows up in the process list,
        # and scoped to https://github.com/ so it is never sent to any other remote.
        b64 = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        n = int(env.get("GIT_CONFIG_COUNT") or 0)
        for k, v in (("credential.https://github.com.helper", ""),
                     ("http.https://github.com/.extraheader", f"Authorization: Basic {b64}")):
            env[f"GIT_CONFIG_KEY_{n}"], env[f"GIT_CONFIG_VALUE_{n}"] = k, v
            n += 1
        env["GIT_CONFIG_COUNT"] = str(n)
    return env


def git(args, cwd=None, token=None):
    p = subprocess.run(GIT + list(args), cwd=str(cwd) if cwd else None, stdin=subprocess.DEVNULL,
                       capture_output=True, env=_git_env(token))
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


def lines(res):
    rc, out, _ = res
    return [l for l in out.split("\n") if l.strip()] if rc == 0 else []


def zlist(res):
    """Output of a git command run with -z, split on NUL."""
    rc, out, _ = res
    return [x.lstrip("\n") for x in out.split("\0") if x.strip("\n")] if rc == 0 else []


def basename(p):
    return p.rstrip("/").rsplit("/", 1)[-1]


def is_font(p):
    b = basename(p).lower()
    return "." in b[1:] and b[b.rindex("."):] in FONT_EXTS


def in_vscode(p):
    return "/.vscode/" in "/" + p


def is_dropper(p):
    return basename(p).lower() == DROPPER


def ere_escape(s):
    return re.sub(r'([\\.^$|?*+()\[\]{}])', r'\\\1', s)


def payload_start(d):
    """Same cut rule as the filter helper: offset where the payload begins, or None."""
    hits = ioc_hits(d)
    if not hits:
        return None
    pos = min(hits)
    ls = d.rfind(b"\n", 0, pos) + 1
    q, e = pos, pos                     # whitespace run touching the payload start
    while q > ls and d[q - 1:q] in (b" ", b"\t"):
        q -= 1
    while e < len(d) and d[e:e + 1] in (b" ", b"\t"):
        e += 1
    if e - q >= 20 and d[ls:q].strip():  # real code, then lots of spaces, then payload
        return q
    runs = list(re.finditer(rb"[ \t]{20,}", d[ls:pos]))
    if runs and d[ls:ls + runs[-1].start()].strip():
        return ls + runs[-1].start()
    return ls


IOC_ERE = "|".join([ere_escape(i) for i in IOCS] + [ere for ere, _ in IOC_PATTERNS])


def font_verdict(data):
    """None if `data` looks like a real font, else the reason it is malicious."""
    if ioc_hits(data):
        return "contains PolinRider payload"
    if data.startswith(LFS_POINTER):
        return None
    if not data.strip():
        return "empty font file (leftover of a payload / earlier cleanup)"
    if data.startswith(FONT_MAGIC) or data[34:36] == b"LP":   # LP = EOT signature
        return None
    return "not a real font (wrong file header)"


def api(path, token):
    req = urllib.request.Request(API + path, headers={
        "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
        "User-Agent": "polinrider-cleaner"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def list_repos(token, include_orgs):
    aff = "owner,organization_member" if include_orgs else "owner"
    repos, page = [], 1
    while True:
        chunk = api(f"/user/repos?per_page=100&page={page}&affiliation={aff}", token)
        if not chunk:
            return repos
        repos += chunk
        page += 1


# ---------- scanning ----------
def history(gd):
    """{commit: {(blob, path), ...}} - every file version added/changed by every commit reachable
    from any ref (merges are diffed against each parent, so nothing is missed).
    One git call, no pathspecs -> no Windows command-line length limit, no missed duplicate blobs."""
    rc, out, _ = git(["log", "--all", "-m", "--raw", "--no-renames", "--no-abbrev", "-z",
                      "--format=%x01%H"], cwd=gd)
    hist = {}
    if rc != 0:
        return hist
    toks, cur, i = out.split("\0"), None, 0
    while i < len(toks):
        t = toks[i].lstrip("\n")
        if t.startswith("\x01"):
            cur = t[1:].strip()
            hist.setdefault(cur, set())
        elif t.startswith(":") and i + 1 < len(toks):
            meta = t[1:].split()          # old_mode new_mode old_sha new_sha status
            if cur and len(meta) >= 5 and not meta[4].startswith("D") and meta[1] != "160000":
                hist[cur].add((meta[3], toks[i + 1]))
            i += 1
        i += 1
    return hist


def read_blobs(gd, shas):
    """Yield (sha, bytes) for each blob, streamed through ONE `git cat-file --batch` process."""
    if not shas:
        return
    pr = subprocess.Popen(GIT + ["cat-file", "--batch"], cwd=str(gd), stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        for sha in shas:
            pr.stdin.write(sha.encode() + b"\n")
            pr.stdin.flush()
            head = pr.stdout.readline().split()
            if len(head) < 3:                 # "<sha> missing"
                continue
            data = pr.stdout.read(int(head[2]))
            pr.stdout.read(1)                 # trailing newline
            if head[1] == b"blob":
                yield sha, data
    finally:
        pr.stdin.close()
        pr.stdout.close()
        pr.wait()


def malicious_tasks(gd):
    """tasks.json files (e.g. .vscode/tasks.json) that ever held a malicious auto-run task:
    a known payload domain, or runOn:folderOpen together with a download/exec command."""
    def paths(*extra):
        return set(zlist(git(["log", "--all", "-z", "--format=", "--name-only"] + list(extra)
                             + ["--", "*tasks.json"], cwd=gd)))
    out = set()
    for d in SUSPECT_TASKS:
        out |= paths("-S" + d)
    out |= paths("-Gfolder[Oo]pen") & paths("-G(curl|wget|powershell|mshta|cmd /c|cmd.exe|node |bash -c|http)")
    return out


def tip_files(gd, ref, tf, bad_blobs):
    """Files still infected in the snapshot at `ref`."""
    hits = []
    args = ["grep", "-z", "-a", "-l", "-F"]
    for i in IOCS:
        args += ["-e", i]
    hits += zlist(git(args + [ref], cwd=gd))
    args = ["grep", "-z", "-I", "-l", "-E"]          # -I: patterns never on binary files
    for ere, _ in IOC_PATTERNS:
        args += ["-e", ere]
    hits += zlist(git(args + [ref], cwd=gd))
    hits += zlist(git(["grep", "-z", "-I", "-l", "-E", NODE_RE, ref, "--", "*package.json"], cwd=gd))
    hits = [h[len(ref) + 1:] if h.startswith(ref + ":") else h for h in hits]
    for entry in zlist(git(["ls-tree", "-r", "-z", ref], cwd=gd)):
        meta, _, path = entry.partition("\t")
        sha = meta.split()[2] if len(meta.split()) > 2 else ""
        if (path in tf or is_dropper(path) or (REMOVE_VSCODE and in_vscode(path))
                or (is_font(path) and sha in bad_blobs)):
            hits.append(path)
    return sorted(set(hits))


def scan(gd):
    hist = history(gd)
    found = {}
    # 1. payload strings anywhere in history (one pass over all IOCs)
    for sha in lines(git(["log", "--all", "--format=%H", "-G" + IOC_ERE], cwd=gd)):
        found[sha] = "payload"
    # 2. package.json hooks; init/api files next to a hooked package.json are malicious
    hook_dirs, cur = set(), None
    for t in zlist(git(["log", "--all", "-z", "--format=%x01%H", "--name-only", "-G" + NODE_RE,
                        "--", "*package.json"], cwd=gd)):
        if t.startswith("\x01"):
            cur = t[1:].strip()
        elif basename(t) == "package.json":
            found.setdefault(cur, "pkg-hook")
            hook_dirs.add(t.rsplit("/", 1)[0] + "/" if "/" in t else "")
    tf = {d + f for d in hook_dirs for f in SUSPECT_FILES} | malicious_tasks(gd)
    # 3. fake fonts: check the CONTENT of every version of every font-named file, under every path
    want = {}
    for ch in hist.values():
        for blob, path in ch:
            if is_font(path):
                want.setdefault(blob, set()).add(path)
    bad_blobs, fonts, good_font_paths = {}, {}, set()
    for sha, data in read_blobs(gd, list(want)):
        v = font_verdict(data)
        if not v:
            good_font_paths |= want[sha]
        else:
            bad_blobs[sha] = v
            for p in want[sha]:
                fonts[p] = v
    # 4. commits that add/change any of the files that get removed
    for c, ch in hist.items():
        for blob, path in ch:
            if is_dropper(path):
                found.setdefault(c, "dropper")
            elif path in tf:
                found.setdefault(c, "init/api/tasks file")
            elif blob in bad_blobs and is_font(path):
                found.setdefault(c, "fake font")
            elif REMOVE_VSCODE and in_vscode(path):
                found.setdefault(c, ".vscode")
    sus = set()
    for d in SUSPECT_TASKS:
        sus |= set(lines(git(["log", "--all", "--format=%H", "-S" + d, "--", "*tasks.json"], cwd=gd)))
    sus -= set(found)
    sus_paths = set()
    for d in SUSPECT_TASKS:
        sus_paths |= set(zlist(git(["log", "--all", "-z", "--format=", "--name-only", "-S" + d,
                                    "--", "*tasks.json"], cwd=gd)))
    sus_paths = {p for p in sus_paths if p not in tf and not (REMOVE_VSCODE and in_vscode(p))}
    latest = {}                       # path -> newest blob of that path (git log is newest first)
    for ch in hist.values():
        for blob, path in ch:
            latest.setdefault(path, blob)
    bad = set(found)
    branches = {}
    for ref in lines(git(["for-each-ref", "--format=%(refname)", "refs/heads"], cwd=gd)):
        n = len(set(lines(git(["rev-list", ref], cwd=gd))) & bad)
        tip = tip_files(gd, ref, tf, bad_blobs)
        if n or tip:
            branches[ref[len("refs/heads/"):]] = {"commits": n, "tip_files": tip}
    head = [e.partition("\t")[2] for e in zlist(git(["ls-tree", "-r", "-z", "HEAD"], cwd=gd))]
    review = [n for n in head if basename(n) in SUSPECT_FILES and n not in tf]
    # code at HEAD that loads one of the fake fonts (report only - fix by hand)
    loaders = []
    if fonts:
        args = ["grep", "-z", "-l", "-F", "("]
        for name in sorted({basename(p) for p in fonts}):
            args += ["-e", name]
        args += [")", "--and", "(", "-e", "readFileSync", "-e", "eval(", "-e", "Function(",
                 "-e", "require(", "-e", "child_process", ")", "HEAD"]
        loaders = [h[5:] if h.startswith("HEAD:") else h for h in zlist(git(args, cwd=gd))]
        loaders = [h for h in loaders if not is_font(h)]
    return {"commits": found, "suspect": sus, "branches": branches, "review": review,
            "fonts": fonts, "bad_blobs": bad_blobs, "tf": tf, "loaders": loaders,
            "sus_paths": sorted(sus_paths), "latest": latest, "good_font_paths": good_font_paths}


def commit_line(gd, sha):
    rc, out, _ = git(["show", "-s", "--format=%h  %ad  %an  %s", "--date=short", sha], cwd=gd)
    return out.strip()[:110]


def remaining(sc):
    return len(sc["commits"]) + sum(len(v["tip_files"]) for v in sc["branches"].values())


def post_check(src, dst, extra_drop=()):
    """Problems the indicator rescan cannot see: a branch that filter-repo deleted (all of its
    commits became empty) would silently stay infected, and files you chose to remove must be gone."""
    probs = []
    gone = sorted(set(branch_heads(src)) - set(branch_heads(dst)))
    if gone:
        probs.append("branch(es) " + ", ".join(g[len("refs/heads/"):] for g in gone)
                     + " would become completely empty - delete or fix them by hand")
    if extra_drop:
        for ref in branch_heads(dst):
            left = set(zlist(git(["ls-tree", "-r", "-z", "--name-only", ref], cwd=dst))) & set(extra_drop)
            if left:
                probs.append(f"{ref[len('refs/heads/'):]} still contains {', '.join(sorted(left))}")
    return probs


# ---------- cleaning ----------
# Runs as its own process, using git-filter-repo as a library. Closures can share state, which
# string callbacks cannot: blobs are marked bad in blob_cb and dropped per version in commit_cb.
FILTER_HELPER = r'''
import json, re, sys
import git_filter_repo as fr

cfg = json.load(open(sys.argv[1], encoding="utf-8"))
MARKERS = [m.encode("utf-8") for m in cfg["iocs"]]
PATTERNS = [re.compile(p.encode("utf-8")) for p in cfg["ioc_regexes"]]
DROP = set(p.encode("utf-8") for p in cfg["drop_paths"])
DROPPER = cfg["dropper"].encode("utf-8")
BAD = set(s.encode("ascii") for s in cfg["bad_font_blobs"])
FONT_EXTS = tuple(e.encode("ascii") for e in cfg["font_exts"])
VSCODE = cfg["remove_vscode"]
NODE_RE = re.compile(cfg["node_re"].encode("utf-8"))
HOOKS = [(a.encode("utf-8"), b.encode("utf-8")) for a, b in cfg["hooks"]]
CMD = re.compile(r'node\s+(?:\./)?(?:init|api)(?:\.[cm]?js)?(?:\s+[^&|;"]*)?')
bad_ids = set()


def fix_script(v):
    parts = re.split(r'(\s*(?:&&|\|\||;)\s*)', v)
    cmds, ops = parts[0::2], parts[1::2]
    keep = [i for i, c in enumerate(cmds) if not CMD.fullmatch(c.strip())]
    if len(keep) == len(cmds):
        return v
    if not keep:
        return None
    out = cmds[keep[0]]
    for x, y in zip(keep, keep[1:]):
        out += ops[y - 1] + cmds[y]
    return out


def clean_package_json(d):
    try:
        obj = json.loads(d.decode("utf-8-sig"))
    except Exception:
        obj = None
    if isinstance(obj, dict) and isinstance(obj.get("scripts"), dict):
        changed = False
        for k in list(obj["scripts"]):
            v = obj["scripts"][k]
            if isinstance(v, str):
                nv = fix_script(v)
                if nv != v:
                    changed = True
                    if nv is None or not nv.strip():
                        del obj["scripts"][k]
                    else:
                        obj["scripts"][k] = nv
        if not changed:
            return d
        m = re.search(rb'\n([ \t]+)"', d)
        out = json.dumps(obj, indent=m.group(1).decode() if m else "  ", ensure_ascii=False) + "\n"
        if b"\r\n" in d:
            out = out.replace("\n", "\r\n")
        return out.encode("utf-8")
    if NODE_RE.search(d):
        for a, r in HOOKS:
            d = d.replace(a, r)
    return d


def payload_start(d):
    """Offset where the payload begins, or None.
    `};<500 spaces>payload` -> cut at the spaces, the real `};` stays.
    `var _$_1e42=...` / payload on its own line -> cut from the start of that line."""
    hits = [x for x in (d.find(m) for m in MARKERS) if x != -1]
    for rx in PATTERNS:
        m = rx.search(d)
        if m:
            hits.append(m.start())
    if not hits:
        return None
    pos = min(hits)
    ls = d.rfind(b"\n", 0, pos) + 1
    q, e = pos, pos                     # whitespace run touching the payload start
    while q > ls and d[q - 1:q] in (b" ", b"\t"):
        q -= 1
    while e < len(d) and d[e:e + 1] in (b" ", b"\t"):
        e += 1
    if e - q >= 20 and d[ls:q].strip():  # real code, then lots of spaces, then payload
        return q
    runs = list(re.finditer(rb"[ \t]{20,}", d[ls:pos]))
    if runs and d[ls:ls + runs[-1].start()].strip():
        return ls + runs[-1].start()
    return ls


def blob_cb(blob, *_):
    if blob.original_id in BAD:
        bad_ids.add(blob.id)
    d = blob.data
    if b"\x00" in d[:8192]:
        return
    if b'"scripts"' in d:
        d = clean_package_json(d)
    cut = payload_start(d)
    if cut is not None:                          # payload is appended: cut it (and everything after)
        d = d[:cut].rstrip() + b"\n"
    if d != blob.data:
        blob.data = d


def dropped(fc):
    fn = fc.filename
    if fn in DROP or fn.rsplit(b"/", 1)[-1].lower() == DROPPER:
        return True
    if VSCODE and b"/.vscode/" in b"/" + fn:
        return True
    return fn.lower().endswith(FONT_EXTS) and (fc.blob_id in bad_ids or fc.blob_id in BAD)


def commit_cb(commit, *_):
    commit.file_changes = [fc for fc in commit.file_changes if not (fc.type == b"M" and dropped(fc))]


args = fr.FilteringOptions.parse_args(["--force", "--quiet"])
fr.RepoFilter(args, blob_callback=blob_cb, commit_callback=commit_cb).run()
'''


def run_filter_repo(src, dst, sc, extra_drop=()):
    if dst.exists():
        rmtree(dst)
    shutil.copytree(long_path(src), long_path(dst), symlinks=True)
    WORK.mkdir(parents=True, exist_ok=True)
    HELPER.write_text(FILTER_HELPER, encoding="utf-8")
    cfg_path = WORK / f"_filter_cfg_{os.getpid()}.json"
    cfg_path.write_text(json.dumps({
        "iocs": IOCS, "ioc_regexes": [py for _, py in IOC_PATTERNS], "drop_paths": sorted(set(sc["tf"]) | set(extra_drop)), "dropper": DROPPER,
        "bad_font_blobs": sorted(sc["bad_blobs"]), "font_exts": list(FONT_EXTS),
        "remove_vscode": REMOVE_VSCODE, "node_re": NODE_RE, "hooks": HOOKS}), encoding="utf-8")
    try:
        p = subprocess.run([sys.executable, str(HELPER), str(cfg_path)], cwd=str(dst),
                           stdin=subprocess.DEVNULL, capture_output=True)
    finally:
        cfg_path.unlink()
    return p.returncode == 0, p.stderr.decode("utf-8", "replace")


def branch_heads(gd):
    out = {}
    for line in lines(git(["for-each-ref", "--format=%(refname) %(objectname)", "refs/heads"], cwd=gd)):
        ref, sha = line.rsplit(" ", 1)
        out[ref] = sha
    return out


def remote_heads(url, token):
    """{refs/heads/x: sha} as they are on GitHub right now, or None if it can't be read."""
    rc, out, _ = git(["ls-remote", "--heads", url], token=token)
    if rc != 0:
        return None
    return {ref: sha for sha, _, ref in (l.partition("\t") for l in out.splitlines() if "\t" in l)}


def lease_args(gd, expected=None):
    """--force-with-lease for every branch: the push only overwrites a branch if it still is
    exactly what we cleaned. Commits pushed in the meantime are never silently destroyed."""
    out = []
    for line in lines(git(["for-each-ref", "--format=%(refname) %(objectname)", "refs/heads"], cwd=gd)):
        ref, sha = line.rsplit(" ", 1)
        exp = sha if expected is None else expected.get(ref, "")
        out.append(f"--force-with-lease={ref}:{exp}")
    return out


# ---------- UI ----------
def table(rows):
    print(f"\n{B}{'#':>3}  {'REPOSITORY':<42} {'COMMITS':>7} {'BRANCHES':>8} {'TIP':>4}  STATUS{X}")
    for n, r in enumerate(rows, 1):
        s = r["scan"]
        if s is None:
            print(f"{n:>3}  {r['full']:<42} {'-':>7} {'-':>8} {'-':>4}  {Y}clone/scan failed{X}")
            continue
        c, b = len(s["commits"]), len(s["branches"])
        tip = sum(len(v["tip_files"]) for v in s["branches"].values())
        if r.get("already"):
            print(f"{n:>3}  {r['full']:<42} {'-':>7} {'-':>8} {'-':>4}  {G}already cleaned on GitHub{X}")
            continue
        if r.get("stale"):
            st = f"{R}INFECTED{X} {Y}(local copy outdated - use --fresh){X}"
        elif c or tip:
            st = f"{R}INFECTED{X}"
        elif s["suspect"] or s["review"]:
            st = f"{Y}review by hand{X}"
        else:
            st = f"{G}clean{X}"
        flag = f" {D}(archived){X}" if r["meta"].get("archived") else ""
        print(f"{n:>3}  {r['full']:<42} {c:>7} {b:>8} {tip:>4}  {st}{flag}")


def detail(r):
    s, gd = r["scan"], r["gd"]
    print(f"\n{B}=== {r['full']} ==={X}")
    print(f"Infected commits: {len(s['commits'])}   Branches: {len(s['branches'])}")
    for br, v in s["branches"].items():
        print(f"  {R}{br}{X}: {v['commits']} commit(s); still in tip: {', '.join(v['tip_files']) or 'no'}")
    for sha, kind in list(s["commits"].items())[:12]:
        print(f"  {D}[{kind}]{X} {commit_line(gd, sha)}")
    if len(s["commits"]) > 12:
        print(f"  ... and {len(s['commits']) - 12} more")
    fonts = sorted(s["fonts"].items())
    for fp, why in fonts[:10]:
        print(f"  {R}FONT{X} {fp}  -> {why}")
    if len(fonts) > 10:
        print(f"  ... and {len(fonts) - 10} more fake font path(s)")
    if s["loaders"]:
        print(f"  {Y}code that LOADS a fake font (fix by hand after cleanup): {', '.join(s['loaders'][:8])}{X}")
    if s["review"]:
        print(f"  {Y}files to review by hand (may be legit): {', '.join(s['review'][:8])}{X}")
    if s["suspect"]:
        print(f"  {Y}tasks.json with suspicious URLs in {len(s['suspect'])} commit(s) - manual review needed{X}")


def is_infected(sc):
    return bool(sc["commits"]) or any(v["tip_files"] for v in sc["branches"].values())


def needs_review(sc):
    return bool(sc["review"] or sc["loaders"] or sc["sus_paths"])


# ---------- interactive review: show which files go, and their code, one by one ----------
REVIEW_DIR = WORK / "_review"     # temporary .txt copies opened in an editor (deleted at exit)
PREVIEW_LINES = 40
LINE_WIDTH = 200


def get_blob(gd, sha):
    for _, data in read_blobs(gd, [sha]):
        return data
    return None


def planned_changes(sc):
    """({path: reason} deleted from the whole history, [paths] that get edited)."""
    deleted = {}
    for p in sc["latest"]:
        if p in sc["tf"]:
            deleted[p] = "init/api/tasks file"
        elif is_dropper(p):
            deleted[p] = "dropper script"
        elif p in sc["fonts"]:
            deleted[p] = "fake font - " + sc["fonts"][p]
            if p in sc["good_font_paths"]:
                deleted[p] += "; only the fake versions go, the REAL font is restored"
        elif REMOVE_VSCODE and in_vscode(p):
            deleted[p] = ".vscode folder"
    edited = sorted({p for v in sc["branches"].values() for p in v["tip_files"]} - set(deleted))
    return deleted, edited


def show_code(path, data, whole_file_removed, full=False):
    """Print a file like a code block. '-' red lines = removed by the cleanup."""
    if data is None:
        print(f"  {Y}(content not available){X}")
        return
    if b"\x00" in data[:8192]:
        print(f"  {D}binary file, {len(data)} bytes, starts with: {data[:16].hex(' ')}{X}")
        return
    pos = payload_start(data)
    cut, cut_col = None, 0
    if pos is not None:
        cut = data[:pos].count(b"\n")
        cut_col = len(data[data.rfind(b"\n", 0, pos) + 1:pos].decode("utf-8", "replace"))
    text = data.decode("utf-8", "replace").split("\n")
    if text and text[-1] == "":
        text.pop()
    text = [t.rstrip("\r") for t in text]

    def removed(i):
        return whole_file_removed or (cut is not None and i >= cut) or (
            basename(path) == "package.json" and re.search(NODE_RE, text[i]))

    def visible(s):
        s = s.replace("\t", "    ")
        s = re.sub(r" {20,}", lambda m: f"{Y}<{len(m.group(0))} spaces>{X}", s)   # expose hidden code
        return s

    idx = list(range(len(text)))
    if not full and len(idx) > PREVIEW_LINES:
        if cut is not None and cut > PREVIEW_LINES - 10:      # show the start AND the payload area
            idx = idx[:10] + [None] + idx[max(10, cut - 5):cut - 5 + PREVIEW_LINES - 10]
        else:
            idx = idx[:PREVIEW_LINES]
    w = len(str(len(text)))
    print(f"  {D}{'-' * 70}{X}")
    for i in idx:
        if i is None:
            print(f"  {D}{'.' * w}  ...{X}")
            continue
        raw = text[i]
        if len(raw) > LINE_WIDTH + 600:
            raw = raw[:LINE_WIDTH + 600]
        tag = f"  {R}<-- PAYLOAD{X}" if ioc_hits(text[i].encode("utf-8", "replace")) else ""
        if i == cut and cut_col and not whole_file_removed:    # real code + hidden payload on one line
            keep, gone = visible(raw[:cut_col]), visible(raw[cut_col:])
            print(f"  {R}{i + 1:>{w}} ~{X} {keep}{R}[CUT FROM HERE >]{X} {gone[:LINE_WIDTH]}"
                  f"{D} ...{X}{tag}")
            continue
        line = visible(raw)
        if len(raw) > LINE_WIDTH:
            line = visible(raw[:LINE_WIDTH]) + f"{D} ... (+{len(text[i]) - LINE_WIDTH} chars){X}"
        if removed(i):
            print(f"  {R}{i + 1:>{w}} -{X} {line}{tag}")
        else:
            print(f"  {D}{i + 1:>{w}}{X}   {line}{tag}")
    print(f"  {D}{'-' * 70}{X}")
    shown = sum(1 for i in idx if i is not None)
    if shown < len(text):
        print(f"  {D}showing {shown} of {len(text)} lines - press m for all{X}")


def open_in_editor(name, data):
    """Open a SAFE .txt copy (never the original extension: a .js double-click on Windows RUNS it)."""
    REVIEW_DIR.mkdir(parents=True, exist_ok=True)
    f = REVIEW_DIR / (re.sub(r"[^A-Za-z0-9._-]", "_", name)[-100:] + ".txt")
    f.write_bytes(data or b"")
    ed = os.environ.get("VISUAL") or os.environ.get("EDITOR")
    try:
        if ed:
            import shlex
            subprocess.run(shlex.split(ed, posix=os.name != "nt") + [str(f)])
        elif os.name == "nt":
            subprocess.Popen(["notepad.exe", str(f)])
        elif sys.platform == "darwin":
            subprocess.Popen(["open", "-t", str(f)])
        else:
            subprocess.Popen(["xdg-open", str(f)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"  {D}opened {f}{X}")
    except OSError as e:
        print(f"  {Y}could not start an editor ({e}); the file is here: {f}{X}")


def review_repo(r):
    """Shows what the cleanup will do to this repo and walks through the files one by one.
    'Review by hand' files get a remove/keep decision -> r['extra_drop']."""
    sc, gd = r["scan"], r["gd"]
    deleted, edited = planned_changes(sc)
    review = {}
    for p in sc["review"]:
        data = get_blob(gd, sc["latest"][p]) if p in sc["latest"] else None
        if data and ioc_hits(data):
            review[p] = f"{R}CONTAINS THE HIDDEN PAYLOAD - recommended: [r]emove{X}"
        else:
            review[p] = "suspicious name (init/api) but no package.json hook runs it"
    for p in sc["loaders"]:
        review[p] = "code that reads/evals a fake font file"
    for p in sc["sus_paths"]:
        review[p] = "tasks.json with a suspicious URL (vercel.app / onrender.com)"
    for p in list(review):
        if p in deleted:
            del review[p]
    r.setdefault("extra_drop", set())
    print(f"\n{B}What the cleanup will do in {r['full']}:{X}")
    if deleted:
        print(f"  {R}DELETED from the whole history ({len(deleted)}):{X}")
        for p, why in sorted(deleted.items()):
            print(f"    {R}x{X} {p}  {D}({why}){X}")
    if edited:
        print(f"  {Y}EDITED (payload lines / package.json hooks cut out) ({len(edited)}):{X}")
        for p in edited:
            print(f"    {Y}~{X} {p}")
    if review:
        print(f"  {B}REVIEW BY HAND - you decide ({len(review)}):{X}")
        for p, why in sorted(review.items()):
            print(f"    ? {p}  {D}({why}){X}")
    items = [("del", p, w) for p, w in sorted(deleted.items())] + [("edit", p, "") for p in edited]
    viewing = bool(items) and ask(f"\nShow the code of these {len(items)} file(s) one by one? [y]es / [n]o: ",
                                  ("y", "n")) == "y"
    items += [("review", p, w) for p, w in sorted(review.items())]
    n_total = len(items)
    for n, (kind, p, why) in enumerate(items, 1):
        if kind != "review" and not viewing:
            continue
        data = get_blob(gd, sc["latest"][p]) if p in sc["latest"] else None
        label = {"del": f"{R}WILL BE DELETED{X}", "edit": f"{Y}WILL BE EDITED{X}",
                 "review": f"{B}REVIEW BY HAND{X}"}[kind]
        print(f"\n{B}[{n}/{n_total}] {p}{X}  {label}  {D}{why}{X}")
        full = False
        while True:
            show_code(p, data, kind == "del", full)
            if kind == "review":
                a = ask("  [r]emove this file from the whole history / [k]eep it / [m]ore lines / [o]pen in editor: ",
                        ("r", "k", "m", "o"))
            else:
                a = ask("  [Enter] next file / [m]ore lines / [o]pen in editor / [s]kip the rest: ",
                        ("", "m", "o", "s"))
            if a == "m":
                full = True
                continue
            if a == "o":
                open_in_editor(f"{r['full']}__{p}", data)
                continue
            break
        if a == "r":
            r["extra_drop"].add(p)
            print(f"  {R}-> {p} will be removed from the whole history{X}")
        elif a == "k":
            print(f"  {G}-> kept{X}")
        elif a == "s":
            viewing = False


def confirm_repo(r, state):
    """'clean', 'skip' or 'reviewed' (review-only repo where you removed nothing). Raises KeyboardInterrupt on quit."""
    infected = is_infected(r["scan"])
    if state["all"]:
        return "clean" if infected else "reviewed"
    review_repo(r)
    if not infected and not r["extra_drop"]:
        return "reviewed"
    a = ask(f"\nClean {r['full']} now? [y]es / [n]o / [a]ll remaining (no more questions) / [q]uit: ",
            ("y", "n", "a", "q"))
    if a == "q":
        raise KeyboardInterrupt
    if a == "a":
        state["all"] = True
    return "skip" if a == "n" else "clean"


def clean_flow(r, token, state):
    """Returns a short status string."""
    detail(r)
    if r["meta"].get("archived"):
        print(f"{Y}Repo is archived: GitHub rejects pushes. Unarchive it first, then rerun.{X}")
        return "SKIPPED (archived)"
    choice = confirm_repo(r, state)
    if choice == "skip":
        return "SKIPPED by you"
    if choice == "reviewed":
        return "REVIEWED (nothing removed)"
    dst = CLEAN / r["full"].replace("/", "__")
    ok, err = run_filter_repo(r["gd"], dst, r["scan"], r.get("extra_drop", ()))
    if not ok:
        print(f"{R}git filter-repo failed:{X}\n{err[-1500:]}")
        return "FAILED (filter-repo)"
    left = remaining(scan(dst))
    print(f"{G if not left else R}Verification: {left} indicator(s) remaining after cleanup.{X}")
    if left:
        print(f"{Y}Not pushing - inspect {dst} by hand.{X}")
        return f"NOT PUSHED ({left} indicator(s) remain)"
    probs = post_check(r["gd"], dst, r.get("extra_drop", ()))
    if probs:
        print(f"{R}Not pushing: {'; '.join(probs)}{X}")
        return f"NOT PUSHED ({'; '.join(probs)})"
    git(["remote", "remove", "origin"], cwd=dst)
    git(["remote", "add", "origin", r["meta"]["clone_url"]], cwd=dst)
    lease = lease_args(r["gd"])       # expected = branch tips in the untouched backup
    # Real write-permission test (the API "permissions" field only shows owner rights)
    rc, _, err = git(["push", "--dry-run", "origin"] + lease + ["refs/heads/*:refs/heads/*"],
                     cwd=dst, token=token)
    if rc != 0:
        if "stale info" in err:
            print(f"{Y}GitHub has commits that are not in your local copy (pushed after it was made).{X}")
            return "SKIPPED (GitHub changed since the local copy - rerun with --fresh)"
        print(f"{R}Write-permission test FAILED for {r['full']}.{X}")
        print(err.strip()[:400])
        print("Token in use ends with: ..." + token[-4:])
        return "FAILED (no write permission)"
    rc, out, err = git(["push", "origin"] + lease + ["refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*"],
                       cwd=dst, token=token)
    if rc == 0:
        if "Everything up-to-date" in err:
            print(f"{G}Nothing to upload: GitHub already has exactly this cleaned history.{X}")
            return "ALREADY CLEAN (GitHub already had the cleaned history)"
        print(f"{G}Pushed (force). Updated on GitHub:{X}")
        for l in err.splitlines():
            if "->" in l:
                print(f"  {D}{l.strip()}{X}")
        return "CLEANED + PUSHED"
    print(f"{R}Push failed:{X}\n{err.strip()[:600]}")
    return "FAILED (push rejected - protected branch?)"


PLAN = f"""
{B}WHAT THIS SCRIPT WILL DO (step by step){X}
  1. Log in with your token and list your repositories.
  2. Download a full backup of each repo to {BACKUP}
     (if copies already exist you choose: work on existing, or delete them and clone new).
     The backup is NEVER modified by the cleanup.
  3. Scan ALL branches and the FULL commit history for:
       - PolinRider payload (_$_1e42, global['!'], global['_V'] + extra_iocs.txt)
       - temp_auto_push.bat
       - "node init" / "node api" hooks inside package.json scripts
       - init.js / api.js files used by those hooks
       - fake fonts (*.woff2/.woff/.ttf/.otf/.eot that are really JavaScript)
       - malicious .vscode/tasks.json, and the whole .vscode folder
  4. Show a table: which repos are affected, how many commits/branches.
  5. You choose: clean ALL repos automatically, or ONE BY ONE with a yes/no for each.
  6. For each repo to be cleaned:
       a. rewrite a LOCAL copy of the history (removes the items above)
       b. verify the copy is clean - if anything remains, NOTHING is pushed
       c. test that your token can write to the repo (dry-run)
       d. force-push every branch and tag (with lease: a branch that changed on
          GitHub since the backup is NOT overwritten)
  7. Print a summary and save it to {WORK / "report.txt"}
"""


def write_report(name, lines_):
    WORK.mkdir(parents=True, exist_ok=True)
    rep = WORK / name
    rep.write_text(time.strftime("%Y-%m-%d %H:%M:%S") + "\n" + "\n".join(lines_) + "\n", encoding="utf-8")
    return rep


def parse_selection(text, n):
    """'1,3,5-8' -> [1, 3, 5, 6, 7, 8] (1-based, within 1..n). None if invalid."""
    out = []
    for part in re.split(r"[,\s]+", text.strip()):
        if not part:
            continue
        m = re.fullmatch(r"(\d+)(?:-(\d+))?", part)
        if not m:
            return None
        a, b = int(m.group(1)), int(m.group(2) or m.group(1))
        if not (1 <= a <= b <= n):
            return None
        out += [i for i in range(a, b + 1) if i not in out]
    return out or None


def print_findings(rows):
    """Under the table: per repo, WHAT would be removed / needs a decision."""
    shown = False
    for n, r in enumerate(rows, 1):
        s = r["scan"]
        if not s or r.get("already") or not (is_infected(s) or needs_review(s)):
            continue
        if not shown:
            print(f"\n{B}FINDINGS (number = row in the table){X}")
            shown = True
        deleted, edited = planned_changes(s)
        print(f"{n:>3}  {r['full']}")
        for p, why in sorted(deleted.items())[:6]:
            print(f"       {R}x delete{X} {p}  {D}({why}){X}")
        if len(deleted) > 6:
            print(f"       {D}... and {len(deleted) - 6} more file(s) to delete{X}")
        for p in edited[:6]:
            print(f"       {Y}~ edit  {X} {p}  {D}(payload / hook cut out){X}")
        if len(edited) > 6:
            print(f"       {D}... and {len(edited) - 6} more file(s) to edit{X}")
        for p in s["review"] + s["loaders"] + s["sus_paths"]:
            if p not in deleted:
                print(f"       {B}? review{X} {p}  {D}(you decide: remove or keep){X}")


def choose_mode(argv, rows, infected, review_only):
    """Returns (mode, todo). mode '1' = all automatic, '2' = one by one, 'q' = quit."""
    sel = next((a.split("=", 1)[1] for a in argv if a.startswith("--select=")), None)
    if "--select" in argv:
        i = argv.index("--select")
        sel = argv[i + 1] if i + 1 < len(argv) else ""
    if sel is not None:
        idx = parse_selection(sel, len(rows))
        if idx is None:
            sys.exit(f"--select: invalid list '{sel}' (use row numbers from the table, e.g. 1,3,5-8)")
        return "2", [rows[i - 1] for i in idx if rows[i - 1]["scan"]]
    if "--all" in argv:
        return "1", infected
    if "--one-by-one" in argv or "--interactive" in argv:
        return "2", infected + review_only
    print(f"\n{B}{len(infected)} repositories need cleaning, {len(review_only)} only need a review by hand. "
          f"How do you want to proceed?{X}")
    print("  [1] Clean ALL infected repos automatically (no more questions; review-only repos are left alone)")
    print("  [2] ONE BY ONE - for each repo I list the files that will be removed, show their code")
    print("      one by one, let you decide on the 'review by hand' files, then ask yes/no")
    print("  [3] SELECT repos by their number in the table (e.g. 3  or  1,4,7-9), then one by one")
    print("  [q] Quit without changing anything")
    mode = ask("Choose 1 / 2 / 3 / q: ", ("1", "2", "3", "q"))
    if mode == "q":
        return "q", []
    if mode == "1":
        return "1", infected
    if mode == "2":
        return "2", infected + review_only
    while True:
        try:
            text = input(f"Repo numbers (1-{len(rows)}): ")
        except EOFError:
            return "q", []
        idx = parse_selection(text, len(rows))
        if idx:
            picked = [rows[i - 1] for i in idx if rows[i - 1]["scan"]]
            print("Selected: " + ", ".join(r["full"] for r in picked))
            return "2", picked
        print(f"{Y}Invalid - type numbers from the table, like 3 or 1,4,7-9{X}")


def github_main(argv):
    orgs = "--orgs" in argv
    print(PLAN)
    try:
        token = os.environ.get("GITHUB_TOKEN", "").strip() or read_secret("GitHub token (hidden): ").strip()
    except EOFError:
        sys.exit("No token given.")
    try:
        me = api("/user", token)["login"]
        metas = list_repos(token, orgs)
    except urllib.error.HTTPError as e:
        sys.exit(f"GitHub API error {e.code}: {e.reason} (token rejected or rate-limited)")
    except urllib.error.URLError as e:
        sys.exit(f"Cannot reach GitHub: {e.reason}")
    print(f"Logged in as {me}; {len(metas)} repositories.")
    BACKUP.mkdir(parents=True, exist_ok=True)
    # ---- existing local copies: reuse or start fresh? ----
    gds = {m["full_name"]: BACKUP / (m["full_name"].replace("/", "__") + ".git") for m in metas}
    existing = [n for n, g in gds.items() if g.exists()]
    fresh = False
    if existing:
        if "--fresh" in argv:
            fresh = True
        elif "--reuse" in argv:
            fresh = False
        else:
            print(f"\n{B}{len(existing)} of {len(metas)} repositories already have a local copy in {BACKUP}{X}")
            print("  [1] WORK ON EXISTING copies (fast; skips cloning those)")
            print("      note: commits pushed to GitHub after that copy was made are NOT in it")
            print("            (such branches are detected and NOT overwritten)")
            print("  [2] CLONE NEW versions (deletes the existing local copies, downloads fresh from GitHub)")
            fresh = ask("Choose 1 / 2: ", ("1", "2")) == "2"
        if fresh:
            print(f"{Y}Deleting {len(existing)} existing local copies...{X}")
            for n in existing:
                rmtree(gds[n])
    if fresh and CLEAN.exists():
        rmtree(CLEAN)
    CLEAN.mkdir(parents=True, exist_ok=True)
    rows = []
    for i, m in enumerate(metas, 1):
        gd = gds[m["full_name"]]
        print(f"[{i}/{len(metas)}] scanning {m['full_name']}"[:78].ljust(78), end="\r", flush=True)
        reused = gd.exists() and git(["rev-parse", "--git-dir"], cwd=gd)[0] == 0
        if reused:
            rc = 0
        else:
            if gd.exists():
                rmtree(gd)
            rc, _, _ = git(["clone", "--bare", "-q", m["clone_url"], str(gd)], token=token)
        row = {"full": m["full_name"], "meta": m, "gd": gd, "scan": scan(gd) if rc == 0 else None, "result": ""}
        rows.append(row)
        # A reused backup is the PRE-cleanup state. If GitHub already matches the cleaned copy
        # from an earlier run, the repo is already clean there - don't show it as infected again.
        if reused and row["scan"] and is_infected(row["scan"]):
            remote, dst = remote_heads(m["clone_url"], token), CLEAN / m["full_name"].replace("/", "__")
            if remote is not None and remote != branch_heads(gd):
                if dst.exists() and remote == branch_heads(dst):
                    row["already"] = True
                else:
                    row["stale"] = True
    print(" " * 78)
    table(rows)
    already = [r for r in rows if r.get("already")]
    stale = [r for r in rows if r.get("stale")]
    for r in already:
        r["result"] = "ALREADY CLEAN on GitHub (cleaned in an earlier run)"
    if already:
        print(f"\n{G}{len(already)} repo(s) are already cleaned on GitHub (from an earlier run) - skipped.{X}")
    if stale:
        print(f"{Y}{len(stale)} repo(s) changed on GitHub after your local copy was made: "
              f"{', '.join(r['full'] for r in stale)}\n  -> rerun with --fresh to scan what is on GitHub now.{X}")
    infected = [r for r in rows if r["scan"] and is_infected(r["scan"]) and not r.get("already")]
    review_only = [r for r in rows if r["scan"] and not is_infected(r["scan"]) and needs_review(r["scan"])]
    print_findings(rows)
    if not infected and not review_only and not any(a.startswith("--select") for a in argv):
        print(f"\n{G}Nothing to clean.{X}")
    else:
        mode, todo = choose_mode(argv, rows, infected, review_only)
        state = {"all": mode == "1"}
        try:
            for n, r in enumerate(todo, 1):
                print(f"\n{B}##### [{n}/{len(todo)}] {r['full']}{X}")
                try:
                    r["result"] = clean_flow(r, token, state)
                except KeyboardInterrupt:
                    raise
                except Exception as e:           # one failing repo never stops the run
                    r["result"] = f"FAILED ({type(e).__name__}: {e})"
                    print(f"{R}{r['result']}{X}")
        except KeyboardInterrupt:
            print(f"\n{Y}Stopped by you. Repos not yet processed were left untouched.{X}")
    out = [f"{r['full']:<45} {r['result']}" for r in rows if r["result"]]
    unscanned = [r["full"] for r in rows if r["scan"] is None]
    print(f"\n{B}===== SUMMARY ====={X}")
    print("\n".join(out) or "Nothing was changed.")
    if unscanned:
        print(f"{Y}Could not clone/scan: {', '.join(unscanned)}{X}")
    report = write_report("report.txt", out + [f"unscanned: {u}" for u in unscanned])
    print(f"\nReport saved: {report}\nBackups (original, pre-cleanup): {BACKUP}")
    print("Now REVOKE this token, and re-clone any local copies of the cleaned repos.")
    print("Note: GitHub keeps old commits reachable from pull requests / forks; ask GitHub Support "
          "to purge cached views if the payload must disappear completely.")


# ====================== LOCAL REPOSITORIES ======================
LOCAL_PLAN = f"""
{B}LOCAL MODE - WHAT WILL HAPPEN (step by step){X}
  1. You give a folder; every git repository inside it is found (node_modules etc. skipped).
  2. Each repo is scanned (all branches + full history), same checks as GitHub mode.
  3. You choose: clean ALL repos, or ONE BY ONE (yes/no each).
  4. You choose: local only / force-push every cleaned repo / ask per repo.
  5. For each repo that is cleaned:
       a. SAFETY: repo must have no uncommitted changes (otherwise it is skipped, nothing touched)
       b. fetch origin, bring local branches level with origin (so nothing on GitHub is lost)
       c. backup of the repo -> {LOCAL_BACKUP}
       d. history is rewritten on a scratch copy and verified clean
       e. your local repo is updated to the cleaned history (current branch is reset to it)
       f. leftover UNTRACKED suspicious files (init.js, api.js, .vscode, temp_auto_push.bat,
          fake fonts) are deleted
       g. optional: force-push all branches/tags to origin (with lease)
  6. Summary + report saved.
"""


def find_repos(root):
    root = Path(root).expanduser()
    out = []
    for dirpath, dirnames, _ in os.walk(root):
        if (Path(dirpath) / ".git").exists():
            out.append(Path(dirpath))
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
    return out


def leftover_untracked(path, tf):
    """Untracked / ignored files that match the suspicious patterns (incl. fake fonts on disk)."""
    names = zlist(git(["ls-files", "-z", "--others", "--exclude-standard"], cwd=path))
    names += zlist(git(["ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--directory"], cwd=path))
    hits = {n for n in names if is_dropper(n) or n in tf or (REMOVE_VSCODE and in_vscode(n))}
    tracked = set(zlist(git(["ls-files", "-z"], cwd=path)))
    root = Path(path)
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in (".git", "node_modules")]
        for f in fns:
            full = Path(dp) / f
            rel = full.relative_to(root).as_posix()
            if not is_font(rel) or rel in tracked:
                continue
            try:
                if full.stat().st_size > 50_000_000:
                    continue
                if font_verdict(full.read_bytes()):
                    hits.add(rel)
            except OSError:
                pass
    return sorted(hits)


def local_clean(r, push, token):
    path = r["gd"]
    if git(["status", "--porcelain", "--untracked-files=no"], cwd=path)[1].strip():
        return "SKIPPED (uncommitted changes - commit or stash first)"
    cur = git(["symbolic-ref", "--short", "-q", "HEAD"], cwd=path)[1].strip()
    if not cur:
        return "SKIPPED (detached HEAD - checkout a branch first)"
    has_origin = "origin" in git(["remote"], cwd=path)[1].split()
    diverged, expected = [], {}
    if has_origin:
        rc, _, err = git(["fetch", "origin", "--prune"], cwd=path, token=token)
        if rc != 0:
            if push:
                return "SKIPPED (cannot fetch origin: " + err.strip()[:120] + ")"
            print(f"{Y}Could not fetch origin - continuing with what is local.{X}")
        else:
            for line in lines(git(["for-each-ref", "--format=%(refname) %(objectname)", "refs/remotes/origin"], cwd=path)):
                rb, sha = line.rsplit(" ", 1)
                if rb.endswith("/HEAD"):
                    continue
                b = rb[len("refs/remotes/origin/"):]
                expected["refs/heads/" + b] = sha
                if git(["show-ref", "--verify", "--quiet", f"refs/heads/{b}"], cwd=path)[0] != 0:
                    git(["branch", b, rb], cwd=path)              # remote-only branch -> make it local so it gets cleaned too
                elif git(["merge-base", "--is-ancestor", b, rb], cwd=path)[0] == 0:
                    if b == cur:
                        git(["merge", "--ff-only", rb], cwd=path)  # local was behind origin
                    else:
                        git(["branch", "-f", b, rb], cwd=path)
                elif git(["merge-base", "--is-ancestor", rb, b], cwd=path)[0] != 0:
                    diverged.append(b)                              # local and origin both have own commits
    lease = []
    if push:
        if not has_origin:
            return "SKIPPED (no 'origin' remote to push to)"
        if diverged:
            return f"SKIPPED (branch(es) {', '.join(diverged)} diverged from origin - merge/rebase first, a force-push would lose commits)"
        lease = lease_args(path, expected)
        rc, _, err = git(["push", "--dry-run", "origin"] + lease + ["refs/heads/*:refs/heads/*"], cwd=path, token=token)
        if rc != 0:
            return "SKIPPED (push permission test failed: " + err.strip()[:150] + ")"
    tag = safe_tag(Path(path).name, Path(path).resolve())
    bk = LOCAL_BACKUP / (tag + ".git")
    LOCAL_BACKUP.mkdir(parents=True, exist_ok=True)
    if bk.exists():
        rmtree(bk)
    rc, _, err = git(["clone", "-q", "--mirror", str(path), str(bk)])
    if rc != 0:
        return "FAILED (backup: " + err.strip()[:150] + ")"
    sc = scan(bk)                       # rescan: branches may have moved during the origin sync
    dst = CLEAN / ("local__" + tag)
    extra = r.get("extra_drop", set())
    ok, err = run_filter_repo(bk, dst, sc, extra)
    if not ok:
        print(f"{R}git filter-repo failed:{X}\n{err[-1500:]}")
        return "FAILED (filter-repo)"
    left = remaining(scan(dst))
    print(f"{G if not left else R}Verification: {left} indicator(s) remaining after cleanup.{X}")
    if left:
        return f"NOT APPLIED ({left} indicator(s) remain - inspect {dst})"
    probs = post_check(bk, dst, extra)
    if probs:
        print(f"{R}Not applied: {'; '.join(probs)}{X}")
        return f"NOT APPLIED ({'; '.join(probs)})"
    # ---- apply cleaned history to the local repo ----
    rc, _, err = git(["fetch", "--force", "--no-tags", str(dst), "+refs/heads/*:refs/cleaned/*",
                      "+refs/tags/*:refs/tags/*"], cwd=path)
    if rc != 0:
        return "FAILED (could not fetch cleaned history: " + err.strip()[:150] + ")"
    errors = []
    for ref in lines(git(["for-each-ref", "--format=%(refname)", "refs/cleaned"], cwd=path)):
        b = ref[len("refs/cleaned/"):]
        if b == cur:
            rc, _, err = git(["reset", "-q", "--hard", ref], cwd=path)
        else:
            rc, _, err = git(["branch", "-f", b, ref], cwd=path)
        if rc != 0:
            errors.append(f"{b}: {err.strip()[:100]}")
        git(["update-ref", "-d", ref], cwd=path)
    if errors:
        print(f"{R}Some branches could not be updated (file locked / checked out in another worktree?):{X}")
        print("\n".join("  " + e for e in errors))
        return f"PARTIALLY APPLIED ({len(errors)} branch(es) failed - original in {bk})"
    removed = []
    for n in leftover_untracked(path, set(sc["tf"]) | set(extra)):
        try:
            remove_path(Path(path) / n)
            removed.append(n)
        except OSError as e:
            print(f"{Y}could not delete {n}: {e}{X}")
    if removed:
        print(f"{D}deleted untracked suspicious files: {', '.join(removed[:10])}{X}")
    status = "CLEANED LOCALLY"
    if push:
        rc, _, err = git(["push", "origin"] + lease + ["refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*"],
                         cwd=path, token=token)
        if rc == 0:
            status = "CLEANED + PUSHED"
            git(["fetch", "origin", "--prune", "--force"], cwd=path, token=token)
        else:
            print(f"{R}Push failed:{X}\n{err.strip()[:500]}")
            status = "CLEANED LOCALLY, PUSH FAILED (protected branch, or origin changed meanwhile?)"
    else:
        # old infected history is still referenced by remote-tracking refs -> drop them so the local repo is really clean
        for ref in lines(git(["for-each-ref", "--format=%(refname)", "refs/remotes"], cwd=path)):
            git(["update-ref", "-d", ref], cwd=path)
        status += " (origin NOT updated - remote-tracking refs removed; push later with --force)"
    # drop old reflogs so gc can really delete the infected objects - but keep the user's stash list
    refs = [x for x in lines(git(["for-each-ref", "--format=%(refname)"], cwd=path)) if x != "refs/stash"]
    git(["reflog", "expire", "--expire=now", "--expire-unreachable=now", "HEAD"] + refs, cwd=path)
    git(["gc", "--prune=now", "-q"], cwd=path)
    if git(["rev-parse", "-q", "--verify", "refs/stash"], cwd=path)[0] == 0:
        status += " [stash kept - it may still hold old infected commits: `git stash clear` when done]"
    return status


def local_main(argv):
    print(LOCAL_PLAN)
    root = ""
    if "--local" in argv:
        i = argv.index("--local")
        if i + 1 < len(argv) and not argv[i + 1].startswith("--"):
            root = argv[i + 1]
    example = Path.home() / "projects"
    while not root or not Path(root).expanduser().is_dir():
        try:
            root = input(f"Folder that contains your git repos (e.g. {example}): ").strip().strip('"').strip("'")
        except EOFError:
            sys.exit("No folder given.")
    repos = find_repos(root)
    print(f"Found {len(repos)} git repositories under {root}")
    rows = []
    for i, path in enumerate(repos, 1):
        rel = os.path.relpath(path, Path(root).expanduser())
        print(f"[{i}/{len(repos)}] scanning {rel}"[:78].ljust(78), end="\r", flush=True)
        rows.append({"full": rel if rel != "." else Path(root).expanduser().resolve().name, "meta": {},
                     "gd": path, "scan": scan(path), "result": ""})
    print(" " * 78)
    table(rows)
    infected = [r for r in rows if is_infected(r["scan"])]
    review_only = [r for r in rows if not is_infected(r["scan"]) and needs_review(r["scan"])]
    print_findings(rows)
    if infected or review_only or any(a.startswith("--select") for a in argv):
        mode, todo = choose_mode(argv, rows, infected, review_only)
        if mode != "q":
            if "--push" in argv:
                pm = "2"
            elif "--no-push" in argv:
                pm = "1"
            else:
                print(f"\n{B}After cleaning, should I force-push to GitHub (origin)?{X}")
                print("  [1] NO - clean the local repos only")
                print("  [2] YES - force-push every cleaned repo")
                print("  [3] ASK me for each repository")
                pm = ask("Choose 1 / 2 / 3: ", ("1", "2", "3"))
            token = None
            if pm != "1":
                try:
                    token = os.environ.get("GITHUB_TOKEN", "").strip() or read_secret(
                        "GitHub token for pushing (hidden; just press Enter to use your normal git login): ").strip() or None
                except EOFError:
                    token = None
            state = {"all": mode == "1"}
            CLEAN.mkdir(parents=True, exist_ok=True)
            try:
                for n, r in enumerate(todo, 1):
                    print(f"\n{B}##### [{n}/{len(todo)}] {r['full']}{X}")
                    detail(r)
                    choice = confirm_repo(r, state)
                    if choice != "clean":
                        r["result"] = "SKIPPED by you" if choice == "skip" else "REVIEWED (nothing removed)"
                        continue
                    push = pm == "2"
                    if pm == "3":
                        push = ask(f"Also force-push {r['full']} to origin afterwards? [y/n]: ", ("y", "n")) == "y"
                    try:
                        r["result"] = local_clean(r, push, token)
                    except Exception as e:
                        r["result"] = f"FAILED ({type(e).__name__}: {e})"
                    print(f"{G if r['result'].startswith('CLEANED') else Y}{r['result']}{X}")
            except KeyboardInterrupt:
                print(f"\n{Y}Stopped by you. Remaining repos untouched.{X}")
    else:
        print(f"\n{G}Nothing to clean.{X}")
    out = [f"{r['full']:<45} {r['result']}" for r in rows if r["result"]]
    print(f"\n{B}===== LOCAL SUMMARY ====={X}")
    print("\n".join(out) or "Nothing was changed.")
    rep = write_report("report_local.txt", out)
    print(f"\nReport: {rep}\nBackups of changed local repos: {LOCAL_BACKUP}")
    print("Reminder: delete and reinstall node_modules in cleaned projects, and clean this PC too "
          "(look for temp_auto_push.bat, run an antivirus scan) or the malware re-infects.")


def check_requirements():
    if shutil.which("git") is None:
        sys.exit("git not found - install it (Windows: https://git-scm.com | macOS: xcode-select --install "
                 "or brew install git | Linux: sudo apt/dnf/pacman install git)")
    m = re.search(r"(\d+)\.(\d+)", git(["--version"])[1])
    if not m or (int(m.group(1)), int(m.group(2))) < (2, 31):
        sys.exit(f"git 2.31 or newer is required (found: {m.group(0) if m else 'unknown'})")
    p = subprocess.run([sys.executable, "-c", "import git_filter_repo"], capture_output=True)
    if p.returncode != 0:
        sys.exit(f"git-filter-repo missing for {sys.executable}\n"
                 f"  install:  {Path(sys.executable).name} -m pip install git-filter-repo\n"
                 "  ('externally-managed-environment' error on Linux/macOS? use a virtual "
                 "environment - see README.md)")


def main():
    argv = sys.argv[1:]
    print(f"{B}polinRyder {VERSION}  (file: {Path(__file__).resolve()}){X}")
    check_requirements()
    if "--local" in argv:
        target = "2"
    elif "--github" in argv:
        target = "1"
    else:
        print("\nWhat do you want to clean?")
        print("  [1] GitHub repositories (cloud)")
        print("  [2] Git repositories in a folder on THIS computer (local)")
        print("  [3] Both (local first, then GitHub)")
        target = ask("Choose 1 / 2 / 3: ", ("1", "2", "3"))
    if target in ("2", "3"):
        local_main(argv)
    if target in ("1", "3"):
        github_main(argv)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Y}Aborted.{X}")
        sys.exit(130)
    finally:
        if REVIEW_DIR.exists():          # don't leave copies of malware text lying around
            try:
                rmtree(REVIEW_DIR)
            except OSError:
                pass
