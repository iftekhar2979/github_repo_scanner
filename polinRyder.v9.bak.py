#!/usr/bin/env python3
"""
polinrider_cleaner.py

Scan YOUR OWN GitHub repos for PolinRider injection (all branches, full history),
show what is affected, and - repo by repo, only after explicit confirmation -
rewrite history to remove it and force-push.

Requirements: Python 3.8+, git, and git-filter-repo   (pip install git-filter-repo)
Usage:  python polinrider_cleaner.py              -> shows the plan, asks ONE question (all / one-by-one)
        python polinrider_cleaner.py --all        -> clean everything, no questions at all
        python polinrider_cleaner.py --one-by-one -> yes/no before each repository
        --local [FOLDER] -> clean git repos on THIS PC (optionally force-push); --github -> GitHub only
        (local extras: --push / --no-push to skip the push question)
        add --fresh  -> delete existing local copies and clone new ones (no question)
        add --reuse  -> work on existing local copies (no question)
        add --orgs to include organization repos too
        (set env var GITHUB_TOKEN to skip the hidden token prompt)
Token: classic PAT with `repo` scope, or fine-grained PAT with
       Contents: Read & Write + Metadata: Read on all your repos.
The token is typed at a hidden prompt, never written to disk, never put in a URL.

Extra indicators: put one literal string per line in `extra_iocs.txt`
next to this script (copy them from your reference document).
"""
import base64, getpass, json, os, re, shutil, stat, subprocess, sys, urllib.request, urllib.error
from pathlib import Path

API = "https://api.github.com"
WORK = Path.home() / "polinrider_work"
BACKUP = WORK / "backups"      # pristine mirrors of every repo (your safety net)
CLEAN = WORK / "clean"         # scratch copies that get rewritten
LOCAL_BACKUP = WORK / "local_backups"   # backup of each LOCAL repo before it is changed

# Known PolinRider indicators (OpenSourceMalware reports). Extend via extra_iocs.txt
IOCS = ["_$_1e42", "global['!']", 'global["!"]', "global['_V']", 'global["_V"]',
        "rmcej%otb%", "Cot%3t=shtP"]
extra = Path(__file__).with_name("extra_iocs.txt")
if extra.exists():
    IOCS += [l.strip() for l in extra.read_text(encoding="utf-8").splitlines() if l.strip()]
# "Fake font" variant: a file named *.woff2 / *.woff / *.ttf / *.otf that is really JavaScript
# (payload hidden in e.g. public/fonts/fa-solid-400.woff2). Detected by IOC strings OR by a wrong file header.
FONT_MAGIC = {".woff2": (b"wOF2",), ".woff": (b"wOFF",),
              ".ttf": (b"\x00\x01\x00\x00", b"true", b"ttcf"), ".otf": (b"OTTO", b"\x00\x01\x00\x00", b"true")}
# package.json scripts calling  node init / node init.js / node api / node api.js
# (alone, or chained with && || ;  -> the call is removed, the rest of the script is kept)
NODE_RE = r'node +(\./)?(init|api)(\.js)?( |"|;|&|\||$)'
HOOKS = []   # literal fallback for package.json files that are not valid JSON
for _c in ("node init", "node init.js", "node api", "node api.js"):
    HOOKS += [(f"{_c} && ", ""), (f"{_c}&& ", ""), (f' && {_c}"', '"'), (f'&& {_c}"', '"')]
SUSPECT_FILES = ("init.js", "api.js", "init", "api", "init.cjs", "api.cjs", "init.mjs", "api.mjs")   # deleted when a package.json hook uses them
# (malicious .vscode/tasks.json files are deleted too; the rest of .vscode is left alone)
REMOVE_VSCODE = True     # delete every .vscode/ folder (any depth) from the whole history
VSCODE_SPECS = [":(glob).vscode/**", ":(glob)**/.vscode/**"]
def in_vscode(path):
    return "/.vscode/" in "/" + path
DROPPER = "temp_auto_push.bat"          # propagation script - deleted from history
SUSPECT_TASKS = ("vercel.app", "onrender.com")   # in tasks.json -> reported, NOT auto-removed

os.system("")  # enable ANSI colors on Windows consoles
FILTER_REPO = [sys.executable, "-m", "git_filter_repo"]


def rmtree(path):
    def _fix(func, p, _):
        os.chmod(p, stat.S_IWRITE)
        func(p)
    shutil.rmtree(path, onerror=_fix)  # Windows: .git files are read-only


R, G, Y, B, D, X = "\033[31m", "\033[32m", "\033[33m", "\033[36m", "\033[2m", "\033[0m"


# ---------- helpers ----------
def git(args, cwd=None, token=None):
    cmd = ["git"]
    if token:
        b64 = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        cmd += ["-c", "credential.helper=", "-c", f"http.extraheader=Authorization: Basic {b64}"]
    p = subprocess.run(cmd + args, cwd=cwd, capture_output=True, text=True, errors="replace",
                       env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
    return p.returncode, p.stdout, p.stderr


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


def sh_lines(rc_out):
    rc, out, _ = rc_out
    return [l for l in out.splitlines() if l.strip()] if rc == 0 else []


# ---------- scanning ----------
def infected_commits(gd, tf=None):
    found = {}
    for ioc in IOCS:
        for sha in sh_lines(git(["log", "--all", "--format=%H", "-S" + ioc], cwd=gd)):
            found[sha] = "payload"
    for sha in sh_lines(git(["log", "--all", "--format=%H", "--diff-filter=A", "--", "*" + DROPPER], cwd=gd)):
        found.setdefault(sha, "dropper")
    for sha in sh_lines(git(["log", "--all", "--format=%H", "-G" + NODE_RE, "--", "*package.json"], cwd=gd)):
        found.setdefault(sha, "pkg-hook")
    if REMOVE_VSCODE:
        for sha in sh_lines(git(["log", "--all", "--format=%H", "--"] + VSCODE_SPECS, cwd=gd)):
            found.setdefault(sha, ".vscode")
    tf = target_files(gd) if tf is None else tf
    if tf:
        cur = None
        for line in sh_lines(git(["log", "--all", "--format=%x01%H", "--name-only", "--"] + sorted(tf), cwd=gd)):
            if line.startswith("\x01"):
                cur = line[1:]
            elif line in tf and cur:          # exact file name only, not files inside a folder named api/
                found.setdefault(cur, "init/api/tasks file")
    return found


def target_files(gd):
    """init.js / api.js files (root + next to every package.json that ever had a `node init|api` hook)."""
    dirs = {""}
    for line in sh_lines(git(["log", "--all", "--format=", "--name-only", "-G" + NODE_RE,
                              "--", "*package.json"], cwd=gd)):
        dirs.add(line.rsplit("/", 1)[0] + "/" if "/" in line else "")
    return {d + f for d in dirs for f in SUSPECT_FILES} | malicious_tasks(gd) | set(malicious_fonts(gd))


def malicious_fonts(gd):
    """{path: reason} for font-named files (any commit, any branch) that carry an IOC or are not a real font."""
    rc, out, _ = git(["rev-list", "--objects", "--all"], cwd=gd)
    if rc != 0:
        return {}
    by_sha = {}
    for line in out.splitlines():
        if " " in line:
            sha, path = line.split(" ", 1)
            if os.path.splitext(path)[1].lower() in FONT_MAGIC:
                by_sha.setdefault(sha, set()).add(path)
    if not by_sha:
        return {}
    marks = [i.encode() for i in IOCS]
    bad = {}
    pr = subprocess.Popen(["git", "cat-file", "--batch"], cwd=gd, stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        for sha, paths in by_sha.items():
            pr.stdin.write(sha.encode() + b"\n")
            pr.stdin.flush()
            head = pr.stdout.readline().split()
            if len(head) < 3 or head[1] != b"blob":
                continue
            data = pr.stdout.read(int(head[2]))
            pr.stdout.read(1)
            for path in paths:
                magic = FONT_MAGIC[os.path.splitext(path)[1].lower()]
                if any(m in data for m in marks):
                    bad[path] = "contains PolinRider payload"
                elif len(data) >= 4 and not data.startswith(magic):
                    bad[path] = "not a real font (wrong file header)"
    finally:
        pr.stdin.close()
        pr.wait()
    return bad


def malicious_tasks(gd):
    """tasks.json files (e.g. .vscode/tasks.json) that ever held a malicious auto-run task:
    a known payload domain, or runOn:folderOpen together with a download/exec command."""
    def paths(*extra):
        return set(sh_lines(git(["log", "--all", "--format=", "--name-only"] + list(extra)
                                + ["--", "*tasks.json"], cwd=gd)))
    out = set()
    for d in SUSPECT_TASKS:
        out |= paths("-S" + d)
    out |= paths("-Gfolder[Oo]pen") & paths("-G(curl|wget|powershell|mshta|cmd /c|cmd.exe|node |bash -c|http)")
    return out


def suspicious_tasks(gd):
    out = set()
    for d in SUSPECT_TASKS:
        out |= set(sh_lines(git(["log", "--all", "--format=%H", "-S" + d, "--", "*tasks.json"], cwd=gd)))
    return out


def scan(gd):
    tf = target_files(gd)
    bad = infected_commits(gd, tf)
    fonts = malicious_fonts(gd)
    sus = suspicious_tasks(gd) - set(bad)
    branches = {}
    for ref in sh_lines(git(["for-each-ref", "--format=%(refname:short)", "refs/heads"], cwd=gd)):
        revs = set(sh_lines(git(["rev-list", ref], cwd=gd)))
        n = len(revs & set(bad))
        if n:
            branches[ref] = {"commits": n, "tip_files": []}
        # files still infected at the tip of this branch
        args = ["grep", "-a", "-l", "-F"]
        for i in IOCS:
            args += ["-e", i]
        tip = sh_lines(git(args + [ref], cwd=gd))
        tip = [t.split(":", 1)[1] for t in tip if ":" in t]
        hk = sh_lines(git(["grep", "-I", "-l", "-E", NODE_RE, ref, "--", "*package.json"], cwd=gd))
        tip += [t.split(":", 1)[1] for t in hk if ":" in t]
        tip += [n for n in sh_lines(git(["ls-tree", "-r", "--name-only", ref, "--"] + sorted(tf), cwd=gd))
                if n in tf]
        if REMOVE_VSCODE:
            tip += [n for n in sh_lines(git(["ls-tree", "-r", "--name-only", ref], cwd=gd)) if in_vscode(n)]
        if tip:
            branches.setdefault(ref, {"commits": 0, "tip_files": []})["tip_files"] = tip
    names = sh_lines(git(["ls-tree", "-r", "--name-only", "HEAD"], cwd=gd))
    review = [n for n in names if n.rsplit("/", 1)[-1] in SUSPECT_FILES and n not in tf]
    return {"commits": bad, "suspect": sus, "branches": branches, "review": review, "fonts": fonts}


def commit_line(gd, sha):
    rc, out, _ = git(["show", "-s", "--format=%h  %ad  %an  %s", "--date=short", sha], cwd=gd)
    return out.strip()[:110]


# ---------- cleaning ----------
# Runs inside git-filter-repo for every blob in history.
BLOB_CB_BODY = r'''
import re, json
d = blob.data
if b'\x00' in d[:8192]:
    return
if b'"scripts"' in d:
    N = r'node\s+(?:\./)?(?:init|api)(?:\.js)?(?:\s+[^&|;"]*)?'
    def fix(v):
        parts = re.split(r'(\s*(?:&&|\|\||;)\s*)', v)
        cmds, ops = parts[0::2], parts[1::2]
        keep = [i for i, c in enumerate(cmds) if not re.fullmatch(N, c.strip())]
        if len(keep) == len(cmds):
            return v
        if not keep:
            return None
        out = cmds[keep[0]]
        for x, y in zip(keep, keep[1:]):
            out += ops[y - 1] + cmds[y]
        return out
    try:
        obj = json.loads(d.decode('utf-8'))
    except Exception:
        obj = None
    if isinstance(obj, dict) and isinstance(obj.get('scripts'), dict):
        changed = False
        for k in list(obj['scripts']):
            v = obj['scripts'][k]
            if isinstance(v, str):
                nv = fix(v)
                if nv != v:
                    changed = True
                    if nv is None or not nv.strip():
                        del obj['scripts'][k]
                    else:
                        obj['scripts'][k] = nv
        if changed:
            m = re.search(rb'\n([ \t]+)"', d)
            ind = m.group(1).decode() if m else '  '
            out = json.dumps(obj, indent=ind, ensure_ascii=False) + '\n'
            if b'\r\n' in d:
                out = out.replace('\n', '\r\n')
            d = out.encode('utf-8')
    elif re.search(NODE_RE.encode(), d):
        for a, r in H:
            d = d.replace(a, r)
i = [d.find(m) for m in M]
i = [x for x in i if x != -1]
if i:
    s = d.rfind(b'\n', 0, min(i)) + 1
    d = d[:s].rstrip() + b'\n'
blob.data = d
'''

def run_filter_repo(src, dst):
    if dst.exists():
        rmtree(dst)
    shutil.copytree(src, dst)
    markers = [i.encode() for i in IOCS]
    drop = sorted(f.encode() for f in target_files(src)) + [DROPPER.encode()]
    blob_cb = (f"M={markers!r}\nH={[(x.encode(), y.encode()) for x, y in HOOKS]!r}\n"
               f"NODE_RE={NODE_RE!r}\n" + BLOB_CB_BODY)
    name_cb = (f"D={drop!r}\nV={REMOVE_VSCODE!r}\n"
               "if filename in D or filename.endswith(D[-1]):\n"
               "    return None\n"
               "if V and b'/.vscode/' in b'/' + filename:\n"
               "    return None\n"
               "return filename")
    p = subprocess.run(FILTER_REPO + ["--force", "--blob-callback", blob_cb,
                        "--filename-callback", name_cb], cwd=dst, capture_output=True, text=True)
    return p.returncode == 0, p.stderr


def tail_preview(gd, branch, path):
    rc, out, _ = git(["show", f"{branch}:{path}"], cwd=gd)
    lines = out.rstrip().splitlines()[-3:] if rc == 0 else ["<unreadable>"]
    return [("   " + l[:110]) for l in lines]


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
        if c or tip:
            st = f"{R}INFECTED{X}"
        elif s["suspect"] or s["review"]:
            st = f"{Y}review tasks.json{X}"
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
    for fp, why in list(s.get("fonts", {}).items())[:10]:
        print(f"  {R}FONT{X} {fp}  -> {why}")
    if s["review"]:
        print(f"  {Y}files to review by hand (may be legit): {', '.join(s['review'][:8])}{X}")
    if s["suspect"]:
        print(f"  {Y}tasks.json with suspicious URLs in {len(s['suspect'])} commit(s) - manual review needed{X}")


def is_infected(sc):
    return bool(sc["commits"]) or any(v["tip_files"] for v in sc["branches"].values())


def clean_flow(r, token, confirm=None):
    """Returns a short status string. confirm=None -> never asks anything."""
    detail(r)
    if r["meta"].get("archived"):
        print(f"{Y}Repo is archived: GitHub rejects pushes. Unarchive it first, then rerun.{X}")
        return "SKIPPED (archived)"
    if confirm and not confirm(r):
        return "SKIPPED by you"
    dst = CLEAN / r["full"].replace("/", "__")
    ok, err = run_filter_repo(r["gd"], dst)
    if not ok:
        print(f"{R}git filter-repo failed:{X}\n{err}")
        return "FAILED (filter-repo)"
    after = scan(dst)
    left = len(after["commits"]) + sum(len(v["tip_files"]) for v in after["branches"].values())
    print(f"{G if not left else R}Verification: {left} indicator(s) remaining after cleanup.{X}")
    if left:
        print(f"{Y}Not pushing - inspect {dst} by hand.{X}")
        return f"NOT PUSHED ({left} indicator(s) remain)"
    # Real write-permission test (the API "permissions" field only shows owner rights)
    git(["remote", "remove", "origin"], cwd=dst)
    git(["remote", "add", "origin", r["meta"]["clone_url"]], cwd=dst)
    rc, _, err = git(["push", "--dry-run", "--force", "origin", "refs/heads/*:refs/heads/*"],
                     cwd=dst, token=token)
    if rc != 0:
        print(f"{R}Write-permission test FAILED for {r['full']}.{X}")
        print(err.strip()[:400])
        print("Token in use ends with: ..." + token[-4:])
        return "FAILED (no write permission)"
    rc, out, err = git(["push", "--force", "origin", "refs/heads/*:refs/heads/*",
                        "refs/tags/*:refs/tags/*"], cwd=dst, token=token)
    if rc == 0:
        print(f"{G}Pushed (force).{X}")
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
       - malicious .vscode/tasks.json, and the whole .vscode folder
  4. Show a table: which repos are affected, how many commits/branches.
  5. You choose: clean ALL repos automatically, or ONE BY ONE with a yes/no for each.
  6. For each repo to be cleaned:
       a. rewrite a LOCAL copy of the history (removes the items above)
       b. verify the copy is clean - if anything remains, NOTHING is pushed
       c. test that your token can write to the repo (dry-run)
       d. force-push every branch and tag
  7. Print a summary and save it to {WORK / "report.txt"}
"""


def github_main(argv):
    orgs = "--orgs" in argv
    if shutil.which("git") is None:
        sys.exit("git not found")
    if subprocess.run(FILTER_REPO + ["--version"], capture_output=True).returncode != 0:
        sys.exit("git-filter-repo missing:  pip install git-filter-repo")
    print(PLAN)
    token = os.environ.get("GITHUB_TOKEN", "").strip() or getpass.getpass("GitHub token (hidden): ").strip()
    try:
        me = api("/user", token)["login"]
    except urllib.error.HTTPError as e:
        sys.exit(f"Token rejected ({e.code})")
    metas = list_repos(token, orgs)
    print(f"Logged in as {me}; {len(metas)} repositories.")
    BACKUP.mkdir(parents=True, exist_ok=True)
    CLEAN.mkdir(parents=True, exist_ok=True)
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
            print("  [2] CLONE NEW versions (deletes the existing local copies, downloads fresh from GitHub)")
            c = ""
            while c not in ("1", "2"):
                c = input("Choose 1 / 2: ").strip()
            fresh = c == "2"
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
        print(f"[{i}/{len(metas)}] scanning {m['full_name']}".ljust(78), end="\r")
        if gd.exists() and git(["rev-parse", "--git-dir"], cwd=gd)[0] == 0:
            rc = 0   # reuse existing copy
        else:
            if gd.exists():
                rmtree(gd)
            rc, _, _ = git(["clone", "--bare", m["clone_url"], str(gd)], token=token)
        rows.append({"full": m["full_name"], "meta": m, "gd": gd,
                     "scan": scan(gd) if rc == 0 else None, "result": ""})
    print(" " * 78)
    table(rows)
    todo = [r for r in rows if r["scan"] and is_infected(r["scan"])]
    if not todo:
        print(f"\n{G}Nothing to clean.{X}")
    else:
        if "--all" in argv:
            mode = "1"
        elif "--one-by-one" in argv or "--interactive" in argv:
            mode = "2"
        else:
            print(f"\n{B}{len(todo)} repositories need cleaning. How do you want to proceed?{X}")
            print("  [1] Clean ALL of them automatically (no more questions)")
            print("  [2] ONE BY ONE - I ask yes/no before each repository")
            print("  [q] Quit without changing anything")
            mode = ""
            while mode not in ("1", "2", "q"):
                mode = input("Choose 1 / 2 / q: ").strip().lower()
        if mode == "q":
            todo = []
        state = {"all": mode == "1"}

        def confirm(r):
            if state["all"]:
                return True
            while True:
                a = input(f"\nClean {r['full']} now? [y]es / [n]o / [a]ll remaining / [q]uit: ").strip().lower()
                if a == "a":
                    state["all"] = True
                    return True
                if a == "q":
                    raise KeyboardInterrupt
                if a in ("y", "n"):
                    return a == "y"

        try:
            for n, r in enumerate(todo, 1):
                print(f"\n{B}##### [{n}/{len(todo)}] {r['full']}{X}")
                try:
                    r["result"] = clean_flow(r, token, confirm=confirm)
                except KeyboardInterrupt:
                    raise
                except Exception as e:           # one failing repo never stops the run
                    r["result"] = f"FAILED ({type(e).__name__}: {e})"
                    print(f"{R}{r['result']}{X}")
        except KeyboardInterrupt:
            print(f"\n{Y}Stopped by you. Repos not yet processed were left untouched.{X}")
    lines = [f"{r['full']:<45} {r['result']}" for r in rows if r["result"]]
    unscanned = [r["full"] for r in rows if r["scan"] is None]
    print(f"\n{B}===== SUMMARY ====={X}")
    print("\n".join(lines) or "Nothing was changed.")
    if unscanned:
        print(f"{Y}Could not clone/scan: {', '.join(unscanned)}{X}")
    report = WORK / "report.txt"
    report.write_text("\n".join(lines + [f"unscanned: {u}" for u in unscanned]), encoding="utf-8")
    print(f"\nReport saved: {report}\nBackups (original, pre-cleanup): {BACKUP}")
    print("Now REVOKE this token, and re-clone any local copies of the cleaned repos.")


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
       f. leftover UNTRACKED suspicious files (init, init.js, api.js, .vscode, temp_auto_push.bat) are deleted
       g. optional: force-push all branches/tags to origin
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
        dirnames[:] = [d for d in dirnames if d not in ("node_modules", ".venv", "venv", "__pycache__", "AppData", "$RECYCLE.BIN")]
    return out


def leftover_untracked(path, tf):
    """Untracked / ignored files that match the suspicious patterns."""
    names = sh_lines(git(["ls-files", "--others", "--exclude-standard"], cwd=path))
    names += sh_lines(git(["ls-files", "--others", "--ignored", "--exclude-standard", "--directory"], cwd=path))
    hits = []
    for n in names:
        base = n.rstrip("/").rsplit("/", 1)[-1]
        if base == DROPPER or n in tf or (REMOVE_VSCODE and in_vscode(n if not n.endswith("/") else n)):
            hits.append(n)
    return hits


def local_clean(r, push, token):
    path, name = r["gd"], r["full"]
    if git(["status", "--porcelain", "--untracked-files=no"], cwd=path)[1].strip():
        return "SKIPPED (uncommitted changes - commit or stash first)"
    cur = git(["symbolic-ref", "--short", "-q", "HEAD"], cwd=path)[1].strip()
    if not cur:
        return "SKIPPED (detached HEAD - checkout a branch first)"
    has_origin = "origin" in git(["remote"], cwd=path)[1].split()
    diverged = []
    if has_origin:
        rc, _, err = git(["fetch", "origin", "--prune"], cwd=path, token=token)
        if rc != 0:
            if push:
                return "SKIPPED (cannot fetch origin: " + err.strip()[:120] + ")"
            print(f"{Y}Could not fetch origin - continuing with what is local.{X}")
        else:
            for rb in sh_lines(git(["for-each-ref", "--format=%(refname:short)", "refs/remotes/origin"], cwd=path)):
                if rb == "origin" or rb.endswith("/HEAD"):
                    continue
                b = rb[len("origin/"):]
                if git(["show-ref", "--verify", "--quiet", f"refs/heads/{b}"], cwd=path)[0] != 0:
                    git(["branch", b, rb], cwd=path)              # remote-only branch -> make it local so it gets cleaned too
                elif git(["merge-base", "--is-ancestor", b, rb], cwd=path)[0] == 0:
                    if b == cur:
                        git(["merge", "--ff-only", rb], cwd=path)  # local was behind origin
                    else:
                        git(["branch", "-f", b, rb], cwd=path)
                elif git(["merge-base", "--is-ancestor", rb, b], cwd=path)[0] != 0:
                    diverged.append(b)                              # local and origin both have own commits
    if push:
        if not has_origin:
            return "SKIPPED (no 'origin' remote to push to)"
        if diverged:
            return f"SKIPPED (branch(es) {', '.join(diverged)} diverged from origin - merge/rebase first, a force-push would lose commits)"
        rc, _, err = git(["push", "--dry-run", "--force", "origin", "refs/heads/*:refs/heads/*"], cwd=path, token=token)
        if rc != 0:
            return "SKIPPED (push permission test failed: " + err.strip()[:150] + ")"
    tag = re.sub(r"[^A-Za-z0-9._-]", "_", str(path))[-90:]
    bk = LOCAL_BACKUP / (tag + ".git")
    LOCAL_BACKUP.mkdir(parents=True, exist_ok=True)
    if bk.exists():
        rmtree(bk)
    rc, _, err = git(["clone", "--mirror", str(path), str(bk)])
    if rc != 0:
        return "FAILED (backup: " + err.strip()[:150] + ")"
    tf = target_files(bk)
    dst = CLEAN / ("local__" + tag)
    ok, err = run_filter_repo(bk, dst)
    if not ok:
        return "FAILED (filter-repo)"
    after = scan(dst)
    left = len(after["commits"]) + sum(len(v["tip_files"]) for v in after["branches"].values())
    print(f"{G if not left else R}Verification: {left} indicator(s) remaining after cleanup.{X}")
    if left:
        return f"NOT APPLIED ({left} indicator(s) remain)"
    # ---- apply cleaned history to the local repo ----
    git(["fetch", "--force", "--no-tags", str(dst), "+refs/heads/*:refs/cleaned/*", "+refs/tags/*:refs/tags/*"], cwd=path)
    for ref in sh_lines(git(["for-each-ref", "--format=%(refname)", "refs/cleaned"], cwd=path)):
        b = ref[len("refs/cleaned/"):]
        if b == cur:
            git(["reset", "--hard", ref], cwd=path)
        else:
            git(["branch", "-f", b, ref], cwd=path)
        git(["update-ref", "-d", ref], cwd=path)
    removed = []
    for n in leftover_untracked(path, tf):
        full = Path(path) / n
        try:
            shutil.rmtree(full, onerror=lambda f, p_, _: (os.chmod(p_, stat.S_IWRITE), f(p_))) if full.is_dir() else (os.chmod(full, stat.S_IWRITE), full.unlink())
            removed.append(n)
        except OSError as e:
            print(f"{Y}could not delete {n}: {e}{X}")
    if removed:
        print(f"{D}deleted untracked suspicious files: {', '.join(removed[:10])}{X}")
    status = "CLEANED LOCALLY"
    if push:
        rc, _, err = git(["push", "--force", "origin", "refs/heads/*:refs/heads/*", "refs/tags/*:refs/tags/*"], cwd=path, token=token)
        if rc == 0:
            status = "CLEANED + PUSHED"
            git(["fetch", "origin", "--prune", "--force"], cwd=path, token=token)
        else:
            print(f"{R}Push failed:{X}\n{err.strip()[:500]}")
            status = "CLEANED LOCALLY, PUSH FAILED (protected branch?)"
    else:
        # old infected history is still referenced by remote-tracking refs -> drop them so the local repo is really clean
        for ref in sh_lines(git(["for-each-ref", "--format=%(refname)", "refs/remotes"], cwd=path)):
            git(["update-ref", "-d", ref], cwd=path)
        status += " (origin NOT updated - remote-tracking refs removed; push later with --force)"
    git(["reflog", "expire", "--expire=now", "--all"], cwd=path)
    git(["gc", "--prune=now", "-q"], cwd=path)
    return status


def local_main(argv):
    print(LOCAL_PLAN)
    root = ""
    if "--local" in argv:
        i = argv.index("--local")
        if i + 1 < len(argv) and not argv[i + 1].startswith("--"):
            root = argv[i + 1]
    while not root or not Path(root).expanduser().is_dir():
        root = input("Folder that contains your git repos (e.g. C:\\Users\\Iftekhar\\projects): ").strip().strip('"')
    repos = find_repos(root)
    print(f"Found {len(repos)} git repositories under {root}")
    rows = []
    for i, path in enumerate(repos, 1):
        rel = os.path.relpath(path, Path(root).expanduser())
        print(f"[{i}/{len(repos)}] scanning {rel}".ljust(78), end="\r")
        rows.append({"full": rel if rel != "." else Path(root).name, "meta": {}, "gd": path,
                     "scan": scan(path), "result": ""})
    print(" " * 78)
    table(rows)
    todo = [r for r in rows if is_infected(r["scan"])]
    if todo:
        if "--all" in argv:
            mode = "1"
        elif "--one-by-one" in argv:
            mode = "2"
        else:
            print(f"\n{B}{len(todo)} repositories need cleaning. How do you want to proceed?{X}")
            print("  [1] Clean ALL of them automatically")
            print("  [2] ONE BY ONE - I ask yes/no before each repository")
            print("  [q] Quit without changing anything")
            mode = ""
            while mode not in ("1", "2", "q"):
                mode = input("Choose 1 / 2 / q: ").strip().lower()
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
                pm = ""
                while pm not in ("1", "2", "3"):
                    pm = input("Choose 1 / 2 / 3: ").strip()
            token = None
            if pm != "1":
                token = os.environ.get("GITHUB_TOKEN", "").strip() or getpass.getpass(
                    "GitHub token for pushing (hidden; just press Enter to use your normal git login): ").strip() or None
            state = {"all": mode == "1"}
            CLEAN.mkdir(parents=True, exist_ok=True)
            try:
                for n, r in enumerate(todo, 1):
                    print(f"\n{B}##### [{n}/{len(todo)}] {r['full']}{X}")
                    detail(r)
                    if not state["all"]:
                        a = ""
                        while a not in ("y", "n", "a", "q"):
                            a = input(f"Clean {r['full']} now? [y]es / [n]o / [a]ll remaining / [q]uit: ").strip().lower()
                        if a == "q":
                            raise KeyboardInterrupt
                        if a == "n":
                            r["result"] = "SKIPPED by you"
                            continue
                        if a == "a":
                            state["all"] = True
                    push = pm == "2"
                    if pm == "3":
                        push = input(f"Also force-push {r['full']} to origin afterwards? [y/N]: ").strip().lower() == "y"
                    try:
                        r["result"] = local_clean(r, push, token)
                    except Exception as e:
                        r["result"] = f"FAILED ({type(e).__name__}: {e})"
                    print(f"{G if r['result'].startswith('CLEANED') else Y}{r['result']}{X}")
            except KeyboardInterrupt:
                print(f"\n{Y}Stopped by you. Remaining repos untouched.{X}")
    else:
        print(f"\n{G}Nothing to clean.{X}")
    lines = [f"{r['full']:<45} {r['result']}" for r in rows if r["result"]]
    print(f"\n{B}===== LOCAL SUMMARY ====={X}")
    print("\n".join(lines) or "Nothing was changed.")
    WORK.mkdir(parents=True, exist_ok=True)
    (WORK / "report_local.txt").write_text("\n".join(lines), encoding="utf-8")
    print(f"\nReport: {WORK / 'report_local.txt'}\nBackups of changed local repos: {LOCAL_BACKUP}")
    print("Reminder: clean this PC too (look for temp_auto_push.bat, run an antivirus scan) or the malware re-infects.")


def main():
    argv = sys.argv[1:]
    print(f"{B}polinrider_cleaner v9  (file: {Path(__file__).resolve()}){X}")
    if shutil.which("git") is None:
        sys.exit("git not found")
    if subprocess.run(FILTER_REPO + ["--version"], capture_output=True).returncode != 0:
        sys.exit("git-filter-repo missing:  pip install git-filter-repo")
    if "--local" in argv:
        target = "2"
    elif "--github" in argv:
        target = "1"
    else:
        print("\nWhat do you want to clean?")
        print("  [1] GitHub repositories (cloud)")
        print("  [2] Git repositories in a folder on THIS computer (local)")
        print("  [3] Both (local first, then GitHub)")
        target = ""
        while target not in ("1", "2", "3"):
            target = input("Choose 1 / 2 / 3: ").strip()
    if target in ("2", "3"):
        local_main(argv)
    if target in ("1", "3"):
        github_main(argv)


if __name__ == "__main__":
    main()
