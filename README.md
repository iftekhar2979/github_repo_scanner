# polinRyder.py: PolinRider malware cleaner for git repositories

`polinRyder.py` scans **your own** GitHub repositories, or git repositories on this computer,
for the *PolinRider* injection. It checks all branches and the full history. It shows what is
affected and, only after you confirm, rewrites the history to remove the malware. It can
then force-push the cleaned history.

It runs on **Windows, macOS and Linux**.

> ⚠️ **This tool rewrites git history and can force-push.** Anyone who has cloned an affected
> repo must re-clone it afterwards. Read [Safety](#safety-what-protects-you) before your first run.

---

## What it detects and removes

| Indicator | What happens |
|---|---|
| Payload strings (`_$_1e42`, `global['!']`, `global['_V']`, `global.i='A10-…'`, and others) | The payload is cut out of every file version. ⚠️ Everything from the payload's start to the end of that file is removed (see [Known limitations](#known-limitations)) |
| Code hidden behind 200+ spaces at the end of a line | Cut out (the real code before the spaces is kept) |
| `"node init"` / `"node api"` hooks in `package.json` scripts | Only the hook is removed; the rest of the script is kept |
| `init.js` / `api.js` (and `.cjs`/`.mjs`) next to a hooked `package.json` | Deleted from the whole history |
| Fake fonts (`.woff2/.woff/.ttf/.otf/.eot` that are really JavaScript) | Fake versions deleted; a real font that was overwritten is restored |
| `temp_auto_push.bat` (propagation script) | Deleted from the whole history |
| Every `.vscode/` folder, including malicious `tasks.json` | Deleted from the whole history |
| `tasks.json` with `vercel.app` / `onrender.com` URLs, loaders of fake fonts, unhooked `init.js`/`api.js` | Reported as **review by hand**: you decide (remove/keep) |

You can add more indicators: put one literal string per line in a file named
`extra_iocs.txt` **next to the script**.

---

## Requirements (all platforms)

| Tool | Minimum version | Check with |
|---|---|---|
| Python | 3.8 | `python --version` (Windows) / `python3 --version` |
| git | **2.31** | `git --version` |
| git-filter-repo (Python module) | any recent | `python -c "import git_filter_repo"` |

**Important:** `git-filter-repo` must be installed **for the same Python that runs the script**.
The script imports it as a library. If you install it with `brew install git-filter-repo` or
`apt install git-filter-repo`, only the command-line tool is installed, and your Python cannot
import it. Use `pip` (Windows) or a virtual environment (macOS/Linux), as shown below.

---

## Setup on Windows (10 / 11)

1. **Install Git for Windows:** <https://git-scm.com/download/win> (keep the default options).
2. **Install Python 3:** <https://www.python.org/downloads/windows/>.
   On the first installer screen, tick **"Add python.exe to PATH"**.
3. Open **PowerShell** (or Command Prompt) in the folder that contains `polinRyder.py`:

   ```powershell
   python --version          # 3.8 or newer
   git --version             # 2.31 or newer
   python -m pip install --upgrade git-filter-repo
   python -c "import git_filter_repo; print('ok')"
   ```

   If `python` opens the Microsoft Store, use `py` instead of `python` in every command
   (for example `py -m pip install git-filter-repo` and `py polinRyder.py`).

4. Run it:

   ```powershell
   python polinRyder.py
   ```

Notes for Windows:
- Long paths (deep `node_modules`, long repo names) are handled by the script. You do **not**
  need to change the Windows registry.
- Use a real console window (PowerShell, Windows Terminal, or cmd). The token prompt is hidden there.

---

## Setup on macOS

1. **Install git and Python 3**. Choose **one** option:
   - Apple Command Line Tools (simplest): `xcode-select --install`
   - Homebrew: `brew install git python`
2. Open **Terminal** in the folder that contains `polinRyder.py` and create a virtual environment.
   This is needed because Homebrew's Python blocks a plain `pip install`
   (*externally-managed-environment*):

   ```bash
   python3 --version                         # 3.8 or newer
   git --version                             # 2.31 or newer
   python3 -m venv ~/polinrider-venv
   ~/polinrider-venv/bin/python -m pip install --upgrade pip git-filter-repo
   ~/polinrider-venv/bin/python -c "import git_filter_repo; print('ok')"
   ```

3. Run it with the venv's Python. You don't need to activate the venv first:

   ```bash
   ~/polinrider-venv/bin/python polinRyder.py
   ```

   You can also activate the venv first (`source ~/polinrider-venv/bin/activate`) and then run
   `python polinRyder.py`.

---

## Setup on Linux

1. **Install git, Python 3 and venv support** using your distribution's command:

   | Distribution | Command |
   |---|---|
   | Ubuntu / Debian / Mint | `sudo apt update && sudo apt install git python3 python3-venv` |
   | Fedora / RHEL / Rocky | `sudo dnf install git python3` |
   | Arch / Manjaro | `sudo pacman -S git python` |
   | openSUSE | `sudo zypper install git python3` |

   Check `git --version`. **Ubuntu 20.04 (git 2.25) and Debian 11 (git 2.30) are too old.**
   Upgrade git first:
   - Ubuntu: `sudo add-apt-repository ppa:git-core/ppa && sudo apt update && sudo apt install git`
   - Debian 11: install git from `bullseye-backports`.

2. Create a virtual environment and install git-filter-repo into it. Recent Ubuntu, Debian and
   Fedora versions block a plain `pip install` (*externally-managed-environment*):

   ```bash
   python3 -m venv ~/polinrider-venv
   ~/polinrider-venv/bin/python -m pip install --upgrade pip git-filter-repo
   ~/polinrider-venv/bin/python -c "import git_filter_repo; print('ok')"
   ```

3. Run it:

   ```bash
   ~/polinrider-venv/bin/python polinRyder.py
   ```

Optional: to open review files in your own editor (`[o]` in the review screen), set
`EDITOR` or `VISUAL`, for example `export EDITOR=nano`. Otherwise `xdg-open` is used.

---

## GitHub token (only needed for GitHub mode or pushing)

Create a token at **GitHub → Settings → Developer settings → Personal access tokens**:

- **Classic token:** scope `repo`
- **Fine-grained token:** *All repositories*, with **Contents: Read and write** and **Metadata: Read**

The script asks for the token at a hidden prompt. It is never written to disk or put in a URL
or on a command line, and it is only sent to `https://github.com`. To skip the prompt, set it
as an environment variable for that terminal session:

```bash
export GITHUB_TOKEN=ghp_xxx          # macOS / Linux
```
```powershell
$env:GITHUB_TOKEN = "ghp_xxx"        # Windows PowerShell
```

**Revoke the token when you are done.**

---

## Usage

Replace `python` with `py` (Windows) or `~/polinrider-venv/bin/python` (macOS/Linux), as above.

```text
python polinRyder.py                     # interactive: choose GitHub / local / both
python polinRyder.py --github            # GitHub repos only
python polinRyder.py --local ~/projects  # git repos in a folder on this computer
```

| Option | Meaning |
|---|---|
| `--github` | Clean your GitHub repositories |
| `--local [FOLDER]` | Clean every git repo found under FOLDER (asks if omitted) |
| `--all` | Clean every infected repo, no further questions |
| `--one-by-one` | Show files and code per repo, ask yes/no for each |
| `--select 3,5-7` | Only these rows of the result table, one by one |
| `--orgs` | GitHub mode: include repos of organizations you belong to |
| `--fresh` / `--reuse` | GitHub mode: re-clone or reuse existing backup copies |
| `--push` / `--no-push` | Local mode: force-push cleaned repos to `origin`, or don't |

Typical first run: run without `--all`, read the table and the **FINDINGS** list, and choose
**[2] one by one**.

### Where files go

Everything is stored under `polinrider_work` in your home folder
(`C:\Users\<you>\polinrider_work` on Windows, `~/polinrider_work` on macOS and Linux):

| Folder / file | Contents |
|---|---|
| `backups/` | Untouched bare clones of every GitHub repo, made **before** cleaning (your safety net) |
| `local_backups/` | Untouched mirror of each local repo, made before it was changed |
| `clean/` | Scratch copies where history is rewritten |
| `report.txt` / `report_local.txt` | Summary of the last run |

---

## Safety: what protects you

- Nothing is changed until you confirm. The only exception is `--all`, which skips the questions.
- A backup is made before every change.
- Each cleaned copy is **re-scanned**. If any indicator remains, nothing is pushed or applied.
- If cleaning would delete a whole branch, or a file you chose to remove is still there, nothing
  is pushed or applied, and you are told why.
- Pushes use `--force-with-lease`. A branch that changed on GitHub since the backup is **not** overwritten.
- Local mode skips repos with uncommitted changes, a detached HEAD, or branches that diverged
  from `origin`.

## After cleaning

1. **Revoke the GitHub token.**
2. Delete and re-clone every other copy of the cleaned repos (other PCs, CI caches, teammates' clones).
3. In cleaned projects, delete `node_modules` and reinstall.
4. **Clean the computer itself.** Look for `temp_auto_push.bat` and run an antivirus scan.
   Otherwise the malware re-infects your repos.
5. GitHub keeps old commits reachable through pull requests and forks. Ask GitHub Support to
   purge cached views if the payload must disappear completely.
6. If you have a stash, it may still hold infected commits. Run `git stash clear` when you no longer need it.

## Known limitations

- When a payload is found in a file, the cut removes **everything from the payload's start to
  the end of that file**. The real attack appends its payload at the end, so this is normally
  correct. But if real code came *after* the payload in the same file, that code is removed too.
  Use the one-by-one review (red `-` lines are removed) and compare with the backup if unsure.
- Archived GitHub repos are skipped (GitHub rejects pushes). Unarchive them, then run again.
- Protected branches reject force-pushes. Temporarily allow force-push for them on GitHub.

## Troubleshooting

| Message | Fix |
|---|---|
| `git-filter-repo missing for …` | Install it for **that** Python (see your OS section above) |
| `error: externally-managed-environment` | Use the virtual-environment steps (macOS/Linux) |
| `git 2.31 or newer is required` | Upgrade git (see Linux notes, or reinstall Git for Windows) |
| `GitHub API error 401` | Token is wrong, expired, or lacks the scopes listed above |
| `Write-permission test FAILED` | Fine-grained token lacks *Contents: Read and write* for that repo |
| `SKIPPED (GitHub changed since the local copy …)` | Rerun with `--fresh` |
| `SKIPPED (uncommitted changes …)` | Commit or stash your work in that repo first |
| `NOT APPLIED (branch(es) … would become completely empty …)` | That branch contains only malicious files. Delete it by hand (`git branch -D name`, and `git push origin --delete name` if it is on GitHub) |
