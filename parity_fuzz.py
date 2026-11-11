"""Randomized parity of prometheus_core.stage_and_write with `git add -A` + `git write-tree`.

usage: python3 core/parity_fuzz.py [iterations-per-category] [seed]

Each category starts from a random committed tree, applies random work-tree
edits, then stages both ways: git into a scratch index and a private object
dir, the module into its own store. Prints one line per category and exits 1
on any mismatched tree, naming the seed that reproduces it. An error is not a
mismatch: the engine reruns that call on git, so it only costs speed; such
fallbacks are counted apart from deliberate `route:` refusals.
"""

import os
import random
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "runtime"))
import prometheus_core as core  # noqa: E402

NAMES = ["a", "a.txt", "a-", "a0", "a.b", "b", "B", "x y", "ü.txt", "z", "dir", "dir.txt", "dir-"]
CATEGORIES = {
    "plain": {},
    "text-auto": {"attributes": "* text=auto\n"},
    "autocrlf-true": {"config": [("core.autocrlf", "true")]},
    "eol-attributes": {"attributes": "*.txt eol=lf\n*.b eol=crlf\n*.dat binary\n", "config": [("core.autocrlf", "input")]},
    "gitignore": {"gitignore": True},
    "staged": {"stage": True},
    "untracked-hidden": {"config": [("status.showUntrackedFiles", "no")]},
    "symlinks-off": {"config": [("core.symlinks", "false")]},
}


def git(root, *args, env=None):
    proc = subprocess.run(["git", "-C", str(root), *args], capture_output=True, env=env)
    if proc.returncode:
        raise RuntimeError(f"git {' '.join(args)}: {proc.stderr.decode(errors='replace')}")
    return proc.stdout.decode().rstrip()  # leading whitespace is data: " M a.txt" starts with a space


def changed_paths(root):
    return [line[3:] for line in git(root, "-c", "core.quotePath=false", "status", "--porcelain", "-uall").splitlines()]


def tracked_paths(root):
    return [line for line in git(root, "-c", "core.quotePath=false", "ls-files").splitlines() if line]


def content(rng):
    kind = rng.random()
    if kind < 0.15:
        return bytes(rng.randrange(256) for _ in range(rng.randrange(1, 40)))
    lines = [rng.choice(["x", "y", "line", ""]) * rng.randrange(1, 4) for _ in range(rng.randrange(0, 5))]
    eol = rng.choice([b"\n", b"\r\n", b"\n", b"\r\n", b"\r"])
    body = eol.join(line.encode() for line in lines)
    return body + (eol if rng.random() < 0.7 else b"")


def rel(rng, depth=0):
    name = rng.choice(NAMES)
    return name if depth > 1 or rng.random() < 0.5 else f"{name}/{rel(rng, depth + 1)}"


def place(root, path, rng, mode="file"):
    full = root / path
    try:
        full.parent.mkdir(parents=True, exist_ok=True)
        if full.is_symlink() or full.is_file():
            full.unlink()
        elif full.is_dir():
            shutil.rmtree(full)
        if mode == "link":
            os.symlink(rng.choice(["a", "../a.txt", "dir", "missing", "."]), full)
        else:
            full.write_bytes(content(rng))
            if rng.random() < 0.2:
                full.chmod(0o755)
    except (OSError, NotADirectoryError):
        pass  # a parent is a file or a link: skip this edit


def build(root, rng, spec):
    root.mkdir()
    git(root, "init", "-q")
    for key, value in spec.get("config", []):
        git(root, "config", key, value)
    if "attributes" in spec:
        (root / ".gitattributes").write_text(spec["attributes"])
    if spec.get("gitignore"):
        rules = rng.sample(["*.b", "!keep.b", "dir/", "a0", "x y/", "*.dat", "!dir/a"], rng.randrange(1, 5))
        (root / ".gitignore").write_text("\n".join(rules) + "\n")
    for _ in range(rng.randrange(3, 15)):
        place(root, rel(rng), rng, "link" if rng.random() < 0.1 else "file")
    git(root, "add", "-A")
    git(root, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "base", "--allow-empty")


def mutate(root, rng, spec):
    tracked = tracked_paths(root)
    for _ in range(rng.randrange(1, 10)):
        action = rng.random()
        if tracked and action < 0.3:
            target = root / rng.choice(tracked)
            if target.is_file() and not target.is_symlink():
                target.write_bytes(content(rng)) if rng.random() < 0.7 else target.chmod(target.stat().st_mode ^ 0o111)
        elif tracked and action < 0.45:
            target = root / rng.choice(tracked)
            if target.is_symlink() or target.is_file():
                target.unlink()
        elif action < 0.55:
            place(root, rel(rng), rng, "link")
        else:
            place(root, rel(rng), rng)
    if spec.get("stage"):
        changed = changed_paths(root)
        for path in rng.sample(changed, k=min(len(changed), rng.randrange(0, 3))):
            flag = ["-N"] if rng.random() < 0.3 else []
            try:
                git(root, "add", *flag, "--", path.strip('"'))
            except RuntimeError:
                pass


def cli_tree(root, tmp):
    index = Path(tmp) / "index"
    real = root / ".git" / "index"
    if real.exists():
        shutil.copy2(real, index)
    env = {**os.environ, "GIT_INDEX_FILE": str(index), "GIT_OBJECT_DIRECTORY": str(Path(tmp) / "cli-objects"),
           "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(root / ".git" / "objects")}
    Path(env["GIT_OBJECT_DIRECTORY"]).mkdir()
    git(root, "-c", "core.splitIndex=false", "add", "-A", env=env)
    return git(root, "-c", "core.splitIndex=false", "write-tree", "--missing-ok", env=env)


def run(category, spec, iterations, seed):
    failures, routed, fell_back = [], 0, []
    for i in range(iterations):
        case = f"{seed}:{category}:{i}"
        rng = random.Random(case)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "r"
            build(root, rng, spec)
            mutate(root, rng, spec)
            expected = cli_tree(root, tmp)
            try:
                got = core.stage_and_write(str(root), str(Path(tmp) / "core-objects"), [], [])
            except RuntimeError as exc:
                got = f"error: {exc}"
            if got.startswith("error: route:"):
                routed += 1  # the engine hands this call to git, whose answer is `expected` by definition
            elif got.startswith("error: "):
                fell_back.append((case, got[7:]))
            elif got != expected:
                failures.append((case, expected, got))
    return failures, routed, fell_back


def main():
    iterations = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    seed = sys.argv[2] if len(sys.argv) > 2 else "f0"
    env = {"HOME": tempfile.mkdtemp(), "GIT_CONFIG_NOSYSTEM": "1"}
    os.environ.update(env)
    bad = 0
    for category, spec in CATEGORIES.items():
        failures, routed, fell_back = run(category, spec, iterations, seed)
        bad += len(failures)
        status = "pass" if not failures else "FAIL"
        print(f"{category:15} {status} {iterations - len(failures)}/{iterations} (routed to git: {routed},"
              f" fell back to git: {len(fell_back)}{' e.g. ' + fell_back[0][0] + ' ' + fell_back[0][1] if fell_back else ''})"
              + (f"  first: {failures[0][0]} git={failures[0][1]} core={failures[0][2]}" if failures else ""))
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
