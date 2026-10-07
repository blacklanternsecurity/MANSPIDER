import json
import os
import subprocess
import sys
from pathlib import Path


def _run_manspider(args, home, cwd):
    env = os.environ.copy()
    env["HOME"] = str(home)
    return subprocess.run(
        [sys.executable, "-m", "man_spider.manspider", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_json_lines_output_local_mode(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    seed = tmp_path / "seed"
    seed.mkdir()
    (seed / "secrets.kdbx").write_text("KDBX stub")
    (seed / "app.config").write_text('password = "hunter2"\n')
    (seed / "readme.txt").write_text("nothing to see here\n")

    out = tmp_path / "out.jsonl"
    repo_root = Path(__file__).parent.parent
    result = _run_manspider([str(seed), "-q", "--json", str(out)], home, repo_root)
    assert result.returncode == 0, result.stderr

    assert out.exists(), "expected JSON Lines output file to be created"
    records = [json.loads(line) for line in out.read_text().splitlines() if line.strip()]
    assert records, "expected at least one match record"

    # every record is well-formed and carries the core fields
    for r in records:
        assert set(["target", "share", "path", "match_type", "rule", "triage"]).issubset(r)
        assert r["triage"] in ("green", "yellow", "red", "black")

    by_type = {r["match_type"] for r in records}
    # the .kdbx extension rule (black) and at least one content match
    assert "extension" in by_type
    assert "content" in by_type
    kdbx = [r for r in records if r["path"].endswith("secrets.kdbx")]
    assert kdbx and kdbx[0]["triage"] == "black"
    content = [r for r in records if r["match_type"] == "content"]
    assert content and content[0]["pattern"] and content[0]["count"] >= 1
