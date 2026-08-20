import multiprocessing
import os
import subprocess
import sys
from pathlib import Path

import pytest


START_METHODS = [
    method for method in ("fork", "forkserver", "spawn") if method in multiprocessing.get_all_start_methods()
]


@pytest.mark.parametrize("start_method", START_METHODS)
def test_spiderling_logging_and_messages_across_processes(start_method, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    loot_dir = tmp_path / "loot"
    helper = Path(__file__).with_name("multiprocessing_helper.py")
    env = os.environ.copy()
    env["HOME"] = str(home)

    result = subprocess.run(
        [sys.executable, str(helper), start_method, str(loot_dir)],
        cwd=Path(__file__).parent.parent,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.count("MANSPIDER command executed") == 1
    assert result.stdout.count('example.txt: matched "synthetic-content" 1 times') == 2
    assert result.stdout.count("synthetic child console message") == 2
    assert "processed messages: 2" in result.stdout
    assert "cannot pickle 'weakref.ReferenceType' object" not in result.stderr

    logfiles = list((home / ".manspider" / "logs").glob("manspider_*.log"))
    assert len(logfiles) == 1
    logfile_content = logfiles[0].read_text(encoding="utf-8")
    assert logfile_content.count("MANSPIDER command executed") == 1
    assert logfile_content.count('example.txt: matched "synthetic-content" 1 times') == 2
    assert logfile_content.count("synthetic child console message") == 2
