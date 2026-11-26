import stat
import tempfile
from argparse import Namespace
from pathlib import Path

from man_spider.lib.file import RemoteFile
from man_spider.lib.spider import MANSPIDER


class FakeSMBConnection:
    def __init__(self, payload):
        self.payload = payload

    def getFile(self, share, name, callback):
        callback(self.payload)


class FakeSMBClient:
    def __init__(self, payload):
        self.conn = FakeSMBConnection(payload)


def make_options(targets, loot_dir):
    return Namespace(
        targets=targets,
        threads=1,
        maxdepth=1,
        quiet=True,
        username="",
        password="",
        domain="",
        hash="",
        kerberos=False,
        aes_key=None,
        dc_ip=None,
        max_failed_logons=None,
        max_filesize=1024,
        sharenames=[],
        exclude_sharenames=[],
        dirnames=[],
        exclude_dirnames=[],
        no_download=False,
        or_logic=False,
        exclude_extensions=[],
        extensions=[],
        filenames=[],
        content=[],
        loot_dir=str(loot_dir),
        modified_after=None,
        modified_before=None,
        verbose=False,
    )


def test_remote_file_writes_to_the_provided_private_directory(tmp_path):
    tmp_dir = tmp_path / "manspider-tmp"
    tmp_dir.mkdir(mode=0o700)

    remote_file = RemoteFile(
        "documents/report.txt",
        "share",
        "host",
        tmp_dir=tmp_dir,
    )
    assert remote_file.tmp_filename is None

    remote_file.get(FakeSMBClient(b"confidential contents"))

    assert remote_file.tmp_filename.parent == tmp_dir
    assert remote_file.tmp_filename.read_bytes() == b"confidential contents"
    assert stat.S_IMODE(remote_file.tmp_filename.stat().st_mode) == 0o600


def test_remote_file_generates_unique_temporary_files(tmp_path):
    filenames = []
    for contents in (b"first", b"second"):
        remote_file = RemoteFile("documents/report.txt", "share", "host", tmp_dir=tmp_path)
        remote_file.get(FakeSMBClient(contents))
        filenames.append(remote_file.tmp_filename)

    assert filenames[0] != filenames[1]


def test_manspider_uses_and_removes_a_private_temporary_directory(tmp_path):
    spider = MANSPIDER(make_options(targets=[], loot_dir=tmp_path / "loot"))
    tmp_dir = spider.tmp_dir

    assert tmp_dir.parent == Path(tempfile.gettempdir())
    assert tmp_dir.name.startswith("manspider-")
    assert tmp_dir != Path("/tmp/.manspider")
    assert stat.S_IMODE(tmp_dir.stat().st_mode) == 0o700

    spider.start()

    assert not tmp_dir.exists()
