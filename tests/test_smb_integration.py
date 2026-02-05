"""
SMB integration test using impacket's SimpleSMBServer.

This test:
1. Spins up a local SMB server on a high port (no root needed)
2. Populates it with test files
3. Verifies we can connect and list files via SMB client
4. Runs MANSPIDER against the server and verifies content extraction
"""

import shutil
import socket
import threading
import time
from argparse import Namespace
from pathlib import Path

import pytest
from impacket.smbconnection import SMBConnection
from impacket.smbserver import SimpleSMBServer

from man_spider.lib.util import Target


def get_free_port() -> int:
    """Find a free port to use for the SMB server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class SMBTestServer:
    """Simple wrapper around impacket's SimpleSMBServer for testing."""

    def __init__(self, share_path: str, port: int):
        self.share_path = share_path
        self.port = port
        self.server = None
        self.thread = None

    def start(self):
        """Start the SMB server in a background thread."""
        self.server = SimpleSMBServer(
            listenAddress="127.0.0.1",
            listenPort=self.port,
        )
        self.server.setSMB2Support(True)
        self.server.addShare("testshare", self.share_path, "Test Share")

        self.thread = threading.Thread(target=self.server.start, daemon=True)
        self.thread.start()
        time.sleep(0.5)  # Give server time to start

    def stop(self):
        """Stop the SMB server."""
        if self.server:
            self.server.stop()


@pytest.fixture(scope="module")
def smb_server(tmp_path_factory):
    """
    Fixture that spins up an SMB server with test files.

    Uses module scope so the server is started once and shared across all tests.

    Yields:
        tuple: (SMBTestServer instance, Path to share directory)
    """
    # Create share directory
    tmp_path = tmp_path_factory.mktemp("smb")
    share_path = tmp_path / "share"
    share_path.mkdir()

    # Copy a subset of test files to the share
    testdata = Path(__file__).parent.parent / "testdata"
    test_files = ["test.docx", "test.pdf", "test-utf8.txt"]

    for filename in test_files:
        src = testdata / filename
        if src.exists():
            shutil.copy(src, share_path / filename)

    # Start server on a free port
    port = get_free_port()
    server = SMBTestServer(str(share_path), port=port)
    server.start()

    yield server, share_path

    # Cleanup
    server.stop()


class TestSMBServer:
    """Tests for the SMB server infrastructure."""

    def test_server_starts_and_has_files(self, smb_server):
        """Verify the SMB server starts and has files."""
        server, share_path = smb_server

        # Verify server is running (thread is alive)
        assert server.thread is not None
        assert server.thread.is_alive()

        # Verify test files exist in share
        assert (share_path / "test.docx").exists()
        assert (share_path / "test.pdf").exists()
        assert (share_path / "test-utf8.txt").exists()

    def test_client_can_connect_and_list_shares(self, smb_server):
        """Verify we can connect to the SMB server and list shares."""
        server, share_path = smb_server

        # Connect to the server
        conn = SMBConnection("127.0.0.1", "127.0.0.1", sess_port=server.port, timeout=5)
        conn.login("", "")  # Anonymous login

        # List shares
        shares = conn.listShares()
        share_names = [share["shi1_netname"].rstrip("\x00").lower() for share in shares]

        assert "testshare" in share_names

        conn.close()

    def test_client_can_list_files(self, smb_server):
        """Verify we can list files in the share."""
        server, share_path = smb_server

        # Connect to the server
        conn = SMBConnection("127.0.0.1", "127.0.0.1", sess_port=server.port, timeout=5)
        conn.login("", "")  # Anonymous login

        # List files in share
        conn.connectTree("testshare")
        files = conn.listPath("testshare", "*")
        filenames = [f.get_longname() for f in files if f.get_longname() not in (".", "..")]

        assert "test.docx" in filenames
        assert "test.pdf" in filenames
        assert "test-utf8.txt" in filenames

        conn.close()


def create_test_options(targets, loot_dir, **kwargs) -> Namespace:
    """Create an options Namespace matching MANSPIDER's expected structure."""
    defaults = {
        "targets": targets,
        "username": "",
        "password": "",
        "domain": "",
        "hash": "",
        "loot_dir": str(loot_dir),
        "maxdepth": 10,
        "threads": 1,
        "filenames": [],
        "extensions": [],
        "exclude_extensions": [],
        "content": [],
        "sharenames": [],
        "exclude_sharenames": [],
        "dirnames": [],
        "exclude_dirnames": [],
        "quiet": True,
        "no_download": False,
        "max_failed_logons": None,
        "or_logic": False,
        "max_filesize": 10 * 1024 * 1024,  # 10MB
        "verbose": False,
        "modified_after": None,
        "modified_before": None,
        "kerberos": False,
        "aes_key": None,
        "dc_ip": None,
    }
    defaults.update(kwargs)
    return Namespace(**defaults)


@pytest.fixture(scope="module")
def smb_server_full(tmp_path_factory):
    """
    Fixture that spins up an SMB server with ALL test files.

    Uses module scope so the server is started once and shared across all tests.
    """
    # Create share directory
    tmp_path = tmp_path_factory.mktemp("smb_full")
    share_path = tmp_path / "share"
    share_path.mkdir()

    # Copy ALL test files to the share
    testdata = Path(__file__).parent.parent / "testdata"
    for f in testdata.iterdir():
        if f.is_file():
            shutil.copy(f, share_path / f.name)

    # Start server on a free port
    port = get_free_port()
    server = SMBTestServer(str(share_path), port=port)
    server.start()

    yield server, share_path

    # Cleanup
    server.stop()


class TestMANSPIDER:
    """Integration tests that run MANSPIDER against the SMB server."""

    # Base names to search for in loot filenames (MANSPIDER removes hyphens and adds prefix)
    # Format: original filename -> pattern to search for in loot filename
    EXPECTED_TEXT_PATTERNS = [
        "testascii",  # test-ascii.txt
        "testutf8.txt",  # test-utf8.txt (exact, no hyphen version)
        "testutf8bom",  # test-utf8-bom.txt
        "testutf16le",  # test-utf16le.txt
        "testutf16be",  # test-utf16be.txt
        "testutf16bom",  # test-utf16-bom.txt
        "testlatin1",  # test-latin1.txt
        "testcp1252",  # test-cp1252.txt
    ]

    EXPECTED_DOCUMENT_PATTERNS = [
        "test.docx",
        "test.pdf",
        "test.xlsx",
        "test.doc",
        "test.xls",
    ]

    EXPECTED_BINARY_PATTERNS = [
        "testbinarysmall",  # test-binary-small.bin
        "testbinarymedium",  # test-binary-medium.bin
        "testbinarylarge",  # test-binary-large.bin
        "testbinarystart",  # test-binary-start.bin
        "testbinaryend",  # test-binary-end.bin
    ]

    def _find_matching_files(self, loot_dir, patterns, extension):
        """Check if loot files contain expected patterns."""
        loot_files = [f.name.lower() for f in loot_dir.rglob(f"*{extension}")]
        found = set()
        for pattern in patterns:
            pattern_lower = pattern.lower()
            for loot_file in loot_files:
                if pattern_lower in loot_file:
                    found.add(pattern)
                    break
        return found

    def test_manspider_finds_password_in_all_text_files(self, smb_server_full, tmp_path):
        """MANSPIDER finds Password123 in ALL text encoding variants."""
        from man_spider.lib.spider import MANSPIDER

        server, share_path = smb_server_full
        loot_dir = tmp_path / "loot"
        loot_dir.mkdir()

        target = Target("127.0.0.1", server.port)

        options = create_test_options(
            targets=[target],
            loot_dir=loot_dir,
            content=["Password123"],
            extensions=[".txt"],
            exclude_sharenames=["IPC$"],  # Exclude IPC$ to avoid local file access
        )

        spider = MANSPIDER(options)
        spider.start()

        # Check that ALL expected text files were found
        found = self._find_matching_files(loot_dir, self.EXPECTED_TEXT_PATTERNS, ".txt")
        missing = set(self.EXPECTED_TEXT_PATTERNS) - found
        assert not missing, f"Missing text patterns: {missing}. Found: {list(loot_dir.rglob('*.txt'))}"

    def test_manspider_finds_password_in_all_document_files(self, smb_server_full, tmp_path):
        """MANSPIDER finds Password123 in ALL document formats (docx, pdf, xlsx, doc, xls)."""
        from man_spider.lib.spider import MANSPIDER

        server, share_path = smb_server_full
        loot_dir = tmp_path / "loot"
        loot_dir.mkdir()

        target = Target("127.0.0.1", server.port)

        options = create_test_options(
            targets=[target],
            loot_dir=loot_dir,
            content=["Password123"],
            extensions=[".docx", ".pdf", ".xlsx", ".doc", ".xls"],
            exclude_sharenames=["IPC$"],
        )

        spider = MANSPIDER(options)
        spider.start()

        # Check that ALL expected document files were found
        all_found = set()
        for ext in [".docx", ".pdf", ".xlsx", ".doc", ".xls"]:
            patterns = [p for p in self.EXPECTED_DOCUMENT_PATTERNS if p.endswith(ext)]
            all_found.update(self._find_matching_files(loot_dir, patterns, ext))

        missing = set(self.EXPECTED_DOCUMENT_PATTERNS) - all_found
        assert not missing, f"Missing document patterns: {missing}. Found: {list(loot_dir.rglob('*'))}"

    def test_manspider_finds_password_in_all_binary_files(self, smb_server_full, tmp_path):
        """MANSPIDER finds Password123 in ALL binary files with embedded text."""
        from man_spider.lib.spider import MANSPIDER

        server, share_path = smb_server_full
        loot_dir = tmp_path / "loot"
        loot_dir.mkdir()

        target = Target("127.0.0.1", server.port)

        options = create_test_options(
            targets=[target],
            loot_dir=loot_dir,
            content=["Password123"],
            extensions=[".bin"],
            exclude_sharenames=["IPC$"],
        )

        spider = MANSPIDER(options)
        spider.start()

        # Check that ALL expected binary files were found
        found = self._find_matching_files(loot_dir, self.EXPECTED_BINARY_PATTERNS, ".bin")
        missing = set(self.EXPECTED_BINARY_PATTERNS) - found
        assert not missing, f"Missing binary patterns: {missing}. Found: {list(loot_dir.rglob('*.bin'))}"
