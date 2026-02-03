"""
Basic SMB integration test using impacket's SimpleSMBServer.

This test:
1. Spins up a local SMB server on a high port (no root needed)
2. Populates it with test files
3. Verifies we can connect and list files via SMB client
"""

import shutil
import socket
import threading
import time
from pathlib import Path

import pytest
from impacket.smbconnection import SMBConnection
from impacket.smbserver import SimpleSMBServer


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
