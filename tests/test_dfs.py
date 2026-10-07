"""
Unit tests for the DFS parsers — no live DC required.

The v1 'pkt' blob is built the way AD stores it (MS-DFSNM) and round-tripped
through parse_pkt; the v2 path and map builder are tested against constructed
LDAP entries.
"""
import struct

from man_spider.lib.dfs import DFSShare, _LdapEntry, _query_v2, build_dfs_maps, parse_pkt


def _u16(v):
    return struct.pack("<H", v)


def _u32(v):
    return struct.pack("<I", v)


def _wstr(text):
    encoded = text.encode("utf-16-le")
    return _u16(len(encoded)) + encoded


def _build_target(server, share):
    body = b"\x00" * 8 + _u32(2) + _u32(1) + _wstr(server) + _wstr(share)
    return _u32(len(body) + 4) + body


def _build_domainroot_blob(prefix, targets, comment=""):
    target_list = _u32(len(targets)) + b"".join(_build_target(s, sh) for s, sh in targets)
    return (
        b"\xAA" * 16
        + _wstr(prefix)
        + _wstr(prefix.upper())
        + _u32(1)
        + _u32(1)
        + _wstr(comment)[0:2]
        + comment.encode("utf-16-le")
        + b"\x00" * 8
        + b"\x00" * 8
        + b"\x00" * 8
        + _u32(3)
        + _u32(len(target_list))
        + target_list
        + _u32(0)
        + _u32(300)
    )


def _build_pkt(elements):
    out = _u32(1) + _u32(len(elements))
    for name, blob in elements:
        encoded = name.encode("utf-16-le")
        out += _u16(len(encoded)) + encoded + _u32(len(blob)) + blob
    return out


def test_v1_single_namespace_single_target():
    pkt = _build_pkt([(r"\domainroot\public", _build_domainroot_blob(r"\corp.local\public", [("FS01", "reports$")]))])
    shares = parse_pkt(pkt)
    assert len(shares) == 1
    assert shares[0].remote_server_name == "FS01"
    assert shares[0].remote_share_name == "reports$"
    assert shares[0].dfs_folder_path == "public"


def test_v1_multiple_targets_all_returned():
    pkt = _build_pkt(
        [
            (
                r"\domainroot\public",
                _build_domainroot_blob(r"\corp.local\public", [("FS01", "r$"), ("FS02", "r$"), ("FS03", "o$")]),
            )
        ]
    )
    shares = parse_pkt(pkt)
    assert [s.remote_server_name for s in shares] == ["FS01", "FS02", "FS03"]
    assert {s.dfs_folder_path for s in shares} == {"public"}


def test_v1_siteroot_skipped():
    pkt = _build_pkt(
        [
            (r"\siteroot", b"\x00" * 32),
            (r"\domainroot\public", _build_domainroot_blob(r"\corp.local\public", [("FS01", "pub$")])),
        ]
    )
    shares = parse_pkt(pkt)
    assert len(shares) == 1 and shares[0].remote_server_name == "FS01"


def test_v1_truncation_never_raises():
    pkt = _build_pkt([(r"\domainroot\public", _build_domainroot_blob(r"\corp.local\public", [("FS01", "pub$")]))])
    for cut in range(len(pkt)):
        parse_pkt(pkt[:cut])  # must not raise


def test_v1_empty_blob():
    assert parse_pkt(b"") == []


def test_v2_xml_target_list():
    xml = '<?xml version="1.0"?><metadata><target>\\\\FS02\\data$</target></metadata>'
    target_list = _u16(len(xml)) + xml.encode("utf-16-le")
    entry = _LdapEntry(
        "CN=data,CN=finance,CN=Dfs-Configuration,CN=System,DC=corp,DC=local",
        {"msdfs-targetlistv2": [target_list], "msdfs-linkpathv2": ["/data".encode("utf-8")]},
    )
    shares = _query_v2([entry])
    assert len(shares) == 1
    assert shares[0].remote_server_name == "FS02"
    assert shares[0].remote_share_name == "data$"
    assert shares[0].dfs_folder_path == "finance\\data"


def test_build_dfs_maps_records_both_host_forms():
    shares = [DFSShare(remote_share_name="reports$", remote_server_name="FS01", dfs_folder_path="public")]
    shares_dict, namespaces, backing = build_dfs_maps(shares, "corp.local")

    assert "\\\\fs01\\reports$" in shares_dict
    assert "\\\\fs01.corp.local\\reports$" in shares_dict
    assert all(v == "\\\\corp.local\\public" for v in shares_dict.values())
    assert namespaces == ["\\\\corp.local\\public"]
    # only one canonical host per server is added as a scan target
    assert backing == {"FS01"}
