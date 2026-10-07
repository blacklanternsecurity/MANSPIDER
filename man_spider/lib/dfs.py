"""
Domain-based DFS discovery via LDAP.

When domain credentials are in use, query the DC for DFS namespaces so that:
  * replicas of the same namespace (e.g. SYSVOL across every DC) are scanned once
  * the servers backing DFS shares are added as scan targets, so DFS-published
    shares aren't missed

Covers DFS v1 (the binary "pkt" blob on fTDfs objects) and v2 (the XML target
list on msDFS-Linkv2 objects). Adapted from SnafflePy's DfsFinder. Standalone
(non-domain) DFS is NOT covered — its config lives in the server registry, not
AD, and would require the MS-DFSNM RPC instead.
"""

import struct
import logging
import xml.etree.ElementTree as ET

log = logging.getLogger("manspider.dfs")


class DFSShare:
    __slots__ = ("remote_share_name", "remote_server_name", "dfs_folder_path")

    def __init__(self, remote_share_name=None, remote_server_name=None, dfs_folder_path=None):
        self.remote_share_name = remote_share_name
        self.remote_server_name = remote_server_name
        self.dfs_folder_path = dfs_folder_path

    def __repr__(self):
        return f"<DFSShare \\\\{self.remote_server_name}\\{self.remote_share_name} -> {self.dfs_folder_path}>"


class _Reader:
    """Little-endian cursor over the DFS blob."""

    def __init__(self, data, offset=0):
        self.data = data
        self.pos = offset

    def uint16(self):
        value = struct.unpack_from("<H", self.data, self.pos)[0]
        self.pos += 2
        return value

    def uint32(self):
        value = struct.unpack_from("<I", self.data, self.pos)[0]
        self.pos += 4
        return value

    def take(self, count):
        chunk = self.data[self.pos : self.pos + count]
        self.pos += count
        return chunk

    def unicode(self, byte_count):
        return self.take(byte_count).decode("utf-16-le", errors="replace")


class _LdapEntry:
    """Thin accessor over an impacket SearchResultEntry."""

    __slots__ = ("dn", "_attrs")

    def __init__(self, dn, attrs):
        self.dn = dn
        self._attrs = attrs

    @classmethod
    def from_search_result(cls, entry):
        dn = str(entry["objectName"])
        attrs = {}
        for attribute in entry["attributes"]:
            name = str(attribute["type"]).lower()
            attrs[name] = [bytes(v) for v in attribute["vals"]]
        return cls(dn, attrs)

    def get_str(self, name):
        values = self._attrs.get(name.lower())
        if not values:
            return None
        return values[0].decode("utf-8", errors="replace")

    def get_str_array(self, name):
        values = self._attrs.get(name.lower())
        if not values:
            return None
        return [v.decode("utf-8", errors="replace") for v in values]

    def get_bytes(self, name):
        values = self._attrs.get(name.lower())
        if not values:
            return None
        return values[0]

    def get_bytes_array(self, name):
        return self._attrs.get(name.lower())


def parse_pkt(pkt):
    """Parse the DFS v1 binary 'pkt' blob (MS-DFSNM). Returns a list of DFSShare."""
    shares = []
    object_list = []
    try:
        reader = _Reader(pkt)
        reader.uint32()  # blob_version
        blob_element_count = reader.uint32()

        for _ in range(blob_element_count):
            blob_name_size = reader.uint16()
            blob_name = reader.unicode(blob_name_size)
            blob_data_size = reader.uint32()
            blob_data = reader.take(blob_data_size)

            prefix = None
            target_list = None

            if blob_name == "\\siteroot":
                pass
            elif blob_name.startswith("\\domainroot"):
                blob = _Reader(blob_data)
                blob.take(16)  # root_or_link_guid
                prefix = blob.unicode(blob.uint16())
                blob.unicode(blob.uint16())  # short_prefix
                blob.uint32()  # type
                blob.uint32()  # state
                comment_size = blob.uint16()
                if comment_size:
                    blob.unicode(comment_size)
                blob.take(8)  # prefix_timestamp
                blob.take(8)  # state_timestamp
                blob.take(8)  # comment_timestamp
                blob.uint32()  # version

                dfs_targetlist_blob_size = blob.uint32()
                dfs_targetlist_blob = blob.take(dfs_targetlist_blob_size)
                reserved_blob_size = blob.uint32()
                blob.take(reserved_blob_size)
                blob.uint32()  # referral_ttl

                targets = _Reader(dfs_targetlist_blob)
                target_count = targets.uint32()
                for _j in range(target_count):
                    targets.uint32()  # target_entry_size
                    targets.take(8)  # target_time_stamp
                    targets.uint32()  # target_state
                    targets.uint32()  # target_type
                    server_name = targets.unicode(targets.uint16())
                    share_name = targets.unicode(targets.uint16())
                    if target_list is None:
                        target_list = []
                    target_list.append(f"\\\\{server_name}\\{share_name}")

            object_list.append({"Name": blob_name, "Prefix": prefix, "TargetList": target_list})
    except (struct.error, IndexError, ValueError):
        # truncated or unexpected blob — keep whatever we already decoded
        pass

    for item in object_list:
        prefix = item["Prefix"]
        if prefix is None:
            continue
        parts = prefix.split("\\", 2)
        if len(parts) < 3:
            continue
        dfsns = parts[2]

        for target in item["TargetList"] or []:
            target_parts = target.split("\\")
            if len(target_parts) < 4:
                continue
            shares.append(
                DFSShare(
                    remote_share_name=target_parts[3],
                    remote_server_name=target_parts[2],
                    dfs_folder_path=dfsns,
                )
            )

    return shares


def _query_v1(entries):
    dfs_shares = []
    for entry in entries:
        dfs_namespace = entry.dn.replace("CN=", "").split(",")[0]
        remote_names = entry.get_str_array("remoteservername")
        pkt = entry.get_bytes_array("pkt")

        if remote_names:
            for name in remote_names:
                try:
                    if "\\" in name:
                        dfs_shares.append(
                            DFSShare(
                                remote_share_name=entry.get_str("name"),
                                remote_server_name=name.split("\\")[2],
                                dfs_folder_path=dfs_namespace,
                            )
                        )
                except Exception as e:
                    log.debug(f"error parsing DFSv1 remoteservername {name!r}: {e}")

        if pkt and pkt[0]:
            dfs_shares.extend(parse_pkt(pkt[0]))

    return dfs_shares


def _query_v2(entries):
    dfs_shares = []
    for entry in entries:
        parts = entry.dn.replace("CN=", "").split(",")
        if len(parts) < 2:
            continue
        dfs_namespace = parts[1]

        target_list = entry.get_bytes("msdfs-targetlistv2")
        if not target_list:
            continue
        try:
            # strip the 2-byte length prefix, then it's UTF-16 XML
            xml_text = target_list[2:].decode("utf-16-le", errors="replace")
            root = ET.fromstring(xml_text)
        except Exception as e:
            log.debug(f"error parsing DFSv2 target list: {e}")
            continue

        for node in root.iter():
            target = (node.text or "").strip()
            if "\\" not in target:
                continue
            try:
                target_parts = target.split("\\")
                dfs_leaf_name = (entry.get_str("msdfs-linkpathv2") or "").replace("/", "\\")
                dfs_shares.append(
                    DFSShare(
                        remote_share_name=target_parts[3],
                        remote_server_name=target_parts[2],
                        dfs_folder_path=f"{dfs_namespace}{dfs_leaf_name}",
                    )
                )
            except Exception as e:
                log.debug(f"error parsing DFSv2 target {target!r}: {e}")

    return dfs_shares


def discover_dfs_shares(domain, dc_ip=None, username="", password="", nthash="", use_kerberos=False, aes_key=""):
    """
    Query the domain controller over LDAP and return a list of DFSShare.
    Returns [] on any failure (DFS discovery is additive, never fatal).
    """
    from impacket.ldap import ldap as impacket_ldap
    from impacket.ldap import ldapasn1

    base_dn = "DC=" + domain.replace(".", ",DC=")
    target = dc_ip or domain
    url = f"ldap://{target}"
    lmhash = "aad3b435b51404eeaad3b435b51404ee" if nthash else ""

    try:
        conn = impacket_ldap.LDAPConnection(url, base_dn, dc_ip)
        if use_kerberos:
            conn.kerberosLogin(username, password, domain, lmhash, nthash, aes_key, kdcHost=dc_ip)
        else:
            conn.login(username, password, domain, lmhash, nthash)
    except Exception as e:
        log.warning(f"DFS discovery: LDAP connection to {target} failed: {e}")
        return []

    def run_query(ldap_filter, props):
        entries = []

        def per_record(item):
            if isinstance(item, ldapasn1.SearchResultEntry):
                entries.append(_LdapEntry.from_search_result(item))

        paged = ldapasn1.SimplePagedResultsControl(criticality=True, size=500)
        conn.search(
            searchBase=base_dn,
            searchFilter=ldap_filter,
            scope=ldapasn1.Scope("wholeSubtree"),
            attributes=list(props),
            searchControls=[paged],
            perRecordCallback=per_record,
        )
        return entries

    dfs_shares = []
    try:
        v1_entries = run_query("(objectClass=fTDfs)", ["remoteservername", "pkt", "cn", "name"])
        dfs_shares.extend(_query_v1(v1_entries))
    except Exception as e:
        log.warning(f"DFS discovery: v1 (fTDfs) query failed: {e}")
    try:
        v2_entries = run_query(
            "(objectClass=msDFS-Linkv2)", ["msdfs-linkpathv2", "msDFS-TargetListv2", "cn", "name"]
        )
        dfs_shares.extend(_query_v2(v2_entries))
    except Exception as e:
        log.warning(f"DFS discovery: v2 (msDFS-Linkv2) query failed: {e}")

    try:
        conn.close()
    except Exception:
        pass

    return dfs_shares


def build_dfs_maps(dfs_shares, domain):
    """
    From a list of DFSShare, build:
      shares_dict    -- {"\\\\host\\share" (lowercased): namespace_path}, with both
                        the short and FQDN host forms recorded
      namespace_paths -- list of "\\\\domain\\folderpath"
      backing_hosts  -- set of server hostnames backing DFS shares
    """
    shares_dict = {}
    namespace_paths = []
    backing_hosts = set()

    for share in dfs_shares:
        if not share.remote_server_name or not share.remote_share_name:
            continue

        namespace_path = f"\\\\{domain}\\{share.dfs_folder_path}"
        if namespace_path not in namespace_paths:
            namespace_paths.append(namespace_path)

        server = share.remote_server_name
        # record both short and FQDN forms in the lookup dict so a share enumerated
        # under either name is recognized as a DFS replica
        hostnames = {server}
        if server.lower().endswith(domain.lower()):
            hostnames.add(server.split(".")[0])
        else:
            hostnames.add(f"{server}.{domain}")

        # but only add ONE canonical form per server as a scan target
        backing_hosts.add(server)

        for host in hostnames:
            key = f"\\\\{host}\\{share.remote_share_name}".lower()
            shares_dict.setdefault(key, namespace_path)

    return shares_dict, namespace_paths, backing_hosts
