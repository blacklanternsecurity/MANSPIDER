import re
import json
import queue
import logging
from time import sleep
import multiprocessing
from pathlib import Path

from man_spider.lib.spiderling import *
from man_spider.lib.parser import FileParser
from man_spider.lib.logger import configure_logging
from man_spider.lib.rules import load_default_rules, RuleSet
from man_spider.lib.util import Target

# set up logging
log = logging.getLogger("manspider")


def run_spiderling(spiderling_cls, target, parent):
    """Configure child-process logging before starting a spiderling."""

    configure_logging(parent.log_queue, level=parent.log_level)
    spiderling_cls(target, parent)


class MANSPIDER:
    def __init__(self, options, log_queue=None):

        self.targets = options.targets
        self.threads = options.threads
        self.maxdepth = options.maxdepth
        self.quiet = options.quiet
        self.log_queue = log_queue
        self.log_level = logging.DEBUG if options.verbose else logging.INFO

        self.username = options.username
        self.password = options.password
        self.domain = options.domain
        self.nthash = options.hash
        self.use_kerberos = options.kerberos
        self.aes_key = options.aes_key
        self.dc_ip = options.dc_ip
        self.max_failed_logons = options.max_failed_logons
        self.max_filesize = options.max_filesize

        self.share_whitelist = options.sharenames
        self.share_blacklist = options.exclude_sharenames

        self.dir_whitelist = options.dirnames
        self.dir_blacklist = options.exclude_dirnames

        self.no_download = options.no_download

        # JSON Lines output (None to disable); opened lazily in the parent process
        self.json_file = getattr(options, "json", None)
        self._json_fh = None

        # applies "or" logic instead of "and"
        # e.g. file is downloaded if filename OR extension OR content match
        self.or_logic = options.or_logic

        self.extension_blacklist = options.exclude_extensions
        self.file_extensions = options.extensions

        if self.file_extensions:
            extensions_str = '"' + '", "'.join(list(self.file_extensions)) + '"'
            log.info(f"Searching by file extension: {extensions_str}")

        self.init_filename_filters(options.filenames)

        # Decide the active curated rule set.
        #   - no user filters at all        -> use curated defaults
        #   - user filters + --use-default-rules -> combine both
        #   - user filters only             -> user filters only (no curated)
        user_has_filters = bool(
            options.filenames
            or options.extensions
            or options.exclude_extensions
            or options.content
        )
        use_defaults = getattr(options, "use_default_rules", False)
        self.rules = RuleSet()
        content_rules = []
        if (not user_has_filters) or use_defaults:
            default_rules = load_default_rules()
            # file-location rules (filename/extension/path) gate file selection
            for rule in default_rules.file_rules:
                self.rules.add(rule)
            content_rules = default_rules.content

        self.parser = FileParser(options.content, content_rules=content_rules, quiet=self.quiet)

        self.failed_logons = 0

        self.spiderling_pool = [None] * self.threads
        self.spiderling_queue = multiprocessing.Manager().Queue()

        # prevents needing to continually instantiate new SMBClients
        # {target: SMBClient() ...}
        self.smb_client_cache = dict()

        # directory to store documents when searching contents
        self.tmp_dir = Path("/tmp/.manspider")
        self.tmp_dir.mkdir(exist_ok=True)

        # directory to store matching documents
        self.loot_dir = Path.home() / ".manspider" / "loot"

        if options.loot_dir:
            self.loot_dir = Path(options.loot_dir)

        self.loot_dir.mkdir(parents=True, exist_ok=True)

        if not options.no_download:
            log.info(f"Matching files will be downloaded to {self.loot_dir}")

        self.modified_after = options.modified_after
        self.modified_before = options.modified_before

        if self.modified_after:
            log.info(f"Filtering files modified after: {self.modified_after.strftime('%Y-%m-%d')}")
        if self.modified_before:
            log.info(f"Filtering files modified before: {self.modified_before.strftime('%Y-%m-%d')}")

        # automatic domain-based DFS discovery (when domain credentials are in use)
        self.init_dfs()

    def init_dfs(self):
        """
        Discover domain-based DFS namespaces via LDAP (only when domain creds are set).
        Adds DFS backing servers as scan targets and sets up a shared claim map so that
        replicas of the same namespace are scanned only once.
        """
        self.dfs_shares_dict = {}
        self.dfs_namespace_paths = []
        self.dfs_claimed = None

        # requires domain credentials and at least one remote (SMB) target
        if not self.domain:
            return
        if not any(isinstance(t, Target) for t in self.targets):
            return

        from man_spider.lib.dfs import discover_dfs_shares, build_dfs_maps

        log.info("Domain credentials detected; discovering DFS namespaces via LDAP...")
        try:
            dfs_shares = discover_dfs_shares(
                self.domain,
                self.dc_ip,
                self.username,
                self.password,
                self.nthash,
                self.use_kerberos,
                self.aes_key or "",
            )
        except Exception as e:
            log.warning(f"DFS discovery failed: {e}")
            return

        if not dfs_shares:
            log.info("No DFS namespaces discovered")
            return

        self.dfs_shares_dict, self.dfs_namespace_paths, backing_hosts = build_dfs_maps(dfs_shares, self.domain)
        log.info(
            f"Discovered {len(self.dfs_shares_dict)} DFS share path(s) across "
            f"{len(self.dfs_namespace_paths)} namespace(s)"
        )

        # add DFS backing servers as scan targets so DFS-published shares aren't missed
        existing = {t.host.lower() for t in self.targets if isinstance(t, Target)}
        added = 0
        for host in sorted(backing_hosts):
            if host.lower() not in existing:
                self.targets.append(Target(host=host))
                existing.add(host.lower())
                added += 1
        if added:
            log.info(f"Added {added} DFS backing server(s) as scan targets")

        # shared across spiderling processes: first replica to claim a namespace scans it
        self.dfs_claimed = multiprocessing.Manager().dict()

    def __getstate__(self):
        """Exclude parent-only runtime objects when serializing a spiderling's configuration."""

        state = self.__dict__.copy()
        state["spiderling_pool"] = [None] * self.threads
        state["smb_client_cache"] = {}
        # file handles aren't picklable and are only used in the parent
        state["_json_fh"] = None
        return state

    def start(self):

        for target in self.targets:
            try:
                while 1:
                    for i, process in enumerate(self.spiderling_pool):
                        # if there's room in the pool
                        if process is None or not process.is_alive():
                            # start spiderling
                            self.spiderling_pool[i] = multiprocessing.Process(
                                target=run_spiderling, args=(Spiderling, target, self), daemon=False
                            )
                            self.spiderling_pool[i].start()
                            # success, break out of infinite loop
                            assert False
                        else:
                            # otherwise, clear the queue
                            self.check_spiderling_queue()

            except AssertionError:
                continue

            # save on CPU
            sleep(0.1)

        while 1:
            self.check_spiderling_queue()
            dead_spiderlings = [s is None or not s.is_alive() for s in self.spiderling_pool]
            if all(dead_spiderlings):
                break

        # make sure the queue is empty
        self.check_spiderling_queue()

        self.close_json()

    def init_file_extensions(self, file_extensions):
        """
        Get ready to search by file extension
        """

        self.file_extensions = FileExtensions()
        if file_extensions:
            self.file_extensions.update(file_extensions)

    def init_filename_filters(self, filename_filters):
        """
        Get ready to search by filename
        """

        # strings to look for in filenames
        # if empty, all filenames are matched
        self.filename_filters = []
        for f in filename_filters:
            regex_str = str(f)
            try:
                if not any([f.startswith(x) for x in ["^", ".*"]]):
                    regex_str = rf".*{regex_str}"
                if not any([f.endswith(x) for x in ["$", ".*"]]):
                    regex_str = rf"{regex_str}.*"
                self.filename_filters.append(re.compile(regex_str, re.I))
            except re.error as e:
                log.error(f'Unsupported filename regex "{f}": {e}')
                sleep(1)
        if self.filename_filters:
            filename_filter_str = '"' + '", "'.join([f.pattern for f in self.filename_filters]) + '"'
            log.info(f"Searching by filename: {filename_filter_str}")

    def check_spiderling_queue(self):
        """
        Empty the spiderling queue
        """

        while 1:
            try:
                message = self.spiderling_queue.get_nowait()
                self.process_message(message)

            except queue.Empty:
                break

    def process_message(self, message):
        """
        Process messages from spiderlings
        Log messages, errors, files, etc.
        """
        if message.type == "m":
            self.write_json_record(message.content)
            return
        if message.type == "a":
            if message.content == False:
                self.failed_logons += 1
            if self.lockout_threshold():
                log.error(f"REACHED MAXIMUM FAILED LOGONS OF {self.max_failed_logons:,}")
                log.error("KILLING EXISTING SPIDERLINGS AND CONTINUING WITH GUEST/NULL SESSIONS")
                # for spiderling in self.spiderling_pool:
                #    spiderling.kill()
                self.username = ""
                self.password = ""
                self.nthash = ""
                self.domain = ""

    def write_json_record(self, record):
        """Append one match record to the JSON Lines output file (parent process only)."""
        if not self.json_file:
            return
        try:
            if self._json_fh is None:
                self._json_fh = open(self.json_file, "a", encoding="utf-8")
            self._json_fh.write(json.dumps(record, default=str) + "\n")
            self._json_fh.flush()
        except Exception as e:
            log.warning(f"Error writing JSON record: {e}")

    def close_json(self):
        if self._json_fh is not None:
            try:
                self._json_fh.close()
            except Exception:
                pass
            self._json_fh = None

    def lockout_threshold(self):
        """
        Return True if we've reached max failed logons
        """

        if self.max_failed_logons is not None:
            if self.failed_logons >= self.max_failed_logons and self.domain:
                return True
        return False

    def get_smb_client(self, target):
        """
        Check if we already have an smb_client cached
        If not, then create it
        """

        smb_client = self.smb_client_cache.get(target, None)

        if smb_client is None:
            smb_client = SMBClient(
                target.host,
                self.username,
                self.password,
                self.domain,
                self.nthash,
                self.use_kerberos,
                self.aes_key,
                self.dc_ip,
                port=target.port,
            )
            logon_result = smb_client.login()
            if logon_result == False:
                self.failed_logons += 1
            self.smb_client_cache[target] = smb_client

        return smb_client
