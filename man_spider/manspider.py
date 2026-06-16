#!/usr/bin/env python3

import sys
import pathlib
import logging
import argparse
import traceback
from time import sleep
import multiprocessing
from datetime import datetime

from man_spider.lib import *


# set up logging
log = logging.getLogger("manspider")
log.setLevel(logging.INFO)


def go(options):

    log.info("MANSPIDER command executed: " + " ".join(sys.argv))

    try:
        # warn if --or-logic is enabled
        if options.or_logic and options.content and not all([type(t) == pathlib.PosixPath for t in options.targets]):
            log.warning(
                'WARNING: "--or-logic" causes files to be content-searched even if filename/extension filters do not match!!'
            )
            sleep(2)

        # if no filters were specified, just enumerate and print shares for each
        # remote target (like `smbclient -L`) instead of spidering
        if not (options.filenames or options.extensions or options.exclude_extensions or options.content):
            remote_targets = [t for t in options.targets if not isinstance(t, pathlib.PosixPath)]
            if not remote_targets:
                log.error("Please specify at least one of --filenames, --content, --extensions, or --exclude-extensions")
                return
            log.info("No filters specified; listing shares only")
            for target in remote_targets:
                smb_client = SMBClient(
                    target.host,
                    options.username,
                    options.password,
                    options.domain,
                    options.hash,
                    options.kerberos,
                    options.aes_key,
                    options.dc_ip,
                    port=target.port,
                )
                if smb_client.login() is None:
                    log.warning(f"{target.host}: Could not connect")
                    continue
                shares = smb_client.shares
                if shares:
                    log.info(f"{target.host}: {len(shares)} shares:")
                    for share in shares:
                        log.info(f"  {share}")
                        json_log({"type": "share", "target": target.host, "port": target.port, "share": share})
                else:
                    log.warning(f"{target.host}: No shares found (or enumeration denied)")
            return

        # exit if --maxdepth is invalid
        if options.maxdepth <= 0:
            log.error("--maxdepth must be greater than zero")
            return

        log.info(f"Skipping files larger than {bytes_to_human(options.max_filesize)}")
        log.info(f"Using {options.threads:,} threads")

        manspider = MANSPIDER(options)
        manspider.start()

    except KeyboardInterrupt:
        log.critical("Interrupted")

    except Exception as e:
        if log.level <= logging.DEBUG:
            log.critical(traceback.format_exc())
        else:
            log.critical(f"Critical error (-v to debug): {e}")

    finally:
        # make sure temp files are cleaned up before exiting
        # rmdir(manspider.tmp_dir)
        pass


def load_content_wordlist(filepath, options):
    """Read a plain wordlist (one word/phrase per line) and append each entry to options.content."""
    wordlist_path = pathlib.Path(filepath)
    if not wordlist_path.exists():
        log.error(f"Wordlist file not found: {filepath}")
        sys.exit(1)

    words = [line.strip() for line in wordlist_path.open() if line.strip() and not line.startswith("#")]

    if not words:
        log.error(f"Wordlist file is empty: {filepath}")
        sys.exit(1)

    log.info(f"Loaded {len(words)} words from {filepath}")
    options.content = list(options.content) + words
    return options


def main():

    # The logging setup (lib/logger.py) shares a multiprocessing Queue between the
    # parent's QueueListener (console output) and the child worker's QueueHandler.
    # Python 3.14 changed the default start method on Linux to "forkserver", which
    # re-imports modules in the child and creates a *new*, unlistened queue -> no
    # console output. Force "fork" so parent and child share the same queue.
    try:
        multiprocessing.set_start_method("fork", force=True)
    except (ValueError, RuntimeError):
        pass

    interrupted = False

    examples = """

    # EXAMPLES

    Example 1: Search the network for filenames that may contain creds
    $ manspider 192.168.0.0/24 -f passw user admin account network login logon cred -d evilcorp -u bob -p Passw0rd

    Example 2: Search for XLSX files containing "password"
    $ manspider share.evilcorp.local -c password -e xlsx -d evilcorp -u bob -p Passw0rd

    Example 3: Search for interesting file extensions
    $ manspider share.evilcorp.local -e bat com vbs ps1 psd1 psm1 pem key rsa pub reg txt cfg conf config -d evilcorp -u bob -p Passw0rd

    Example 4: Search for finance-related files
    $ manspider share.evilcorp.local --dirnames bank financ payable payment reconcil remit voucher vendor eft swift -f '[0-9]{5,}' -d evilcorp -u bob -p Passw0rd
    """

    parser = argparse.ArgumentParser(
        description="Scan for juicy data on SMB shares. Matching files and logs are stored in $HOME/.manspider. All filters are case-insensitive."
    )
    parser.add_argument(
        "targets",
        nargs="+",
        type=make_targets,
        help='IPs, Hostnames, CIDR ranges, or files containing targets to spider (NOTE: local searching also supported, specify directory name or keyword "loot" to search downloaded files)',
    )
    parser.add_argument("-u", "--username", default="", help="username for authentication")
    parser.add_argument("-p", "--password", default="", help="password for authentication")
    parser.add_argument("-d", "--domain", default="", help="domain for authentication")
    parser.add_argument("-l", "--loot-dir", default="", help="loot directory (default ~/.manspider/)")
    parser.add_argument("-m", "--maxdepth", type=int, default=10, help="maximum depth to spider (default: 10)")
    parser.add_argument("-H", "--hash", default="", help="NTLM hash for authentication")
    parser.add_argument(
        "-k",
        "--kerberos",
        action="store_true",
        help="Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters",
    )
    parser.add_argument(
        "-aesKey",
        "--aes-key",
        action="store",
        metavar="HEX",
        help="AES key to use for Kerberos Authentication (128 or 256 bits)",
    )
    parser.add_argument(
        "-dc-ip",
        "--dc-ip",
        action="store",
        metavar="IP",
        help="IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter",
    )
    parser.add_argument("-t", "--threads", type=int, default=5, help="concurrent threads (default: 5)")
    parser.add_argument(
        "-f",
        "--filenames",
        nargs="+",
        default=[],
        help="filter filenames using regex (space-separated)",
        metavar="REGEX",
    )
    parser.add_argument(
        "-e",
        "--extensions",
        nargs="+",
        default=[],
        help="only show filenames with these extensions (space-separated, e.g. `docx xlsx` for only word & excel docs)",
        metavar="EXT",
    )
    parser.add_argument(
        "--exclude-extensions", nargs="+", default=[], help="ignore files with these extensions", metavar="EXT"
    )
    parser.add_argument(
        "-c",
        "--content",
        nargs="+",
        default=[],
        help="search for file content using regex (multiple supported)",
        metavar="REGEX",
    )
    parser.add_argument(
        "--sharenames",
        nargs="+",
        default=[],
        help="only search shares with these names (multiple supported)",
        metavar="SHARE",
    )
    parser.add_argument(
        "--exclude-sharenames",
        nargs="*",
        default=["IPC$", "C$", "ADMIN$", "PRINT$"],
        help="don't search shares with these names (multiple supported)",
        metavar="SHARE",
    )
    parser.add_argument(
        "--dirnames",
        nargs="+",
        default=[],
        help="only search directories containing these strings (multiple supported)",
        metavar="DIR",
    )
    parser.add_argument(
        "--exclude-dirnames",
        nargs="+",
        default=[],
        help="don't search directories containing these strings (multiple supported)",
        metavar="DIR",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="don't display matching file content")
    parser.add_argument("-n", "--no-download", action="store_true", help="don't download matching files")
    parser.add_argument("-mfail", "--max-failed-logons", type=int, help="limit failed logons", metavar="INT")
    parser.add_argument(
        "-o",
        "--or-logic",
        action="store_true",
        help="use OR logic instead of AND (files are downloaded if filename OR extension OR content match)",
    )
    parser.add_argument(
        "-s",
        "--max-filesize",
        type=human_to_int,
        default=human_to_int("10M"),
        help='don\'t retrieve files over this size, e.g. "500K" or ".5M" (default: 10M)',
        metavar="SIZE",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="show debugging messages")
    parser.add_argument(
        "--wordlist",
        default=None,
        metavar="FILE",
        help="path to a wordlist file (one word per line) to search for in file contents",
    )
    parser.add_argument(
        "--modified-after",
        type=str,
        metavar="DATE",
        help="only show files modified after this date (format: YYYY-MM-DD)",
    )
    parser.add_argument(
        "--modified-before",
        type=str,
        metavar="DATE",
        help="only show files modified before this date (format: YYYY-MM-DD)",
    )
    parser.add_argument(
        "--json",
        dest="json",
        nargs="?",
        const="-",
        default=None,
        metavar="FILE",
        help="write results (shares, matched/looted files) as JSON Lines; to FILE, "
        "or to stdout if no FILE is given (in which case logs are sent to stderr)",
    )

    syntax_error = False
    try:
        if len(sys.argv) == 1:
            parser.print_help()
            sys.exit(1)

        options = parser.parse_args()

        if options.wordlist:
            options = load_content_wordlist(options.wordlist, options)

        if options.verbose:
            log.setLevel("DEBUG")

        # configure JSON Lines output (must happen before forking the worker)
        set_json_output(options.json)

        if options.kerberos and "KRB5CCNAME" not in os.environ:
            log.error("KRB5CCNAME is not set in the environment")
            sys.exit(1)

        # Parse date filters
        if options.modified_after:
            try:
                options.modified_after = datetime.strptime(options.modified_after, "%Y-%m-%d")
            except ValueError:
                log.error("Invalid date format for --modified-after. Use YYYY-MM-DD")
                sys.exit(1)
        else:
            options.modified_after = None

        if options.modified_before:
            try:
                options.modified_before = datetime.strptime(options.modified_before, "%Y-%m-%d")
            except ValueError:
                log.error("Invalid date format for --modified-before. Use YYYY-MM-DD")
                sys.exit(1)
        else:
            options.modified_before = None

        # normalize extensions: split each entry on whitespace so that a quoted
        # `--extensions "ini cfg"` behaves the same as `--extensions ini cfg`,
        # then ensure a leading dot and lowercase
        def normalize_extensions(extensions):
            normalized = []
            for entry in extensions:
                for extension in entry.split():
                    if not extension.startswith("."):
                        extension = f".{extension}"
                    normalized.append(extension.lower())
            return normalized

        options.extensions = normalize_extensions(options.extensions)
        options.exclude_extensions = normalize_extensions(options.exclude_extensions)

        # lowercase share names
        options.sharenames = [s.lower() for s in options.sharenames]
        options.exclude_sharenames = [s.lower() for s in options.exclude_sharenames]

        # lowercase directory names
        options.dirnames = [s.lower() for s in options.dirnames]
        options.exclude_dirnames = [s.lower() for s in options.exclude_dirnames]

        # deduplicate targets
        targets = set()
        [[targets.add(t) for t in g] for g in options.targets]
        options.targets = list(targets)

        p = multiprocessing.Process(target=go, args=(options,), daemon=False)
        p.start()
        listener.start()

    except argparse.ArgumentError as e:
        syntax_error = True
        log.error(e)
        log.error("Check your syntax")
        sys.exit(2)

    except KeyboardInterrupt:
        log.critical("Interrupted")
        sys.exit(1)

    # pretty format all errors if we're not debugging
    except Exception as e:
        if log.level <= logging.DEBUG:
            log.critical(traceback.format_exc())
        else:
            log.critical(f"Critical error (-v to debug): {e}")

    finally:
        if "-h" in sys.argv or "--help" in sys.argv or len(sys.argv) == 1 or syntax_error:
            print(examples)
        sleep(1)
        try:
            # wait for go to finish
            p.join()
        except:
            pass
        try:
            # stop the log listener
            listener.stop()
        except:
            pass


if __name__ == "__main__":
    main()
