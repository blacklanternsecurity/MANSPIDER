import re
import logging
from time import sleep
import subprocess as sp
from pathlib import Path
from kreuzberg import extract_file_sync
from charset_normalizer import from_path

from man_spider.lib.util import *
from man_spider.lib.logger import *
from man_spider.lib.rules import Rule
from man_spider.lib.parser.certs import inspect_cert, CERT_EXTENSIONS

log = logging.getLogger("manspider.parser")


def is_text_file(filepath):
    """Detect if file is plain text using charset-normalizer."""
    result = from_path(filepath)
    best = result.best()
    # Only consider it a text file if we have high confidence
    # and the encoding is detected (not binary)
    if best is None or best.encoding is None:
        return False
    # Reject if decoded content has too many replacement characters —
    # this means charset-normalizer forced a binary file through as text
    text = str(best)
    if text and text.count("\ufffd") / len(text) > 0.01:
        return False
    return True


def extract_text_file(filepath):
    """Extract text from plain text file, auto-detecting encoding."""
    result = from_path(filepath)
    best = result.best()
    return str(best) if best else None


def line_at(text, index, max_len=500):
    """Return the (truncated) line of text containing the given character index."""
    if text is None:
        return None
    start = text.rfind("\n", 0, index) + 1
    end = text.find("\n", index)
    if end < 0:
        end = len(text)
    return text[start:end].strip()[:max_len]


def extract_strings_from_binary(filepath, min_length=4):
    """
    Extract printable ASCII strings from a binary file.
    Similar to the Unix 'strings' command.
    """
    import string

    printable = set(string.printable) - set("\x0b\x0c")  # Exclude vertical tab and form feed

    with open(filepath, "rb") as f:
        data = f.read()

    result = []
    current = []
    for byte in data:
        char = chr(byte) if byte < 128 else None
        if char and char in printable:
            current.append(char)
        else:
            if len(current) >= min_length:
                result.append("".join(current))
            current = []
    if len(current) >= min_length:
        result.append("".join(current))

    return "\n".join(result)


class FileParser:
    # don't parse files with these extensions
    extension_blacklist = {
        # Archive formats
        ".zip",
        ".gz",
        ".tar",
        ".bz2",
        ".7z",
        ".rar",
        ".xz",
        ".tgz",
        ".tbz2",
        # Encrypted/protected formats
        ".enc",
        ".gpg",
        ".pgp",
        ".asc",
        # Compiled/binary formats that are rarely useful to parse
        ".exe",
        ".dll",
        ".so",
        ".dylib",
    }

    def __init__(self, filters, content_rules=None, quiet=False):
        self.content_rules = []
        self.init_content_filters(filters, content_rules)
        self.quiet = quiet

    def init_content_filters(self, file_content, content_rules=None):
        """
        Get ready to search by file content.

        User-supplied -c regexes become plain "user-content" rules (triage
        yellow); curated Rule objects are appended as-is.
        """

        # content Rule objects; if empty, content is ignored
        self.content_rules = []
        for f in file_content:
            try:
                re.compile(f, re.I)  # validate before wrapping
            except re.error as e:
                log.error(f'Unsupported file content regex "{f}": {e}')
                sleep(1)
                continue
            self.content_rules.append(
                Rule(name="user-content", triage="yellow", location="content", match_type="regex", patterns=[f])
            )

        if content_rules:
            self.content_rules.extend(content_rules)

        if file_content:
            content_filter_str = '"' + '", "'.join(file_content) + '"'
            log.info(f"Searching by file content: {content_filter_str}")

    @property
    def has_content_rules(self):
        return bool(self.content_rules)

    def should_parse(self, filename):
        """True if this file should be sent through the parser (content search or cert inspection)."""
        if self.has_content_rules:
            return True
        return Path(filename).suffix.lower() in CERT_EXTENSIONS

    def match(self, file_content):
        """
        Finds all regex matches in file content.
        Yields (rule, compiled_pattern, (start, end)) for each hit.
        """

        for rule in self.content_rules:
            for rx in rule.regexes:
                for match in rx.finditer(file_content):
                    yield (rule, rx, match.span())

    def match_magic(self, file):
        """
        Returns True if the file isn't of a blacklisted file type
        """
        file_path = Path(file)
        extension = file_path.suffix.lower()

        if extension in self.extension_blacklist:
            log.debug(f'Not parsing {file}: blacklisted extension: "{extension}"')
            return False

        return True

    def grep(self, content, pattern):

        if not self.quiet:
            try:
                """
                GREP(1)
                    -E, --extended-regexp
                        Interpret PATTERN as an extended regular expression
                    -i, --ignore-case
                        Ignore case distinctions
                    -m NUM, --max-count=NUM
                        Stop reading a file after NUM matching lines
                """
                grep_process = sp.Popen(
                    ["grep", "-Eim", "5", "--color=always", pattern], stdin=sp.PIPE, stdout=sp.PIPE
                )
                grep_output = grep_process.communicate(content)[0]
                for line in grep_output.splitlines():
                    log.info(better_decode(line[:500]))
            except (sp.SubprocessError, OSError, IndexError):
                pass

    def parse_file(self, file, pretty_filename=None):
        """
        Parse a file on the local filesystem
        """

        if pretty_filename is None:
            pretty_filename = str(file)

        log.debug(f"Parsing file: {pretty_filename}")

        matches = []

        try:
            matches = self.extract_text(file, pretty_filename=pretty_filename)

        except Exception as e:
            if log.level <= logging.DEBUG:
                log.warning(f"Error extracting text from {pretty_filename}: {e}")
            else:
                log.warning(f"Error extracting text from {pretty_filename} (-v to debug)")

        return matches

    def extract_text(self, file, pretty_filename):
        """
        Extracts text from a file.
        Uses charset-normalizer for plain text files (handles UTF-16, etc.)
        Falls back to kreuzberg for binary formats (docx, pdf, xlsx, etc.)
        """

        # blacklist certain mime types
        if not self.match_magic(file):
            return []

        # certificate / key material gets dedicated parsing (parse + report only)
        cert_extension = Path(file).suffix.lower()
        if cert_extension in CERT_EXTENSIONS:
            result = inspect_cert(str(file), cert_extension)
            if result is not None:
                reasons, triage = result
                context = "; ".join(reasons)
                log.info(
                    ColoredFormatter.triage(
                        f"{pretty_filename}: [{triage.upper()}] certificate — {context}", triage
                    )
                )
                return [
                    {
                        "match_type": "certificate",
                        "triage": triage,
                        "rule": "Certificate",
                        "pattern": None,
                        "count": None,
                        "context": context,
                    }
                ]
            # not a parseable cert — fall through to normal content extraction

        # Try charset-normalizer first for text files (handles UTF-16, etc.)
        if is_text_file(str(file)):
            text_content = extract_text_file(str(file))
            log.debug(f"Extracted text from {pretty_filename} using charset-normalizer")
        else:
            # Try kreuzberg for document formats (docx, pdf, xlsx, etc.)
            try:
                result = extract_file_sync(str(file))
                text_content = result.content
            except Exception as e:
                # Kreuzberg doesn't support this file type, try extracting raw strings
                log.debug(f"Kreuzberg failed for {pretty_filename}: {e}, trying string extraction")
                text_content = extract_strings_from_binary(str(file))

        # Guard against None content
        if text_content is None:
            return []

        # Guard against binary garbage: if more than 1% of characters are
        # Unicode replacement chars (U+FFFD), the file was decoded incorrectly.
        # Fall back to raw ASCII string extraction to avoid dumping huge binary chunks.
        if text_content and text_content.count("\ufffd") / len(text_content) > 0.01:
            log.debug(f"High replacement char ratio in {pretty_filename}, falling back to string extraction")
            text_content = extract_strings_from_binary(str(file))
            if text_content is None:
                return []

        # try to convert to UTF-8 for grep-friendliness
        try:
            binary_content = text_content.encode("utf-8", errors="ignore")
        except Exception:
            pass

        # count the matches, keyed by (rule, compiled pattern), remembering the first span
        counts = dict()
        first_span = dict()
        for rule, rx, span in self.match(text_content):
            key = (rule, rx)
            counts[key] = counts.get(key, 0) + 1
            if key not in first_span:
                first_span[key] = span

        records = []
        for (rule, rx), match_count in counts.items():
            log.info(
                ColoredFormatter.triage(
                    f'{pretty_filename}: [{rule.triage.upper()}] matched "{rx.pattern}" '
                    f'{match_count:,} times (rule: {rule.name})',
                    rule.triage,
                )
            )
            # run grep for pretty output
            if not self.quiet:
                self.grep(binary_content, rx.pattern)

            records.append(
                {
                    "match_type": "content",
                    "triage": rule.triage,
                    "rule": rule.name,
                    "pattern": rx.pattern,
                    "count": match_count,
                    "context": line_at(text_content, first_span[(rule, rx)][0]),
                }
            )

        return records
