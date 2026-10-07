"""
Lightweight classification rules adapted from Snaffler's TOML rule set.

This is a pragmatic adaptation, not a full port: we model Snaffle rules that
match on a file's name, extension, path, or content, and attach a triage
severity to each match. Relay-chaining, Discard/CheckForKeys actions, and
share/directory scopes are intentionally not modeled here.
"""

import re
import logging
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    import tomli as tomllib

log = logging.getLogger("manspider.rules")

# directory holding the vendored Snaffler DefaultRules TOML tree
DEFAULT_RULES_DIR = Path(__file__).parent / "default"

# higher number == more interesting (Snaffler's Black is the crown jewels)
TRIAGE_SEVERITY = {"green": 1, "yellow": 2, "red": 3, "black": 4}

# locations we know how to evaluate, keyed by Snaffler's MatchLocation
_LOCATION_MAP = {
    "FileName": "filename",
    "FileExtension": "extension",
    "FilePath": "path",
    "FileContentAsString": "content",
}

# match types we know how to turn into a regex, keyed by Snaffler's WordListType
_MATCH_TYPES = {"Exact", "Contains", "Regex", "EndsWith", "StartsWith"}


class Rule:
    """A single classification rule: a set of patterns + where/how to match + triage."""

    __slots__ = ("name", "triage", "location", "match_type", "patterns", "_regexes")

    def __init__(self, name, triage, location, match_type, patterns):
        self.name = name
        self.triage = triage  # "green" | "yellow" | "red" | "black"
        self.location = location  # "filename" | "extension" | "path" | "content"
        self.match_type = match_type  # "regex" | "exact" | "contains" | "endswith" | "startswith"
        self.patterns = list(patterns)
        self._regexes = None

    def __getstate__(self):
        # keep pickling (parent -> spiderling processes) light; recompile lazily
        return (self.name, self.triage, self.location, self.match_type, self.patterns)

    def __setstate__(self, state):
        self.name, self.triage, self.location, self.match_type, self.patterns = state
        self._regexes = None

    @property
    def severity(self):
        return TRIAGE_SEVERITY.get(self.triage, 0)

    def _to_regex(self, pattern):
        """Anchor a pattern per its match_type. Patterns are always regexes
        (never escaped) — Snaffler treats even 'Exact'/'Contains' wordlists as
        unanchored regexes, with the type only adding ^ / $ anchors."""
        if self.match_type == "exact":
            return rf"^{pattern}$"
        if self.match_type == "startswith":
            return rf"^{pattern}"
        if self.match_type == "endswith":
            return rf"{pattern}$"
        # regex and contains are unanchored regexes, used as-is
        return pattern

    @property
    def regexes(self):
        if self._regexes is None:
            compiled = []
            for p in self.patterns:
                try:
                    compiled.append(re.compile(self._to_regex(p), re.I))
                except re.error as e:
                    log.debug(f'rule "{self.name}": bad pattern {p!r}: {e}')
            self._regexes = compiled
        return self._regexes

    def matches(self, value):
        """True if any of this rule's patterns matches the given value."""
        if value is None:
            return False
        for rx in self.regexes:
            if rx.search(value):
                return True
        return False

    def __repr__(self):
        return f"<Rule {self.name} [{self.triage}] {self.location}/{self.match_type} ({len(self.patterns)} patterns)>"


class RuleSet:
    """The active rules, grouped by where they match."""

    def __init__(self, rules=None):
        self.filename = []
        self.extension = []
        self.path = []
        self.content = []
        for rule in rules or []:
            self.add(rule)

    def add(self, rule):
        getattr(self, rule.location).append(rule)

    @property
    def file_rules(self):
        """Rules evaluated against a file's name/extension/path (not content)."""
        return self.filename + self.extension + self.path

    def __bool__(self):
        return bool(self.filename or self.extension or self.path or self.content)

    def __len__(self):
        return len(self.filename) + len(self.extension) + len(self.path) + len(self.content)


def _parse_toml_rules(path):
    """Yield Rule objects from one TOML file, skipping anything we don't model."""
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except Exception as e:
        log.debug(f"failed to load rule file {path}: {e}")
        return

    for entry in data.get("ClassifierRules", []):
        action = entry.get("MatchAction")
        if action != "Snaffle":
            # Discard / Relay / CheckForKeys / etc. are out of scope for this adaptation
            yield ("skip", None)
            continue

        location = _LOCATION_MAP.get(entry.get("MatchLocation"))
        if location is None:
            yield ("skip", None)
            continue

        word_list_type = entry.get("WordListType", "Regex")
        if word_list_type not in _MATCH_TYPES:
            yield ("skip", None)
            continue

        patterns = entry.get("WordList") or []
        if not patterns:
            yield ("skip", None)
            continue

        triage = str(entry.get("Triage", "green")).lower()
        if triage not in TRIAGE_SEVERITY:
            triage = "green"

        yield (
            "keep",
            Rule(
                name=entry.get("RuleName", "unnamed"),
                triage=triage,
                location=location,
                match_type=word_list_type.lower(),
                patterns=patterns,
            ),
        )


def load_default_rules(rules_dir=DEFAULT_RULES_DIR):
    """Load the vendored Snaffler DefaultRules tree into a RuleSet."""
    ruleset = RuleSet()
    kept = 0
    skipped = 0
    for toml_path in sorted(Path(rules_dir).rglob("*.toml")):
        for outcome, rule in _parse_toml_rules(toml_path):
            if outcome == "keep":
                ruleset.add(rule)
                kept += 1
            else:
                skipped += 1

    log.info(
        f"Loaded {kept} default classification rules "
        f"({len(ruleset.filename)} filename, {len(ruleset.extension)} extension, "
        f"{len(ruleset.path)} path, {len(ruleset.content)} content); "
        f"skipped {skipped} unsupported rules"
    )
    return ruleset
