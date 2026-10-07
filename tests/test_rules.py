import pickle

from man_spider.lib.rules import Rule, RuleSet, load_default_rules


def test_load_default_rules_populates_all_locations():
    rs = load_default_rules()
    assert len(rs) > 0
    # the vendored Snaffler DefaultRules tree covers every location we model
    assert rs.filename
    assert rs.extension
    assert rs.content
    assert rs.path
    # file_rules is the union of name/extension/path rules (content handled separately)
    assert len(rs.file_rules) == len(rs.filename) + len(rs.extension) + len(rs.path)


def test_known_extension_rule_round_trips():
    rs = load_default_rules()
    kdbx = [r for r in rs.extension if any("kdbx" in p for p in r.patterns)]
    assert kdbx, "expected a password-manager extension rule covering .kdbx"
    rule = kdbx[0]
    assert rule.triage == "black"
    assert rule.matches(".kdbx")
    assert not rule.matches(".txt")


def test_match_type_anchoring():
    # patterns are regexes; match_type only adds anchors (never re.escape)
    exact = Rule("x", "red", "extension", "exact", [r"\.pem"])
    assert exact.matches(".pem")
    assert not exact.matches(".pem.bak")

    ends = Rule("x", "red", "filename", "endswith", ["_rsa"])
    assert ends.matches("id_rsa")
    assert not ends.matches("rsa_key")

    contains = Rule("x", "green", "filename", "contains", ["passw"])
    assert contains.matches("mypassword.txt")


def test_severity_ordering():
    assert Rule("a", "black", "filename", "contains", ["x"]).severity > Rule(
        "b", "red", "filename", "contains", ["x"]
    ).severity
    assert Rule("c", "red", "filename", "contains", ["x"]).severity > Rule(
        "d", "green", "filename", "contains", ["x"]
    ).severity


def test_rule_pickles_and_still_matches():
    rule = Rule("x", "black", "extension", "exact", [r"\.kdbx"])
    restored = pickle.loads(pickle.dumps(rule))
    assert restored.matches(".kdbx")
    assert restored.triage == "black"


def test_ruleset_add_routes_by_location():
    rs = RuleSet()
    rs.add(Rule("f", "green", "filename", "contains", ["a"]))
    rs.add(Rule("e", "black", "extension", "exact", [r"\.b"]))
    rs.add(Rule("p", "red", "path", "contains", ["c"]))
    rs.add(Rule("c", "yellow", "content", "regex", ["d"]))
    assert len(rs.filename) == 1 and len(rs.extension) == 1
    assert len(rs.path) == 1 and len(rs.content) == 1
    assert len(rs.file_rules) == 3
