"""Diff tests: added / removed / modified detection and field-level changes."""

from elastdetect.diff import diff_rule_sets, render_table


def _rule(rid, **kw):
    base = {"rule_id": rid, "name": f"name-{rid}", "risk_score": 50}
    base.update(kw)
    return base


def test_added_detected():
    d = diff_rule_sets([_rule("a")], [_rule("a"), _rule("b")])
    added_ids = [r["rule_id"] for r in d.added]
    assert added_ids == ["b"]
    assert d.removed == []
    assert d.modified == []


def test_removed_detected():
    d = diff_rule_sets([_rule("a"), _rule("b")], [_rule("a")])
    removed_ids = [r["rule_id"] for r in d.removed]
    assert removed_ids == ["b"]
    assert d.added == []


def test_modified_field_change():
    old = [_rule("a", risk_score=50, severity="low")]
    new = [_rule("a", risk_score=80, severity="high")]
    d = diff_rule_sets(old, new)
    assert len(d.modified) == 1
    m = d.modified[0]
    assert m.rule_id == "a"
    changed = {c.field: (c.old, c.new) for c in m.changes}
    assert changed["risk_score"] == (50, 80)
    assert changed["severity"] == ("low", "high")


def test_no_change_not_reported_as_modified():
    r = _rule("a", query="x")
    d = diff_rule_sets([dict(r)], [dict(r)])
    assert not d.has_changes


def test_list_order_insensitive():
    old = [_rule("a", tags=["x", "y"])]
    new = [_rule("a", tags=["y", "x"])]
    d = diff_rule_sets(old, new)
    assert d.modified == []


def test_added_field_marked():
    old = [_rule("a")]
    new = [_rule("a", note="new field")]
    d = diff_rule_sets(old, new)
    change = d.modified[0].changes[0]
    assert change.field == "note"
    assert change.old == "<absent>"
    assert change.new == "new field"


def test_removed_field_marked():
    old = [_rule("a", note="gone")]
    new = [_rule("a")]
    d = diff_rule_sets(old, new)
    change = d.modified[0].changes[0]
    assert change.field == "note"
    assert change.new == "<absent>"


def test_to_dict_structure():
    d = diff_rule_sets([_rule("a")], [_rule("a", risk_score=99), _rule("c")])
    out = d.to_dict()
    assert {"added", "removed", "modified"} == set(out)
    assert out["added"][0]["rule_id"] == "c"
    assert out["modified"][0]["changes"][0]["field"] == "risk_score"


def test_render_table_runs():
    d = diff_rule_sets([_rule("a")], [_rule("b"), _rule("a", severity="high")])
    text = render_table(d)
    assert "ADDED" in text
    assert "MODIFIED" in text
    assert "1 added" in text


def test_render_table_no_changes():
    d = diff_rule_sets([_rule("a")], [_rule("a")])
    assert "No differences." in render_table(d)
