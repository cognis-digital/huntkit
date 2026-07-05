"""Loader tests: single file, array file, wrapper, directory, error cases."""

import json
import os

from elastdetect.rules import load_path


def _write(path, obj):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh)


def test_load_single_object(tmp_path):
    p = tmp_path / "one.json"
    _write(p, {"rule_id": "a", "name": "Alpha"})
    res = load_path(str(p))
    assert res.errors == []
    assert len(res.rules) == 1
    assert res.rules[0].rule_id == "a"


def test_load_array(tmp_path):
    p = tmp_path / "many.json"
    _write(p, [{"rule_id": "a"}, {"rule_id": "b"}])
    res = load_path(str(p))
    assert len(res.rules) == 2


def test_load_wrapper(tmp_path):
    p = tmp_path / "wrap.json"
    _write(p, {"rules": [{"rule_id": "a"}, {"rule_id": "b"}]})
    res = load_path(str(p))
    assert len(res.rules) == 2


def test_load_directory(tmp_path):
    _write(tmp_path / "a.json", {"rule_id": "a"})
    _write(tmp_path / "b.json", {"rule_id": "b"})
    (tmp_path / "ignore.txt").write_text("nope", encoding="utf-8")
    res = load_path(str(tmp_path))
    ids = sorted(r.rule_id for r in res.rules)
    assert ids == ["a", "b"]


def test_missing_path_errors():
    res = load_path(os.path.join("definitely", "missing.json"))
    assert res.rules == []
    assert res.errors


def test_invalid_json_errors(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    res = load_path(str(p))
    assert res.rules == []
    assert any("invalid JSON" in e.message for e in res.errors)


def test_non_json_file_errors(tmp_path):
    p = tmp_path / "rule.yaml"
    p.write_text("rule_id: a", encoding="utf-8")
    res = load_path(str(p))
    assert any("not a .json file" in e.message for e in res.errors)


def test_examples_load_clean():
    """The shipped example rules must load and parse."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    examples = os.path.join(here, "examples", "rules")
    res = load_path(examples)
    assert res.errors == []
    assert len(res.rules) >= 3
