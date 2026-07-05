"""Validation tests: passing rules, and each failure mode."""

from elastdetect.validate import validate_rule


def test_valid_query_rule_passes(valid_query_rule):
    rep = validate_rule(valid_query_rule)
    assert rep.ok
    assert rep.errors == []


def test_valid_threshold_rule_passes(valid_threshold_rule):
    rep = validate_rule(valid_threshold_rule)
    assert rep.ok


def test_missing_rule_id_fails(make_rule, DELETE):
    rep = validate_rule(make_rule(rule_id=DELETE))
    assert not rep.ok
    assert any(i.field == "rule_id" for i in rep.errors)


def test_empty_name_fails(make_rule):
    rep = validate_rule(make_rule(name="   "))
    assert not rep.ok
    assert any(i.field == "name" for i in rep.errors)


def test_risk_score_out_of_range_fails(make_rule):
    rep = validate_rule(make_rule(risk_score=150))
    assert not rep.ok
    assert any(i.field == "risk_score" for i in rep.errors)


def test_risk_score_negative_fails(make_rule):
    rep = validate_rule(make_rule(risk_score=-1))
    assert not rep.ok


def test_risk_score_bool_rejected(make_rule):
    # bool is a subclass of int; must not be accepted.
    rep = validate_rule(make_rule(risk_score=True))
    assert not rep.ok
    assert any(i.field == "risk_score" for i in rep.errors)


def test_risk_score_non_int_fails(make_rule):
    rep = validate_rule(make_rule(risk_score="high"))
    assert not rep.ok


def test_invalid_severity_fails(make_rule):
    rep = validate_rule(make_rule(severity="extreme"))
    assert not rep.ok
    assert any(i.field == "severity" for i in rep.errors)


def test_unsupported_type_fails(make_rule):
    rep = validate_rule(make_rule(type="saved_query_unknown"))
    assert not rep.ok
    assert any(i.field == "type" for i in rep.errors)


def test_missing_query_fails(make_rule, DELETE):
    rep = validate_rule(make_rule(query=DELETE))
    assert not rep.ok
    assert any(i.field == "query" for i in rep.errors)


def test_empty_query_fails(make_rule):
    rep = validate_rule(make_rule(query=""))
    assert not rep.ok


def test_threshold_without_threshold_object_fails(make_rule):
    rep = validate_rule(make_rule(type="threshold"))
    assert not rep.ok
    assert any(i.field == "threshold" for i in rep.errors)


def test_threshold_with_bad_value_fails(make_rule):
    rule = make_rule(type="threshold", threshold={"field": ["x"], "value": 0})
    rep = validate_rule(rule)
    assert not rep.ok
    assert any(i.field == "threshold.value" for i in rep.errors)


def test_threshold_with_valid_value_passes(make_rule):
    rule = make_rule(type="threshold", threshold={"field": ["x"], "value": 5})
    rep = validate_rule(rule)
    assert rep.ok


def test_multiple_errors_collected(make_rule, DELETE):
    rep = validate_rule(make_rule(rule_id=DELETE, severity="nope", risk_score=999))
    fields = {i.field for i in rep.errors}
    assert {"rule_id", "severity", "risk_score"}.issubset(fields)
