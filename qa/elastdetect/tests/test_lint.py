"""Lint tests: style warnings are emitted but never block validation."""

from elastdetect.lint import lint_rule


def test_complete_rule_no_warnings(valid_query_rule):
    rep = lint_rule(valid_query_rule)
    assert rep.warnings == []


def test_missing_description_warns(make_rule, DELETE):
    rep = lint_rule(make_rule(description=DELETE))
    assert any(i.field == "description" for i in rep.warnings)


def test_missing_tags_warns(make_rule, DELETE):
    rep = lint_rule(make_rule(tags=DELETE))
    assert any(i.field == "tags" for i in rep.warnings)


def test_empty_tags_warns(make_rule):
    rep = lint_rule(make_rule(tags=[]))
    assert any(i.field == "tags" for i in rep.warnings)


def test_missing_references_warns(make_rule, DELETE):
    rep = lint_rule(make_rule(references=DELETE))
    assert any(i.field == "references" for i in rep.warnings)


def test_short_name_warns(make_rule):
    rep = lint_rule(make_rule(name="short"))
    assert any(i.field == "name" for i in rep.warnings)


def test_missing_false_positives_warns(make_rule, DELETE):
    rep = lint_rule(make_rule(false_positives=DELETE))
    assert any(i.field == "false_positives" for i in rep.warnings)


def test_lint_issues_are_all_warnings(make_rule, DELETE):
    rep = lint_rule(make_rule(description=DELETE, tags=DELETE, references=DELETE))
    assert rep.issues
    assert all(i.level == "warning" for i in rep.issues)
    assert rep.errors == []
