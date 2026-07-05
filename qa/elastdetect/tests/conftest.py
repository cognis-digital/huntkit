"""Shared test fixtures: in-memory valid/invalid rule dicts."""

import copy

import pytest


@pytest.fixture
def valid_query_rule():
    return {
        "rule_id": "test-valid-001",
        "name": "Valid Query Rule For Tests",
        "description": "A complete, valid query rule used in tests.",
        "type": "query",
        "language": "kuery",
        "query": "process.name : \"cmd.exe\"",
        "risk_score": 50,
        "severity": "medium",
        "tags": ["Domain: Endpoint"],
        "references": ["https://example.invalid/ref"],
        "false_positives": ["benign automation"],
    }


@pytest.fixture
def valid_threshold_rule():
    return {
        "rule_id": "test-valid-thr-001",
        "name": "Valid Threshold Rule For Tests",
        "description": "A complete threshold rule.",
        "type": "threshold",
        "language": "kuery",
        "query": "event.outcome : \"failure\"",
        "threshold": {"field": ["source.ip"], "value": 10},
        "risk_score": 40,
        "severity": "low",
        "tags": ["Domain: Identity"],
        "references": ["https://example.invalid/ref"],
        "false_positives": ["service account"],
    }


@pytest.fixture
def make_rule(valid_query_rule):
    """Return a factory that clones the valid rule with overrides applied."""

    def _make(**overrides):
        rule = copy.deepcopy(valid_query_rule)
        for key, val in overrides.items():
            if val is _DELETE:
                rule.pop(key, None)
            else:
                rule[key] = val
        return rule

    return _make


_DELETE = object()


@pytest.fixture
def DELETE():
    return _DELETE
