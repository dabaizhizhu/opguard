"""Domain-separated signing, deterministic canonical JSON, and hash helpers."""

from __future__ import annotations

import hashlib
import hmac

from opguard.base.crypto import args_hash, canonical_json, sign, signatures_equal


def test_canonical_json_sorts_keys_and_uses_compact_separators():
    left = canonical_json({"b": 1, "a": 2, "c": [3, 4]})
    right = canonical_json({"c": [3, 4], "a": 2, "b": 1})
    assert left == right
    assert left == b'{"a":2,"b":1,"c":[3,4]}'


def test_canonical_json_is_deterministic_for_nested_dicts():
    assert canonical_json({"a": {"x": 1, "y": 2}}) == canonical_json({"a": {"y": 2, "x": 1}})


def test_canonical_json_keeps_unicode_when_not_ascii_escaped():
    assert "中文".encode("utf-8") in canonical_json({"k": "中文"})


def test_sign_uses_domain_separated_hmac_sha256():
    payload = {"a": 1, "b": "two"}
    secret = b"k" * 32
    ticket = sign("ticket", payload, secret)
    verdict = sign("verdict", payload, secret)
    permit = sign("permit", payload, secret)
    # Same payload, different domains ⇒ different signatures.
    assert len({ticket, verdict, permit}) == 3
    assert all(len(v) == 64 for v in (ticket, verdict, permit))


def test_sign_matches_manual_hmac_sha256_over_domain_null_separator():
    secret = b"k" * 32
    payload = {"a": 1}
    expected = hmac.new(secret, b"ticket\0" + canonical_json(payload), hashlib.sha256).hexdigest()
    assert sign("ticket", payload, secret) == expected


def test_tampering_the_payload_changes_the_signature():
    secret = b"k" * 32
    original = sign("ticket", {"agent_id": "a"}, secret)
    tampered = sign("ticket", {"agent_id": "b"}, secret)
    assert original != tampered
    # A signature must not match a different payload's signature.
    assert not signatures_equal(original, tampered)


def test_args_hash_is_deterministic_across_key_order():
    assert args_hash("t", "sql", {"a": 1, "b": 2}) == args_hash("t", "sql", {"b": 2, "a": 1})


def test_args_hash_is_sensitive_to_tool_kind_and_values():
    base = args_hash("sql.query", "sql", {"statement": "x"})
    assert base != args_hash("other.tool", "sql", {"statement": "x"})
    assert base != args_hash("sql.query", "shell", {"statement": "x"})
    assert base != args_hash("sql.query", "sql", {"statement": "y"})


def test_args_hash_is_sensitive_to_parameter_order_inside_lists():
    # Dict key order is canonicalized; the order of list *values* is not.
    assert args_hash("t", "sql", {"ids": [1, 2]}) != args_hash("t", "sql", {"ids": [2, 1]})


def test_signatures_equal_is_constant_time_and_exact():
    assert signatures_equal("a" * 64, "a" * 64)
    assert not signatures_equal("a" * 64, "b" * 64)
    assert not signatures_equal("", "a")
    assert not signatures_equal("abc", "abcd")
    assert signatures_equal("", "")