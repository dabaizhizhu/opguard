"""Decision pipeline behaviour: L0 → L1 → L1.5 → L2 → L3, short-circuiting."""

from __future__ import annotations

import dataclasses
import http.server
import json
import os
import threading
import time

import pytest

from conftest import CountingEmbedding, CountingJev

from opguard import (
    HttpJevAuditor,
    OpGuardConfig,
    TicketRejected,
    build_call,
)
from opguard.base.clock import ManualClock
from opguard.base.types import EffectReport, ToolCall, ToolKind
from opguard.policy.embedding import HashingEmbedding, ScriptedEmbedding, cosine
from opguard.policy.jev import JevRequest, JevParseError, JevTimeout, JevTransportError
from opguard.policy.sandbox import ClassifyingSandbox, ScriptedSandbox, SubprocessSandbox
from opguard.policy.rules import normalize_path


def _clean_report():
    return EffectReport(sandbox_id="sbx", effects=(), clean=True, timed_out=False, elapsed_ms=0.0, detail="clean")


# --------------------------------------------------------------------------- L0


def test_bare_call_without_ticket_is_denied_at_l0(make_guard, tmp_path):
    guard = make_guard(tmp_path / "audit.jsonl")
    result = guard.handle(None, build_call("sql", "SELECT id FROM orders WHERE id = 1"))
    assert result.decision == "deny"
    assert result.layer == "L0"
    assert "missing ticket" in result.reason


def test_tampered_ticket_signature_is_denied_at_l0(make_guard, issue_standard, tmp_path):
    guard = make_guard(tmp_path / "audit.jsonl")
    ticket = issue_standard(guard)
    bad = dataclasses.replace(ticket, signature="0" * 64)
    result = guard.handle(bad, build_call("sql", "SELECT 1"))
    assert result.decision == "deny"
    assert result.layer == "L0"
    assert "signature invalid" in result.reason


def test_expired_ticket_is_denied_at_l0(make_guard, issue_standard, clock, tmp_path):
    guard = make_guard(tmp_path / "audit.jsonl")
    ticket = issue_standard(guard, ttl_s=10.0)
    clock.advance(11.0)
    result = guard.handle(ticket, build_call("sql", "SELECT 1"))
    assert result.decision == "deny"
    assert result.layer == "L0"
    assert "expired" in result.reason


def test_resource_outside_ticket_scope_is_denied_at_l0(make_guard, issue_standard, tmp_path):
    guard = make_guard(tmp_path / "audit.jsonl")
    ticket = issue_standard(guard, resources=("sql:orders",), capabilities=("read",))
    result = guard.handle(ticket, build_call("sql", "SELECT id FROM salaries WHERE id = 1"))
    assert result.decision == "deny"
    assert result.layer == "L0"
    assert "resource outside ticket scope" in result.reason


def test_capability_drift_is_denied_at_l0(make_guard, issue_standard, tmp_path):
    guard = make_guard(tmp_path / "audit.jsonl")
    ticket = issue_standard(guard, resources=("sql:orders",), capabilities=("read",))
    result = guard.handle(ticket, build_call("sql", "UPDATE orders SET status = 'x' WHERE id = 7"))
    assert result.decision == "deny"
    assert result.layer == "L0"
    assert "intent drift" in result.reason


def test_malicious_ticket_intent_is_denied_at_l0(make_guard, issue_standard, tmp_path):
    guard = make_guard(tmp_path / "audit.jsonl")
    ticket = issue_standard(guard, intent="wipe every row without a filter")
    result = guard.handle(ticket, build_call("sql", "SELECT id FROM orders WHERE id = 1"))
    assert result.decision == "deny"
    assert result.layer == "L0"
    assert "malicious ticket intent" in result.reason


# --------------------------------------------------------------------------- L1


@pytest.mark.parametrize(
    ("kind", "action", "reason_fragment"),
    [
        ("sql", "DROP TABLE orders", "drop"),
        ("sql", "TRUNCATE TABLE users", "truncate"),
        ("sql", "DELETE FROM orders", "without where"),
        ("sql", "UPDATE users SET role = 'admin'", "without where"),
        ("sql", "DELETE FROM orders WHERE 1 = 1", "tautology"),
        ("shell", "rm -rf /", "root"),
        ("shell", "rm -rf /etc", "system path"),
        ("shell", "echo x > /etc/passwd", "system path"),
        ("shell", "apt-get purge openssl", "package"),
        ("shell", "rm -f /usr/share/java/service.jar", "jar"),
        ("http", "DELETE https://audit.internal/api/users", "collection"),
        ("http", "DELETE https://api.prod.example/v1/users/42", "production"),
    ],
)
def test_l1_hard_deny_short_circuits_before_vector_jev_and_sandbox(
    make_guard, issue_standard, tmp_path, kind, action, reason_fragment
):
    embedding = CountingEmbedding()
    jev = CountingJev()
    sandbox = ScriptedSandbox(_clean_report())
    guard = make_guard(
        tmp_path / "audit.jsonl",
        embedding=embedding,
        jev=jev,
        sandbox=sandbox,
    )
    ticket = issue_standard(guard)
    result = guard.handle(ticket, build_call(kind, action))
    assert result.decision == "deny"
    assert result.layer == "L1"
    assert reason_fragment in result.reason
    # Hard denies never reach the vector, L2, or sandbox components.
    assert embedding.calls == 0
    assert jev.calls == 0
    assert sandbox.calls == 0


# --------------------------------------------------------------------------- L1.5


def test_structured_high_similarity_is_denied_without_jev_or_sandbox(make_guard, issue_standard, tmp_path):
    embedding = CountingEmbedding({"DELETE FROM sessions WHERE user_id = 7 AND expired = true": 0.96})
    jev = CountingJev()
    sandbox = ScriptedSandbox(_clean_report())
    guard = make_guard(tmp_path / "audit.jsonl", embedding=embedding, jev=jev, sandbox=sandbox)
    ticket = issue_standard(guard)
    result = guard.handle(ticket, build_call("sql", "DELETE FROM sessions WHERE user_id = 7 AND expired = true"))
    assert result.decision == "deny"
    assert result.layer == "L1.5"
    assert "high similarity" in result.reason
    assert jev.calls == 0
    assert sandbox.calls == 0


def test_mcp_high_similarity_enters_jev_instead_of_direct_deny(make_guard, issue_standard, tmp_path):
    embedding = CountingEmbedding({"please wipe every row without a filter": 0.96})
    jev = CountingJev(decision="deny", reason="jev nope")
    guard = make_guard(tmp_path / "audit.jsonl", embedding=embedding, jev=jev)
    ticket = issue_standard(guard)
    result = guard.handle(ticket, build_call("mcp", "please wipe every row without a filter"))
    assert result.decision == "deny"
    assert result.layer == "L2"
    assert jev.calls == 1


def test_vector_mid_band_enters_jev(make_guard, issue_standard, tmp_path):
    embedding = CountingEmbedding({"delete every row of the session cache": 0.70})
    jev = CountingJev(decision="deny", reason="jev nope")
    guard = make_guard(tmp_path / "audit.jsonl", embedding=embedding, jev=jev)
    ticket = issue_standard(guard)
    result = guard.handle(ticket, build_call("mcp", "delete every row of the session cache"))
    assert result.decision == "deny"
    assert result.layer == "L2"
    assert jev.calls == 1


def test_vector_low_band_skips_jev_and_allows_directly(make_guard, issue_standard, tmp_path):
    embedding = CountingEmbedding({"select one audit row by id": 0.20})
    jev = CountingJev()
    sandbox = ScriptedSandbox(_clean_report())
    guard = make_guard(tmp_path / "audit.jsonl", embedding=embedding, jev=jev, sandbox=sandbox)
    ticket = issue_standard(guard)
    result = guard.handle(ticket, build_call("mcp", "select one audit row by id"))
    assert result.decision == "allow"
    assert result.layer == "L1.5"
    assert jev.calls == 0
    assert sandbox.calls == 0


def test_hashing_embedding_default_shape_and_determinism():
    embedder = HashingEmbedding(dims=128)
    a = embedder.embed("SELECT id FROM orders")
    b = embedder.embed("SELECT id FROM orders")
    assert a == b
    assert len(a) == 128
    norm = sum(v * v for v in a)
    assert norm == pytest.approx(1.0, abs=1e-9)


def test_scripted_embedding_pins_cosine_and_cosine_basics():
    assert cosine([1.0, 0.0], [1.0, 0.0]) == pytest.approx(1.0)
    assert cosine([1.0, 0.0], [0.0, 1.0]) == pytest.approx(0.0)
    emb = ScriptedEmbedding({"x": 0.8}, prototypes=("p",))
    assert cosine(emb.embed("x"), emb.embed("p")) == pytest.approx(0.8)


# --------------------------------------------------------------------------- L2


def _jev_request() -> JevRequest:
    return JevRequest(
        ticket_id="tkt",
        tool="mcp.tool",
        kind="mcp",
        args_hash="h",
        action_text="rebuild index",
        vector_score=0.7,
        vector_band="mid",
    )


def test_http_jev_auditor_parses_a_valid_allow():
    class OK:
        def post(self, url, body, headers, timeout_s):
            assert headers["content-type"] == "application/json"
            return 200, b'{"decision":"allow","reason":"ok","audit_id":"srv-1"}'

    auditor = HttpJevAuditor("http://localhost/audit", transport=OK())
    resp = auditor.audit(_jev_request(), 0.8)
    assert resp.decision == "allow"
    assert resp.audit_id == "srv-1"


def test_http_jev_timeout_fails_closed():
    class Slow:
        def post(self, url, body, headers, timeout_s):
            time.sleep(timeout_s + 0.3)
            return 200, b'{"decision":"allow","reason":"x","audit_id":"a"}'

    auditor = HttpJevAuditor("http://localhost/audit", transport=Slow())
    with pytest.raises(JevTimeout):
        auditor.audit(_jev_request(), 0.05)


def test_http_jev_transport_failure_fails_closed():
    class Broken:
        def post(self, url, body, headers, timeout_s):
            raise ConnectionError("connection refused")

    auditor = HttpJevAuditor("http://localhost/audit", transport=Broken())
    with pytest.raises(JevTransportError):
        auditor.audit(_jev_request(), 0.8)


def test_http_jev_malformed_json_fails_closed():
    class Junk:
        def post(self, url, body, headers, timeout_s):
            return 200, b"<html>gateway timeout</html>"

    auditor = HttpJevAuditor("http://localhost/audit", transport=Junk())
    with pytest.raises(JevParseError):
        auditor.audit(_jev_request(), 0.8)


def test_http_jev_unknown_decision_fails_closed():
    class Unknown:
        def post(self, url, body, headers, timeout_s):
            return 200, b'{"decision":"maybe","reason":"","audit_id":"a"}'

    auditor = HttpJevAuditor("http://localhost/audit", transport=Unknown())
    with pytest.raises(JevParseError):
        auditor.audit(_jev_request(), 0.8)


class _JevHandler(http.server.BaseHTTPRequestHandler):
    response_status = 200
    response_body = b'{"decision":"allow","reason":"ok","audit_id":"srv"}'

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        self.send_response(self.response_status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(self.response_body)))
        self.end_headers()
        self.wfile.write(self.response_body)

    def log_message(self, *args):
        pass


@pytest.fixture
def jev_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _JevHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield "http://127.0.0.1:%d/audit" % server.server_address[1]
    server.shutdown()
    server.server_close()
    thread.join()


def test_l2_mid_band_jev_deny_via_real_local_server(make_guard, issue_standard, tmp_path, jev_server):
    _JevHandler.response_status = 200
    _JevHandler.response_body = b'{"decision":"deny","reason":"nope","audit_id":"srv"}'
    embedding = CountingEmbedding({"delete every row of the session cache": 0.70})
    guard = make_guard(
        tmp_path / "audit.jsonl",
        config=OpGuardConfig(hmac_secret=b"k" * 32, l2_timeout_s=2.0),
        embedding=embedding,
        jev=HttpJevAuditor(jev_server),
    )
    ticket = issue_standard(guard)
    result = guard.handle(ticket, build_call("mcp", "delete every row of the session cache"))
    assert result.decision == "deny"
    assert result.layer == "L2"
    assert result.audit["jev"]["outcome"] == "deny"


def test_l2_mid_band_jev_malformed_body_fails_closed(make_guard, issue_standard, tmp_path, jev_server):
    _JevHandler.response_status = 200
    _JevHandler.response_body = b"not a json payload"
    embedding = CountingEmbedding({"delete every row of the session cache": 0.70})
    guard = make_guard(
        tmp_path / "audit.jsonl",
        config=OpGuardConfig(hmac_secret=b"k" * 32, l2_timeout_s=2.0),
        embedding=embedding,
        jev=HttpJevAuditor(jev_server),
    )
    ticket = issue_standard(guard)
    result = guard.handle(ticket, build_call("mcp", "delete every row of the session cache"))
    assert result.decision == "deny"
    assert result.layer == "L2"
    assert result.audit["jev"]["outcome"] == "parse_error"


# --------------------------------------------------------------------------- L3


def test_classifying_sandbox_only_labels_and_does_not_execute(tmp_path):
    workspace = str(tmp_path)
    sbx = ClassifyingSandbox(workspace_roots=(workspace,))
    call = ToolCall("fs.write", ToolKind.FS, {"op": "write", "path": f"{workspace}/x.txt", "content": "hi"})
    report = sbx.run(call, timeout_s=2.0, resources=("fs:*",))
    assert report.clean is True
    assert report.effects == ()
    assert not (tmp_path / "x.txt").exists()  # nothing was actually written

    destructive = ToolCall("mcp.tool", ToolKind.MCP, {"command": "wipe every row without a filter"})
    report2 = sbx.run(destructive, timeout_s=2.0, resources=("mcp:*",))
    assert report2.clean is False
    assert "destructive_intent" in report2.effects


def test_scripted_sandbox_sleep_triggers_timeout_fail_closed(make_guard, issue_standard, secret, tmp_path):
    embedding = CountingEmbedding({"rebuild the archive index for one shard": 0.62})
    jev = CountingJev(decision="gray", reason="jev gray")
    sandbox = ScriptedSandbox(_clean_report(), sleep_s=0.5)
    guard = make_guard(
        tmp_path / "audit.jsonl",
        config=OpGuardConfig(hmac_secret=secret, sandbox_timeout_s=0.1),
        embedding=embedding,
        jev=jev,
        sandbox=sandbox,
    )
    ticket = issue_standard(guard)
    result = guard.handle(ticket, build_call("mcp", "rebuild the archive index for one shard"))
    assert result.decision == "deny"
    assert result.layer == "L3"
    assert "timeout" in result.reason


@pytest.fixture
def fixed_workdir(tmp_path, monkeypatch):
    import opguard.policy.sandbox as sb

    from contextlib import contextmanager

    workdir = tmp_path / "sbx"
    workdir.mkdir()

    @contextmanager
    def _tmp(prefix="opguard-sbx-"):
        yield str(workdir)

    monkeypatch.setattr(sb.tempfile, "TemporaryDirectory", _tmp)
    return workdir


def test_subprocess_sandbox_fs_write_read_delete_real_effects(fixed_workdir):
    sbx = SubprocessSandbox()
    write = sbx.run(
        ToolCall("fs.write", ToolKind.FS, {"op": "write", "path": "notes/a.md", "content": "hello sandbox"}),
        timeout_s=2.0,
        resources=(),
    )
    assert write.clean is True
    written = fixed_workdir / "notes" / "a.md"
    assert written.read_text(encoding="utf-8") == "hello sandbox"

    read = sbx.run(
        ToolCall("fs.read", ToolKind.FS, {"op": "read", "path": "notes/a.md", "content": ""}),
        timeout_s=2.0,
        resources=(),
    )
    assert read.clean is True

    delete = sbx.run(
        ToolCall("fs.delete", ToolKind.FS, {"op": "delete", "path": "notes/a.md", "content": ""}),
        timeout_s=2.0,
        resources=(),
    )
    assert delete.clean is True
    assert not written.exists()


@pytest.mark.skipif(os.name != "nt", reason="drive-absolute path escape is Windows-specific here")
def test_subprocess_sandbox_fs_path_escape_is_refused(fixed_workdir):
    sbx = SubprocessSandbox()
    escaped = str(fixed_workdir.resolve().parent / "escaped.txt")
    report = sbx.run(
        ToolCall("fs.write", ToolKind.FS, {"op": "write", "path": escaped, "content": "x"}),
        timeout_s=2.0,
        resources=(),
    )
    assert report.clean is False
    assert "path_escape" in report.effects


def test_subprocess_sandbox_shell_whitelist_real_execution():
    sbx = SubprocessSandbox()
    report = sbx.run(
        ToolCall("shell.exec", ToolKind.SHELL, {"command": "hostname"}),
        timeout_s=2.0,
        resources=(),
    )
    assert report.clean is True
    stdout = report.detail.split("stdout=", 1)[1]
    assert stdout.strip() != ""


def test_subprocess_sandbox_shell_non_whitelist_is_refused():
    sbx = SubprocessSandbox()
    report = sbx.run(
        ToolCall("shell.exec", ToolKind.SHELL, {"command": "rm tmp.txt"}),
        timeout_s=2.0,
        resources=(),
    )
    assert report.clean is False
    assert "whitelist_refused" in report.effects


def test_subprocess_sandbox_shell_pipe_and_redirect_are_refused():
    sbx = SubprocessSandbox()
    pipe = sbx.run(
        ToolCall("shell.exec", ToolKind.SHELL, {"command": "hostname | findstr x"}),
        timeout_s=2.0,
        resources=(),
    )
    assert pipe.clean is False
    assert "shell_structure_refused" in pipe.effects

    redirect = sbx.run(
        ToolCall("shell.exec", ToolKind.SHELL, {"command": "echo hi > out.txt"}),
        timeout_s=2.0,
        resources=(),
    )
    assert redirect.clean is False
    assert "shell_structure_refused" in redirect.effects


def test_subprocess_sandbox_shell_absolute_path_argument_is_refused():
    sbx = SubprocessSandbox()
    report = sbx.run(
        ToolCall("shell.exec", ToolKind.SHELL, {"command": "hostname /tmp"}),
        timeout_s=2.0,
        resources=(),
    )
    assert report.clean is False
    assert "absolute_path" in report.effects


@pytest.mark.parametrize("kind", ["sql", "http"])
def test_subprocess_sandbox_sql_and_http_are_unverifiable(kind):
    sbx = SubprocessSandbox()
    if kind == "sql":
        call = ToolCall("sql.query", ToolKind.SQL, {"statement": "SELECT 1"})
    else:
        call = ToolCall("http.request", ToolKind.HTTP, {"method": "GET", "url": "https://example.com"})
    report = sbx.run(call, timeout_s=2.0, resources=())
    assert report.clean is False
    assert "unverifiable_kind" in report.effects


def test_normalize_path_collapses_dotdot_traversal():
    # Documented observation: ../.. inside a relative path collapses instead of escaping.
    assert normalize_path("../../etc/passwd") == "etc/passwd"
    assert normalize_path("C:/Windows/System32") == "C:/Windows/System32"


# ------------------------------------------------------------------ Windows L1


def test_windows_system_path_write_is_hard_denied(make_guard, issue_standard, tmp_path):
    guard = make_guard(tmp_path / "audit.jsonl")
    ticket = issue_standard(guard)
    result = guard.handle(ticket, build_call("fs", "write C:/Windows/System32/drivers/etc/hosts"))
    assert result.decision == "deny"
    assert result.layer == "L1"
    assert "system path" in result.reason


def test_windows_program_files_delete_with_backslash_is_hard_denied(make_guard, issue_standard, tmp_path):
    guard = make_guard(tmp_path / "audit.jsonl")
    ticket = issue_standard(guard)
    result = guard.handle(ticket, build_call("fs", "delete D:\\Program Files (x86)\\app\\bin.exe"))
    assert result.decision == "deny"
    assert result.layer == "L1"
    assert "system path" in result.reason


def test_windows_drive_root_is_not_writable(make_guard, issue_standard, tmp_path):
    guard = make_guard(tmp_path / "audit.jsonl")
    ticket = issue_standard(guard)
    result = guard.handle(ticket, build_call("fs", "write C:"))
    assert result.decision == "deny"
    assert result.layer == "L1"


def test_workspace_path_is_not_false_positived_by_system_roots(make_guard, issue_standard, tmp_path):
    guard = make_guard(tmp_path / "audit.jsonl")
    ticket = issue_standard(guard)
    result = guard.handle(ticket, build_call("fs", "write /workspace/notes/x.md"))
    assert result.decision == "allow"