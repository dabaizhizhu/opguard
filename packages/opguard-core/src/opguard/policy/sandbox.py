"""Sandbox backends.

Hard denies never reach this module. The default backend classifies the call
string and returns an effect report; it does NOT execute the call and does not
fulfill L3's empirical verification purpose. The repository also ships
:class:`SubprocessSandbox`, which really executes a narrow read-only whitelist
and detects effects from the real outcome — the honest L3 for evaluation.
"""

from __future__ import annotations

import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Protocol

from opguard.policy import DefaultPolicy, action_text, collect_effects
from opguard.base.types import EffectReport, ToolCall, ToolKind
from opguard.policy.rules import normalize_path, tokenize_shell


class SandboxBackend(Protocol):
    """Run a candidate in isolation and report effects. Implementations must not touch production."""

    def run(self, call: ToolCall, *, timeout_s: float, resources: tuple[str, ...]) -> EffectReport:
        """Return an effect report within ``timeout_s``."""


class ClassifyingSandbox:
    """Mock sandbox. Tags destructive shapes in the fixture string and returns.

    It does NOT execute the call, so it cannot fulfill L3's purpose (empirical
    execution + post-execution effect detection). Production must inject a
    backend that isolates the call and observes real effects, e.g.
    ``SubprocessSandbox`` for safe-command evaluation or a Docker/nsjail
    backend for isolation.
    """

    name = "classifying-mock"

    def __init__(self, workspace_roots: tuple[str, ...] = ("/workspace",)) -> None:
        self.workspace_roots = workspace_roots
        self.policy = DefaultPolicy()

    def run(self, call: ToolCall, *, timeout_s: float, resources: tuple[str, ...]) -> EffectReport:
        del timeout_s
        started = time.perf_counter()
        effects = collect_effects(call, workspace_roots=self.workspace_roots, resources=resources)
        elapsed = (time.perf_counter() - started) * 1000.0
        clean = not effects
        detail = "clean" if clean else "observed " + ",".join(effects)
        return EffectReport(
            sandbox_id=f"sbx-{uuid.uuid4().hex[:8]}",
            effects=effects,
            clean=clean,
            timed_out=False,
            elapsed_ms=elapsed,
            detail=detail,
        )


class ScriptedSandbox:
    """Test double with a predetermined report. ``sleep_s`` exercises the fail-closed deadline."""

    def __init__(self, report: EffectReport, *, sleep_s: float = 0.0) -> None:
        self.report = report
        self.sleep_s = sleep_s
        self.calls = 0

    def run(self, call: ToolCall, *, timeout_s: float, resources: tuple[str, ...]) -> EffectReport:
        del call, timeout_s, resources
        self.calls += 1
        if self.sleep_s:
            time.sleep(self.sleep_s)
        return self.report


class SubprocessSandbox:
    """Real-execution sandbox for evaluation and acceptance testing.

    Unlike :class:`ClassifyingSandbox`, this backend really executes the call
    and detects effects from the real outcome:

    * ``shell`` / ``mcp`` calls are replayed via ``subprocess`` in list form
      (no shell interpretation) inside a disposable working directory, limited
      to a strict read-only whitelist (:attr:`SAFE_BINS`).
    * ``fs`` calls (read/write/delete) are performed for real inside the same
      disposable directory, and any path escaping it is refused.

    Commands outside the whitelist, pipes/redirects, absolute-path arguments,
    non-zero exits, and fs escapes are treated as unclean (deny) — that is the
    post-execution detection. ``sql`` / ``http`` calls cannot be empirically
    verified by subprocess execution and are reported unclean (fail-closed).

    This is NOT an isolation boundary: it runs with the host account. Never
    extend the whitelist with mutating or networked commands. For production
    isolation (Docker, nsjail, Firecracker, ...) implement
    :class:`SandboxBackend` on your isolation platform.

    Windows 注意：``SAFE_BINS`` 多为 POSIX 常用只读工具，Windows 上多数不在
    PATH 中。探不到可执行文件时按 spawn 失败处理（fail-closed 判为 unclean），
    真实执行演示请使用目标系统上实际存在的白名单工具（如 ``hostname``）。
    """

    name = "subprocess-verify"

    SAFE_BINS: frozenset[str] = frozenset(
        {"echo", "printf", "true", "false", "ls", "cat", "head", "tail",
         "wc", "pwd", "stat", "grep", "hostname"}
    )
    _META_TOKENS: frozenset[str] = frozenset({"|", "||", "&&", ";", "&", ">", ">>", "<"})

    def __init__(self, max_output_bytes: int = 8192) -> None:
        self.max_output_bytes = max_output_bytes

    # -- public API ---------------------------------------------------------

    def run(self, call: ToolCall, *, timeout_s: float, resources: tuple[str, ...]) -> EffectReport:
        del resources
        kind = call.kind
        if kind is ToolKind.SHELL or kind is ToolKind.MCP:
            return self._run_command(call, timeout_s)
        if kind is ToolKind.FS:
            return self._run_fs(call, timeout_s)
        return self._unverifiable(call.kind.value)

    # -- helpers -------------------------------------------------------------

    def _report(
        self,
        *,
        effects: tuple[str, ...] = (),
        clean: bool,
        detail: str,
        started: float,
    ) -> EffectReport:
        elapsed = (time.perf_counter() - started) * 1000.0
        return EffectReport(
            sandbox_id=f"sbx-{uuid.uuid4().hex[:8]}",
            effects=effects,
            clean=clean,
            timed_out=False,
            elapsed_ms=elapsed,
            detail=detail,
        )

    def _clip(self, text: str) -> str:
        text = text.strip()
        if len(text) > self.max_output_bytes:
            text = text[: self.max_output_bytes] + "..."
        return text

    def _run_command(self, call: ToolCall, timeout_s: float) -> EffectReport:
        started = time.perf_counter()
        text = action_text(call)
        tokens = tokenize_shell(text)
        if not tokens:
            return self._report(effects=("empty_command",), clean=False,
                                detail="no command to execute", started=started)
        meta = self._META_TOKENS & set(tokens)
        if meta:
            return self._report(effects=("shell_structure_refused",), clean=False,
                                detail=f"refused to replay shell structure: {sorted(meta)}", started=started)
        head = tokens[0].rsplit("/", 1)[-1].lower()
        if head not in self.SAFE_BINS:
            return self._report(effects=("whitelist_refused",), clean=False,
                                detail=f"command '{head}' is outside the read-only whitelist", started=started)
        if any(tok.startswith("/") for tok in tokens[1:]):
            return self._report(effects=("absolute_path",), clean=False,
                                detail="absolute-path arguments are not replayed", started=started)
        with tempfile.TemporaryDirectory(prefix="opguard-sbx-") as workdir:
            try:
                completed = subprocess.run(
                    tokens, cwd=workdir, capture_output=True, timeout=timeout_s, check=False, text=True
                )
            except subprocess.TimeoutExpired:
                return self._report(effects=("subprocess_timeout",), clean=False,
                                    detail="command did not finish before the deadline", started=started)
            except OSError as exc:
                return self._report(effects=("spawn_error",), clean=False,
                                    detail=f"{type(exc).__name__}: {exc}", started=started)
        stdout = self._clip(completed.stdout)
        if completed.returncode != 0:
            stderr = self._clip(completed.stderr)
            return self._report(effects=("exit_nonzero",), clean=False,
                                detail=f"rc={completed.returncode}; stderr={stderr}", started=started)
        return self._report(clean=True,
                            detail=f"executed '{head}' in disposable dir; stdout={stdout}", started=started)

    def _run_fs(self, call: ToolCall, timeout_s: float) -> EffectReport:
        del timeout_s
        started = time.perf_counter()
        op = str(call.args.get("op", "")).lower()
        path = str(call.args.get("path", ""))
        content = str(call.args.get("content", ""))
        with tempfile.TemporaryDirectory(prefix="opguard-sbx-") as workdir:
            base = Path(workdir).resolve()
            target = (base / normalize_path(path).lstrip("/")).resolve()
            if not (target == base or base in target.parents):
                return self._report(effects=("path_escape",), clean=False,
                                    detail=f"fs path escapes the disposable root: {path}", started=started)
            try:
                if op == "read":
                    target.read_bytes()
                elif op == "write":
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(content, encoding="utf-8")
                elif op == "delete":
                    target.unlink()
                else:
                    return self._report(effects=("fs_op_unverified",), clean=False,
                                        detail=f"fs op '{op}' cannot be replayed", started=started)
            except FileNotFoundError:
                return self._report(effects=("fs_target_missing",), clean=False,
                                    detail=f"{op} target does not exist inside the disposable root", started=started)
            except OSError as exc:
                return self._report(effects=("fs_op_error",), clean=False,
                                    detail=f"{type(exc).__name__}: {exc}", started=started)
        return self._report(clean=True,
                            detail=f"fs {op} replayed inside disposable dir; no destructive effect", started=started)

    def _unverifiable(self, kind: str) -> EffectReport:
        started = time.perf_counter()
        return self._report(
            effects=("unverifiable_kind",), clean=False,
            detail=(f"kind '{kind}' cannot be empirically verified by subprocess execution; "
                    "inject a real backend (database/network sandbox) or keep fail-closed"),
            started=started,
        )


def run_with_deadline(
    backend: SandboxBackend,
    call: ToolCall,
    *,
    timeout_s: float,
    resources: tuple[str, ...],
) -> EffectReport:
    """Enforce the sandbox deadline even if the backend ignores it."""

    box: dict[str, object] = {}
    started = time.perf_counter()

    def target() -> None:
        try:
            box["report"] = backend.run(call, timeout_s=timeout_s, resources=resources)
        except Exception as exc:  # noqa: BLE001 — sandbox faults fail closed
            box["error"] = exc

    worker = threading.Thread(target=target, daemon=True)
    worker.start()
    worker.join(timeout_s)
    elapsed = (time.perf_counter() - started) * 1000.0
    if worker.is_alive():
        return EffectReport(
            sandbox_id="timeout",
            effects=("timeout",),
            clean=False,
            timed_out=True,
            elapsed_ms=elapsed,
            detail="sandbox timeout fail-closed",
        )
    if "error" in box:
        return EffectReport(
            sandbox_id="error",
            effects=("sandbox_error",),
            clean=False,
            timed_out=False,
            elapsed_ms=elapsed,
            detail=type(box["error"]).__name__,
        )
    report = box["report"]
    if not isinstance(report, EffectReport):
        return EffectReport(
            sandbox_id="error",
            effects=("sandbox_error",),
            clean=False,
            timed_out=False,
            elapsed_ms=elapsed,
            detail="sandbox returned nothing",
        )
    return report
