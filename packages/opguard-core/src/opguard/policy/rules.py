"""Default policy plugin.

Patterns name destructive operations (drop, truncate, unscoped delete, system
path removal, package removal). They are detectors, not procedures.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlparse

from opguard.base.types import ToolCall, ToolKind

PROTOTYPES: tuple[str, ...] = (
    "wipe every row without a filter",
    "delete the entire database",
    "drop all tables",
    "remove the root filesystem",
    "write into the system configuration path",
    "uninstall system packages",
    "delete system jar archives",
    "清空全表数据",
    "删除整个数据库",
    "删除系统根目录",
    "写入系统配置路径",
    "卸载系统软件包",
    "删除系统 jar 包",
)

SYSTEM_ROOTS: tuple[str, ...] = (
    "/bin",
    "/sbin",
    "/usr",
    "/lib",
    "/lib64",
    "/etc",
    "/boot",
    "/sys",
    "/proc",
    "/dev",
    "/root",
    "/opt",
    "/var",
    "/System",
    "/Applications",
)

# Windows 系统目录（驱动器字母无关的第二段目录名），盘符绝对路径的破坏必须进 L1 硬拒。
_WIN_ROOTS: frozenset[str] = frozenset(
    {
        "windows",
        "winnt",
        "program files",
        "program files (x86)",
        "programdata",
        "users",
        "system volume information",
        "$recycle.bin",
    }
)

_DRIVE = re.compile(r"^[a-zA-Z]:$")

_DROP = re.compile(r"\bdrop\s+(database|schema|table)\b", re.IGNORECASE)
_TRUNCATE = re.compile(r"\btruncate\b", re.IGNORECASE)
_ALTER_DROP = re.compile(r"\balter\s+table\b[\s\S]*\bdrop\b", re.IGNORECASE)
_DELETE_FROM = re.compile(r"^\s*delete\s+from\s+[a-z_][\w.]*\b", re.IGNORECASE)
_UPDATE_SET = re.compile(r"^\s*update\s+[a-z_][\w.]*\s+set\b", re.IGNORECASE)
_CREATE_ACCOUNT = re.compile(r"^\s*create\s+(user|role)\b", re.IGNORECASE)
_PRIVILEGE = re.compile(r"\b(superuser|createrole|createdb)\b|\bgrant\s+all\b", re.IGNORECASE)
_SELECTISH = re.compile(r"^\s*(select|show|explain|describe|desc|with)\b", re.IGNORECASE)
_TABLE = re.compile(r"\b(?:from|join|update|into|table)\s+([a-z_][\w.]*)", re.IGNORECASE)
_PKG = re.compile(
    r"\b(apt-get|apt|yum|dnf|apk|pacman)\s+(remove|purge|erase|del|uninstall)\b",
    re.IGNORECASE,
)
_MKFS = re.compile(r"\bmkfs(\.[a-z0-9]+)?\b", re.IGNORECASE)
_DD_DEV = re.compile(r"\bdd\b[\s\S]*\bof=/dev/", re.IGNORECASE)
_FIND_DELETE = re.compile(r"\bfind\b[\s\S]*-delete\b", re.IGNORECASE)
_URL = re.compile(r"https?://[^\s'\"|;]+", re.IGNORECASE)
_READ_BIN = frozenset({"cat", "ls", "head", "tail", "stat", "pwd", "rg", "grep", "wc", "find"})


@dataclass(frozen=True)
class Classification:
    """What the default plugin believes about one call. ``hard_deny`` is L1 only."""

    hard_deny: str | None
    capability: str | None
    targets: tuple[str, ...]
    effects: tuple[str, ...]


class PolicyPlugin(Protocol):
    """Extension point for regex families, prototypes, and effect tags.

    A host may add patterns. This repository does not ship attack content.
    """

    name: str

    def prototypes(self) -> tuple[str, ...]:
        """Destructive-intent phrases used as vector prototypes."""

    def classify(
        self,
        call: ToolCall,
        *,
        workspace_roots: tuple[str, ...],
        resources: tuple[str, ...] = (),
    ) -> Classification:
        """Classify a call. Do not execute it."""


def action_text(call: ToolCall) -> str:
    args = call.args
    if call.kind is ToolKind.SQL:
        return str(args.get("statement", ""))
    if call.kind is ToolKind.SHELL:
        return str(args.get("command", ""))
    if call.kind is ToolKind.HTTP:
        return f"{args.get('method', '')} {args.get('url', '')}".strip()
    if call.kind is ToolKind.FS:
        return f"{args.get('op', '')} {args.get('path', '')}".strip()
    if call.kind is ToolKind.MCP:
        return str(args.get("command", ""))
    parts = [str(value) for value in args.values() if isinstance(value, str)]
    return " ".join(parts)


def normalize_path(path: str) -> str:
    raw = path.replace("\\", "/")
    absolute = raw.startswith("/")
    parts: list[str] = []
    for part in raw.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    if absolute:
        return "/" + "/".join(parts)
    return "/".join(parts)


def is_under(path: str, root: str) -> bool:
    current = normalize_path(path)
    base = normalize_path(root).rstrip("/") or "/"
    if base == "/":
        return current.startswith("/")
    return current == base or current.startswith(base + "/")


def is_system_path(path: str, workspace_roots: tuple[str, ...]) -> bool:
    current = normalize_path(path)
    if any(is_under(current, root) for root in workspace_roots):
        return False
    if current == "/":
        return True
    if any(is_under(current, root) for root in SYSTEM_ROOTS):
        return True
    # Windows：按驱动器字母无关的第二段目录名判定（如 C:/Windows、D:/Program Files），
    # 盘符根（如 "C:"）本身也视为系统路径。
    parts = [part for part in current.split("/") if part]
    if parts and _DRIVE.fullmatch(parts[0]):
        if len(parts) == 1:
            return True
        return parts[1].casefold() in _WIN_ROOTS
    return False


def resource_covers(granted: str, needed: str) -> bool:
    if granted == "*" or granted == needed:
        return True
    if granted.endswith("*") and needed.startswith(granted[:-1]):
        return True
    if granted.startswith("fs:") and needed.startswith("fs:"):
        root = granted[3:]
        path = needed[3:]
        if root == "*":
            return True
        return is_under(path, root)
    if granted.startswith("http:") and needed.startswith("http:"):
        allowed = granted[5:].lower()
        host = needed[5:].lower()
        if allowed == "*":
            return True
        return host == allowed or host.endswith("." + allowed)
    return False


def scope_allows(resources: tuple[str, ...], targets: tuple[str, ...]) -> bool:
    if not targets:
        return True
    return all(any(resource_covers(granted, target) for granted in resources) for target in targets)


def intent_is_malicious(intent: str) -> bool:
    if not intent.strip():
        return False
    if sql_hard_reason(intent) or shell_hard_reason(intent, ("/workspace",)):
        return True
    folded = intent.casefold()
    return any(prototype.casefold() in folded for prototype in PROTOTYPES)


def neutralize_sql(sql: str) -> str:
    """Drop comments and string contents so labels cannot impersonate statements."""

    out: list[str] = []
    index = 0
    length = len(sql)
    while index < length:
        if sql.startswith("--", index):
            newline = sql.find("\n", index)
            index = length if newline < 0 else newline
            continue
        if sql.startswith("/*", index):
            end = sql.find("*/", index + 2)
            index = length if end < 0 else end + 2
            continue
        if sql[index] == "'":
            index += 1
            while index < length:
                if sql.startswith("''", index):
                    index += 2
                    continue
                if sql[index] == "'":
                    index += 1
                    break
                index += 1
            out.append(" '' ")
            continue
        out.append(sql[index])
        index += 1
    return "".join(out)


def _split_sql(neutralized: str) -> list[str]:
    return [part.strip() for part in neutralized.split(";") if part.strip()]


def _where_clause(statement: str) -> str | None:
    match = re.search(r"\bwhere\b", statement, re.IGNORECASE)
    if not match:
        return None
    tail = statement[match.end() :]
    tail = re.split(r"\b(returning|limit|order\s+by|group\s+by)\b", tail, maxsplit=1, flags=re.IGNORECASE)[0]
    return tail.strip().rstrip(";")


def _tautology(where: str) -> bool:
    checks = (
        r"^\s*1\s*=\s*1\s*$",
        r"^\s*true\s*$",
        r"^\s*1\s*$",
        r"\bor\s+1\s*=\s*1\b",
        r"\bor\s+true\b",
        r"\b1\s*=\s*1\b",
        r"^\s*([a-z_][\w]*)\s*=\s*\1\s*$",
        r"^\s*'([^']*)'\s*=\s*'\1'\s*$",
        r"^\s*(\d+)\s*=\s*\1\s*$",
    )
    return any(re.search(pattern, where, re.IGNORECASE) for pattern in checks)


def sql_tables(neutralized: str) -> tuple[str, ...]:
    found = []
    for match in _TABLE.finditer(neutralized):
        name = match.group(1)
        if name.lower() in {"select", "where", "set"}:
            continue
        found.append(name.split(".")[-1])
    return tuple(dict.fromkeys(found))


def sql_hard_reason(text: str) -> str | None:
    neutralized = neutralize_sql(text)
    for statement in _split_sql(neutralized):
        reason = _sql_statement_hard(statement)
        if reason:
            return reason
    return None


def _sql_statement_hard(statement: str) -> str | None:
    if _DROP.search(statement):
        return "drop database, schema, or table"
    if _TRUNCATE.search(statement):
        return "truncate"
    if _ALTER_DROP.search(statement):
        return "alter table drop"
    if _PRIVILEGE.search(statement) and (
        _CREATE_ACCOUNT.search(statement) or re.match(r"^\s*alter\s+(user|role)\b", statement, re.IGNORECASE) or re.match(r"^\s*grant\b", statement, re.IGNORECASE)
    ):
        return "privileged account or grant all"
    if _DELETE_FROM.search(statement) or _UPDATE_SET.search(statement):
        where = _where_clause(statement)
        if where is None:
            return "delete or update without where"
        if _tautology(where):
            return "delete or update with a tautology where"
    return None


def sql_capability(text: str) -> str | None:
    neutralized = neutralize_sql(text)
    parts = _split_sql(neutralized)
    if len(parts) != 1:
        return None
    statement = parts[0]
    if _sql_statement_hard(statement):
        return None
    if _CREATE_ACCOUNT.search(statement):
        return "create_user"
    if _DELETE_FROM.search(statement) or _UPDATE_SET.search(statement):
        return "mutate_scoped"
    if re.match(r"^\s*insert\s+into\b", statement, re.IGNORECASE):
        return "mutate_scoped"
    if _SELECTISH.search(statement):
        return "read"
    return None


def tokenize_shell(command: str) -> list[str]:
    tokens: list[str] = []
    buffer: list[str] = []
    index = 0
    quote: str | None = None
    length = len(command)
    while index < length:
        char = command[index]
        if quote:
            if char == quote:
                quote = None
            else:
                buffer.append(char)
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            index += 1
            continue
        if char in {" ", "\t", "\n"}:
            if buffer:
                tokens.append("".join(buffer))
                buffer = []
            index += 1
            continue
        if command.startswith("||", index) or command.startswith("&&", index) or command.startswith(">>", index):
            if buffer:
                tokens.append("".join(buffer))
                buffer = []
            tokens.append(command[index : index + 2])
            index += 2
            continue
        if char in {"|", ";", "&", ">", "<"}:
            if buffer:
                tokens.append("".join(buffer))
                buffer = []
            tokens.append(char)
            index += 1
            continue
        buffer.append(char)
        index += 1
    if buffer:
        tokens.append("".join(buffer))
    return tokens


def _rm_targets(tokens: list[str]) -> list[str]:
    targets: list[str] = []
    index = 0
    while index < len(tokens):
        if tokens[index] != "rm":
            index += 1
            continue
        index += 1
        while index < len(tokens) and tokens[index].startswith("-") and tokens[index] not in {">", ">>"}:
            if tokens[index] == "--":
                index += 1
                break
            index += 1
        while index < len(tokens) and tokens[index] not in {"|", ";", "||", "&&", "&", ">", ">>", "<"}:
            if not tokens[index].startswith("-"):
                targets.append(tokens[index])
            index += 1
    return targets


def _redirect_targets(tokens: list[str]) -> list[str]:
    targets = []
    for index, token in enumerate(tokens):
        if token in {">", ">>"} and index + 1 < len(tokens):
            targets.append(tokens[index + 1])
    return targets


def shell_hard_reason(command: str, workspace_roots: tuple[str, ...]) -> str | None:
    if _PKG.search(command):
        return "system package removal"
    if _MKFS.search(command) or _DD_DEV.search(command):
        return "block device destroy"
    if _FIND_DELETE.search(command):
        return "find delete"
    tokens = tokenize_shell(command)
    for target in _rm_targets(tokens):
        if target in {"/", "/*", "/**"}:
            return "remove filesystem root"
        path = normalize_path(target)
        if path.endswith(".jar") and is_system_path(path, workspace_roots):
            return "delete system jar"
        if is_system_path(path, workspace_roots):
            return "delete system path"
    for target in _redirect_targets(tokens):
        path = normalize_path(target)
        if is_system_path(path, workspace_roots):
            return "write system path"
    if _copy_to_system(tokens, workspace_roots):
        return "write system path"
    return None


def _copy_to_system(tokens: list[str], workspace_roots: tuple[str, ...]) -> bool:
    index = 0
    while index < len(tokens):
        if tokens[index] not in {"tee", "cp", "mv", "install"}:
            index += 1
            continue
        command = tokens[index]
        index += 1
        operands: list[str] = []
        while index < len(tokens) and tokens[index] not in {"|", ";", "||", "&&", "&", ">", ">>", "<"}:
            if not tokens[index].startswith("-"):
                operands.append(tokens[index])
            index += 1
        if command == "tee":
            candidates = operands
        elif len(operands) >= 2:
            candidates = operands[1:]
        else:
            candidates = []
        for candidate in candidates:
            if is_system_path(normalize_path(candidate), workspace_roots):
                return True
    return False


def _shell_paths(tokens: list[str]) -> list[str]:
    paths = []
    for token in tokens:
        if token.startswith("/") or token.startswith("./") or token.startswith("../"):
            paths.append(normalize_path(token))
    return paths


def shell_capability(command: str, workspace_roots: tuple[str, ...]) -> str | None:
    if shell_hard_reason(command, workspace_roots):
        return None
    tokens = tokenize_shell(command)
    if not tokens:
        return None
    head = tokens[0]
    if head in _READ_BIN and "-delete" not in tokens and "-exec" not in tokens:
        return "read"
    writes = _redirect_targets(tokens) or (head in {"cp", "mv", "tee", "mkdir", "touch", "install"})
    if head == "rm" or writes:
        return "mutate_scoped"
    return None


def shell_targets(command: str, workspace_roots: tuple[str, ...]) -> tuple[str, ...]:
    tokens = tokenize_shell(command)
    paths = _shell_paths(tokens)
    if not paths:
        return ("shell:workspace",)
    tags = []
    for path in paths:
        if any(is_under(path, root) for root in workspace_roots):
            tags.append(f"fs:{path}")
        else:
            tags.append(f"fs:{path}")
    return tuple(dict.fromkeys(tags))


def http_parts(text: str) -> tuple[str, str, str]:
    method, _, rest = text.partition(" ")
    parsed = urlparse(rest.strip())
    return method.upper(), (parsed.hostname or ""), parsed.path or "/"


def _production_host(host: str) -> bool:
    labels = host.lower().split(".")
    return "prod" in labels or "production" in labels


def _collection_destroy(method: str, path: str) -> bool:
    if method not in {"DELETE", "PUT", "PATCH"}:
        return False
    parts = [part for part in path.split("/") if part]
    if not parts:
        return True
    last = parts[-1]
    if last.isdigit() or re.fullmatch(r"[0-9a-fA-F-]{8,}", last):
        return False
    return True


def http_hard_reason(text: str) -> str | None:
    method, host, path = http_parts(text)
    if method in {"DELETE", "PUT", "PATCH"} and _production_host(host):
        return "destructive method on a production host"
    if _collection_destroy(method, path):
        return "collection-level delete or replace"
    return None


def http_capability(text: str) -> str | None:
    if http_hard_reason(text):
        return None
    method, _, path = http_parts(text)
    if method in {"GET", "HEAD"}:
        return "read"
    if method == "POST" and re.search(r"/(users|accounts|principals)(/|$)", path):
        return "create_user"
    if method in {"DELETE", "PATCH", "PUT", "POST"}:
        return "mutate_scoped"
    return None


def http_targets(text: str) -> tuple[str, ...]:
    _, host, _ = http_parts(text)
    if not host:
        return ()
    return (f"http:{host}",)


def fs_hard_reason(text: str, workspace_roots: tuple[str, ...]) -> str | None:
    op, _, path = text.partition(" ")
    if op not in {"write", "delete"} or not path:
        return None
    current = normalize_path(path)
    if op == "delete" and current.endswith(".jar") and is_system_path(current, workspace_roots):
        return "delete system jar"
    if is_system_path(current, workspace_roots):
        return "write or delete system path" if op == "write" else "delete system path"
    return None


def fs_capability(text: str, workspace_roots: tuple[str, ...]) -> str | None:
    if fs_hard_reason(text, workspace_roots):
        return None
    op, _, path = text.partition(" ")
    if not path:
        return None
    if op == "read":
        return "read"
    if op in {"write", "delete"}:
        return "mutate_scoped"
    return None


def prototype_hit(text: str) -> bool:
    folded = text.casefold()
    return any(prototype.casefold() in folded for prototype in PROTOTYPES)


def collect_effects(call: ToolCall, *, workspace_roots: tuple[str, ...], resources: tuple[str, ...]) -> tuple[str, ...]:
    text = action_text(call)
    effects: list[str] = []
    mapping = {
        "drop database, schema, or table": "drop",
        "truncate": "truncate",
        "alter table drop": "drop",
        "delete or update without where": "unscoped_dml",
        "delete or update with a tautology where": "unscoped_dml",
        "privileged account or grant all": "privilege_write",
        "remove filesystem root": "system_path_delete",
        "delete system path": "system_path_delete",
        "delete system jar": "system_jar_delete",
        "write system path": "system_path_write",
        "write or delete system path": "system_path_write",
        "system package removal": "package_removal",
        "block device destroy": "device_destroy",
        "find delete": "system_path_delete",
        "destructive method on a production host": "unauthorized_egress",
        "collection-level delete or replace": "unscoped_dml",
    }
    for reason in (sql_hard_reason(text), shell_hard_reason(text, workspace_roots), http_hard_reason(text) if call.kind is ToolKind.HTTP else None, fs_hard_reason(text, workspace_roots) if call.kind is ToolKind.FS else None):
        if reason and reason in mapping:
            effects.append(mapping[reason])
    if prototype_hit(text):
        effects.append("destructive_intent")
    if resources:
        for match in _URL.finditer(text):
            host = urlparse(match.group(0)).hostname or ""
            if host and not scope_allows(resources, (f"http:{host}",)):
                effects.append("unauthorized_egress")
    return tuple(dict.fromkeys(effects))


class DefaultPolicy:
    """Built-in protection policy. Safe operations stay candidates; hard destroy does not."""

    name = "default-v3"

    def prototypes(self) -> tuple[str, ...]:
        return PROTOTYPES

    def classify(
        self,
        call: ToolCall,
        *,
        workspace_roots: tuple[str, ...],
        resources: tuple[str, ...] = (),
    ) -> Classification:
        text = action_text(call)
        effects = collect_effects(call, workspace_roots=workspace_roots, resources=resources)
        if call.kind is ToolKind.SQL:
            tables = tuple(f"sql:{name}" for name in sql_tables(neutralize_sql(text)))
            return Classification(sql_hard_reason(text), sql_capability(text), tables, effects)
        if call.kind is ToolKind.SHELL:
            return Classification(
                shell_hard_reason(text, workspace_roots),
                shell_capability(text, workspace_roots),
                shell_targets(text, workspace_roots),
                effects,
            )
        if call.kind is ToolKind.HTTP:
            return Classification(http_hard_reason(text), http_capability(text), http_targets(text), effects)
        if call.kind is ToolKind.FS:
            _op, _, path = text.partition(" ")
            target = (f"fs:{normalize_path(path)}",) if path else ()
            return Classification(fs_hard_reason(text, workspace_roots), fs_capability(text, workspace_roots), target, effects)
        # MCP and anything else: concrete command shapes still hard-deny, prose does not.
        hard = sql_hard_reason(text) or shell_hard_reason(text, workspace_roots)
        return Classification(hard, None, ("mcp:*",), effects)
