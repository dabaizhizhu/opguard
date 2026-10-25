"""Minimal .env loader — no third-party dependency.

``load_dotenv`` fills missing keys in ``os.environ`` from a dotenv file.
Existing environment variables are never overwritten.
"""

from __future__ import annotations

import os
from pathlib import Path


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def _parse_line(line: str) -> tuple[str, str] | None:
    raw = line.strip()
    if not raw or raw.startswith("#"):
        return None
    if raw.startswith("export "):
        raw = raw[7:].strip()
    if "=" not in raw:
        return None
    key, _, value = raw.partition("=")
    key = key.strip()
    if not key or not key.replace("_", "").isalnum():
        return None
    value = _strip_quotes(value.strip())
    return key, value


def _candidate_paths(explicit: Path | None) -> list[Path]:
    if explicit is not None:
        return [explicit]
    here = Path(__file__).resolve()
    # .../packages/opguard-core/src/opguard/base/envfile.py
    package_root = here.parents[3]  # packages/opguard-core
    repo_root = here.parents[5] if len(here.parents) > 5 else package_root.parent.parent
    ordered: list[Path] = [
        Path.cwd() / ".env",
        package_root / ".env",
        repo_root / ".env",
    ]
    # de-dupe while preserving order
    seen: set[Path] = set()
    out: list[Path] = []
    for p in ordered:
        try:
            key = p.resolve()
        except OSError:
            key = p
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


def load_dotenv(path: str | Path | None = None) -> Path | None:
    """Load KEY=VALUE pairs into ``os.environ`` without overwriting.

    Searches (when ``path`` is omitted): cwd ``.env``, package root ``.env``,
    then repository root ``.env``. Missing files are ignored (returns ``None``).
    Returns the path that was loaded, or ``None`` if none applied.
    """

    explicit = Path(path) if path is not None else None
    loaded: Path | None = None
    for candidate in _candidate_paths(explicit):
        try:
            if not candidate.is_file():
                continue
            text = candidate.read_text(encoding="utf-8")
        except OSError:
            continue
        for line in text.splitlines():
            parsed = _parse_line(line)
            if parsed is None:
                continue
            key, value = parsed
            if key in os.environ:
                continue
            os.environ[key] = value
        loaded = candidate
        # first existing file wins; do not merge multiple .env files
        break
    return loaded


__all__ = ["load_dotenv"]
