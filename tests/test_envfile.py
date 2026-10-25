"""load_dotenv: no overwrite, quotes, missing file ok."""

from __future__ import annotations

import os
from pathlib import Path

from opguard.base.envfile import load_dotenv


def test_load_dotenv_sets_missing_keys(tmp_path, monkeypatch):
    env_path = tmp_path / ".env"
    env_path.write_text(
        "# comment\n"
        "OPGUARD_HMAC_SECRET=from-file\n"
        "OPGUARD_JEV_URL='http://jev.local/v1/audit'\n"
        'OPENAI_API_KEY="sk-quoted"\n'
        "\n"
        "IGNORED_NO_EQ\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("OPGUARD_HMAC_SECRET", raising=False)
    monkeypatch.delenv("OPGUARD_JEV_URL", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    loaded = load_dotenv(env_path)
    assert loaded == env_path
    assert os.environ["OPGUARD_HMAC_SECRET"] == "from-file"
    assert os.environ["OPGUARD_JEV_URL"] == "http://jev.local/v1/audit"
    assert os.environ["OPENAI_API_KEY"] == "sk-quoted"


def test_load_dotenv_does_not_overwrite(tmp_path, monkeypatch):
    env_path = tmp_path / ".env"
    env_path.write_text("OPGUARD_HMAC_SECRET=from-file\n", encoding="utf-8")
    monkeypatch.setenv("OPGUARD_HMAC_SECRET", "already-set")

    assert load_dotenv(env_path) == env_path
    assert os.environ["OPGUARD_HMAC_SECRET"] == "already-set"


def test_load_dotenv_missing_file_silent(tmp_path):
    missing = tmp_path / "no-such.env"
    assert load_dotenv(missing) is None
