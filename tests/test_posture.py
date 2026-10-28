import json
import subprocess

import pytest

from cyberai import posture


def test_non_windows_is_reported_as_unsupported(monkeypatch):
    monkeypatch.setattr(posture.platform, "system", lambda: "Linux")
    result = posture.collect_windows_posture()
    assert result["supported"] is False
    assert result["findings"] == []


def test_collects_status_and_flags_disabled_protections(monkeypatch):
    payload = {
        "defender_available": True,
        "antivirus_enabled": True,
        "real_time_protection_enabled": False,
        "firewall_profiles": [
            {"name": "Domain", "enabled": True},
            {"name": "Private", "enabled": False},
        ],
        "windows_update_service": "Running",
    }
    monkeypatch.setattr(posture.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        posture.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 0, stdout=json.dumps(payload), stderr=""
        ),
    )

    result = posture.collect_windows_posture()

    assert result["supported"] is True
    assert result["mode"] == "read-only"
    assert len(result["findings"]) == 2
    assert "real-time protection" in result["findings"][0]
    assert "Private" in result["findings"][1]


def test_powershell_timeout_becomes_clear_error(monkeypatch):
    monkeypatch.setattr(posture.platform, "system", lambda: "Windows")

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("powershell.exe", 15)

    monkeypatch.setattr(posture.subprocess, "run", timeout)
    with pytest.raises(RuntimeError, match="read-only Windows check"):
        posture.collect_windows_posture()


def test_only_fixed_powershell_script_is_passed(monkeypatch):
    monkeypatch.setattr(posture.platform, "system", lambda: "Windows")
    captured = {}

    def fake_run(args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(args, 0, stdout='{"firewall_profiles":[]}', stderr="")

    monkeypatch.setattr(posture.subprocess, "run", fake_run)
    posture.collect_windows_posture()

    assert captured["args"][0] == "powershell.exe"
    assert captured["args"][-2] == "-Command"
    assert "Get-MpComputerStatus" in captured["args"][-1]
    assert captured["kwargs"]["shell"] if "shell" in captured["kwargs"] else True
    assert captured["kwargs"]["timeout"] == 15
