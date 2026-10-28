import pytest

from cyberai.response import get_playbook


def test_social_account_playbook_uses_official_recovery_and_warns_against_recovery_scams():
    result = get_playbook("social-account-compromise")
    joined = " ".join(result["steps"]).lower()
    assert "official" in joined
    assert "verification codes" in joined
    assert "does not access accounts" in result["notice"]


def test_supports_windows_and_phishing_scenarios():
    assert get_playbook("windows-suspicious-activity")["steps"]
    assert get_playbook("phishing")["steps"]


def test_rejects_unknown_scenario():
    with pytest.raises(ValueError, match="Unknown incident type"):
        get_playbook("break-into-someone-else-account")
