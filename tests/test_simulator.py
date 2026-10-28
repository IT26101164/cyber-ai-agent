import pytest

from cyberai.simulator import simulate


@pytest.mark.parametrize("scenario", [
    "phishing",
    "suspicious-powershell",
    "account-takeover",
    "ransomware-warning",
])
def test_scenarios_are_synthetic_and_include_defenses(scenario):
    result = simulate(scenario)
    assert result["mode"] == "synthetic-only"
    assert result["indicators"]
    assert result["recommended_defenses"]
    assert "No attack was run" in result["execution"]


def test_rejects_unknown_simulation():
    with pytest.raises(ValueError, match="Unknown simulation"):
        simulate("real-account-hack")
