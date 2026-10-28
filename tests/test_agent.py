import json

import pytest

from cyberai.agent import PlanStore


VALID_RESPONSE = json.dumps({
    "summary": "Review the laptop's security posture.",
    "assumptions": ["The device belongs to the user."],
    "steps": [
        {
            "title": "Review the current status",
            "rationale": "Establish a baseline before changes.",
            "risk": "low",
            "approval_required": False,
            "validation": "Compare the status with Windows Security.",
            "command": "this field must not be retained",
        }
    ],
    "success_criteria": ["The current status is documented."],
    "safety_notes": ["Only assess owned or explicitly authorized systems."],
})


def test_create_plan_stores_only_reviewable_fields(tmp_path):
    store = PlanStore(tmp_path / "plans.json")
    plan = store.create("Review my own Windows laptop", lambda prompt: VALID_RESPONSE)

    assert plan["status"] == "pending_approval"
    assert plan["execution"] == "not_supported"
    assert plan["steps"][0]["approval_required"] is True
    assert "command" not in plan["steps"][0]
    assert store.list()[0]["id"] == plan["id"]


def test_approve_is_manual_only_and_pending_plans_only(tmp_path):
    store = PlanStore(tmp_path / "plans.json")
    plan = store.create("Review my lab", lambda prompt: VALID_RESPONSE)

    reviewed = store.review(plan["id"], "approve")
    assert reviewed["status"] == "approved_for_manual_execution"
    assert reviewed["approval"]["scope"] == "manual_only_no_automated_actions"

    with pytest.raises(ValueError, match="Only pending plans"):
        store.review(plan["id"], "approve")


def test_reject_plan(tmp_path):
    store = PlanStore(tmp_path / "plans.json")
    plan = store.create("Review my lab", lambda prompt: VALID_RESPONSE)

    reviewed = store.review(plan["id"], "reject")
    assert reviewed["status"] == "rejected"


def test_empty_goal_is_rejected(tmp_path):
    store = PlanStore(tmp_path / "plans.json")
    with pytest.raises(ValueError, match="cannot be empty"):
        store.create("  ", lambda prompt: VALID_RESPONSE)


def test_invalid_model_json_is_rejected(tmp_path):
    store = PlanStore(tmp_path / "plans.json")
    with pytest.raises(ValueError, match="valid JSON"):
        store.create("Review my laptop", lambda prompt: "not json")
