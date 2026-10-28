import json

import pytest

from cyberai.forge import CapabilityForge


VALID_RESPONSE = json.dumps({
    "summary": "A small security report helper.",
    "files": [
        {"name": "README.md", "content": "# Draft capability\nReview before use.\n"},
        {"name": "report_helper.py", "content": "def format_report(title):\n    return title.strip()\n"},
    ],
    "review_notes": ["Review the generated Python before using it."],
})


def test_forge_does_not_write_files_before_approval(tmp_path):
    forge = CapabilityForge(tmp_path / "data" / "forge.json", tmp_path / "generated")
    proposal = forge.create("Create a local report helper", lambda prompt: VALID_RESPONSE)

    assert proposal["status"] == "pending_approval"
    assert not (tmp_path / "generated" / proposal["id"]).exists()


def test_approval_writes_only_to_staging_and_never_executes(tmp_path):
    forge = CapabilityForge(tmp_path / "data" / "forge.json", tmp_path / "generated")
    proposal = forge.create("Create a local report helper", lambda prompt: VALID_RESPONSE)

    result = forge.review(proposal["id"], "approve")
    out = tmp_path / "generated" / proposal["id"]

    assert result["status"] == "built_draft_requires_review"
    assert (out / "README.md").exists()
    assert (out / "report_helper.py").exists()
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["execution"] == "never_automatically_executed"
    assert manifest["integration"] == "requires_separate_manual_review"


def test_reject_does_not_write_files(tmp_path):
    forge = CapabilityForge(tmp_path / "data" / "forge.json", tmp_path / "generated")
    proposal = forge.create("Create a report helper", lambda prompt: VALID_RESPONSE)

    result = forge.review(proposal["id"], "reject")
    assert result["status"] == "rejected"
    assert not (tmp_path / "generated" / proposal["id"]).exists()


@pytest.mark.parametrize("name", ["../escape.py", "subdir/file.py", "setup.py", "__init__.py", "run.ps1", "evil.exe"])
def test_disallowed_file_names_and_types_are_rejected(tmp_path, name):
    forge = CapabilityForge(tmp_path / "data" / "forge.json", tmp_path / "generated")
    response = json.dumps({"summary": "bad", "files": [{"name": name, "content": "text"}]})

    with pytest.raises(ValueError):
        forge.create("Test a draft", lambda prompt: response)


def test_model_output_with_too_many_files_is_rejected(tmp_path):
    forge = CapabilityForge(tmp_path / "data" / "forge.json", tmp_path / "generated")
    response = json.dumps({
        "files": [{"name": f"file{i}.txt", "content": "x"} for i in range(4)]
    })

    with pytest.raises(ValueError, match="at most"):
        forge.create("Test a draft", lambda prompt: response)


def test_empty_goal_is_rejected(tmp_path):
    forge = CapabilityForge(tmp_path / "data" / "forge.json", tmp_path / "generated")
    with pytest.raises(ValueError, match="cannot be empty"):
        forge.create(" ", lambda prompt: VALID_RESPONSE)
