from cyberai.defense import analyze_log

def test_detects_indicators_only_in_logs_folder(tmp_path):
    (tmp_path / "sample.log").write_text(
        "normal login\n../secret.txt\nPowerShell -EncodedCommand demo\n",
        encoding="utf-8",
    )
    report = analyze_log(tmp_path, "sample.log")
    assert report["lines_with_indicators"] == 2
    assert "do not prove" in report["warning"]

def test_rejects_path_traversal_filename(tmp_path):
    try:
        analyze_log(tmp_path, "../outside.log")
    except ValueError:
        pass
    else:
        raise AssertionError("Expected unsafe filename to be rejected")
