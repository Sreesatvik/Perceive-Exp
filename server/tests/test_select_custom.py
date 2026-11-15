"""select_custom (custom dropdown) goes through the same server-side gates as `type`."""
import pytest
from unittest.mock import patch
from pydantic import ValidationError

from app.models import ActionInstruction
from app.policy import evaluate_action_risk


def _payload(sensitive=False):
    return {
        "session_id": "select-custom-session",
        "task_instruction": "pick the city",
        "step_number": 1,
        "dom_summary": {
            "url": "http://test.com",
            "elements": [{
                "element_id": "dd-1", "tag": "button", "role": "button", "label_text": "City",
                "is_sensitive": sensitive, "bounding_box": {"x": 1, "y": 1, "w": 10, "h": 10},
            }],
        },
    }


def test_model_accepts_select_custom_and_requires_target_and_value():
    a = ActionInstruction(type="select_custom", target_element_id="dd-1", value="Hyderabad", risk_tier="safe", reasoning_short="r")
    assert a.type == "select_custom"
    with pytest.raises(ValidationError):
        ActionInstruction(type="select_custom", value="x", risk_tier="safe", reasoning_short="r")
    with pytest.raises(ValidationError):
        ActionInstruction(type="select_custom", target_element_id="dd-1", risk_tier="safe", reasoning_short="r")


def test_policy_still_forces_risky_on_sensitive_target_for_select_custom():
    action = {"type": "select_custom", "target_element_id": "dd-1", "value": "[NAME_a1]", "risk_tier": "safe"}
    assert evaluate_action_risk(action, {"is_sensitive": True}) == "risky"
    assert evaluate_action_risk(action, {"is_sensitive": False}) == "safe"


@patch("app.main.generate_action")
def test_analyze_rejects_raw_pii_in_select_custom_value(mock_gen, client):
    mock_gen.return_value = ActionInstruction(
        type="select_custom", target_element_id="dd-1", value="4111111111111111", risk_tier="safe", reasoning_short="r")
    resp = client.post("/analyze", json=_payload())
    assert resp.status_code == 422


@patch("app.main.generate_action")
def test_analyze_accepts_token_value_and_overrides_risk_for_sensitive_target(mock_gen, client):
    mock_gen.return_value = ActionInstruction(
        type="select_custom", target_element_id="dd-1", value="[NAME_a1b2c3]", risk_tier="safe", reasoning_short="r")
    resp = client.post("/analyze", json=_payload(sensitive=True))
    assert resp.status_code == 200
    assert resp.json()["action"]["risk_tier"] == "risky"


@patch("app.main.generate_action")
def test_analyze_still_rejects_hallucinated_target_for_select_custom(mock_gen, client):
    mock_gen.return_value = ActionInstruction(
        type="select_custom", target_element_id="nope", value="Red", risk_tier="safe", reasoning_short="r")
    resp = client.post("/analyze", json=_payload())
    assert resp.status_code == 500  # retried then failed, same as `type`
