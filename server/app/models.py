from pydantic import BaseModel, ConfigDict, Field, model_validator, field_validator
from typing import List, Optional, Literal, Dict

# -------------------------------------------------------------------
# Enum-like Literals per PDF Section 4 contracts
# -------------------------------------------------------------------

TagType = str
RoleType = str
SensitivityTier = Literal[1, 2, 3]
SensitivityType = Literal["PASSWORD", "CARD_NUMBER", "EMAIL", "NAME", "AMOUNT", "PHONE", "AADHAAR", "OTP", "IFSC", "UNKNOWN"]
DetectionMethod = Literal["dom_heuristic", "vision_model", "ocr_regex"]
ActionType = Literal["click", "type", "select_custom", "scroll", "wait", "ask_user_confirmation", "task_complete", "task_failed"]
RiskTier = Literal["safe", "risky"]

# -------------------------------------------------------------------
# Client -> Server Payload Models
# -------------------------------------------------------------------

class BoundingBox(BaseModel):
    x: int
    y: int
    w: int
    h: int

class DOMElement(BaseModel):
    element_id: str
    tag: TagType
    role: RoleType
    label_text: Optional[str] = None
    is_sensitive: bool
    sensitivity_tier: Optional[SensitivityTier] = None
    sensitivity_type: Optional[SensitivityType] = None
    semantic_token: Optional[str] = None
    has_value: bool = False
    bounding_box: BoundingBox

    @model_validator(mode='after')
    def check_sensitive_has_token(self):
        # Fail-closed invariant: the server must never receive a real
        # sensitive value. A sensitive element with actual content
        # must carry a semantic token. A sensitive element with no
        # value yet (has_value=False) is allowed to have a null
        # token, since there's nothing to leak and no real value to
        # back a vault entry with.
        if self.is_sensitive and self.has_value and (self.semantic_token is None or self.semantic_token == ""):
            raise ValueError('Sensitive DOM element with a value must include a semantic_token')
        return self

class DOMSummary(BaseModel):
    url: str
    elements: List[DOMElement] = Field(max_length=500)
    # Bug found live: the LLM previously had zero visibility into plain
    # page text (headings, confirmation/status banners) since `elements`
    # only ever contains form controls (input/button/select/textarea).
    # This meant a genuinely-succeeded action (e.g. "Phone number
    # updated." appearing on the page) gave the model no evidence at all,
    # so it kept re-clicking/re-scrolling instead of recognizing the
    # sub-goal was done. Populated client-side by orchestrator.js's
    # extractPageStatusText() — deliberately short, generic (title/h1/h2/
    # common status-role text), and re-checked for PII client-side before
    # ever being sent.
    page_status_text: Optional[str] = Field(default=None, max_length=300)

class DetectionConfidenceNote(BaseModel):
    element_id: str
    confidence: float = Field(ge=0.0, le=1.0)
    method: DetectionMethod

class FieldMappingRequest(BaseModel):
    slot_ids: List[str] = Field(min_length=1, max_length=10)
    candidate_field_purposes: List[str] = Field(min_length=1, max_length=10)

class ProposedAction(BaseModel):
    """A macro step proposed by the client for server validation (macro replay).

    Treated exactly like an LLM-proposed action: untrusted, and run through the
    same validation/policy pipeline. Deliberately narrower than ActionInstruction:
    it can never declare completion/failure, never carries a risk claim or
    reasoning, and unknown fields are rejected.
    """
    model_config = ConfigDict(extra="forbid")
    type: Literal["click", "type", "select_custom", "scroll", "wait"]
    target_element_id: Optional[str] = Field(default=None, max_length=200)
    value: Optional[str] = Field(default=None, max_length=500)


class ReplayMeta(BaseModel):
    """Identifies which macro step a proposed_action is (audit only; never trusted for authorization)."""
    model_config = ConfigDict(extra="forbid")
    macro_id: str = Field(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    step_index: int = Field(ge=0, le=19)
    total_steps: int = Field(ge=1, le=20)

    @model_validator(mode="after")
    def check_index_in_range(self):
        if self.step_index >= self.total_steps:
            raise ValueError("step_index must be < total_steps")
        return self


class ClientPayload(BaseModel):
    session_id: str
    task_instruction: str = Field(min_length=1, max_length=2000)
    step_number: int
    dom_summary: DOMSummary
    redacted_image_base64: Optional[str] = Field(default=None, max_length=8_000_000)
    detection_confidence_notes: List[DetectionConfidenceNote] = Field(default_factory=list, max_length=500)
    redacted_regions: Optional[List[dict]] = None
    # Set by the client when the PREVIOUS action for this session failed to
    # execute (a stale/missing DOM target, a rejected task_complete
    # postcondition, etc.) — without this, the LLM has no way to know why
    # the page looks unchanged from the last step and may blindly repeat
    # the same failing action or give up prematurely. See
    # llm_client.py's EXECUTION FEEDBACK prompt block.
    last_action_error: Optional[str] = Field(default=None, max_length=1000)
    # Phase C.2(c): narrow, structural-only fallback for task-instruction
    # parsing. When present, task_instruction has already had every
    # candidate raw value replaced client-side with an opaque placeholder
    # (<<SLOT_1>>, <<SLOT_2>>, ...) BEFORE this payload was ever built — the
    # real values never leave the browser. The LLM's only job is to map
    # each slot id to a field purpose based on surrounding wording; see
    # llm_client.py's generate_field_mapping(). This extends the existing
    # /analyze contract rather than adding a parallel endpoint, so it
    # inherits the same auth/rate-limit dependencies unchanged.
    field_mapping_request: Optional[FieldMappingRequest] = None
    # Macro replay: instead of asking the LLM, the client proposes the next
    # recorded step. The server validates it through the SAME pipeline as an
    # LLM action (see app.main._validate_and_finalize). Both fields or neither.
    proposed_action: Optional[ProposedAction] = None
    replay: Optional[ReplayMeta] = None

    @model_validator(mode="after")
    def check_replay_fields(self):
        if (self.proposed_action is None) != (self.replay is None):
            raise ValueError("proposed_action and replay must be provided together")
        if self.proposed_action is not None:
            if self.field_mapping_request is not None:
                raise ValueError("proposed_action cannot be combined with field_mapping_request")
            pa = self.proposed_action
            if pa.type in ("click", "type", "select_custom", "scroll") and not pa.target_element_id:
                raise ValueError(f"target_element_id is required for a proposed '{pa.type}'")
            if pa.type in ("type", "select_custom") and pa.value is None:
                raise ValueError(f"value is required for a proposed '{pa.type}'")
        return self

# -------------------------------------------------------------------
# Server -> Client Action Response Models
# -------------------------------------------------------------------

class ActionInstruction(BaseModel):
    type: ActionType
    target_element_id: Optional[str] = None
    value: Optional[str] = None
    risk_tier: RiskTier
    reasoning_short: str
    # Set by the SERVER (policy.assess_action) on every action; whatever the
    # LLM puts here is overwritten. Deterministic codes only, never page text.
    risk_reasons: List[str] = Field(default_factory=list)

    @field_validator("risk_tier", mode="before")
    @classmethod
    def reject_non_enum_risk_tier(cls, v):
        if v not in ("safe", "risky"):
            raise ValueError(
                f"risk_tier must be 'safe' or 'risky', got {v!r} "
                f"(type {type(v).__name__}) — numeric conversion is client-side only, "
                f"backend does not coerce"
            )
        return v

    @model_validator(mode='after')
    def check_required_fields_based_on_type(self):
        if self.type in ["click", "type", "select_custom"] and not self.target_element_id:
            raise ValueError(f"target_element_id is required for action type '{self.type}'")
        if self.type in ("type", "select_custom") and self.value is None:
            raise ValueError(f"value is required for '{self.type}' action")
        return self

class ServerResponse(BaseModel):
    session_id: str
    step_number: int
    # Exactly one of `action` / `field_mapping` is populated: a normal
    # /analyze call always returns `action` (unchanged from before this
    # phase); a field_mapping_request call (Phase C.2c) returns
    # `field_mapping` instead and leaves `action` null, since a structural
    # slot->field-purpose mapping is not an executable action and must
    # never be run through the click/type risk-tier or PII value-guard
    # checks that exist for real actions.
    action: Optional[ActionInstruction] = None
    field_mapping: Optional[Dict[str, Optional[str]]] = None
    confidence: float = Field(ge=0.0, le=1.0)
