import re
from dataclasses import dataclass, field
from typing import List, Optional

from .injection import scan_text

# Substring STEMS (lower-case), so "delete", "deleting" and "deletion" all hit:
# a whole-word list missed gerunds like "Deleting the account..." ("delete" is
# not a substring of "deleting"). A hit only escalates a click to "risky" (a
# native confirmation dialog) — it never blocks.
DANGEROUS_KEYWORDS = [
    "pay", "purchas", "delet", "remov", "confirm",
    "submit", "transfer", "send", "checkout", "check out", "buy",
    "approv", "authoriz", "authoris", "withdraw", "wire",
    "deactivat", "eras", "wip", "donat", "place order",
]

# Tier-1 vault tokens (mirrors dev2/sensitivity-tiers.js TIER_1_TYPES). The
# client resolves a token to the RAW value at execution time, so where one
# may be typed is a security decision made here, not by the LLM.
TIER_1_TOKEN_TYPES = frozenset({"PASSWORD", "CARD_NUMBER", "AADHAAR", "OTP"})
_TOKEN_SHAPE = re.compile(r'^\[([A-Z_]+)_[A-Za-z0-9]+\]$')

# Ported from dev2/pii-patterns.js so the server enforces the same raw-PII
# shapes the client is supposed to have already tokenized. This is the
# concrete defense against "the LLM echoes or hallucinates a raw-looking
# value instead of a token" (Phase 1.4) — independent of and in addition to
# the client-side leakage auditor, since the LLM's output is never trusted.
VALID_TOKEN_PATTERN = re.compile(r'^\[[A-Za-z0-9_]+\]$')

RAW_PII_VALUE_PATTERNS = {
    "EMAIL": re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'),
    "PHONE": re.compile(r'(?<!\d)[6-9]\d{9}(?!\d)'),
    "CARD_NUMBER": re.compile(r'(?<!\d)(?:\d[ -]?){15}\d(?!\d)'),
    "AADHAAR": re.compile(r'(?<!\d)(?:\d[ -]?){11}\d(?!\d)'),
    "IFSC": re.compile(r'\b[A-Za-z]{4}0[A-Za-z0-9]{6}\b'),
}


def value_field_violates_pii_guard(value: str | None) -> str | None:
    """Returns the matched PII type name if `value` looks like a raw,
    non-tokenized sensitive value; returns None if `value` is safe
    (either a valid token-bracket form, or plain non-PII text)."""
    if not value:
        return None
    if VALID_TOKEN_PATTERN.match(value):
        return None
    for pii_type, pattern in RAW_PII_VALUE_PATTERNS.items():
        if pattern.search(value):
            return pii_type
    return None

@dataclass
class Assessment:
    risk_tier: str                       # "safe" | "risky" — server-derived, never the LLM's word alone
    reasons: List[str] = field(default_factory=list)  # deterministic codes; never page text
    rejection: Optional[str] = None      # set => the action must NOT be executed at all


def assess_action(action: dict, target_element: dict | None) -> Assessment:
    """Server-authoritative verdict on an LLM-proposed action.

    The LLM is an untrusted planner: whatever it says (including its own
    risk_tier or a reasoning_short claiming user approval) can only make the
    outcome MORE cautious, never less. Everything below is derived from the
    payload's ground truth and the action's structure.
    """
    atype = action.get("type")
    reasons: List[str] = []

    # Hard rule (exfiltration): a Tier-1 token resolves to the raw secret in
    # the browser, so it may only ever be typed into a field the client
    # classified as sensitive. Typing it into any other field would put the
    # real password/card/OTP into a page-controlled input.
    if atype in ("type", "select_custom"):
        m = _TOKEN_SHAPE.match(action.get("value") or "")
        if m and m.group(1) in TIER_1_TOKEN_TYPES and not (target_element and target_element.get("is_sensitive")):
            return Assessment("risky", ["tier1_token_into_non_sensitive_field"], rejection="tier1_token_into_non_sensitive_field")

    if target_element and target_element.get("is_sensitive"):
        reasons.append("sensitive_target")

    if atype in ("task_complete", "task_failed") and not reasons:
        return Assessment("safe", [])

    if atype == "click":
        text = f"{target_element.get('label_text', '') if target_element else ''} {action.get('reasoning_short', '')}".lower()
        if any(kw in text for kw in DANGEROUS_KEYWORDS):
            reasons.append("dangerous_keyword")

    # Injection tripwires: never a reason to trust something, only to ask the
    # human. (Detection is evadable; the rules above do not depend on it.)
    if target_element and (scan_text(target_element.get("label_text"), "dom_label") or scan_text(target_element.get("element_id"), "element_id")):
        reasons.append("target_flagged_injection")
    if scan_text(action.get("reasoning_short"), "reasoning"):
        reasons.append("reasoning_echoes_injection")  # a tell that the model was steered

    if reasons:
        return Assessment("risky", reasons)
    claim = action.get("risk_tier")
    if claim == "safe":
        return Assessment("safe", [])
    return Assessment("risky", ["model_declared_risky" if claim == "risky" else "risk_tier_missing"])


def evaluate_action_risk(action: dict, target_element: dict | None) -> str:
    """Returns 'safe' or 'risky'. Independent of LLM-supplied risk_tier."""
    return assess_action(action, target_element).risk_tier
