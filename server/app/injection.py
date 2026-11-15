"""Deterministic prompt-injection signal detection for webpage-derived text.

Design rules
  * Classification, not deletion. A match never removes or rewrites content
    (a normal page can say "ignore the previous filter"); it yields METADATA
    the rest of the server uses: prompt annotations, risk escalation, audit.
  * Metadata only. A Finding holds a source, category, severity and rule id —
    never the matched text — so nothing sensitive or attacker-authored can be
    copied into logs, exceptions or test output through this module.
  * This is a tripwire, not a defense on its own. Regexes are evadable
    (paraphrase, other languages, encodings). The real boundary is the
    server-side policy in policy.py, which does not depend on detection.
"""
import re
import unicodedata
from dataclasses import dataclass
from typing import Iterable, List

# Sources a finding can come from (never contains text).
SOURCES = ("dom_label", "element_id", "page_status_text", "url", "task_instruction", "reasoning", "vision_note")


@dataclass(frozen=True)
class Finding:
    source: str
    category: str
    severity: str  # "high" | "medium"
    rule: str


_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)


def normalize(text: str) -> str:
    """NFKC (folds full-width / stylized letters), drops zero-width and control
    characters, treats separators like '_' '-' '.' as spaces, casefolds."""
    t = unicodedata.normalize("NFKC", str(text or "")).translate(_ZERO_WIDTH)
    t = "".join(" " if unicodedata.category(c).startswith("C") else c for c in t)
    t = re.sub(r"[_\-\.‐-―]+", " ", t)
    return re.sub(r"\s+", " ", t).strip().casefold()


_SENSITIVE_NOUN = r"(?:password|passwords|passcode|credentials?|secrets?|otp|one time (?:code|password)|api key|tokens?|cvv|card numbers?|vault|cookies?|session)"

# (rule id, category, severity, pattern). Patterns run on normalize()d text.
_RULES = [
    ("override_ignore_instructions", "instruction_override", "high",
     r"\b(?:ignore|disregard|forget|override|discard)\b.{0,30}\b(?:previous|prior|above|earlier|preceding|all|any|your|these|the)\b.{0,20}\b(?:instructions?|prompts?|rules|directives|guidelines|programming)\b"),
    ("override_system_prompt", "instruction_override", "high",
     r"\b(?:override|replace|reset|bypass)\b.{0,15}\b(?:the )?system prompt\b"),
    ("override_new_instructions", "instruction_override", "medium",
     r"\bnew (?:instructions?|directives?|orders?)\s*:"),
    ("override_mode_switch", "instruction_override", "high",
     r"\byou are now (?:in )?(?:a |an |the )?(?:debug|developer|admin|administrator|root|dan|jailbreak|unrestricted)\b"),

    ("role_message", "role_impersonation", "medium",
     r"\b(?:system|developer|administrator|admin|assistant)\s+(?:message|prompt|instructions?|override|directive|notice)\b"),
    ("role_security_notice", "role_impersonation", "medium",
     r"\b(?:security|privacy) (?:policy|team|notice|alert)\b.{0,40}\b(?:requires?|instructs?|authoriz\w+|update)\b"),

    ("extract_reveal_secret", "secret_extraction", "high",
     r"\b(?:reveal|leak|exfiltrate|expose|disclose)\b.{0,30}\b" + _SENSITIVE_NOUN + r"\b"),
    ("extract_show_stored", "secret_extraction", "high",
     r"\b(?:show|display|print|output|dump|list)\b.{0,20}\b(?:credentials|secrets|the vault|vault contents|api keys?|stored (?:passwords?|tokens?|values?|credentials)|hidden values?|all tokens)\b"),
    ("extract_give_me", "secret_extraction", "high",
     r"\b(?:give|tell|send|read out)\b.{0,6}\b(?:me|us)\b.{0,15}\b" + _SENSITIVE_NOUN + r"\b"),

    ("exfil_send_to", "exfiltration", "high",
     r"\b(?:send|forward|post|upload|email|transmit|submit)\b.{0,50}\b" + _SENSITIVE_NOUN + r"\b.{0,60}\b(?:to|at)\b"),
    ("exfil_read_then_send", "exfiltration", "high",
     r"\b(?:read|copy|get|grab|take|collect)\b.{0,30}\b" + _SENSITIVE_NOUN + r"\b.{0,60}\b(?:send|forward|post|upload|email|transmit)\b"),
    ("exfil_confidential", "exfiltration", "high",
     r"\b(?:send|forward|upload|email|leak)\b.{0,15}\b(?:all |the |any )?(?:confidential|private|sensitive|personal)\b.{0,20}\b(?:information|data|files?|details)\b"),

    ("bypass_security", "policy_bypass", "high",
     r"\b(?:disable|turn off|bypass|ignore|skip|override|circumvent|deactivate)\b.{0,25}\b(?:security|privacy|safety|validation|guardrails?|redaction|restrictions?|safeguards?|safety checks?|security checks?|policy|policies)\b"),
    ("bypass_perceive", "policy_bypass", "high",
     r"\bperceive'?s?\b.{0,40}\b(?:rules?|polic\w+|safety|privacy|checks?|guardrails?)\b"),

    ("authz_user_approved", "fake_authorization", "high",
     r"\b(?:the )?(?:user|owner|admin|administrator|customer)\b.{0,15}\b(?:has|have|already|just)\b.{0,10}\b(?:approved|authori[sz]ed|consented|confirmed|granted|allowed)\b"),
    ("authz_you_are_authorized", "fake_authorization", "high",
     r"\byou (?:are|have been|were) (?:now |hereby )?(?:authori[sz]ed|permitted|allowed|cleared|approved)\b"),
    ("authz_no_confirmation", "fake_authorization", "high",
     r"\b(?:no (?:further |more )?(?:confirmation|approval|verification)\b.{0,12}\b(?:needed|required|necessary)|without (?:asking|confirmation|approval|consent))\b"),
    ("conceal_from_user", "fake_authorization", "medium",
     r"\bdo not (?:tell|inform|ask|notify|alert|warn|show)\b.{0,10}\b(?:the )?user\b"),

    ("action_move_money", "unauthorized_action", "medium",
     r"\b(?:transfer|wire|send|pay|donate)\b.{0,20}\b(?:money|funds|payment|dollars|rupees|usd|inr|bitcoin|crypto)\b"),
    ("action_delete_all", "unauthorized_action", "medium",
     r"\bdelete\b.{0,10}\b(?:everything|all (?:data|files|accounts?|emails?)|(?:the|your|my) account|account)\b.{0,10}(?:\b(?:immediately|now|permanently)\b|$)"),
    ("action_make_payment", "unauthorized_action", "medium",
     r"\bmake (?:a |the |an )?(?:payment|transfer|purchase|donation)\b"),
    ("action_click_payment_button", "unauthorized_action", "medium",
     r"\b(?:click|press|tap|hit)\b.{0,25}\b(?:payment|purchase|transfer|transaction)\b.{0,15}\b(?:confirm\w*|approv\w*|button)\b"),
    ("action_confirm_payment", "unauthorized_action", "medium",
     r"\b(?:click|press|tap|hit)\b.{0,25}\b(?:confirm|approve|authori[sz]e|complete)\b.{0,15}\b(?:payment|purchase|transfer|transaction|order)\b"),
]
_COMPILED = [(rid, cat, sev, re.compile(pat)) for rid, cat, sev, pat in _RULES]

CATEGORIES = tuple(sorted({c for _, c, _, _ in _RULES}))

_MAX_SCAN_CHARS = 4000  # bound regex work on attacker-sized strings


def scan_text(text, source: str) -> List[Finding]:
    """Returns one Finding per matching rule. Never returns the text."""
    if not text or not isinstance(text, str):
        return []
    norm = normalize(text[:_MAX_SCAN_CHARS])
    if not norm:
        return []
    return [Finding(source, cat, sev, rid) for rid, cat, sev, rx in _COMPILED if rx.search(norm)]


def worst_severity(findings: Iterable[Finding]) -> str | None:
    fs = list(findings)
    if any(f.severity == "high" for f in fs):
        return "high"
    return "medium" if fs else None


def scan_payload(payload) -> dict:
    """Scans every webpage-derived string in a ClientPayload plus the task text.
    Returns { "elements": {element_id: [Finding]}, "page": [Finding],
    "task": [Finding], "all": [Finding] } — metadata only."""
    per_element = {}
    page = []
    dom = payload.dom_summary
    page += scan_text(dom.url, "url")
    page += scan_text(dom.page_status_text, "page_status_text")
    for el in dom.elements:
        fs = scan_text(el.label_text, "dom_label") + scan_text(el.element_id, "element_id")
        if fs:
            per_element[el.element_id] = fs
    task = scan_text(payload.task_instruction, "task_instruction")
    allf = page + task + [f for fs in per_element.values() for f in fs]
    return {"elements": per_element, "page": page, "task": task, "all": allf}


def summarize(findings: Iterable[Finding]) -> list:
    """Audit-safe aggregate: counts per (source, category, severity, rule)."""
    counts: dict = {}
    for f in findings:
        key = (f.source, f.category, f.severity, f.rule)
        counts[key] = counts.get(key, 0) + 1
    return [
        {"source": s, "category": c, "severity": sv, "rule": r, "count": n}
        for (s, c, sv, r), n in sorted(counts.items())
    ]


# ---- audit-log sanitizers: page/LLM-authored strings never go in verbatim ----

_SUPPRESSED = "[SUPPRESSED:injection_signal]"


def audit_safe_text(text, source: str, max_len: int = 160):
    """A string for the audit log: capped, and replaced outright if it carries
    an injection signal or a raw-PII shape."""
    if text is None:
        return None
    from .policy import value_field_violates_pii_guard  # local import: policy imports this module
    if scan_text(text, source) or value_field_violates_pii_guard(str(text)):
        return _SUPPRESSED
    return str(text)[:max_len]


def audit_safe_action(action: dict) -> dict:
    out = dict(action)
    if "reasoning_short" in out:
        out["reasoning_short"] = audit_safe_text(out["reasoning_short"], "reasoning")
    if out.get("target_element_id") is not None:
        out["target_element_id"] = audit_safe_text(out["target_element_id"], "element_id", max_len=64)
    return out


def audit_safe_notes(notes: list) -> list:
    safe = []
    for n in notes:
        d = dict(n)
        if "element_id" in d:
            d["element_id"] = audit_safe_text(d["element_id"], "element_id", max_len=64)
        safe.append(d)
    return safe
