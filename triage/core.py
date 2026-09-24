"""Read-only support triage drafts with bounded, best-effort redaction."""
from __future__ import annotations
import hashlib
import json
import re

VERSION = "0.1.2a1"
__version__ = VERSION
MAX_RECORDS = 5000
MAX_BYTES = 8 * 1024 * 1024
MAX_TEXT = 128 * 1024
MAX_DEPTH = 40

def _encoded(value):
    def validate(item, depth=0):
        if depth > MAX_DEPTH:
            raise ValueError("JSON nesting limit exceeded")
        if type(item) is dict:
            if any(type(key) is not str for key in item):
                raise ValueError("JSON object keys must be strings")
            for child in item.values():
                validate(child, depth+1)
        elif type(item) is list:
            for child in item:
                validate(child, depth+1)
        elif type(item) not in (str, int, float, bool, type(None)):
            raise ValueError("input must contain only JSON values")
    validate(value)
    try:
        data = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise ValueError("input must be finite JSON") from None
    if len(data) > MAX_BYTES:
        raise ValueError("JSON size limit exceeded")
    return data

def _snapshot(value):
    return json.loads(_encoded(value))

def _digest(value):
    return "sha256:" + hashlib.sha256(_encoded(value)).hexdigest()

def _text(value, *, identifier=False):
    limit = 512 if identifier else MAX_TEXT
    if type(value) is not str or len(value) > limit or (identifier and not value.strip()):
        raise ValueError("invalid or oversized text field")
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise ValueError("invalid Unicode text") from None
    if identifier and any(ord(c) < 32 for c in value):
        raise ValueError("invalid identifier")
    return value

def _records(value):
    if type(value) is not list or len(value) > MAX_RECORDS:
        raise ValueError("catalog must be a bounded list")
    return value

_REDACTIONS = [
    ("email", re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}")),
    ("api_key", re.compile(r"(?i)\b(?:sk|pk|key|token)[-_][A-Za-z0-9_-]{12,}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("authorization", re.compile(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}")),
    ("credential", re.compile(r"(?i)\b(?:password|passwd|api[_-]?key|secret)\s*[:=]\s*[^\s,;]+")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("card_number", re.compile(r"\b(?:\d[ -]?){13,19}\b")),
    ("phone", re.compile(r"\+?\d{1,3}[ .-]?\(?\d{2,4}\)?[ .-]?\d{3}[ .-]?\d{3,4}\b")),
]
_SENSITIVE_KEYS = {"password", "passwd", "secret", "token", "api_key", "apikey",
                   "authorization", "ssn", "credit_card", "card_number"}
_PLACEHOLDER = re.compile(r"\[REDACTED-[A-Z_]+\]")

def _scrub(text, where="", inventory=None):
    text = _text(text)
    for kind, pattern in _REDACTIONS:
        def substitute(match):
            if inventory is not None:
                inventory.append({"field": where, "kind": kind})
            return "[REDACTED-"+kind.upper()+"]"
        text = pattern.sub(substitute, text)
    return text

def _sanitize(value):
    value = _snapshot(value)
    def walk(item):
        if type(item) is str:
            return _scrub(item)
        if type(item) is list:
            return [walk(child) for child in item]
        if type(item) is dict:
            result = {}
            for key, child in item.items():
                safe_key = _scrub(key)
                if safe_key in result:
                    raise ValueError("redaction creates ambiguous object keys")
                result[safe_key] = ("[REDACTED-SECRET]" if key.lower().replace("-", "_") in _SENSITIVE_KEYS
                                    else walk(child))
            return result
        return item
    return walk(value)

def organize_request(raw):
    raw = _snapshot(raw)
    if type(raw) is not dict:
        raise ValueError("request must be an object")
    for field in ("ticket_id", "subject", "body"):
        _text(raw.get(field), identifier=field=="ticket_id")
    for field in ("product", "region"):
        if field in raw and raw[field] is not None:
            _text(raw[field], identifier=True)
    redactions = []
    result = {
        "ticket_id": _scrub(raw["ticket_id"], "ticket_id", redactions),
        "subject": _scrub(raw["subject"], "subject", redactions),
        "body": _scrub(raw["body"], "body", redactions),
        "product_hint": _scrub(raw["product"], "product", redactions) if raw.get("product") else None,
        "region_hint": _scrub(raw["region"], "region", redactions) if raw.get("region") else None,
        "redactions": redactions, "raw_digest": _digest(raw)}
    result["organized_digest"] = _digest(result)
    return result

def _request(request):
    request = _snapshot(request)
    if type(request) is not dict:
        raise ValueError("organized request must be an object")
    digest = request.pop("organized_digest", None)
    if digest != _digest(request) or not {"ticket_id", "subject", "body", "redactions", "raw_digest"} <= set(request):
        raise ValueError("organized request digest is missing or mismatched")
    for field in ("ticket_id", "subject", "body"):
        _text(request[field], identifier=field=="ticket_id")
        if _scrub(request[field]) != request[field]:
            raise ValueError("organized request contains unredacted detected data")
    for field in ("product_hint", "region_hint"):
        if request.get(field) is not None:
            _text(request[field], identifier=True)
            if _scrub(request[field]) != request[field]:
                raise ValueError("organized request metadata contains detected data")
    if type(request["raw_digest"]) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", request["raw_digest"]):
        raise ValueError("invalid raw request digest")
    if type(request["redactions"]) is not list or any(type(item) is not dict or set(item) != {"field", "kind"}
            or item["field"] not in ("ticket_id", "subject", "body", "product", "region")
            or item["kind"] not in {name for name, _ in _REDACTIONS} for item in request["redactions"]):
        raise ValueError("invalid redaction inventory")
    request["organized_digest"] = digest
    return request

def attach_privacy_policy(request, policies):
    request = _request(request)
    policies = _snapshot(_records(policies))
    specific, generic, ids = [], [], set()
    for policy in policies:
        if type(policy) is not dict:
            raise ValueError("policy must be an object")
        ident = _text(policy.get("policy_id"), identifier=True)
        if ident in ids:
            raise ValueError("duplicate policy identity")
        ids.add(ident)
        products = policy.get("applies_to_products")
        if type(products) is not list or not products or any(not _text(x, identifier=True) for x in products):
            raise ValueError("policy product scope must be a nonempty list")
        regions = policy.get("applies_to_regions")
        if regions is not None:
            if type(regions) is not list or not regions or any(not _text(x, identifier=True) for x in regions):
                raise ValueError("policy region scope must be a nonempty list")
            if "*" not in regions and request.get("region_hint") not in regions:
                continue
        if request.get("product_hint") in products and request.get("product_hint") != "*":
            specific.append(policy)
        elif products == ["*"]:
            generic.append(policy)
    selected = specific if specific else generic
    return _sanitize(selected[0]) if len(selected) == 1 else None

_AREA_RULES = [("billing", ["invoice", "charge", "payment", "refund", "billing"]),
               ("auth", ["login", "password", "2fa", "sign in", "locked out"]),
               ("performance", ["slow", "timeout", "latency", "hang"]),
               ("data", ["export", "import", "sync", "missing data", "lost"])]
_TYPE_RULES = [("outage", ["down", "outage", "unavailable", "cannot access"]),
               ("bug", ["error", "crash", "broken", "fails", "exception"]),
               ("how-to", ["how do i", "how to", "where can", "question"]),
               ("billing-dispute", ["refund", "overcharged", "dispute"])]
_SEV_RULES = [("critical", ["outage", "data loss", "security", "breach", "down for all"]),
              ("high", ["cannot access", "blocked", "urgent", "production"]),
              ("low", ["how do i", "how to", "cosmetic", "typo"])]


def _match(text, rules, default):
    for label, keywords in rules:
        found = [word for word in keywords if re.search(
            r"(?<!\w)" + r"\s+".join(re.escape(part) for part in word.split()) + r"(?!\w)", text)]
        if found:
            return label, [f"matched {label!r} on keyword(s) {found}"]
    return default, [f"no rule keyword matched; defaulted to {default!r}"]

def _query_text(request):
    return _PLACEHOLDER.sub(" ", request["subject"]+" "+request["body"]).lower()

def classify(request):
    request = _request(request)
    text = _query_text(request)
    area, r1 = _match(text, _AREA_RULES, "general")
    kind, r2 = _match(text, _TYPE_RULES, "question")
    severity, r3 = _match(text, _SEV_RULES, "medium")
    return {"product_area": area, "issue_type": kind, "severity": severity,
            "rationale": r1+r2+r3, "confidence": "heuristic"}

def find_similar_cases(request, resolved_cases, limit=3):
    request = _request(request)
    if type(limit) is not int or not 0 <= limit <= 100:
        raise ValueError("case limit must be an integer from 0 to 100")
    cases = _snapshot(_records(resolved_cases))
    words = set(re.findall(r"[a-z]{3,}", _query_text(request)))
    scored, ids, safe_ids = [], set(), set()
    for case in cases:
        if type(case) is not dict:
            raise ValueError("case must be an object")
        ident = _text(case.get("case_id"), identifier=True)
        _text(case.get("summary"))
        if case.get("resolution") is not None:
            _text(case["resolution"])
        if ident in ids:
            raise ValueError("duplicate case identity")
        ids.add(ident)
        scoped_out = False
        for field, hint in (("product", "product_hint"), ("region", "region_hint")):
            if field in case:
                _text(case[field], identifier=True)
                if case[field] != request.get(hint):
                    scoped_out = True
        if scoped_out:
            continue
        safe = _sanitize(case)
        if safe["case_id"] in safe_ids:
            raise ValueError("redaction creates ambiguous case identities")
        safe_ids.add(safe["case_id"])
        cw = set(re.findall(r"[a-z]{3,}", _PLACEHOLDER.sub(" ", safe["summary"]).lower()))
        union = words | cw
        similarity = len(words & cw)/len(union) if union else 0
        if similarity > 0:
            scored.append({"case_id": safe["case_id"], "similarity": round(similarity, 3),
                "resolution": safe.get("resolution"), "shared_terms": sorted(words & cw)[:8]})
    scored.sort(key=lambda item: (-item["similarity"], item["case_id"]))
    return scored[:limit]

def run_telemetry_lookups(requested, allowlist, lookup_results):
    requested = _snapshot(_records(requested))
    if type(allowlist) not in (set, frozenset) or len(allowlist) > MAX_RECORDS:
        raise ValueError("allowlist must be a bounded set of lookup names")
    if type(lookup_results) is not dict:
        raise ValueError("lookup results must be an object")
    for name in [*requested, *allowlist]:
        _text(name, identifier=True)
        if _scrub(name) != name:
            raise ValueError("lookup names must not contain detected sensitive data")
    ran, refused = {}, []
    for name in sorted(set(requested)):
        if name in allowlist:
            ran[name] = _sanitize(lookup_results.get(name, "NO_DATA"))
        else:
            refused.append({"lookup": name, "reason": "not on the pre-approved allowlist (CAP-05)"})
    result = {"ran": ran, "refused": refused}
    _encoded(result)
    return result

_INTERNAL_LEAK = re.compile(r"(?i)(internal|prod-db|stacktrace|traceback|server-\d+|\.py:\d+|REDACTED)")

def build_triage_card(request, classification, policy, similar, telemetry):
    request = _request(request)
    if classification != classify(request):
        raise ValueError("classification does not match the organized request")
    classification = _snapshot(classification)
    similar = _sanitize(_records(similar))
    telemetry = _sanitize(telemetry)
    if type(telemetry) is not dict or type(telemetry.get("ran")) is not dict or type(telemetry.get("refused")) is not list:
        raise ValueError("telemetry must contain ran and refused collections")
    if policy is not None and (type(policy) is not dict or not _text(policy.get("policy_id"), identifier=True)):
        raise ValueError("policy must contain its identity")
    draft = "Hello, thank you for contacting support. A support agent can review your request and help with next steps."
    card = {"schema": "triage/card/v1", "assistant_version": VERSION,
        "ticket_id": request["ticket_id"], "request_raw_digest": request["raw_digest"],
        "request_organized_digest": request["organized_digest"],
        "classification": classification,
        "privacy_policy": _scrub(policy["policy_id"]) if policy else "NONE_APPLICABLE — record gap",
        "redactions_applied": _snapshot(request["redactions"]),
        "similar_cases": similar, "telemetry": telemetry, "customer_safe_draft": draft,
        "draft_leak_screen": {"clean": True, "hits": [], "scope": "fixed acknowledgment text only"},
        "input_review_flags": sorted(set(_INTERNAL_LEAK.findall(request["subject"]+" "+request["body"]))),
        "escalation": {"how": "assign to a human agent now", "available": True,
                       "note": "escalation is immediate and unconditional"},
        "privacy_notes": ["Pattern-based redaction is incomplete; human privacy review is required.",
                          "Caller-supplied policy and lookup allowlist are not independently authorized."],
        "draft_only": True, "human_agent_required": True, "sent": False}
    card["card_digest"] = _digest(card)
    return card

def triage(raw_request, policies, resolved_cases, telemetry_allowlist, telemetry_requests, telemetry_results):
    request = organize_request(raw_request)
    return build_triage_card(request, classify(request), attach_privacy_policy(request, policies),
        find_similar_cases(request, resolved_cases),
        run_telemetry_lookups(telemetry_requests, telemetry_allowlist, telemetry_results))
