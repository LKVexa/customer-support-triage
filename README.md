# Customer Support Triage

**0.1.2a1 — experimental partial candidate, JY-S009-P001**

A pure Python library for redaction, rule-based classification, policy selection,
case similarity, selection of supplied telemetry, and support triage cards.
It sends no messages, performs no live lookup, and changes no customer account.

## Install and use

Python 3.10 or newer; no third-party runtime dependencies.

~~~sh
python -m pip install .
python -m unittest discover -s tests -t .
~~~

~~~python
from triage.core import triage

card = triage(
    {"ticket_id": "T-100", "subject": "Cannot access billing",
     "body": "The page reports an error.", "product": "billing-suite", "region": "EU"},
    policies=[{"policy_id": "billing-eu", "applies_to_products": ["billing-suite"],
               "applies_to_regions": ["EU"]}],
    resolved_cases=[],
    telemetry_allowlist={"account_status"},
    telemetry_requests=["account_status"],
    telemetry_results={"account_status": "active"},
)
~~~

All outputs require a human agent. Cards retain draft_only, human_agent_required,
sent: false, and an immediate escalation option. The package cannot actually route
or send anything.

## Redaction and customer draft

Intake scrubs ticket ID, subject, body, product and region hints. Selected case
resolutions, policy data and nested telemetry receive recursive redaction.
Common email, card, phone, SSN, API-token, authorization and credential-assignment
patterns are covered. Sensitive dictionary keys such as password and token have
their values replaced. Ambiguous keys or case identities created by redaction
raise ValueError. Raw extra request metadata is hashed but not retained.

Redaction is heuristic and incomplete. Names, addresses, obfuscated credentials,
encoded data and unrecognized personal information may remain. A clean screen
does not certify privacy. Inspect the full internal card before sharing it.

customer_safe_draft is a fixed acknowledgment: it echoes no request, classification,
case or telemetry text and makes no claim that routing or follow-up already occurred.
Its leak-screen scope is only that fixed text. input_review_flags separately expose
detected internal identifiers or redaction markers in intake for agent review.

## Scope and classification

A single matching product policy wins; otherwise one generic policy may apply.
Ambiguous matches return no policy. Optional applies_to_regions restricts selection;
a missing or different region cannot satisfy a restricted policy. This selects
caller-supplied records only and is not a determination of legal applicability.

Cases with explicit product or region scope must match the request. Legacy unscoped
cases remain caller-controlled; scope labels do not enforce tenant authorization.
Similarity uses deterministic token overlap after removing redaction markers.
Duplicate case/policy identities and malformed records are rejected.

Classification uses bounded word/phrase matches, including flexible whitespace,
with the existing ordered keyword priorities. Rationale is heuristic. It does not
understand negation, sarcasm or actual incident impact. A human can escalate immediately.

Telemetry selection requires a set or frozenset allowlist of exact lookup names.
A string cannot authorize substring matches. Duplicate requests collapse and
refusals are recorded deterministically. Denied payloads are never inspected.
The caller is responsible for approving the allowlist and supplying authorized data.

## Input integrity and limits

Requests and catalogs must be finite JSON-shaped data with string object keys.
Catalogs/lookup requests allow up to 5,000 entries, identifiers 512 characters,
text 128 KiB, serialized models 8 MiB and nested JSON depth 40. Case result limit
must be an integer from 0 to 100. Invalid input raises ValueError.

Organized requests carry a digest of their sanitized body; downstream functions
reject modified requests. Card construction recomputes classification and rejects
mismatches. Cards preserve raw and organized request digests and their own content
digest. Unsalted hashes are not anonymization, authentication or authorization;
low-entropy raw data may be guessable. Returned objects are detached snapshots.

## Compatibility and validation

Version 0.1.1-partial -> 0.1.2a1 adds request provenance and organized_digest,
changes classification substring matching and duplicate lookup handling, and
replaces interpolated customer text with a fixed draft. Regenerate organized
requests and cards; construct requests with organize_request before low-level APIs.

57 tests include 22 inherited checks and 35 new regressions. Source and installed
wheel results are in [CHECK_RUNS](docs/CHECK_RUNS.json), with the [audit](docs/AUDIT.md)
and [security boundaries](SECURITY.md). CI covers Linux Python 3.10/3.12/3.14 and
Windows Python 3.12.

Live ticket/CRM connectors, identity/tenant enforcement, human-review UI, model-based
classification and the original 210-parent roadmap remain outside this candidate.
No production readiness or complete PII removal is claimed.

## License

Copyright 2026 **RUSSELL PHILIP SMITHSON**.
[Apache License 2.0](LICENSE), with [NOTICE](NOTICE).
No third-party code is vendored.
