# Security and privacy boundaries

This package transforms caller-supplied data. It has no messaging, network retrieval,
account mutation or customer-routing capability. Telemetry allowlists and policy
catalogs are assertions by the caller, not independently checked permissions.

Pattern-based redaction is incomplete. Unrecognized names, addresses, identifiers,
encoded/obfuscated secrets and personal information may remain. Do not treat
draft_leak_screen.clean as certification of the entire card. It applies only to
the fixed acknowledgment. Human privacy review is mandatory before sharing.

Explicit product/region scope avoids simple cross-scope matching, but unscoped
legacy cases remain eligible. The caller must enforce tenant access, authorization,
data minimization, retention and catalog ownership outside this library.

Canonical digests detect accidental changes. They do not authenticate data and can
be recomputed by callers. Raw request hashes are unsalted and may permit guessing
low-entropy content. Do not publish them as a substitute for anonymization.

The classifier is an ordered keyword heuristic. It can misinterpret negation,
context and impact. Similarity does not validate a resolution, and policy selection
does not establish legal applicability. Immediate human escalation remains available.

JSON/text/count/depth limits protect normal boundaries, not malicious in-process
Python code or process resource exhaustion. Exposed services need request limits
and isolation before deserialization. No third-party runtime dependencies exist;
no build-tool vulnerability scan is claimed. Report defects privately using
synthetic, sanitized reproductions.
