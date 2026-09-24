# Audit and hardening — 0.1.2a1

Date: 2026-09-23. Source: JY-S009-P001 / 0.1.1-partial / run-0001 / product.
Reviewed all intake, policy, classification, similarity, telemetry and card code.
Original source remains separate from this maintenance checkout.

## Repaired findings

- Ticket ID/product metadata bypassed redaction; selected case resolutions and
  nested telemetry could reintroduce detected sensitive data. Intake metadata and
  selected downstream content are scrubbed, including common secret dictionary keys.
- The old README claimed no downstream sensitive text could survive. Documentation
  now states the limits of heuristic redaction and requires human privacy review.
- Customer drafts echoed arbitrary subject text and asserted routing/follow-up that
  never occurred. Fixed acknowledgment text removes those unverified claims.
- Arbitrary classification could be interpolated into customer text. Card building
  now recomputes classification and refuses mismatches.
- The organized request had no downstream integrity binding, and the final card
  dropped raw provenance. Organized digests are verified; card provenance is retained.
- Substring matches classified downloading as down and changing as hang. Bounded
  word/phrase matching avoids these cases; redaction placeholders no longer become
  similarity terms.
- Policy scope accepted wrong shapes; case IDs/resolutions/limits were unchecked.
  Strict catalogs, duplicate detection and optional region/product boundaries
  replace ambiguous behavior.
- An allowlist string could authorize lookup substrings. Only sets/frozensets of
  exact names are accepted. Requests deduplicate and sort; denied values are untouched.
- Unbounded text, nesting, catalogs and JSON payloads are now constrained. Generic
  errors omit raw source values. Selected data remains detached from caller objects.
- Redaction collisions in keys/case identities now fail rather than silently merge.

## Verification and release

22 inherited tests passed before changes. The subject-leak assertion now checks
that the fixed draft is clean while input review flags preserve the concern.
57 source and installed-wheel tests pass, including 35 new regressions.
Historical check evidence remains separate. CI covers Linux Python 3.10/3.12/3.14
and Windows Python 3.12.

Version 0.1.1-partial -> 0.1.2a1. Rebuild organized requests/cards and inspect
classification behavior changes. Added packaging, pinned-action CI, README,
security documentation and Apache 2.0 LICENSE/NOTICE naming RUSSELL PHILIP SMITHSON.

There are no third-party runtime dependencies to upgrade or scan. No build-tool
vulnerability scan is claimed. No complete PII removal, access authorization,
legal policy decision or production readiness is asserted.
