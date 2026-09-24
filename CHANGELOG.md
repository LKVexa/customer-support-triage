# 0.1.2a1 — 2026-09-23

- Redact intake metadata and selected nested case/policy/telemetry data.
- Use fixed customer acknowledgment without source echoes or false routing claims.
- Bind organized requests and recompute classification before card assembly.
- Validate catalogs, scope, limits and exact telemetry allowlists.
- Add 35 regressions, packaging, Apache 2.0 LICENSE/NOTICE, README and CI.
- Compatibility: regenerate organized requests/cards; redaction remains heuristic.

# Changelog — Customer Support Triage Assistant (JY-S009-P001)

## 0.1.1-partial — 2026-09-14 (audit A010, repairs only)

Baseline fingerprint: build-0001 product.zip
sha256 8a3320b5f982d912b99e57685dde52095ddc2a35956820d1c97ed19d646f36bb
(baseline version 0.1.0-partial; baseline suite 12/12 PASS before changes).
All findings below were reproduced on the unmodified baseline with live
probes before fixing.

### Fixed

- **A010-F1 (GRD-04 leak-screen bypass via subject).** Observed: subject
  "internal prod-db traceback on server-42" was echoed verbatim into
  customer_safe_draft while draft_leak_screen reported clean=true, because
  the screen stripped the subject before matching. Expected: the whole
  customer-facing draft is screened. Fix: screen the entire draft.
- **A010-F2 (error-contract leak).** Observed: non-string ticket_id/
  subject/body caused a bare TypeError from the regex engine to escape
  organize_request. Expected: the documented ValueError contract. Fix:
  explicit type validation with ValueError.
- **A010-F3 (non-strict canonicalization).** Observed: float('nan') in a
  request was accepted and serialized as the non-JSON token NaN inside the
  provenance digest, making raw_digest non-interoperable. Fix: _digest now
  uses allow_nan=False and raises ValueError for non-canonicalizable input.
- **A010-F4 (aliasing / silent card-integrity break).** Observed: the
  triage card stored caller-supplied mutable objects (classification,
  redactions, similar_cases, telemetry; telemetry results also aliased the
  source dict), so post-build mutation changed card content while
  card_digest stayed stale. Fix: deep-copy into the card and into
  telemetry results.
- **A010-F5 (bare KeyError leak).** Observed: a resolved case missing
  'summary' raised bare KeyError from find_similar_cases. Fix: validate
  entries and raise ValueError naming the offending index.

### Compatibility

Repairs only; no public API added or removed; existing well-formed inputs
produce identical cards except assistant_version and card_digest. New
strictness: non-string request fields, NaN/Infinity values, and malformed
resolved cases now raise ValueError instead of crashing with bare
TypeError/KeyError or passing silently. One baseline behavior was
strengthened (leak screen now covers the echoed subject); no baseline test
asserted the old behavior, so none were weakened.

### Rollback

Restore build-0001 product.zip (sha256 above). No data-format or storage
migration involved.
