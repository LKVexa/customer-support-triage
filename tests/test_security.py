import copy
import json
import unittest
from unittest.mock import patch
from triage.core import (organize_request, classify, attach_privacy_policy, find_similar_cases,
                        run_telemetry_lookups, build_triage_card, triage, _digest)
from tests.test_triage import RAW, POLICIES, CASES

class SecurityRegressions(unittest.TestCase):
    def request(self, **extra):
        return organize_request(dict(RAW, **extra))

    def test_ticket_and_product_metadata_redacted(self):
        req = self.request(ticket_id="alice@example.com", product="key_abcdefghijklmnop")
        self.assertNotIn("alice@example.com", json.dumps(req))
        self.assertNotIn("abcdefghijklmnop", json.dumps(req))
        self.assertEqual({r["field"] for r in req["redactions"]}, {"ticket_id", "product", "body"})

    def test_bearer_and_github_token_scrubbed(self):
        req = self.request(body="Bearer abcdefghijklmnop ghp_abcdefghijklmnopqrstuv password=private-value")
        self.assertNotIn("abcdefghijklmnop", req["body"])
        self.assertNotIn("private-value", req["body"])

    def test_ssn_and_dotted_phone_scrubbed(self):
        req = self.request(body="123-45-6789 phone 1.212.555.0199")
        self.assertNotIn("123-45", req["body"])
        self.assertNotIn("555", req["body"])

    def test_invalid_metadata_rejected(self):
        for value in ([], {}, True, 7):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.request(product=value)

    def test_request_size_limit(self):
        with patch("triage.core.MAX_TEXT", 10), self.assertRaises(ValueError):
            self.request()

    def test_request_nesting_limit(self):
        with patch("triage.core.MAX_DEPTH", 1), self.assertRaises(ValueError):
            self.request(extra={"nested": {"deep": 1}})

    def test_invalid_json_key_rejected(self):
        with self.assertRaises(ValueError):
            self.request(extra={1: "value"})

    def test_raw_extra_metadata_not_retained(self):
        req = self.request(extra={"secret": "private-value"})
        self.assertNotIn("private-value", json.dumps(req))

    def test_organized_digest_tampering_rejected(self):
        req = self.request()
        req["body"] = "different"
        with self.assertRaises(ValueError):
            classify(req)

    def test_forged_organized_sensitive_text_rejected(self):
        req = self.request()
        req["body"] = "alice@example.com"
        req.pop("organized_digest")
        req["organized_digest"] = _digest(req)
        with self.assertRaises(ValueError):
            classify(req)

    def test_substring_keywords_do_not_trigger_outage(self):
        c = classify(self.request(subject="download question", body="changing my settings"))
        self.assertNotEqual(c["issue_type"], "outage")
        self.assertEqual(c["product_area"], "general")

    def test_multispace_phrase_classification(self):
        c = classify(self.request(subject="cannot   access", body=""))
        self.assertEqual(c["issue_type"], "outage")

    def test_redaction_markers_do_not_create_similar_cases(self):
        req = self.request(subject="alice@example.com", body="")
        self.assertEqual(find_similar_cases(req, [{"case_id": "C", "summary": "redacted email"}]), [])

    def test_policy_snapshot_detached(self):
        policies = copy.deepcopy(POLICIES)
        result = attach_privacy_policy(self.request(), policies)
        policies[0]["policy_id"] = "changed"
        self.assertEqual(result["policy_id"], "PP-EU")

    def test_policy_region_restriction_honored(self):
        policies = [{"policy_id": "EU", "applies_to_products": ["billing-suite"], "applies_to_regions": ["EU"]}]
        self.assertIsNone(attach_privacy_policy(self.request(region="US"), policies))
        self.assertEqual(attach_privacy_policy(self.request(region="EU"), policies)["policy_id"], "EU")
        self.assertIsNone(attach_privacy_policy(self.request(), policies))

    def test_policy_scope_string_rejected(self):
        with self.assertRaises(ValueError):
            attach_privacy_policy(self.request(), [{"policy_id": "P", "applies_to_products": "billing-suite"}])

    def test_duplicate_policy_identity_rejected(self):
        with self.assertRaises(ValueError):
            attach_privacy_policy(self.request(), [POLICIES[0], POLICIES[0]])

    def test_case_resolution_redacted(self):
        result = find_similar_cases(self.request(), [{"case_id": "C", "summary": "billing error",
            "resolution": "Contact alice@example.com with key_abcdefghijklmnop"}])
        self.assertNotIn("alice@example.com", json.dumps(result))
        self.assertNotIn("abcdefghijklmnop", json.dumps(result))

    def test_case_scope_honored(self):
        cases = [{"case_id": "C", "summary": "billing error", "product": "other"}]
        self.assertEqual(find_similar_cases(self.request(), cases), [])

    def test_invalid_case_limit_rejected(self):
        for value in (-1, True, 1.5, 101):
            with self.subTest(value=value), self.assertRaises(ValueError):
                find_similar_cases(self.request(), CASES, limit=value)

    def test_case_id_and_resolution_types_validated(self):
        for value in ({"case_id": 1, "summary": "billing"},
                      {"case_id": "C", "summary": "billing", "resolution": []}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                find_similar_cases(self.request(), [value])

    def test_duplicate_case_id_rejected(self):
        with self.assertRaises(ValueError):
            find_similar_cases(self.request(), [CASES[0], CASES[0]])

    def test_redacted_case_id_collision_rejected(self):
        cases = [{"case_id": ident, "summary": "billing"} for ident in ("a@example.com", "b@example.com")]
        with self.assertRaises(ValueError):
            find_similar_cases(self.request(), cases)

    def test_allowlist_string_cannot_authorize_substring(self):
        with self.assertRaises(ValueError):
            run_telemetry_lookups(["status"], "account_status", {"status": "private"})

    def test_telemetry_nested_values_and_secret_keys_redacted(self):
        result = run_telemetry_lookups(["status"], {"status"},
            {"status": {"password": "private-value", "nested": ["alice@example.com"]}})
        self.assertNotIn("private-value", json.dumps(result))
        self.assertNotIn("alice@example.com", json.dumps(result))

    def test_denied_lookup_never_reads_payload(self):
        result = run_telemetry_lookups(["denied"], set(), {"denied": object()})
        self.assertEqual(result["ran"], {})

    def test_duplicate_lookups_deduplicated(self):
        result = run_telemetry_lookups(["denied", "denied", "status", "status"], {"status"}, {})
        self.assertEqual(len(result["refused"]), 1)
        self.assertEqual(result["ran"], {"status": "NO_DATA"})

    def test_telemetry_order_is_deterministic(self):
        args = ({"a", "b"}, {"a": 1, "b": 2})
        self.assertEqual(run_telemetry_lookups(["a", "b", "x"], *args),
                         run_telemetry_lookups(["x", "b", "a"], *args))

    def test_redaction_key_collisions_fail(self):
        with self.assertRaises(ValueError):
            run_telemetry_lookups(["x"], {"x"}, {"x": {"a@example.com": 1, "b@example.com": 2}})

    def test_telemetry_nonfinite_rejected(self):
        with self.assertRaises(ValueError):
            run_telemetry_lookups(["x"], {"x"}, {"x": float("nan")})

    def test_forged_classification_rejected(self):
        req = self.request()
        c = classify(req)
        c["product_area"] = "secret-team"
        with self.assertRaises(ValueError):
            build_triage_card(req, c, None, [], {"ran": {}, "refused": []})

    def test_draft_never_echoes_arbitrary_subject(self):
        card = triage(dict(RAW, subject="prod-db secret project"), [], [], set(), [], {})
        self.assertNotIn("secret project", card["customer_safe_draft"])
        self.assertNotIn("routed", card["customer_safe_draft"])
        self.assertNotIn("shortly", card["customer_safe_draft"])
        self.assertTrue(card["input_review_flags"])

    def test_card_carries_request_provenance(self):
        card = triage(RAW, POLICIES, CASES, set(), [], {})
        self.assertEqual(card["request_raw_digest"], _digest(RAW))
        expected = card.pop("card_digest")
        self.assertEqual(_digest(card), expected)

    def test_catalog_count_limit(self):
        with patch("triage.core.MAX_RECORDS", 1), self.assertRaises(ValueError):
            find_similar_cases(self.request(), CASES)

    def test_long_nonmatching_text_is_accepted(self):
        # Guards against redaction patterns rejecting ordinary long tokens.
        req = self.request(subject="a"*20000, body="")
        self.assertEqual(req["subject"], "a"*20000)
