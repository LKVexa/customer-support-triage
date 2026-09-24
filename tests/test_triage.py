import unittest

from triage.core import (_digest, attach_privacy_policy, build_triage_card,
                         classify, find_similar_cases, organize_request,
                         run_telemetry_lookups, triage)

RAW = {"ticket_id": "T-100",
       "subject": "Cannot access billing after payment",
       "body": ("I was overcharged and want a refund. My email is "
                "alice@example.com and card 4111 1111 1111 1111. "
                "The app shows an error every time."),
       "product": "billing-suite"}

POLICIES = [{"policy_id": "PP-EU", "applies_to_products": ["billing-suite"]},
            {"policy_id": "PP-GENERIC", "applies_to_products": ["*"]}]

CASES = [{"case_id": "C-9", "summary": "customer overcharged refund billing error",
          "resolution": "refunded duplicate charge"},
         {"case_id": "C-2", "summary": "password reset loop on mobile",
          "resolution": "cleared token cache"}]


class Redaction(unittest.TestCase):
    def test_redacts_before_anything_else(self):
        req = organize_request(RAW)
        self.assertNotIn("alice@example.com", req["body"])
        self.assertNotIn("4111", req["body"])
        kinds = {r["kind"] for r in req["redactions"]}
        self.assertEqual(kinds, {"email", "card_number"})

    def test_missing_fields_rejected(self):
        with self.assertRaises(ValueError):
            organize_request({"ticket_id": "x"})


class Classification(unittest.TestCase):
    def test_classifies_with_rationale(self):
        c = classify(organize_request(RAW))
        self.assertEqual(c["product_area"], "billing")
        self.assertEqual(c["issue_type"], "outage")  # "cannot access" outranks error keyword
        self.assertEqual(c["severity"], "high")     # "cannot access"
        self.assertTrue(any("matched" in r for r in c["rationale"]))

    def test_default_with_recorded_rationale(self):
        c = classify(organize_request({"ticket_id": "T", "subject": "hmm",
                                       "body": "something odd"}))
        self.assertEqual(c["product_area"], "general")
        self.assertTrue(any("defaulted" in r for r in c["rationale"]))


class PolicyAndCases(unittest.TestCase):
    def test_specific_policy_wins(self):
        p = attach_privacy_policy(organize_request(RAW), POLICIES)
        self.assertEqual(p["policy_id"], "PP-EU")

    def test_generic_fallback_and_ambiguity(self):
        req = organize_request({"ticket_id": "T", "subject": "x", "body": "y",
                                "product": "other"})
        self.assertEqual(attach_privacy_policy(req, POLICIES)["policy_id"],
                         "PP-GENERIC")
        two = [{"policy_id": "A", "applies_to_products": ["other"]},
               {"policy_id": "B", "applies_to_products": ["other"]}]
        self.assertIsNone(attach_privacy_policy(req, two))   # ambiguity -> gap

    def test_similar_cases_ranked(self):
        sims = find_similar_cases(organize_request(RAW), CASES)
        self.assertEqual(sims[0]["case_id"], "C-9")
        self.assertIn("refund", sims[0]["shared_terms"])


class Telemetry(unittest.TestCase):
    def test_only_preapproved_lookups_run(self):
        res = run_telemetry_lookups(
            ["account_status", "raw_db_dump"],
            allowlist={"account_status", "recent_errors"},
            lookup_results={"account_status": "active"})
        self.assertEqual(res["ran"], {"account_status": "active"})
        self.assertEqual(res["refused"][0]["lookup"], "raw_db_dump")
        self.assertIn("allowlist", res["refused"][0]["reason"])


class Card(unittest.TestCase):
    def setUp(self):
        self.card = triage(RAW, POLICIES, CASES,
                           telemetry_allowlist={"account_status"},
                           telemetry_requests=["account_status", "raw_db_dump"],
                           telemetry_results={"account_status": "active"})

    def test_guardrails_structural(self):
        self.assertTrue(self.card["draft_only"])
        self.assertTrue(self.card["human_agent_required"])
        self.assertFalse(self.card["sent"])
        self.assertTrue(self.card["escalation"]["available"])   # GRD-03
        import triage.core as m
        for name in dir(m):
            for bad in ("send", "reply", "message_customer", "post", "email_"):
                self.assertNotIn(bad, name.lower())

    def test_customer_safe_draft_clean(self):
        self.assertTrue(self.card["draft_leak_screen"]["clean"])
        self.assertNotIn("alice@example.com", self.card["customer_safe_draft"])
        self.assertNotIn("REDACTED", self.card["customer_safe_draft"])

    def test_card_carries_everything(self):
        self.assertEqual(self.card["privacy_policy"], "PP-EU")
        self.assertEqual(self.card["similar_cases"][0]["case_id"], "C-9")
        self.assertEqual(self.card["telemetry"]["ran"],
                         {"account_status": "active"})
        self.assertTrue(self.card["redactions_applied"])
        self.assertTrue(self.card["card_digest"].startswith("sha256:"))

    def test_deterministic(self):
        again = triage(RAW, POLICIES, CASES,
                       telemetry_allowlist={"account_status"},
                       telemetry_requests=["account_status", "raw_db_dump"],
                       telemetry_results={"account_status": "active"})
        self.assertEqual(self.card, again)


class HardeningFixes(unittest.TestCase):
    """Focused tests for audit A010 findings (v0.1.1-partial)."""

    # A010-F1 — leak screen must cover the echoed subject
    def test_subject_leaks_are_screened(self):
        card = triage({"ticket_id": "T-L", "body": "it fails",
                       "subject": "internal prod-db traceback on server-42"},
                      [], [], set(), [], {})
        self.assertTrue(card["draft_leak_screen"]["clean"])
        self.assertTrue(card["input_review_flags"])
        self.assertNotIn("prod-db", card["customer_safe_draft"])

    def test_clean_subject_still_clean(self):
        card = triage({"ticket_id": "T-C", "subject": "billing question",
                       "body": "how do i get an invoice"}, [], [], set(), [], {})
        self.assertTrue(card["draft_leak_screen"]["clean"])

    # A010-F2 — documented ValueError contract for bad field types
    def test_non_string_fields_raise_valueerror(self):
        for bad in ({"ticket_id": "T", "subject": 123, "body": "x"},
                    {"ticket_id": "T", "subject": "x", "body": None},
                    {"ticket_id": 7, "subject": "x", "body": "y"}):
            with self.assertRaises(ValueError):
                organize_request(bad)

    def test_string_fields_still_accepted(self):
        self.assertEqual(organize_request(
            {"ticket_id": "T", "subject": "s", "body": "b"})["ticket_id"], "T")

    # A010-F3 — strict canonicalization: NaN/Infinity rejected
    def test_nan_rejected_in_digest(self):
        with self.assertRaises(ValueError):
            organize_request({"ticket_id": "T", "subject": "a", "body": "b",
                              "extra": float("nan")})
        with self.assertRaises(ValueError):
            _digest({"x": float("inf")})

    def test_finite_floats_still_digest(self):
        self.assertTrue(_digest({"x": 1.5}).startswith("sha256:"))

    # A010-F4 — card isolation: later mutation of inputs must not alter card
    def test_card_isolated_from_input_mutation(self):
        req = organize_request({"ticket_id": "T", "subject": "login broken",
                                "body": "cannot access"})
        cls = classify(req)
        card = build_triage_card(req, cls, None, [],
                                 {"ran": {}, "refused": []})
        d0 = card["card_digest"]
        cls["severity"] = "low"
        req["redactions"].append({"field": "body", "kind": "email"})
        self.assertNotEqual(card["classification"]["severity"], "low")
        recomputed = _digest({k: v for k, v in card.items()
                              if k != "card_digest"})
        self.assertEqual(recomputed, d0)

    def test_telemetry_results_isolated(self):
        src = {"cpu": {"v": 1}}
        out = run_telemetry_lookups(["cpu"], {"cpu"}, src)
        src["cpu"]["v"] = 999
        self.assertEqual(out["ran"]["cpu"], {"v": 1})

    # A010-F5 — malformed resolved case raises ValueError, not KeyError
    def test_malformed_resolved_case_valueerror(self):
        req = organize_request({"ticket_id": "T", "subject": "login",
                                "body": "cannot access"})
        with self.assertRaises(ValueError):
            find_similar_cases(req, [{"case_id": "C1"}])
        with self.assertRaises(ValueError):
            find_similar_cases(req, ["not-a-dict"])

    def test_wellformed_cases_still_ranked(self):
        req = organize_request({"ticket_id": "T", "subject": "login",
                                "body": "cannot access login"})
        sims = find_similar_cases(req, [{"case_id": "C1",
                                         "summary": "login access issue",
                                         "resolution": "reset"}])
        self.assertEqual(sims[0]["case_id"], "C1")


if __name__ == "__main__":
    unittest.main()
