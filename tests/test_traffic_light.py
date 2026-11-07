import unittest

from backend.models.enums import TrafficLight as L
from backend.models.enums import Verdict as V
from backend.models.enums import YellowReason as R
from backend.policies.traffic_light import Assessment, decide


def A(**kw):
    base = dict(verdict=V.TRUE_POSITIVE, confidence=0.9, evidence_count=3)
    base.update(kw)
    return Assessment(**base)


class TrafficLightTests(unittest.TestCase):
    def test_red_requires_tp_with_enough_evidence(self):
        d = decide(A())
        self.assertEqual((d.light, d.verdict), (L.RED, V.TRUE_POSITIVE))

    def test_red_with_single_evidence_goes_yellow(self):
        d = decide(A(evidence_count=1))
        self.assertEqual(d.light, L.YELLOW)
        self.assertIn(R.UNSUPPORTED_CLAIM, d.reasons)

    def test_green_needs_positive_legitimacy_evidence(self):
        ok = decide(A(verdict=V.BENIGN_TRUE_POSITIVE, evidence_count=1, has_legitimacy_evidence=True))
        self.assertEqual(ok.light, L.GREEN)
        no = decide(A(verdict=V.FALSE_POSITIVE, evidence_count=1, has_legitimacy_evidence=False))
        self.assertEqual(no.light, L.YELLOW)  # "no encontré nada malo" no basta

    def test_tool_failure_is_never_green(self):
        d = decide(A(verdict=V.FALSE_POSITIVE, evidence_count=2, has_legitimacy_evidence=True, tool_failures=["cmdb_asset"]))
        self.assertEqual(d.light, L.YELLOW)
        self.assertIn(R.TOOL_FAILED, d.reasons)

    def test_empty_required_result_is_yellow(self):
        d = decide(A(empty_required=["cmdb_asset"]))
        self.assertIn(R.EMPTY_RESULT, d.reasons)

    def test_tp_with_authorized_change_is_contradictory(self):
        d = decide(A(authorized_change=True))
        self.assertEqual(d.light, L.YELLOW)
        self.assertIn(R.CONTRADICTORY_EVIDENCE, d.reasons)

    def test_low_confidence(self):
        d = decide(A(confidence=0.5))
        self.assertIn(R.LOW_CONFIDENCE, d.reasons)

    def test_critical_asset_requires_more_certainty_to_dismiss(self):
        d = decide(A(verdict=V.FALSE_POSITIVE, confidence=0.8, evidence_count=2,
                     has_legitimacy_evidence=True, asset_criticality="critical"))
        self.assertIn(R.CRITICAL_ASSET_AMBIGUOUS, d.reasons)

    def test_injection_and_missing_runbook(self):
        d = decide(A(injection_detected=True, runbook_found=False))
        self.assertEqual({R.POSSIBLE_PROMPT_INJECTION, R.NO_RUNBOOK}, set(d.reasons))

    def test_undetermined_is_always_yellow_with_explanation(self):
        d = decide(Assessment(verdict=V.UNDETERMINED, confidence=0.0))
        self.assertEqual((d.light, d.verdict), (L.YELLOW, V.UNDETERMINED))
        self.assertTrue(d.reasons and d.missing)

    def test_yellow_always_explains_what_is_missing(self):
        d = decide(A(injection_detected=True))
        self.assertTrue(d.missing)


if __name__ == "__main__":
    unittest.main()
