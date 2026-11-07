"""Triaje de extremo a extremo sobre los casos de ejemplo (sin pydantic, sin red, sin IA: juez heurístico)."""
import unittest

from backend.config import get_settings
from backend.integrations.soc_client import FixtureSOCClient, SOCClient
from backend.models.enums import TrafficLight as L
from backend.models.enums import Verdict as V
from backend.models.enums import YellowReason as R
from backend.triage.investigation import investigate, is_authorized
from backend.triage.llm import HeuristicJudge, JudgeError, parse_judge_output, extract_json
from backend.triage.records import JudgeEvidence, JudgeOutput


def run(alert_id, client=None, judge=None):
    return investigate(client or FixtureSOCClient(), judge or HeuristicJudge(), get_settings(), alert_id)


class InvestigationTests(unittest.TestCase):
    def test_001_true_positive_is_red_with_containment_proposal(self):
        i = run("ALERT-DEMO-001")
        self.assertEqual((i.decision.light, i.decision.verdict), (L.RED, V.TRUE_POSITIVE))
        self.assertGreaterEqual(len(i.evidence), 2)
        self.assertEqual(i.containment_proposal, {"target": "j.martin", "operation": "disable_account"})
        self.assertEqual(i.severity, "critical")  # activo crítico x severidad alta (matriz placeholder)

    def test_002_authorized_change_is_green_btp(self):
        i = run("ALERT-DEMO-002")
        self.assertEqual((i.decision.light, i.decision.verdict), (L.GREEN, V.BENIGN_TRUE_POSITIVE))
        self.assertTrue(any(e.reference == "CHG-2026-1187" for e in i.evidence))

    def test_003_known_good_is_green_fp(self):
        i = run("ALERT-DEMO-003")
        self.assertEqual((i.decision.light, i.decision.verdict), (L.GREEN, V.FALSE_POSITIVE))

    def test_004_prompt_injection_forces_yellow(self):
        i = run("ALERT-DEMO-004")
        self.assertEqual(i.decision.light, L.YELLOW)
        self.assertIn(R.POSSIBLE_PROMPT_INJECTION, i.decision.reasons)
        self.assertTrue(any("inyección" in w for w in i.warnings))

    def test_005_missing_asset_is_yellow(self):
        i = run("ALERT-DEMO-005")
        self.assertEqual(i.decision.light, L.YELLOW)
        self.assertIn(R.EMPTY_RESULT, i.decision.reasons)

    def test_006_contradictory_evidence_is_yellow(self):
        i = run("ALERT-DEMO-006")
        self.assertEqual(i.decision.light, L.YELLOW)
        self.assertIn(R.CONTRADICTORY_EVIDENCE, i.decision.reasons)

    def test_unknown_alert_is_yellow_not_closed(self):
        i = run("ALERT-NOPE")
        self.assertEqual((i.decision.light, i.decision.verdict), (L.YELLOW, V.UNDETERMINED))

    def test_api_failure_is_visible_and_never_green(self):
        class Broken(FixtureSOCClient):
            def get_asset(self, host):
                raise RuntimeError("API caída")
        i = run("ALERT-DEMO-002", client=Broken())
        self.assertEqual(i.decision.light, L.YELLOW)
        self.assertIn(R.TOOL_FAILED, i.decision.reasons)
        self.assertTrue(any(c.outcome == "error" for c in i.trace))

    def test_hallucinated_references_are_dropped(self):
        class Liar:
            name = "liar"
            def judge(self, context, known_refs):
                return JudgeOutput(V.TRUE_POSITIVE, 0.99, "Ataque", [
                    JudgeEvidence("E-INVENTADO-1", "dato falso", V.TRUE_POSITIVE),
                    JudgeEvidence("E-INVENTADO-2", "otro dato falso", V.TRUE_POSITIVE)])
        i = run("ALERT-DEMO-001", judge=Liar())
        self.assertEqual(i.decision.light, L.YELLOW)
        self.assertEqual(i.evidence, [])
        self.assertIn(R.UNSUPPORTED_CLAIM, i.decision.reasons)

    def test_judge_crash_goes_yellow(self):
        class Crash:
            name = "crash"
            def judge(self, context, known_refs):
                raise RuntimeError("sin conexión con el modelo")
        i = run("ALERT-DEMO-001", judge=Crash())
        self.assertEqual(i.decision.light, L.YELLOW)

    def test_every_evidence_comes_from_a_tool_in_the_trace(self):
        for aid in FixtureSOCClient().list_alert_ids():
            i = run(aid)
            tools = {c.tool for c in i.trace}
            for e in i.evidence:
                self.assertIn(e.source, tools)

    def test_never_executes_containment_during_triage(self):
        c = FixtureSOCClient()
        for aid in c.list_alert_ids():
            run(aid, client=c)
        self.assertEqual(c.containment_log, [])

    def test_containment_requires_token_in_client(self):
        from backend.integrations.soc_client import SOCError
        with self.assertRaises(SOCError):
            FixtureSOCClient().request_containment(target="x", operation="isolate_host", approval_token="")


class HelpersTests(unittest.TestCase):
    def test_authorized_window(self):
        chg = {"status": "approved", "start": "2026-11-03T22:00:00Z", "end": "2026-11-04T02:00:00Z"}
        self.assertTrue(is_authorized(chg, "2026-11-04T00:41:00Z"))
        self.assertFalse(is_authorized(chg, "2026-11-04T05:00:00Z"))
        self.assertFalse(is_authorized({**chg, "status": "pending"}, "2026-11-04T00:41:00Z"))
        self.assertFalse(is_authorized(chg, "fecha-rota"))

    def test_llm_output_parsing(self):
        out = parse_judge_output(extract_json('texto {"verdict":"true_positive","confidence":1.7,"summary":"x",'
                                               '"evidence":[{"reference":"E-1","finding":"f","supports":"true_positive"}]} fin'))
        self.assertEqual(out.verdict, V.TRUE_POSITIVE)
        self.assertEqual(out.confidence, 1.0)  # se acota a [0, 1]
        with self.assertRaises(JudgeError):
            parse_judge_output({"verdict": "quizas"})
        with self.assertRaises(JudgeError):
            extract_json("sin json")


if __name__ == "__main__":
    unittest.main()
