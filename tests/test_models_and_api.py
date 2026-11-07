"""Pruebas que necesitan pydantic / fastapi (se saltan si no están instalados)."""
import os
import tempfile
import unittest
from datetime import datetime, timezone

try:
    import pydantic  # noqa: F401
    HAS_PYDANTIC = True
except ImportError:
    HAS_PYDANTIC = False

try:
    import fastapi  # noqa: F401
    import httpx  # noqa: F401
    HAS_API = HAS_PYDANTIC
except ImportError:
    HAS_API = False


@unittest.skipUnless(HAS_PYDANTIC, "pydantic no instalado")
class ModelTests(unittest.TestCase):
    def setUp(self):
        from backend.config import get_settings
        from backend.integrations.soc_client import FixtureSOCClient
        from backend.triage.engine import TriageEngine
        from backend.triage.llm import HeuristicJudge
        self.engine = TriageEngine(FixtureSOCClient(), HeuristicJudge(), get_settings())

    def test_engine_results_validate_for_all_fixtures(self):
        from backend.models.enums import TrafficLight as L
        expected = {"ALERT-DEMO-001": L.RED, "ALERT-DEMO-002": L.GREEN, "ALERT-DEMO-003": L.GREEN,
                    "ALERT-DEMO-004": L.YELLOW, "ALERT-DEMO-005": L.YELLOW, "ALERT-DEMO-006": L.YELLOW,
                    "ALERT-NOPE": L.YELLOW}
        for aid, light in expected.items():
            r = self.engine.run(aid)
            self.assertEqual(r.alert_id, aid)
            self.assertEqual(r.light, light, aid)
            self.assertTrue(r.requires_human_approval)

    def test_schema_rejects_incoherent_results(self):
        from pydantic import ValidationError
        from backend.models.triage_result import TriageResult
        base = dict(alert_id="X", confidence=0.9, summary="s", recommended_action="close")
        with self.assertRaises(ValidationError):  # verde sin evidencias
            TriageResult(verdict="false_positive", light="green", **base)
        with self.assertRaises(ValidationError):  # amarillo sin motivos
            TriageResult(verdict="undetermined", light="yellow", missing_information=["x"], **base)
        with self.assertRaises(ValidationError):  # sin aprobación humana
            TriageResult(verdict="undetermined", light="yellow", yellow_reasons=["A1_tool_failed"],
                         missing_information=["x"], requires_human_approval=False, **base)

    def test_human_review_rules(self):
        from backend.models.enums import HumanAction, Status, Verdict
        from backend.review import apply_decision
        yellow = self.engine.run("ALERT-DEMO-004")
        with self.assertRaises(ValueError):  # un amarillo no se acepta tal cual
            apply_decision(yellow, reviewer="ana", action=HumanAction.ACCEPT)
        done = apply_decision(yellow, reviewer="ana", action=HumanAction.CORRECT,
                              final_verdict=Verdict.TRUE_POSITIVE, comment="Es malware")
        self.assertEqual(done.status, Status.CORRECTED)
        with self.assertRaises(ValueError):  # ya decidida
            apply_decision(done, reviewer="ana", action=HumanAction.ESCALATE)

        green = self.engine.run("ALERT-DEMO-002")
        closed = apply_decision(green, reviewer="ana", action=HumanAction.ACCEPT)
        self.assertEqual(closed.status, Status.CLOSED)

    def test_containment_requires_token_when_approved(self):
        from pydantic import ValidationError
        from backend.models.triage_result import ContainmentRequest
        with self.assertRaises(ValidationError):
            ContainmentRequest(target="h", operation="isolate_host", approved=True)


@unittest.skipUnless(HAS_API, "fastapi/httpx no instalados")
class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        os.environ["DB_PATH"] = os.path.join(cls.tmp.name, "test.db")
        os.environ["SOC_CLIENT_MODE"] = "fixture"
        os.environ["LLM_MODE"] = "heuristic"
        from backend.config import get_settings
        get_settings.cache_clear()
        from fastapi.testclient import TestClient
        from backend.main import app
        cls.c = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_full_flow_with_human_approval_for_containment(self):
        r = self.c.post("/alerts/ALERT-DEMO-001/triage")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["light"], "red")
        # sin confirmación explícita no se ejecuta
        no = self.c.post("/alerts/ALERT-DEMO-001/containment", json={"reviewer": "ana", "confirm": False})
        self.assertEqual(no.status_code, 422)
        forged = self.c.post("/alerts/ALERT-DEMO-001/containment", json={"reviewer": "ana", "confirm": "true"})
        self.assertEqual(forged.status_code, 422)
        ok = self.c.post("/alerts/ALERT-DEMO-001/containment", json={"reviewer": "ana", "confirm": True})
        self.assertEqual(ok.status_code, 200)
        self.assertTrue(ok.json()["result"]["containment"]["approved"])
        self.assertTrue(ok.json()["result"]["containment"]["approval_token"].startswith("sha256:"))
        again = self.c.post("/alerts/ALERT-DEMO-001/containment", json={"reviewer": "ana", "confirm": True})
        self.assertEqual(again.status_code, 409)
        replay = self.c.post("/alerts/ALERT-DEMO-001/triage")
        self.assertTrue(replay.json()["containment"]["approved"])
        self.assertEqual([r["event"] for r in self.c.get("/alerts/ALERT-DEMO-001/audit").json()],
                         ["triage", "containment_executed"])

    def test_containment_blocked_for_non_red(self):
        self.c.post("/alerts/ALERT-DEMO-002/triage")
        r = self.c.post("/alerts/ALERT-DEMO-002/containment", json={"reviewer": "ana", "confirm": True})
        self.assertIn(r.status_code, (404, 409))

    def test_decision_and_metrics(self):
        self.c.post("/alerts/ALERT-DEMO-003/triage")
        d = self.c.post("/alerts/ALERT-DEMO-003/decision", json={"reviewer": "ana", "action": "accept"})
        self.assertEqual(d.status_code, 200)
        self.assertEqual(d.json()["status"], "closed")
        replay = self.c.post("/alerts/ALERT-DEMO-003/triage")
        self.assertEqual(replay.json()["status"], "closed")
        m = self.c.get("/metrics").json()
        self.assertGreaterEqual(m["processed"], 1)

    def test_unprocessed_alert_is_404(self):
        self.assertEqual(self.c.get("/alerts/ALERT-DEMO-005").status_code, 404)


if __name__ == "__main__":
    unittest.main()
