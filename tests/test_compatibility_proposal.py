import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import propose_compatibility as proposal


class ProposalTests(unittest.TestCase):
    def evidence(self):
        return {"candidate_codex_version": "0.162.0", "supported_codex_version": proposal.supported_version(),
                "status": "needs-review", "live_relay_validated": False, "schema_changes": ["changed: Initialize.json"]}

    def test_untrusted_evidence_cannot_claim_live_validation_or_inject_pr_body(self):
        proposal.validate_evidence(self.evidence(), "0.162.0")
        for key, value in [("live_relay_validated", True), ("status", "passed\n- [x] approved"),
                           ("candidate_codex_version", "0.163.0"), ("schema_changes", "bad")]:
            evidence = self.evidence()
            evidence[key] = value
            with self.assertRaises(ValueError):
                proposal.validate_evidence(evidence, "0.162.0")

    def exercise(self, responses, failure=False):
        calls = []
        def fake_run(*args):
            calls.append(args)
            if args[:3] == ("gh", "pr", "list") or args[:3] == ("gh", "issue", "list"):
                return responses.get("existing", "[]")
            if args[:2] == ("git", "ls-remote"):
                return responses.get("branch", "")
            if args[:2] == ("git", "show"):
                return json.dumps(self.evidence())
            return "example-sha"
        with tempfile.TemporaryDirectory() as temporary:
            previous = pathlib.Path.cwd()
            try:
                os.chdir(temporary)
                path = pathlib.Path("compatibility/candidates/0.162.0.json")
                path.parent.mkdir(parents=True)
                path.write_text(json.dumps(self.evidence()))
                environment = {"GITHUB_REPOSITORY": "example/rcodex", "GITHUB_RUN_ID": "123",
                               "CANDIDATE": "0.162.0", "DEFAULT_BRANCH": "main"}
                with patch.dict(os.environ, environment), patch.object(sys, "argv", ["proposal"] + (["--failure"] if failure else [])), \
                        patch.object(proposal, "run", fake_run), patch.object(proposal, "write_body") as create:
                    proposal.main()
                    return calls, create.call_args
            finally:
                os.chdir(previous)

    def test_proposal_is_draft_with_unchecked_personal_test_signoff(self):
        calls, create = self.exercise({})
        self.assertIn(("git", "push", "origin", "automation/codex-compatibility-0.162.0"), calls)
        self.assertIn("--draft", create.args)
        self.assertIn("- [ ] I personally tested", create.args[2])
        self.assertNotIn("- [x]", create.args[2])

    def test_existing_proposal_is_not_rewritten(self):
        calls, create = self.exercise({"existing": '[{"number": 42}]'})
        self.assertIsNone(create)
        self.assertFalse(any(call[0] == "git" for call in calls))

    def test_retry_after_successful_push_recovers_without_pushing_again(self):
        calls, create = self.exercise({"branch": "example-sha refs/heads/automation/codex-compatibility-0.162.0"})
        self.assertIsNotNone(create)
        self.assertFalse(any(call[:2] == ("git", "push") for call in calls))

    def test_failure_issues_are_deduplicated(self):
        _, create = self.exercise({}, failure=True)
        self.assertEqual(create.args[0], "issue")
        _, create = self.exercise({"existing": '[{"title": "Codex compatibility check needs attention"}]'}, failure=True)
        self.assertIsNone(create)


if __name__ == "__main__":
    unittest.main()
