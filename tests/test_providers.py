from __future__ import annotations

import json
import os
import unittest
from unittest.mock import patch

from pp.models import ContextSlice
from pp.providers import create_provider
from pp.providers.base import ProposalInput
from pp.providers.local import LocalPatchProposer
from pp.providers.openai import OpenAIPatchProposer


class _FakeHTTPResponse:
    def __init__(self, payload: str) -> None:
        self._payload = payload.encode("utf-8")

    def read(self) -> bytes:
        return self._payload

    def __enter__(self) -> "_FakeHTTPResponse":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        del exc_type, exc, tb
        return False


class ProviderTests(unittest.TestCase):
    def test_create_provider_local_aliases(self) -> None:
        for alias in ["local", "local-openai", "vllm", "lmstudio"]:
            provider = create_provider(alias)
            self.assertIsInstance(provider, LocalPatchProposer)

    def test_openai_provider_requires_key(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RuntimeError):
                OpenAIPatchProposer()

    def test_local_provider_uses_openai_compatible_endpoint(self) -> None:
        captured: dict[str, object] = {}

        def fake_urlopen(req: object, timeout: int = 0) -> _FakeHTTPResponse:
            captured["timeout"] = timeout
            full_url = req.full_url  # type: ignore[attr-defined]
            captured["url"] = full_url
            body_raw = req.data.decode("utf-8", errors="replace")  # type: ignore[attr-defined]
            captured["body"] = json.loads(body_raw)
            captured["headers"] = dict(req.header_items())  # type: ignore[attr-defined]
            content = (
                "```json\n"
                "{"
                "\"diff\":\"--- a/x.txt\\n+++ b/x.txt\\n@@ -1 +1 @@\\n-a\\n+b\\n\","
                "\"rationale\":\"fix value\","
                "\"risk_notes\":\"low\","
                "\"confidence\":0.7"
                "}\n"
                "```"
            )
            raw = json.dumps({"choices": [{"message": {"content": content}}]})
            return _FakeHTTPResponse(raw)

        with patch("pp.providers.openai_compatible.request.urlopen", side_effect=fake_urlopen):
            with patch.dict(
                os.environ,
                {
                    "PP_LOCAL_BASE_URL": "http://127.0.0.1:8000/v1",
                    "PP_LOCAL_MODEL": "Qwen/Qwen2.5-Coder-7B-Instruct",
                    "PP_LOCAL_TIMEOUT_SEC": "5",
                },
                clear=False,
            ):
                provider = LocalPatchProposer()
                proposal = provider.propose(
                    ProposalInput(
                        command="pytest -q",
                        failure_output="AssertionError: expected b got a",
                        context=ContextSlice(
                            locations=[],
                            snippets={"x.txt:1": "a"},
                            failing_assertions=["expected b got a"],
                        ),
                        previous_attempts=[],
                        write_allowlist=["x.txt"],
                        deny_write=[],
                    )
                )

        self.assertIn("+++ b/x.txt", proposal.diff)
        self.assertEqual("fix value", proposal.rationale)
        self.assertEqual("low", proposal.risk_notes)
        self.assertEqual(0.7, proposal.confidence)
        self.assertEqual(captured["url"], "http://127.0.0.1:8000/v1/chat/completions")
        body = captured["body"]
        self.assertEqual(body["model"], "Qwen/Qwen2.5-Coder-7B-Instruct")
        self.assertEqual(captured["timeout"], 5)
        headers = captured["headers"]
        self.assertNotIn("Authorization", headers)

    def test_local_provider_fallback_rewrites_single_file_on_empty_diff(self) -> None:
        responses = [
            json.dumps(
                {
                    "choices": [
                        {
                            "message": {
                                "content": (
                                    '{"diff":"","rationale":"need sort",'
                                    '"risk_notes":"low","confidence":0.6}'
                                )
                            }
                        }
                    ]
                }
            ),
            json.dumps(
                {
                    "choices": [
                        {
                            "message": {
                                "content": (
                                    '{"diff":"","rationale":"retry empty",'
                                    '"risk_notes":"low","confidence":0.4}'
                                )
                            }
                        }
                    ]
                }
            ),
            json.dumps(
                {
                    "choices": [
                        {
                            "message": {
                                "content": (
                                    '{"path":"stats_utils.py",'
                                    '"content":"def median(values):\\n'
                                    '    ordered = sorted(values)\\n'
                                    '    mid = len(ordered) // 2\\n'
                                    '    return ordered[mid]",'
                                    '"rationale":"sort before indexing",'
                                    '"risk_notes":"low","confidence":0.8}'
                                )
                            }
                        }
                    ]
                }
            ),
        ]
        call_count = {"n": 0}

        def fake_urlopen(req: object, timeout: int = 0) -> _FakeHTTPResponse:
            del req, timeout
            idx = call_count["n"]
            call_count["n"] += 1
            return _FakeHTTPResponse(responses[idx])

        with patch("pp.providers.openai_compatible.request.urlopen", side_effect=fake_urlopen):
            with patch.dict(
                os.environ,
                {
                    "PP_LOCAL_BASE_URL": "http://127.0.0.1:8000/v1",
                    "PP_LOCAL_MODEL": "Qwen/Qwen2.5-Coder-7B-Instruct",
                    "PP_LOCAL_TIMEOUT_SEC": "5",
                },
                clear=False,
            ):
                provider = LocalPatchProposer()
                proposal = provider.propose(
                    ProposalInput(
                        command="python -m unittest discover -s tests -v",
                        failure_output="AssertionError: 1 != 5",
                        context=ContextSlice(
                            locations=[],
                            snippets={"tests/test_stats.py:8": "assert median([9, 1, 5]) == 5"},
                            failing_assertions=["AssertionError: 1 != 5"],
                        ),
                        previous_attempts=[],
                        write_allowlist=["stats_utils.py"],
                        deny_write=[],
                        editable_files={
                            "stats_utils.py": (
                                "def median(values):\n"
                                "    ordered = list(values)\n"
                                "    mid = len(ordered) // 2\n"
                                "    return ordered[mid]\n"
                            )
                        },
                    )
                )

        self.assertEqual(call_count["n"], 3)
        self.assertIn("+++ b/stats_utils.py", proposal.diff)
        self.assertIn("sorted(values)", proposal.diff)

    @unittest.skipUnless(os.getenv("PP_RUN_LOCAL_LM_SMOKE") == "1", "Set PP_RUN_LOCAL_LM_SMOKE=1")
    def test_local_model_smoke(self) -> None:
        # This test intentionally runs only when user opts in with a live local model server.
        with patch.dict(
            os.environ,
            {
                "PP_LOCAL_MODEL": os.getenv("PP_LOCAL_MODEL", "Qwen/Qwen2.5-Coder-7B-Instruct"),
                "PP_LOCAL_BASE_URL": os.getenv("PP_LOCAL_BASE_URL", "http://127.0.0.1:8000/v1"),
                "PP_LOCAL_TIMEOUT_SEC": os.getenv("PP_LOCAL_TIMEOUT_SEC", "240"),
            },
            clear=False,
        ):
            provider = LocalPatchProposer()
            proposal = provider.propose(
                ProposalInput(
                    command="python -m pytest -q",
                    failure_output="AssertionError: expected 2 but got 1",
                    context=ContextSlice(
                        locations=[],
                        snippets={"tests/test_math.py:12": "assert add(1, 1) == 2"},
                        failing_assertions=["assert add(1, 1) == 2"],
                    ),
                    previous_attempts=[],
                    write_allowlist=["src/**", "tests/**"],
                    deny_write=[],
                )
            )
        self.assertIsInstance(proposal.diff, str)
        self.assertIsInstance(proposal.rationale, str)


if __name__ == "__main__":
    unittest.main()
