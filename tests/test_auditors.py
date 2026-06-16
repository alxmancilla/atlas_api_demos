import json
import os
import unittest
from unittest.mock import patch

import requests

import atlas_ip_access_analyzer as ip_analyzer
import atlas_organization_security_audit as org_audit
import atlas_security_auditor as auditor


class FakeResponse:
    def __init__(self, status_code, json_data=None, text=None, headers=None):
        self.status_code = status_code
        self._json_data = json_data
        self.text = text if text is not None else (json.dumps(json_data) if json_data is not None else "")
        self.headers = headers or {}

    def json(self):
        if self._json_data is None:
            raise ValueError("no JSON")
        return self._json_data

    def raise_for_status(self):
        if not 200 <= self.status_code < 300:
            error = requests.exceptions.HTTPError()
            error.response = self
            raise error


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.headers = {}
        self.auth = None

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class AuditTests(unittest.TestCase):
    def test_organization_uses_shared_check_status_for_overall_status(self):
        result = org_audit.ProjectAuditResult(
            "project-id",
            "Project",
            [auditor.CheckResult("Check", auditor.CheckStatus.FAIL)],
        )

        self.assertIs(result.overall_status(), auditor.CheckStatus.FAIL)

    def test_project_auditor_defaults_to_dry_run(self):
        env = {
            "ATLAS_PUBLIC_KEY": "public",
            "ATLAS_PRIVATE_KEY": "private",
            "ATLAS_PROJECT_ID": "project-id",
        }

        with patch.dict(os.environ, env, clear=True):
            self.assertTrue(auditor.load_config()["DRY_RUN"])

    def test_organization_auditor_defaults_to_dry_run(self):
        env = {
            "ATLAS_PUBLIC_KEY": "public",
            "ATLAS_PRIVATE_KEY": "private",
            "ATLAS_ORG_ID": "org-id",
        }

        with patch.dict(os.environ, env, clear=True):
            self.assertTrue(org_audit.load_config()["DRY_RUN"])

    def test_get_all_pages_fetches_until_total_count(self):
        client = auditor.AtlasClient("public", "private")
        pages = iter([
            {"results": [{"id": "one"}], "totalCount": 3},
            {"results": [{"id": "two"}, {"id": "three"}], "totalCount": 3},
        ])
        endpoints = []

        def fake_get(endpoint):
            endpoints.append(endpoint)
            return next(pages)

        client.get = fake_get

        self.assertEqual(
            client.get_all_pages("/groups/project-id/accessList"),
            [{"id": "one"}, {"id": "two"}, {"id": "three"}],
        )
        self.assertEqual(
            endpoints,
            [
                "/groups/project-id/accessList?pageNum=1&itemsPerPage=100",
                "/groups/project-id/accessList?pageNum=2&itemsPerPage=100",
            ],
        )

    def test_shared_client_retries_transient_status_and_sets_timeout(self):
        client = auditor.AtlasClient("public", "private", timeout=12, max_retries=1)
        client.session = FakeSession([
            FakeResponse(500, {"error": "temporary"}),
            FakeResponse(200, {"ok": True}),
        ])

        with patch("atlas_security_auditor.time.sleep"):
            self.assertEqual(client.get("/groups/project-id"), {"ok": True})

        self.assertEqual(len(client.session.calls), 2)
        self.assertEqual(client.session.calls[0][2]["timeout"], 12)

    def test_dry_run_mutations_do_not_call_network(self):
        client = auditor.AtlasClient("public", "private", dry_run=True)
        client.session = FakeSession([AssertionError("network should not be called")])

        self.assertEqual(client.delete("/groups/project-id/accessList/0.0.0.0%2F0"), {})

    def test_ip_analyzer_marks_incomplete_results(self):
        results = {
            "checked": ip_analyzer.ProjectIPResult(["192.0.2.10/32"], False),
            "failed": ip_analyzer.ProjectIPResult([], False, "Atlas API Error: 500"),
        }

        self.assertTrue(ip_analyzer.has_incomplete_results(results))

    def test_ip_analyzer_client_retries_transient_status_and_sets_timeout(self):
        client = ip_analyzer.AtlasAPIClient("public", "private", timeout=7, max_retries=1)
        client.session = FakeSession([
            FakeResponse(503, {"error": "temporary"}),
            FakeResponse(200, {"ok": True}),
        ])

        with patch("atlas_ip_access_analyzer.time.sleep"):
            self.assertEqual(client._make_request("groups/project-id"), {"ok": True})

        self.assertEqual(len(client.session.calls), 2)
        self.assertEqual(client.session.calls[0][2]["timeout"], 7)


if __name__ == "__main__":
    unittest.main()
