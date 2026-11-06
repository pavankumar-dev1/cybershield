import unittest

from app import app


class InvalidJsonRequestTests(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_endpoints_reject_malformed_json(self):
        endpoints = [
            "/api/footprint",
            "/api/password",
            "/api/phishing",
            "/api/permissions",
            "/api/wifi",
            "/api/scan-all",
        ]

        for endpoint in endpoints:
            with self.subTest(endpoint=endpoint):
                response = self.client.post(
                    endpoint,
                    data="{not valid json",
                    content_type="application/json",
                )
                self.assertEqual(response.status_code, 400)
                self.assertEqual(
                    response.get_json(),
                    {"error": "Request body must be a valid JSON object"},
                )

    def test_endpoints_reject_non_object_json(self):
        endpoints = [
            "/api/footprint",
            "/api/password",
            "/api/phishing",
            "/api/permissions",
            "/api/wifi",
            "/api/scan-all",
        ]

        for endpoint in endpoints:
            with self.subTest(endpoint=endpoint):
                response = self.client.post(endpoint, json=["unexpected", "array"])
                self.assertEqual(response.status_code, 400)
                self.assertEqual(
                    response.get_json(),
                    {"error": "Request body must be a valid JSON object"},
                )

    def test_endpoints_reject_empty_body(self):
        endpoints = [
            "/api/footprint",
            "/api/password",
            "/api/phishing",
            "/api/permissions",
            "/api/wifi",
            "/api/scan-all",
        ]

        for endpoint in endpoints:
            with self.subTest(endpoint=endpoint):
                response = self.client.post(
                    endpoint,
                    data="",
                    content_type="application/json",
                )
                self.assertEqual(response.status_code, 400)
                self.assertEqual(
                    response.get_json(),
                    {"error": "Request body must be a valid JSON object"},
                )


if __name__ == "__main__":
    unittest.main()
