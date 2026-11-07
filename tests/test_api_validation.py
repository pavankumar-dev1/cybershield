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


class InvalidFieldTypeTests(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def assert_bad_request(self, endpoint, payload, expected_error):
        response = self.client.post(endpoint, json=payload)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json(), {"error": expected_error})

    def test_text_fields_reject_non_strings(self):
        cases = [
            ("/api/footprint", {"text": 123}, "text"),
            ("/api/password", {"password": 123}, "password"),
            ("/api/phishing", {"url": ["https://example.com"]}, "url"),
            ("/api/wifi", {"encryption": None}, "encryption"),
            ("/api/scan-all", {"text": False}, "text"),
            ("/api/scan-all", {"password": 123}, "password"),
            ("/api/scan-all", {"url": {}}, "url"),
            ("/api/scan-all", {"encryption": 3}, "encryption"),
        ]

        for endpoint, payload, field in cases:
            with self.subTest(endpoint=endpoint, field=field):
                self.assert_bad_request(
                    endpoint, payload, f"Field '{field}' must be a string"
                )

    def test_permissions_reject_non_string_values(self):
        cases = [
            {"permissions": 123},
            {"permissions": ["CAMERA", 123]},
            {"permissions": {"permission": "CAMERA"}},
        ]

        for payload in cases:
            with self.subTest(payload=payload):
                self.assert_bad_request(
                    "/api/permissions",
                    payload,
                    "Field 'permissions' must be a string or a list of strings",
                )
                self.assert_bad_request(
                    "/api/scan-all",
                    payload,
                    "Field 'permissions' must be a string or a list of strings",
                )

    def test_wifi_public_flag_requires_boolean(self):
        for endpoint in ("/api/wifi", "/api/scan-all"):
            with self.subTest(endpoint=endpoint):
                self.assert_bad_request(
                    endpoint,
                    {"is_public": "false"},
                    "Field 'is_public' must be a boolean",
                )

    def test_permissions_accept_string_and_string_list(self):
        payloads = [
            {"permissions": "CAMERA, READ_SMS"},
            {"permissions": ["CAMERA", "READ_SMS"]},
        ]

        for payload in payloads:
            with self.subTest(payload=payload):
                response = self.client.post("/api/permissions", json=payload)
                self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
