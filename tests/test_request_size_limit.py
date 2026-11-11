import unittest

from app import app


class RequestSizeLimitTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_oversized_json_returns_413_json_error(self):
        payload = b'{"text":"' + (b'a' * (64 * 1024)) + b'"}'

        response = self.client.post(
            "/api/footprint",
            data=payload,
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(
            response.get_json(),
            {"error": "Request body exceeds the 64 KB limit"},
        )


if __name__ == "__main__":
    unittest.main()
