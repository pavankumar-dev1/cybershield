# CyberShield API

The Flask application exposes JSON POST endpoints. Send a JSON object with the fields listed below. Request bodies are limited to 64 KB; larger bodies receive HTTP 413 with a JSON error. Invalid JSON, non-object JSON, and fields with unsupported JSON types are rejected with HTTP 400.

| Endpoint | Request fields | Purpose |
|---|---|---|
| `/api/footprint` | `text` (string) | Checks text for configured leak-related keywords |
| `/api/password` | `password` (string) | Scores basic password characteristics |
| `/api/phishing` | `url` (string) | Reports heuristic URL indicators |
| `/api/permissions` | `permissions` (string or list of strings) | Reviews Android-style permission names |
| `/api/wifi` | `encryption` (string), `is_public` (boolean) | Estimates Wi-Fi configuration risk |
| `/api/scan-all` | Any supported fields above | Runs all checks and returns results plus a dashboard |

## Example requests

```bash
curl -X POST http://127.0.0.1:10000/api/phishing \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

```bash
curl -X POST http://127.0.0.1:10000/api/wifi \
  -H "Content-Type: application/json" \
  -d '{"encryption":"WPA3","is_public":false}'
```

## Error format

Validation errors use HTTP 400 and a JSON object containing an `error` message. Requests larger than 64 KB receive HTTP 413. For example:

```json
{"error": "Field 'url' must be a string"}
```

## Interpretation

Statuses are heuristic outputs. In particular, a SAFE result means only that the current rules did not flag the input; it is not a guarantee that the input is safe. See [the security policy](../SECURITY.md).
