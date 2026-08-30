from __future__ import annotations

import importlib
import io
import json
import os
import pathlib
import sys
import unittest
from types import SimpleNamespace
from unittest import mock
from urllib.error import HTTPError, URLError


LAMBDA_DIR = pathlib.Path(__file__).parents[1] / "lambda"
sys.path.insert(0, str(LAMBDA_DIR))
os.environ["BASE_URL"] = "https://homeassistant.example.invalid"
os.environ["LOG_LEVEL"] = "INFO"
lambda_function = importlib.import_module("lambda_function")


class FakeResponse:
    def __init__(self, body: dict | bytes, status: int = 200):
        self.body = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit: int) -> bytes:
        return self.body


def discovery_event(token: str | None = "secret-discovery-token") -> dict:
    scope = {"type": "BearerToken"}
    if token is not None:
        scope["token"] = token
    return {
        "directive": {
            "header": {
                "namespace": "Alexa.Discovery",
                "name": "Discover",
                "payloadVersion": "3",
                "messageId": "test-message",
            },
            "payload": {"scope": scope},
        }
    }


def control_event(token: str = "secret-control-token") -> dict:
    return {
        "directive": {
            "header": {
                "namespace": "Alexa.PowerController",
                "name": "TurnOn",
                "payloadVersion": "3",
                "messageId": "test-message",
                "correlationToken": "correlation-token",
            },
            "endpoint": {
                "scope": {"type": "BearerToken", "token": token},
                "endpointId": "light#licht_2",
            },
            "payload": {},
        }
    }


class LambdaHandlerTest(unittest.TestCase):
    context = SimpleNamespace(aws_request_id="aws-request-id")

    @mock.patch.object(lambda_function.urllib.request, "urlopen")
    def test_discovery_forwards_to_home_assistant(self, urlopen):
        expected = {"event": {"header": {"name": "Discover.Response"}, "payload": {"endpoints": []}}}
        urlopen.return_value = FakeResponse(expected)

        actual = lambda_function.lambda_handler(discovery_event(), self.context)

        self.assertEqual(expected, actual)
        request = urlopen.call_args.args[0]
        self.assertEqual("https://homeassistant.example.invalid/api/alexa/smart_home", request.full_url)
        self.assertEqual("Bearer secret-discovery-token", request.headers["Authorization"])
        self.assertEqual(6.5, urlopen.call_args.kwargs["timeout"])

    @mock.patch.object(lambda_function.urllib.request, "urlopen")
    def test_control_token_is_read_from_endpoint_scope(self, urlopen):
        expected = {"event": {"header": {"name": "Response"}, "payload": {}}}
        urlopen.return_value = FakeResponse(expected)

        actual = lambda_function.lambda_handler(control_event(), self.context)

        self.assertEqual(expected, actual)
        request = urlopen.call_args.args[0]
        self.assertEqual("Bearer secret-control-token", request.headers["Authorization"])

    @mock.patch.object(lambda_function.urllib.request, "urlopen")
    def test_missing_token_is_rejected_without_origin_call(self, urlopen):
        actual = lambda_function.lambda_handler(discovery_event(token=None), self.context)

        self.assertEqual("INVALID_AUTHORIZATION_CREDENTIAL", actual["event"]["payload"]["type"])
        urlopen.assert_not_called()

    @mock.patch.object(lambda_function.urllib.request, "urlopen")
    def test_payload_v2_is_rejected(self, urlopen):
        event = discovery_event()
        event["directive"]["header"]["payloadVersion"] = "2"

        actual = lambda_function.lambda_handler(event, self.context)

        self.assertEqual("INVALID_DIRECTIVE", actual["event"]["payload"]["type"])
        urlopen.assert_not_called()

    @mock.patch.object(lambda_function.urllib.request, "urlopen")
    def test_unauthorized_origin_maps_to_authorization_error(self, urlopen):
        urlopen.side_effect = HTTPError("https://example", 401, "Unauthorized", {}, io.BytesIO())

        actual = lambda_function.lambda_handler(control_event(), self.context)

        self.assertEqual("INVALID_AUTHORIZATION_CREDENTIAL", actual["event"]["payload"]["type"])
        self.assertEqual("light#licht_2", actual["event"]["endpoint"]["endpointId"])

    @mock.patch.object(lambda_function.urllib.request, "urlopen")
    def test_unreachable_origin_maps_to_endpoint_unreachable(self, urlopen):
        urlopen.side_effect = URLError("timeout")

        actual = lambda_function.lambda_handler(control_event(), self.context)

        self.assertEqual("ENDPOINT_UNREACHABLE", actual["event"]["payload"]["type"])

    @mock.patch.object(lambda_function.urllib.request, "urlopen")
    def test_oversized_origin_response_is_rejected(self, urlopen):
        urlopen.return_value = FakeResponse(b"x" * (lambda_function.MAX_PAYLOAD_BYTES + 1))

        actual = lambda_function.lambda_handler(control_event(), self.context)

        self.assertEqual("INTERNAL_ERROR", actual["event"]["payload"]["type"])

    @mock.patch.object(lambda_function.urllib.request, "urlopen")
    def test_access_token_is_never_logged(self, urlopen):
        token = "do-not-log-this-token"
        urlopen.return_value = FakeResponse({"event": {"payload": {}}})

        with self.assertLogs(lambda_function.LOGGER, level="INFO") as logs:
            lambda_function.lambda_handler(control_event(token), self.context)

        self.assertNotIn(token, "\n".join(logs.output))


if __name__ == "__main__":
    unittest.main()
