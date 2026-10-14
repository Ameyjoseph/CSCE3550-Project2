
import json
import threading
import urllib.request
import urllib.error
from http.server import HTTPServer

import pytest
import jwt

from main import MyServer

@pytest.fixture(scope="module")
def server():
    httpd = HTTPServer(("127.0.0.1", 0), MyServer)
    thread = threading.Thread(
        target=httpd.serve_forever, daemon=True
    )
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_port}"
    httpd.shutdown()
    httpd.server_close()
    thread.join()


def request(url, method="GET"):
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()


def test_jwks_endpoint(server):
    status, body = request(server + "/.well-known/jwks.json")
    assert status == 200
    data = json.loads(body)
    assert "keys" in data
    assert len(data["keys"]) >= 1


def test_jwk_fields(server):
    _, body = request(server + "/.well-known/jwks.json")
    for key in json.loads(body)["keys"]:
        assert key["kty"] == "RSA"
        assert key["alg"] == "RS256"
        assert key["use"] == "sig"
        assert all(field in key for field in ("kid", "n", "e"))


def test_auth(server):
    status, token = request(server + "/auth", "POST")
    assert status == 200
    header = jwt.get_unverified_header(token)
    assert header["alg"] == "RS256"
    payload = jwt.decode(
        token, options={"verify_signature": False}
    )
    assert payload["exp"] > __import__("time").time()


def test_expired_auth(server):
    status, token = request(
        server + "/auth?expired=true", "POST"
    )
    assert status == 200
    payload = jwt.decode(
        token, options={"verify_signature": False}
    )
    assert payload["exp"] <= __import__("time").time()


@pytest.mark.parametrize(
    "method", ["PUT", "PATCH", "DELETE", "HEAD"]
)
def test_unsupported_methods(server, method):
    status, _ = request(server + "/auth", method)
    assert status == 405


def test_unknown_get(server):
    status, _ = request(server + "/unknown")
    assert status == 405


def test_unknown_post(server):
    status, _ = request(server + "/unknown", "POST")
    assert status == 405

