
import base64
import datetime
import json
import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

HOST = "localhost"
PORT = 8080
DB_FILE = "totally_not_my_privateKeys.db"


def current_time():
    return int(datetime.datetime.now(datetime.timezone.utc).timestamp())


def initialize_database():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
        """)

        now = current_time()

        for expiration in (now - 3600, now + 7200):
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            conn.execute(
                "INSERT INTO keys (key, exp) VALUES (?, ?)",
                (pem, expiration)
            )


def get_key(expired=False):
    now = current_time()
    with sqlite3.connect(DB_FILE) as conn:
        if expired:
            return conn.execute(
                "SELECT kid, key, exp FROM keys "
                "WHERE exp <= ? ORDER BY exp DESC LIMIT 1",
                (now,)
            ).fetchone()

        return conn.execute(
            "SELECT kid, key, exp FROM keys "
            "WHERE exp > ? ORDER BY exp DESC LIMIT 1",
            (now,)
        ).fetchone()


def int_to_base64(value):
    size = (value.bit_length() + 7) // 8
    raw = value.to_bytes(size, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class MyServer(BaseHTTPRequestHandler):
    def send_json(self, status, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path != "/auth":
            self.send_response(405)
            self.end_headers()
            return

        # Authentication is mocked for this assignment.
        expired = "expired" in parse_qs(
            parsed.query, keep_blank_values=True
        )
        row = get_key(expired)

        if row is None:
            self.send_json(500, {"error": "No matching key"})
            return

        kid, pem, expiration = row

        payload = {
            "sub": "userABC",
            "user": "userABC",
            "iat": current_time(),
            "exp": expiration if expired else current_time() + 3600
        }

        token = jwt.encode(
            payload,
            pem,
            algorithm="RS256",
            headers={"kid": str(kid)}
        )

        body = token.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if urlparse(self.path).path != "/.well-known/jwks.json":
            self.send_response(405)
            self.end_headers()
            return

        with sqlite3.connect(DB_FILE) as conn:
            rows = conn.execute(
                "SELECT kid, key FROM keys WHERE exp > ?",
                (current_time(),)
            ).fetchall()

        public_keys = []

        for kid, pem in rows:
            private_key = serialization.load_pem_private_key(
                pem, password=None
            )
            numbers = private_key.public_key().public_numbers()

            public_keys.append({
                "alg": "RS256",
                "kty": "RSA",
                "use": "sig",
                "kid": str(kid),
                "n": int_to_base64(numbers.n),
                "e": int_to_base64(numbers.e)
            })

        self.send_json(200, {"keys": public_keys})

    def do_PUT(self):
        self.send_response(405)
        self.end_headers()

    do_PATCH = do_PUT
    do_DELETE = do_PUT
    do_HEAD = do_PUT


if __name__ == "__main__":
    initialize_database()
    server = HTTPServer((HOST, PORT), MyServer)

    print(f"JWKS server running at http://{HOST}:{PORT}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

