# Generate the self-signed server certificate with:
# openssl req -x509 -newkey rsa:2048 -nodes -keyout server.key -out server.crt -days 365 -subj "/CN=server.netsec.lab" -addext "subjectAltName=DNS:server.netsec.lab"

import http.server
import json
import secrets
import ssl
import threading
from http.cookies import SimpleCookie

sessions = {}


# Port 8443: home page, login and session check
class WebHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/me":
            cookie = SimpleCookie(self.headers.get("Cookie", ""))
            if "session" in cookie and cookie["session"].value in sessions:
                body = json.dumps({"user": sessions[cookie["session"].value]})
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body.encode())
            else:
                self.send_response(401)
                self.end_headers()
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Hello")

    def do_POST(self):
        length = int(self.headers["Content-Length"])
        data = json.loads(self.rfile.read(length))
        if data["password"] == "netsec":
            token = secrets.token_hex(16)
            sessions[token] = data["user"]
            self.send_response(200)
            self.send_header("Set-Cookie", "session=" + token + "; Secure; HttpOnly")
            self.end_headers()
        else:
            self.send_response(401)
            self.end_headers()


# Port 8444: return the CN of the client certificate
class WhoamiHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        cn = ""
        for rdn in self.connection.getpeercert()["subject"]:
            for key, value in rdn:
                if key == "commonName":
                    cn = value
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(cn.encode())


# TLS context with the self-signed server certificate
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("server.crt", "server.key")

# mTLS context: same certificate, client certificate required and signed by the course CA
mtls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
mtls_context.load_cert_chain("server.crt", "server.key")
mtls_context.verify_mode = ssl.CERT_REQUIRED
mtls_context.load_verify_locations("ca.crt")

# Start the mTLS server in a thread and the normal server in the main thread
mtls_server = http.server.HTTPServer(("", 8444), WhoamiHandler)
mtls_server.socket = mtls_context.wrap_socket(mtls_server.socket, server_side=True)
threading.Thread(target=mtls_server.serve_forever).start()

server = http.server.HTTPServer(("", 8443), WebHandler)
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
