# Setup (run once, in this folder):
#   pip install hypercorn aioquic
#   openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365 \ -subj "/CN=server.netsec.lab" -addext "subjectAltName=DNS:server.netsec.lab"


import asyncio
import hashlib
from hypercorn.asyncio import serve
from hypercorn.config import Config


# Handle every HTTP request
async def app(scope, receive, send):
    if scope["type"] != "http":
        return

    # Read the whole request body
    body = b""
    more = True
    while more:
        message = await receive()
        body += message.get("body", b"")
        more = message.get("more_body", False)

    # Choose the response text
    if scope["method"] == "POST" and scope["path"] == "/hash":
        text = hashlib.sha256(body).hexdigest()
    elif scope["path"] == "/proto":
        text = "HTTP/" + scope["http_version"]
    else:
        text = "OK"

    # Send the response
    await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain")]})
    await send({"type": "http.response.body", "body": text.encode()})


# HTTPS on TCP 4433 and HTTP/3 on UDP 4433
config = Config()
config.bind = ["0.0.0.0:4433"]
config.quic_bind = ["0.0.0.0:4433"]
config.certfile = "cert.pem"
config.keyfile = "key.pem"
config.alt_svc_headers = ['h3=":4433"']

asyncio.run(serve(app, config))
