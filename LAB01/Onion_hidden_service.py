import os
import shutil
import subprocess
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

# Create the service folder (Tor wants it private) and add the course key
os.makedirs("hidden_service", mode=0o700, exist_ok=True)
os.makedirs("hidden_service/authorized_clients", mode=0o700, exist_ok=True)
shutil.copy("netsec.auth", "hidden_service/authorized_clients/netsec.auth")

# Write the Tor config: onion port 80 goes to local port 8090
with open("torrc", "w") as f:
    f.write("HiddenServiceDir " + os.path.abspath("hidden_service") + "\n")
    f.write("HiddenServicePort 80 127.0.0.1:8090\n")

# Start Tor in the background
subprocess.Popen(["/opt/homebrew/bin/tor", "-f", "torrc"])

# Wait for Tor to create the address, then show it
while not os.path.exists("hidden_service/hostname"):
    time.sleep(1)
print(open("hidden_service/hostname").read())

# Last token received, shared by the onion service and the VPN port
token = ""

class Handler(BaseHTTPRequestHandler):
    # Return the home page, or the last token on /claim
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        if self.path == "/claim":
            self.wfile.write(token.encode())
        else:
            self.wfile.write(b"Hello from my onion service")

    # Save the token sent in the body
    def do_POST(self):
        global token
        length = int(self.headers["Content-Length"])
        token = self.rfile.read(length).decode()
        self.send_response(200)
        self.end_headers()

# Listen on every interface, so it works on the VPN IP too
HTTPServer(("0.0.0.0", 8090), Handler).serve_forever()
