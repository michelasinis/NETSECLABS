import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

# notes stored in memory
notes = {}
next_id = 1


class Handler(BaseHTTPRequestHandler):
    # send a status code and an optional JSON body
    def send(self, status, data=None):
        self.send_response(status)
        if data is None:
            self.end_headers()
        else:
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode())

    def do_GET(self):
        url = urlparse(self.path)
        # home page
        if url.path == "/":
            self.send(200)
        # echo the decoded msg parameter
        elif url.path == "/echo":
            msg = parse_qs(url.query).get("msg", [""])[0]
            self.send(200, {"msg": msg})
        # GET is not allowed on the collection
        elif url.path == "/notes":
            self.send(405)
        # read a single note
        elif url.path.startswith("/notes/"):
            note_id = url.path[7:]
            if note_id.isdigit() and int(note_id) in notes:
                self.send(200, {"id": int(note_id), "text": notes[int(note_id)]})
            else:
                self.send(404)
        else:
            self.send(404)

    def do_POST(self):
        global next_id
        path = urlparse(self.path).path
        # POST is only allowed on /notes
        if path.startswith("/notes/"):
            self.send(405)
            return
        if path != "/notes":
            self.send(404)
            return
        # check the content type
        if self.headers.get("Content-Type") != "application/json":
            self.send(415)
            return
        # read and parse the JSON body
        length = int(self.headers.get("Content-Length", 0))
        try:
            data = json.loads(self.rfile.read(length))
        except ValueError:
            self.send(400)
            return
        if not isinstance(data, dict) or not isinstance(data.get("text"), str):
            self.send(400)
            return
        # save the note
        notes[next_id] = data["text"]
        self.send(201, {"id": next_id})
        next_id += 1

    def do_DELETE(self):
        path = urlparse(self.path).path
        # DELETE is not allowed on the collection
        if path == "/notes":
            self.send(405)
        # delete a single note
        elif path.startswith("/notes/") and path[7:].isdigit() and int(path[7:]) in notes:
            del notes[int(path[7:])]
            self.send(204)
        else:
            self.send(404)

    # PUT and PATCH are not supported on /notes
    def do_PUT(self):
        path = urlparse(self.path).path
        if path == "/notes" or path.startswith("/notes/"):
            self.send(405)
        else:
            self.send(404)

    do_PATCH = do_PUT


# start the server on port 8080
HTTPServer(("", 8080), Handler).serve_forever()
