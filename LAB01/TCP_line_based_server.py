import socket
import threading

# Shared store: every client sees the same data
store = {}


# Takes one command line and returns the response
def handle_command(line):
    # Split into at most 3 parts: command, key, value
    parts = line.split(" ", 2)
    cmd = parts[0]

    # PING -> PONG
    if cmd == "PING":
        return "PONG"

    # ECHO -> everything after "ECHO "
    if cmd == "ECHO":
        return line[5:]

    # SET key value -> save it and answer OK
    if cmd == "SET":
        if len(parts) < 3 or parts[2] == "":
            return "ERR"
        store[parts[1]] = parts[2]
        return "OK"

    # GET key -> the value, or NOT_FOUND
    if cmd == "GET":
        if len(parts) < 2 or parts[1] == "":
            return "ERR"
        if parts[1] in store:
            return store[parts[1]]
        return "NOT_FOUND"

    # Any other command -> ERR
    return "ERR"


# Handles one client (runs in its own thread)
def handle_client(conn):
    buffer = ""

    while True:
        # Read data from the client
        data = conn.recv(1024)

        # Empty data means the client closed the connection
        if not data:
            break

        # Add the new data to the buffer
        buffer += data.decode()

        # Process every complete line in the buffer
        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            response = handle_command(line)
            conn.sendall((response + "\n").encode())

    conn.close()


# Start the server on port 9001
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", 9001))
server.listen()

# Start a new thread for every client
while True:
    conn, addr = server.accept()
    threading.Thread(target=handle_client, args=(conn,)).start()
while True:
    conn, addr = server.accept()
    t = threading.Thread(target=handle_client, args=(conn,))
    t.start()
