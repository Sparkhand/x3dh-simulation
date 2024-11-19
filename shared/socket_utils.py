from socket import *

class Connection:
    def __init__(self, sock, sep = '\r\n'):
        self.sock = sock
        self.buffer = b''
        self.sep = sep.encode()

    def read(self):
        while b'\r\n' not in self.buffer:
            data = self.sock.recv(1024)
            if not data: # (socket closed)
                return None
            self.buffer += data
        line, _, self.buffer = self.buffer.partition(self.sep)
        return line.decode()

    def send(self, line):
        # Check if line is already a bytes object
        if not isinstance(line, bytes):
            line = str(line).encode()
        self.sock.sendall(line + self.sep)

    def close(self):
        self.sock.close()
