"""Bound raw WSGI streams to the advertised HTTP request body."""
class ContentLengthInput:
    def __init__(self, stream, length):
        self.stream, self.remaining = stream, length

    def read(self, size=-1):
        size = self.remaining if size is None or size < 0 else min(size, self.remaining)
        if size == 0:
            return b''
        data = self.stream.read(size)
        self.remaining -= len(data)
        return data

    def readline(self, size=-1):
        size = self.remaining if size is None or size < 0 else min(size, self.remaining)
        if size == 0:
            return b''
        data = self.stream.readline(size)
        self.remaining -= len(data)
        return data

    def __iter__(self):
        return self

    def __next__(self):
        line = self.readline()
        if not line:
            raise StopIteration
        return line
