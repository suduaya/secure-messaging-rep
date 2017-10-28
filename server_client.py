import logging
from log import *
import json
import sys
import random



TERMINATOR = "\r\n"
MAX_BUFSIZE = 64 * 1024

sys.tracebacklimit = 30

class Client:
    count = 0

    def __init__(self, socket, addr):
        self.socket = socket
        self.bufin = ""
        self.bufout = ""
        self.addr = addr
        self.id = None
        self.uuid = None
        self.sa_data = None
        self.pubKey = None
        self.modulus_prime = None
        self.primitive_root = None
        self.client_pubKey = None
        self.client_pubNum = None
        self.sharedKey = None
        self.cipher = None
        self.svPrivNum = None
        self.sv_pubNum = None
        self.svPrivKey = None
        self.svPubKey = None

    def __str__(self):
        """ Converts object into string.
        """
        return "Client(id=%r addr:%s)" % (self.id, str(self.addr))

    def asDict(self):
        return {'id': self.id}

    def parseReqs(self, data):
        """Parse a chunk of data from this client.
        Return any complete requests in a list.
        Leave incomplete requests in the buffer.
        This is called whenever data is available from client socket."""

        if len(self.bufin) + len(data) > MAX_BUFSIZE:
            log(logging.ERROR, "Client (%s) buffer exceeds MAX BUFSIZE. %d > %d" %
                (self, len(self.bufin) + len(data), MAX_BUFSIZE))
            self.bufin = ""

        self.bufin += data
        reqs = self.bufin.split(TERMINATOR)
        print reqs
        self.bufin = reqs[-1]
        return reqs[:-1]

    def sendResult(self, obj):
        """Send an object to this client.
        """
        try:
            self.bufout += json.dumps(obj) + "\n\n"
        except:
            # It should never happen! And not be reported to the client!
            logging.exception("Client.send(%s)" % self)

    def close(self):
        """Shuts down and closes this client's socket.
        Will log error if called on a client with closed socket.
        Never fails.
        """
        log(logging.INFO, "Client.close(%s)" % self)
        try:
            self.socket.close()
        except:
            logging.exception("Client.close(%s)" % self)


