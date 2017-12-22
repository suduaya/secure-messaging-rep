import logging
from log import *
import json, base64
import sys
import random
from Crypto.Hash import SHA512, HMAC
from Crypto.Random import random
from Crypto.PublicKey import RSA
from string import ascii_lowercase
from Security_functions import Security
from Crypto.Protocol.KDF import PBKDF1
from Security_functions import Security

security = Security()   # security module


# Connection status
CONNECTED = 1
NOT_CONNECTED = 2

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
        self.name = None
        self.id = None
        self.uuid = None
        self.salt = None
        self.modulus_prime = None
        self.primitive_root = None
        self.client_pubKey = None
        self.client_pubNum = None
        self.sharedKey = None
        self.svPrivNum = None
        self.svPubNum = None
        self.status = None

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
        #print reqs
        self.bufin = reqs[-1]
        return reqs[:-1]
    
    def processSecure(self, message):
        # Derivated from Session Key
        kdf_key = security.kdf(str(self.sharedKey), self.salt, 32, 4096, lambda p, s: HMAC.new(p, s, SHA512).digest())

        # Ciphering message
        ciphered =  security.AES(message, kdf_key)

        # Encoding ciphered message
        ciphered_b = base64.b64encode(ciphered)

        # Generate HMAC (message, derivated Key)
        HMAC_msg = base64.b64encode((HMAC.new(key=kdf_key, msg=message, digestmod=SHA512)).hexdigest())

        secure = {
                    "type"   : "secure",
                    "content": ciphered_b,
                    "HMAC"   : HMAC_msg,
        }

        return json.dumps(secure) #string format

    def sendResult(self, message):
        """Send an object to this client.
        """
        try:
            if self.status == None:
                self.bufout += json.dumps(message) + "\n\n"

                
            if self.status == CONNECTED:
                if isinstance(message, dict):
                    message =  json.dumps(message)
                    sending = self.processSecure(message)

                self.bufout += sending + "\n\n"

        except:
            # It should never happen! And not be reported to the client!
            logging.exception("Client.send(%s)" % self)

    def close(self):
        """Shuts down and closes this client's socket.
        Will log error if called on a client with closed socket.
        Never fails.
        """
        log(logging.INFO, " Client.close(%s)" % self)
        try:
            self.socket.close()
        except:
            logging.exception(" Client.close(%s)" % self)


