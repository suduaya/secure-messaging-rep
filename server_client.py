from log import *
import json, base64, sys, random, logging
from Crypto.Hash import SHA512, HMAC
from Crypto.Random import random
from Crypto.PublicKey import RSA
from secure import Secure
from Crypto.Protocol.KDF import PBKDF1

secure = Secure()   # secure module


# Connection status
NOT_CONNECTED   = 10000
CONNECTING      = 20000
CONNECTED       = 30000

TERMINATOR = "\r\n"
MAX_BUFSIZE = 64 * 1024

# Colours
class colors:
    TITLE = '\033[95m'
    INFO = '\033[94m'
    VALID = '\033[92m'
    WARNING = '\033[93m'
    ERROR = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

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
        self.modulus_prime = None
        self.primitive_root = None
        self.client_pubKey = None
        self.client_pubNum = None
        self.sharedKey = None
        self.svPrivNum = None
        self.svPubNum = None
        self.status = None
        self.nextRequest = 0

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
        self.bufin = reqs[-1]
        return reqs[:-1]
    
    def processSecure(self, message, msgControl):
        """Ciphering with symetric derivated session key
            Secure Channel
        """

        log(logging.INFO, colors.INFO + " Secure Response" + colors.END)
        # Derivated from Session Key
        salt = secure.symmetricKey(256)
        kdf_key = secure.kdf(str(self.sharedKey), salt, 32, 4096, lambda p, s: HMAC.new(p, s, SHA512).digest())

        # Ciphering message
        ciphered =  secure.AES(message, kdf_key)

        # Encoding ciphered message
        ciphered_b = base64.b64encode(ciphered)

        # Generate HMAC (message, derivated Key)
        HMAC_msg = base64.b64encode((HMAC.new(key=kdf_key, msg=message, digestmod=SHA512)).hexdigest())

        secure_msg = {
                    "type"   : "secure",
                    "content": ciphered_b,  #base64
                    "HMAC"   : HMAC_msg,    #base64
                    "msgControl" : msgControl,
                    "salt": base64.b64encode(salt),
        }

        return json.dumps(secure_msg) #string format

    def sendResult(self, message, msgControl):
        """Send an object to this client.
        """
        try:
            if self.status == None:
                self.bufout += json.dumps(message) + "\n\n"

                
            if self.status == CONNECTED:
                if isinstance(message, dict):
                    message =  json.dumps(message)
                    sending = self.processSecure(message, msgControl)

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


