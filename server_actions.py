import logging
from log import *
import time, base64
from server_registry import *
from server_client import *
from server import *
import json
import random
from Security_functions import Security
from Crypto.Hash import SHA512, HMAC
from Crypto.Random import random
from Crypto.PublicKey import RSA
from string import ascii_lowercase
from Security_functions import Security
from Crypto.Protocol.KDF import PBKDF1

security = Security()

HOST = ""   # All available interfaces
PORT = 8080  # The server port

get_pubNum = lambda x,y,z: int(pow(x,y,z))

def privateNumber():
    secret = int(random.randint(0,100))
    return secret

class ServerActions:
    def __init__(self):

        self.messageTypes = {
            'all': self.processAll,
            'list': self.processList,
            'new': self.processNew,
            'send': self.processSend,
            'recv': self.processRecv,
            'create': self.processCreate,
            'receipt': self.processReceipt,
            'status': self.processStatus,
            'dh': self.processDH,
            'secure': self.processSecure,
        }
        # Registry
        self.registry = ServerRegistry()

        # Par de Chaves Assimetricas
        self.pubKey, self.privKey = security.get_keys()

    def secureMessage_Cipher(self, operation, data, data_key=None):
        """Hybrid Ciphering
        """
        if operation == 'cipher':
            symKey = security.get_symmetricKey(256)
            instance = RSA.importKey(data_key)

            a = security.AES(message=data, key=symKey)
            b = security.rsaCipher(message=symKey, key=instance)
            return a, b  # data ciphered with symKey, symKey ciphered with server pubKey

        if operation == 'decipher':
            instance = RSA.importKey(self.privKey)

            b = security.rsaDecipher(message=data_key, key=instance)
            a = security.D_AES(symKey=b, message=data)
            return a

    def handleRequest(self, s, request, client):
        """Handle a request from a client socket.
        """
        try:
            logging.info("HANDLING message from %s: %r" %
                         (client, repr(request)))

            try:
                req = json.loads(request)
            except:
                logging.exception("Invalid message from client")
                return

            if not isinstance(req, dict):
                log(logging.ERROR, "Invalid message format from client")
                return

            if 'type' not in req:
                log(logging.ERROR, "Message has no TYPE field")
                return

            if req['type'] in self.messageTypes:
                self.messageTypes[req['type']](req, client)
            else:
                log(logging.ERROR, "Invalid message type: " +
                    str(req['type']) + " Should be one of: " + str(self.messageTypes.keys()))
                client.sendResult({"error": "unknown request"})

        except Exception, e:
            logging.exception("Could not handle request")

    def processSecure(self, data, client):
        """ Process Message with type field "secure"
        """
        client.client_pubKey = data['Client_pubkey']
        content = base64.b64decode(data['content'])
        client.salt = base64.b64decode(data['salt'])

        # Compute Derivated key
        kdf_key = security.kdf(str(client.sharedKey), client.salt, 32, 4096, lambda p, s: HMAC.new(p, s, SHA512).digest())
        
        # Decipher Request
        dataFinal = security.D_AES(message= content, symKey= kdf_key)
        req = json.loads(dataFinal)

        # Handle Request
        if req['type'] in dataFinal:
                self.messageTypes[req['type']](req, client)
        return

    def processCreate(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if 'uuid' not in data.keys():
            log(logging.ERROR, "No \"uuid\" field in \"create\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return

        uuid = data['uuid'] # username

        '''
        if not isinstance(uuid, int):
            log(logging.ERROR, "No valid \"uuid\" field in \"create\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return'''

        if self.registry.userExists(uuid):
            log(logging.ERROR, "User already exists: " + json.dumps(data))
            client.sendResult({"error": "uuid already exists"})
            return

        if self.registry.userDirExists(uuid):
            log(logging.ERROR, "User already exists: " + json.dumps(data))
            client.sendResult({"error": "uuid already exists"})
            return

        # Adiciona novo user
        me = self.registry.addUser(data)
        client.id = me.id
        client.sendResult({"resultCreate": me.id})


    def processDH(self, data, client):
        client.uuid = data['uuid']                      # username = uuid
        client.id = self.registry.getId(data['uuid'])   # uuid -> traducao para ID
        phase = int(data['phase'])
        client.modulus_prime = data['modulus_prime']
        client.primitive_root = data['primitive_root']
        client.client_pubNum = int(data['Client_pubNum'])
        client.svPrivNum = privateNumber()

        # Compute Shared Key
        client.svPubNum = int(pow(client.primitive_root, client.svPrivNum, client.modulus_prime))
        new_sharedKey = int(pow(client.client_pubNum, client.svPrivNum, client.modulus_prime))
        client.sharedKey = new_sharedKey 

        if not self.registry.userDirExists(client.uuid):
            log(logging.ERROR, "User doesnt exists: " + json.dumps(data))
            client.sendResult({"error": "uuid doenst exists"})
            return

        client.sendResult({"resultDH":{
                                        "Server_pubNum" : client.svPubNum,
                                        "phase" : phase+1
                                    },
                            "server_pubkey" : self.pubKey,
                        })
        # Change Client Status
        client.status = CONNECTED


    def processList(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        user = 0  # 0 means all users
        userStr = "all users"
        if 'id' in data.keys():
            user = int(data['id'])
            userStr = "user%d" % user

        log(logging.DEBUG, "List %s" % userStr)

        userList = self.registry.listUsers(user)

        client.sendResult({"resultList": userList})

    def processNew(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        user = -1
        if 'id' in data.keys():
            user = int(data['id'])

        if user < 0:
            log(logging.ERROR,
                "No valid \"id\" field in \"new\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return

        client.sendResult(
            {"resultNew": self.registry.userNewMessages(user)})

    def processAll(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        user = -1

        # uuid -> traducao para ID
        if 'uuid' in data.keys():
            user = self.registry.getId((data['uuid']))

        if user < 0:
            log(logging.ERROR,
                "No valid \"id\" field in \"new\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return

        client.sendResult({"resultAll": [self.registry.userAllMessages(user), self.registry.userSentMessages(user)]})

    def processSend(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set(data.keys()).issuperset(set({'src', 'dst', 'msg', 'msg'})):
            log(logging.ERROR,
                "Badly formated \"send\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong message format"})

        srcId = self.registry.getId((data['src']))  # uuid -> traducao para ID
        dstId = self.registry.getId((data['dst']))  # uuid -> traducao para ID

        msg = data['msg']
        copy = data['copy']

        if not self.registry.userExists(srcId):
            log(logging.ERROR,
                "Unknown source id for \"send\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"})
            return

        if not self.registry.userExists(dstId):
            log(logging.ERROR,
                "Unknown destination id for \"send\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"})
            return

        # Save message and copy
        response = self.registry.sendMessage(srcId, dstId, msg, copy)
        client.sendResult({"resultSend": response})

    def processRecv(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id', 'msg'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"recv\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})

        fromId = self.registry.getId((data['uuid'])) # uuid -> traducao para ID
        msg = str(data['msg'])

        if not self.registry.userExists(fromId):
            log(logging.ERROR,
                "Unknown source id for \"recv\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"})
            return

        if not self.registry.messageExists(fromId, msg):
            log(logging.ERROR,
                "Unknown source msg for \"recv\" message: " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"})
            return

        # Read message
        response = self.registry.recvMessage(fromId, msg)
        client.sendResult({"resultRecv": response})

    def processReceipt(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id', 'msg', 'receipt'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"receipt\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong request format"})

        fromId = self.registry.getId((data["id"]))
        msg = str(data['msg'])
        receipt = str(data['receipt'])

        if not self.registry.messageWasRed(str(fromId), msg):
            log(logging.ERROR, "Unknown, or not yet red, message for \"receipt\" request " + json.dumps(data))
            client.sendResult({"error": "wrong parameters"})
            return

        self.registry.storeReceipt(fromId, msg, receipt)

    def processStatus(self, data, client):
        log(logging.DEBUG, "%s" % json.dumps(data))

        if not set({'id', 'msg'}).issubset(set(data.keys())):
            log(logging.ERROR, "Badly formated \"status\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})
        
        fromId = self.registry.getId((data['id']))
        msg = str(data["msg"])

        if(not self.registry.copyExists(fromId, msg)):
            log(logging.ERROR, "Unknown message for \"status\" request: " + json.dumps(data))
            client.sendResult({"error", "wrong parameters"})
            return

        response = self.registry.getReceipts(fromId, msg)
        client.sendResult({"resultStatus": response})
