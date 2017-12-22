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

# Colours
class colors:
    TITLE = '\033[95m'
    INFO = '\033[94m'
    VALID = '\033[92m'
    WARNING = '\033[93m'
    ERROR = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

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
            'refresh': self.processRefresh,
        }
        # Registry
        self.registry = ServerRegistry()

        # Par de Chaves Assimetricas
        self.pubKey, self.privKey = security.get_keys()

    def hybrid(self, operation, data, data_key=None):
        """
        Function used to cipher/decipher requests, generates symetric 
        key and ciphers with pubKey of dst or deciphers with my privKey
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
            #logging.info("HANDLING message from %s: %r" %
            #             (client, repr(request)))

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


    def processRefresh(self, data, client):
        log(logging.INFO, colors.INFO + " Refreshing Keys" + colors.END)
        client_pubkey = data['publickey']
        client.client_pubKey = client_pubkey
        client.modulus_prime = data['modulus_prime']
        client.primitive_root = data['primitive_root']
        client.client_pubNum = int(data['Client_pubNum'])
        client.svPrivNum = privateNumber()

        if not self.registry.updatePublicKey(client.uuid, client_pubkey):
            log(logging.INFO, colors.ERROR + "Error while trying to update Public Key" + colors.END)
            return

        # Compute New Shared Key
        client.svPubNum = int(pow(client.primitive_root, client.svPrivNum, client.modulus_prime))
        new_sharedKey = int(pow(client.client_pubNum, client.svPrivNum, client.modulus_prime))
        

        log(logging.INFO, colors.VALID + " Keys Updated" + colors.END)

        client.sendResult({"resultRefresh":{
                                        "Server_pubNum" : client.svPubNum,
                                    },
                            "server_pubkey" : self.pubKey,
                        })

        client.sharedKey = new_sharedKey

    def processSecure(self, data, client):
        """ Process Message with type field "secure"
        """
        print "\n"
        log(logging.INFO, colors.INFO + " Secure Request " + colors.WARNING + "     username: " + colors.END+ client.uuid +colors.WARNING + colors.END)
        client.client_pubKey = base64.b64decode(data['client_pubkey'])
        content = base64.b64decode(data['content'])
        client.salt = base64.b64decode(data['salt'])
        HMAC_msg = base64.b64decode(data['HMAC'])

        # Compute Derivated key
        kdf_key = security.kdf(str(client.sharedKey), client.salt, 32, 4096, lambda p, s: HMAC.new(p, s, SHA512).digest())
        
        # Decipher Request
        dataFinal = security.D_AES(message= content, symKey= kdf_key)
        req = json.loads(dataFinal)

        # Create HMAC
        HMAC_new = (HMAC.new(key=kdf_key, msg=dataFinal, digestmod=SHA512)).hexdigest() # Criar novo HMAC com o texto recebido e comparar integridade

        # Checking integrity
        if (HMAC_new == HMAC_msg) :
            log(logging.INFO, colors.VALID + " Integrity Checked Sucessfully" + colors.END)
        else:
            log(logging.INFO, colors.ERROR + " Message forged! Sorry! Aborting ..." + colors.END)
            return

        # Handling Request
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
        publicKey = data['Client_pubKey']

        if self.registry.userExists(uuid):
            log(logging.ERROR, colors.ERROR + "User already exists" + colors.END)
            client.sendResult({"error": "User already exists"})
            return

        if self.registry.userDirExists(uuid):
            log(logging.ERROR, colors.ERROR + "User already exists" + colors.END)
            client.sendResult({"error": "User already exists"})
            return

        # Adiciona novo user
        me = self.registry.addUser(data)
        client.id = me.id
        client.sendResult({"resultCreate": me.id})


    def processDH(self, data, client):
        log(logging.INFO, colors.INFO + " Authenticating" + colors.END)
        client.uuid = data['uuid']                      # username = uuid
        client.id = self.registry.getId(data['uuid'])   # uuid -> traducao para ID
        phase = int(data['phase'])
        client.modulus_prime = data['modulus_prime']
        client.primitive_root = data['primitive_root']
        client.client_pubNum = int(data['Client_pubNum'])
        client.svPrivNum = privateNumber()
        passphrase = data['passphrase']

        if not self.registry.userDirExists(client.uuid):
            log(logging.ERROR, colors.ERROR +"Invalid Username" + colors.END)
            client.sendResult({"error": "Invalid Username!"})
            return

        # check password and signature validity
        if not self.registry.checkPassphrase(client.uuid, passphrase):
            log(logging.ERROR, colors.ERROR +"Authentication failed! Wrong passphrase!"+colors.END)
            client.sendResult({"error": "Wrong password!"})
            return

        # Compute Shared Key
        client.svPubNum = int(pow(client.primitive_root, client.svPrivNum, client.modulus_prime))
        new_sharedKey = int(pow(client.client_pubNum, client.svPrivNum, client.modulus_prime))
        client.sharedKey = new_sharedKey

        # connected
        log(logging.DEBUG,colors.VALID + "User authenticated: " + colors.END+ client.uuid)
        
        client.sendResult({"resultDH":{
                                        "Server_pubNum" : client.svPubNum,
                                        "phase" : phase+1
                                    },
                            "server_pubkey" : self.pubKey,
                            "id": client.id,
                            "name": self.registry.users[client.id].description["name"]
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

        log(logging.DEBUG,colors.INFO + "List %s" % userStr + colors.END)

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
        log(logging.INFO, colors.INFO + " Message Box" + colors.END)

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
        log(logging.INFO, colors.INFO + "Sending Message" + colors.END)

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
        log(logging.INFO, colors.INFO + "Receiving Message" + colors.END)

        if not set({'uuid', 'msg'}).issubset(set(data.keys())):
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
        #log(logging.DEBUG, "%s" % json.dumps(data))
        log(logging.INFO, colors.INFO + "New Receipt" + colors.END)

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
        log(logging.INFO, colors.INFO + " Message Status" + colors.END)

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
        client.sendResult({"resultStatus": response, "id": msg})
