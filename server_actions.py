import logging
from log import *
import time, base64
from server_registry import *
from server_client import *
from server import *
import json
import time
import random
from Crypto.Hash import SHA512, HMAC
from Crypto.Random import random
from Crypto.PublicKey import RSA
from string import ascii_lowercase
from secure import Secure
from Crypto.Protocol.KDF import PBKDF1
from citizencard import citizencard


cc = citizencard()
secure = Secure()

HOST = ""   # All available interfaces
PORT = 8080  # The server port

pubNum = lambda x,y,z: int(pow(x,y,z))

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
            'dh': self.processAuthentication,
            'secure': self.processSecure,
            'refresh': self.processRefresh,
            'sync': self.processSync,
        }
        # Registry
        self.registry = ServerRegistry()

        # Par de Chaves Assimetricas
        self.pubKey, self.privKey = secure.get_keys()

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
        """ Refresh keys and session
        """
        log(logging.INFO, colors.INFO + " Refreshing Keys" + colors.END)
        client_pubkey = data['publickey']
        client.modulus_prime = data['modulus_prime']
        client.primitive_root = data['primitive_root']
        client.client_pubNum = int(data['Client_pubNum'])
        client.svPrivNum = privateNumber()

        # update pubkey
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
        content = base64.b64decode(data['content'])
        client.salt = base64.b64decode(data['salt'])
        HMAC_msg = base64.b64decode(data['HMAC'])

        # Compute Derivated key
        kdf_key = secure.kdf(str(client.sharedKey), client.salt, 32, 4096, lambda p, s: HMAC.new(p, s, SHA512).digest())
        
        # Decipher Request
        dataFinal = secure.D_AES(message= content, symKey= kdf_key)
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
        log(logging.INFO, colors.INFO + " Creating New Account" + colors.END)

        if 'uuid' not in data.keys():
            log(logging.ERROR, "No \"uuid\" field in \"create\" message: " +
                json.dumps(data))
            client.sendResult({"error": "wrong message format"})
            return

        uuid = data['uuid']                 # username
        publicKey = data['Client_pubKey']   # user publicKey

        if self.registry.userExists(uuid):
            log(logging.ERROR, colors.ERROR + "User already exists" + colors.END)
            client.sendResult({"error": "                User already exists"})
            return

        if self.registry.userDirExists(uuid):
            log(logging.ERROR, colors.ERROR + "User already exists" + colors.END)
            client.sendResult({"error": "                User already exists"})
            return

        user_cert = data['auth_certificate']        # authentication certificate

        # validade certificado
        if not cc.retrieveStatus(cert= user_cert, mode="AUTHENTICATION"):
            log(logging.ERROR, colors.ERROR + "Your Certificate is revoked!" + colors.END) 
            return
        log(logging.ERROR, colors.VALID + "Certificate Not Revoked" + colors.END) 

        # registar envio
        timestamp = str(int(time.time() * 1000))

        # validade assinatura
        if not cc.signatureValidity(cert=user_cert, timestamp=timestamp):
            log(logging.ERROR, colors.ERROR + "Your Signature isn't valid!" + colors.END) 
            return
        log(logging.ERROR, colors.VALID + "Valid Signature. Current Date: " + str(time.ctime(int(timestamp) / 1000)) + colors.END) 


        # Adiciona novo user
        me = self.registry.addUser(data)
        log(logging.INFO, colors.INFO + " User Added Sucessfully" + colors.END)
        client.id = me.id
        client.sendResult({"resultCreate": me.id})


    def processAuthentication(self, data, client):
        """ Processo de Autenticacao
        """
        phase = int(data['phase'])

        if phase == 1:
            log(logging.INFO, colors.INFO + " Authenticating Credentials" + colors.END)
            client.uuid = data['uuid']                      # username = uuid
            client.id = self.registry.getId(data['uuid'])   # uuid -> traducao para ID
            client.modulus_prime = data['modulus_prime']
            client.primitive_root = data['primitive_root']
            client.client_pubNum = int(data['Client_pubNum'])
            client.svPrivNum = privateNumber()
            passphrase = data['passphrase']
            
            # check username
            if not self.registry.userDirExists(client.uuid):
                log(logging.ERROR, colors.ERROR +"Invalid Username" + colors.END)
                client.sendResult({"error": "                Invalid Username!"})
                return

            # check password
            if not self.registry.checkPassphrase(client.uuid, passphrase):
                log(logging.ERROR, colors.ERROR +"Authentication failed! Wrong passphrase!"+colors.END)
                client.sendResult({"error": "                Wrong password!"})
                return
            log(logging.DEBUG,colors.VALID + "Correct Passphrase" + colors.END)
            
            # Compute Shared Key
            client.svPubNum = pubNum(client.primitive_root, client.svPrivNum, client.modulus_prime)
            
            client.sendResult({"resultDH":{
                                            "Server_pubNum" : client.svPubNum,
                                            "phase" : phase+1
                                        },
                                "server_pubkey" : self.pubKey,
                                "id": client.id,
                                "name": self.registry.users[client.id].description["name"]
                            })

        if phase == 3:
            log(logging.INFO, colors.INFO + " Authenticating Challenge" + colors.END)
            # passphrase
            signed_passphrase = base64.b64decode(data['signed_passphrase'])
            passphrase = data['passphrase']

            # double check password/passphrase
            if not self.registry.checkPassphrase(client.uuid, passphrase):
                log(logging.ERROR, colors.ERROR +"Authentication failed! Wrong passphrase!"+colors.END)
                client.sendResult({"error": "                Wrong password!"})
                return

            # signature validity
            timestamp= str(int(time.time() * 1000))
            user_cert = self.registry.getUserCertificate(uuid= client.uuid ,mode='AUTHENTICATION')

            if user_cert != None:
                if not cc.verify(cert=user_cert, data= base64.b64decode(passphrase), sign= signed_passphrase) and cc.signatureValidity(cert=user_cert, timestamp=timestamp):
                    # Not valid
                    log(logging.ERROR, colors.ERROR +"Invalid Signature!"+colors.END)
                    client.sendResult({"error": "                Invalid Signature!"})
                    return
                # Valid Signature
                log(logging.DEBUG,colors.VALID + "Valid Signature" + colors.END)
            # Valid Challende
            log(logging.DEBUG,colors.VALID + "Challenge Validated" + colors.END)

            # shared key
            new_sharedKey = int(pow(client.client_pubNum, client.svPrivNum, client.modulus_prime))
            client.sharedKey = new_sharedKey
            log(logging.DEBUG,colors.INFO + "Session Estabilished" + colors.END)

            # connected
            log(logging.DEBUG,colors.INFO + "User authenticated" + colors.END)

            client.sendResult({"resultDH":{
                                            "phase" : phase+1
                                        }
                            })

            # Change Client Status
            client.status = CONNECTED
        

    def processList(self, data, client):
        log(logging.INFO, colors.INFO + " Listing Users" + colors.END)

        user = 0
        userStr = "all users"
        if 'id' in data.keys():
            user = int(data['id'])
            userStr = "user%d" % user

        log(logging.DEBUG,colors.INFO + "Looking for all connected users" + colors.END)

        userList = self.registry.listUsers(user)

        client.sendResult({"resultList": userList})


    def processSync(self, data, client):
        log(logging.INFO, colors.INFO + " Synchronizing User's related data" + colors.END)

        user = 0
        userStr = "all users"
        if 'id' in data.keys():
            user = int(data['id'])
            userStr = "user%d" % user

        userList = self.registry.listUsers(user)

        client.sendResult({"resultSync": userList})

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
        log(logging.INFO, colors.VALID + "Message Sent Sucessfully" + colors.END)
        client.sendResult({"resultSend": response})

    def processRecv(self, data, client):
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
        log(logging.INFO, colors.INFO + " Receipt Stored" + colors.END)
        self.registry.storeReceipt(fromId, msg, receipt)

    def processStatus(self, data, client):
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
