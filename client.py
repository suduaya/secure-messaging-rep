import select, socket, sys
import json
import sys
import ast
import time, base64
import random
import logging, socket, datetime
import os
from Crypto.Hash import SHA512, HMAC, SHA256
from Crypto.Random import random
from Crypto.PublicKey import RSA
from string import ascii_lowercase
from Security_functions import Security
from Crypto.Protocol.KDF import PBKDF1
import time
from citizencard import citizencard

security = Security()    # security functions
cc = citizencard()
HOST     = "localhost"   # All available interfaces
PORT     = 8080          # The server port

TERMINATOR  = "\r\n"
MAX_BUFSIZE = 64 * 1024

# Connection status
NOT_CONNECTED   = 10000
CONNECTING      = 20000
CONNECTED       = 30000

# Mathematics for session key / diffie helman
PRIMITIVE_ROOT = 5
MODULUS_PRIME = 0xeb8d2e0bfda29137c04f5a748e88681e87038d2438f1ae9a593f620381e58b47656bf5386f7880da383788a35d3b4a6991d3634b149b3875e0dccff21250dccc0bf865a5b262f204b04e38b2385c7f4fb4e2058f73a8f65252e556b667b1570465b2f6d1beeab215b05cd0e28b9277f3f48c01b1619b30147fcfc87b5b6903e70078babb45c2ee6a6bd4099ab87b01ba09a38c36279b46309ef0df5e45e15df9ba5cb296baa535c60bb0065669fd8078269eb759416d9b27229f9cb6e5f60f7d8756f6f621ad519745f914e81a7c8d09b3c7a764863dd5d5f2bcab5ef283aa3781c985d07f2b1aafb2e7747b3217dbbfea2e91484c31a00e22467c0c7f9d40f73d392594c516b302aa7c1aa6ca5a0b346cc6bfc1cd201dfe78aabf717f6c69f30a896567b07090e352e87fd698128da0594916d27203e22b7bb1f7f860842fd0aee2e532a077629451ef86163fdf567048266050a473d4db27e85a33bc985b16569afddaa9a94a5b9155b32b78c84b261ce7acf7d8d0ef23d4e1d028104aff6a77cab79ecdf7dd19468f67d3cb9b86835cce1a87dbf4b2d3100a9bd7a9e251272bf4e2fed2c2f7535e556b8cc1fc6fcfc1a2ca188c02ea9298bb4a7f12afd4164ad9211f7935f51be3d9d932e835a1fd322e7db75ba587021f8c730d7f021905e89a0ddb80bf8ea53b8f1603cf08c734aadfe7f9184e0de9e91651c3d88deb68fd1bc0188e479747caab9a157ef6ec68295a1bfb6391973364987cda6c7817dfee2ab9d4e0eaefb29154f23eafedcab06d67fbcc5d1788a20315c50f9c6471dbb45419b07ddec0d507c16a0b7e2d79290d3115edcdc2996897015dfa430389a1d63533e52aa6309c76e7069e0a99af65702036e7829bc8e86ad3e23983debf72c82d8e3a2e9d767cccfb2abed6b0b0c9f217bb496ea816ea3c32111f60916d91f8a97cfa38b163ca1261733cd98cb2ff77a7ee9290bda74be8dc206489d06abca4e5ae82ae4923fa43b451fa419da06d74f15e4efc4852bf5edf37e581edeaaefd28a8b3c672bb76068439635adecebaf8311d4018fe8e62892f784d7a44747178c4cb540c58e5e2a660a3f02c873d12b43f0643d3794d8b310fe9fa6d798e0724d38c85c9e4d5c8c9ba645f3411dd4645ef1ef1dad9ba60325b12def1bd706d11386045e450fee2a60c88cf6387dea0521acc4d869fb146a47ef4e34480d30f84ffa0e0e0a4a4c7f1b0a8e642223e8bec4d1c8effd98ba235dc5c5f7e296ecd7476595ef17371a1aec3a38c3e7f7e08e7b5e7c927f5843062f753e5ee85f7e64164dd0ccb7261d4ca3a35058ca88f87275a292e96100005c025742f85be7a2598406b9c792f2ba2a496f8074d899821110effb184e3c679330b182a8c14ba1699f3761168d64e838829c0250c6be87bc8dc2b29954bf6cb450ba7bed793cf97
get_pubNum = lambda x,y,z: int(pow(x,y,z))


def privateNumber():
    secret = random.getrandbits(256)
    return secret

# Colours
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Client class
class Client:

    def __str__(self):
        """ Converts object into string.
        """
        return "Client(id=%r addr:%s)" % (self.id, str(self.addr))

    # Inicializacao
    def __init__(self, host, port):
        self.ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ss.connect((host, port))
        logging.info(bcolors.OKBLUE+"Client listening on"+bcolors.ENDC+"%s", self.ss.getsockname())
        self.inputs = []        # Sockets from which we expect to read

        # Login stuff
        self.uuid = str(sys.argv[1])
        self.passphrase = str(sys.argv[2])
        self.id = None
        self.name = None
        self.certificate = None
        self.serialnumber = None
        self.myDirPath = "clients/" + str(self.uuid)

        # Buffers
        self.bufin = ""
        self.bufout = ""
        self.mail = {}   # inbox
        self.outmail= {} # outbox
        self.Users = []  # user id, uuid, pubkeys

        # Key Pairs
        self.pubKey, self.privKey = None, None

        # Server
        self.serverPubKey = None
        self.serverPubNum = None
        
        # Connection
        self.pubNum = None
        self.privNum = None
        self.modulus_prime = MODULUS_PRIME
        self.primitive_root = PRIMITIVE_ROOT
        self.state = NOT_CONNECTED
        self.salt = None
        self.sharedKey = None

        # Flag de sincronizacao inicial
        self.sync = True
        self.to_receipt = False

    ################################################################################### Aux Functions ###############################################################################

    def getKeyByValue(self, value):
        for k, v in self.mail.items():
            if str(value) == v or isinstance(v, list) and str(value) in v:
                return k
        return None
        
    def loadKeys(self):
        # user path to keys
        path = self.myDirPath + "/key.pem"
        try:
            with open(path, "rb") as f:
                key = RSA.importKey(f.read(), self.passphrase)  # import with passphrase
                self.pubKey, self.privKey = key.publickey().exportKey(format='PEM'),key.exportKey(format='PEM', passphrase=self.passphrase)
                print bcolors.OKBLUE+ "Keys Sucessfully Loaded!" + bcolors.ENDC
                return True
        except:
            print bcolors.FAIL+ "Error! Wrong Passphrase! Aborting..." + bcolors.ENDC
            return False
        return False

    def saveKeys(self):
        self.pubKey, self.privKey = security.get_keys(self.passphrase)
        try:
            os.mkdir(self.myDirPath)
            print bcolors.OKBLUE+ "User Dir(keys) created!"+ bcolors.ENDC
        except:
            pass

        # into file, client dir
        path = self.myDirPath + "/key.pem"
        data = self.privKey     # PEM already

        with open(path, "wb") as f:
            f.write(data)
        return

    def checkUser(self, user):
        for x in self.Users:
            y = dict(x)
            if y['description']['uuid'] == str(user):
                return True
        return False

    def getUUID(self, idd):
        """
        Translation between id to uuid,
        give an id, returns respective uuid
        """
        for x in self.Users:
            y = dict(x)
            if y['id'] == int(idd):
                return str(y['description']['uuid']) 

    def getID(self, idd):
        """
        Translation between uuid to id,
        give an id, returns respective uuid
        """
        for x in self.Users:
            y = dict(x)
            if y['description']['uuid'] == str(idd):
                return str(y['id'])

    def getCert(self, username):
        """
        Translation between uuid to id,
        give an id, returns respective uuid
        """
        for x in self.Users:
            y = dict(x)
            if y['description']['uuid'] == str(username):
                return str(y['description']['auth_certificate'])

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
            instance = RSA.importKey(self.privKey, self.passphrase)

            b = security.rsaDecipher(message=data_key, key=instance)
            a = security.D_AES(symKey=b, message=data)

            return a

    ##################################################################################################################################################################################

    def parseReqs(self, data):
        """Parse a chunk of data from this client.
        Return any complete requests in a list.
        Leave incomplete requests in the buffer.
        This is called whenever data is available from client socket."""

        if len(self.bufin) + len(data) > MAX_BUFSIZE:
            '''log(logging.ERROR, "Client (%s) buffer exceeds MAX BUFSIZE. %d > %d" %
                (self, len(self.bufin) + len(data), MAX_BUFSIZE))'''
            self.bufin = ""

        self.bufin += data
        reqs = self.bufin.split('\n\n') 
        self.bufin = reqs[-1]

        return reqs[:-1]

    def handleRequest(self, request):
        """
        Faz o devido handle dos requests do servidor, 
        tratando dos dados enviados e processando 
        de forma logica
        """
        self.inbox=[]
        self.newMails=[]
        self.mailBox=[]
        self.outbox=[]
        try:
            try:
                req = json.loads(request)
            except:
                return

            if not isinstance(req, dict):
                return

            if 'resultSend' in req:
                # mensagem enviada correctamente
                print bcolors.OKBLUE + "Message Sent Sucessfully!" + bcolors.ENDC
                return

            if 'resultAll' in req:
                i=0
                os.system('clear')

                # Parsing messages
                for x in req['resultAll'][0]:
                    if x[0] == '_':
                        if x not in self.inbox:
                            self.inbox.append(x)
                    else:
                        if x not in self.newMails:
                            self.newMails.append(x)

                for y in req['resultAll'][1]:
                    if y not in self.outbox:
                        self.outbox.append(y)

                # ordered mail, new messages first
                self.mailBox = self.newMails + self.inbox   

                print bcolors.OKGREEN + bcolors.BOLD + "            Mensagens (Inbox/Outbox): \n" + bcolors.ENDC
                print bcolors.WARNING + str(len(self.mailBox)) + " Received Messages: " + bcolors.ENDC
                if len(self.mailBox) == 0:
                        print "You didnt received any message yet.\n"
                for mail in self.mailBox:
                    if mail[0] == '_':
                        i = i + 1
                        aux = mail.split('_')
                        print str(i) + "- Message " +  str(aux[2]) + " from " +  self.getUUID(str(aux[1]))
                    else:
                        i = i + 1
                        aux = mail.split('_')
                        print str(i) + "- Message " +  str(aux[1]) + " from " +  self.getUUID(str(aux[0])) + bcolors.FAIL +" (NEW!)"+bcolors.ENDC
                print "\n"
                print bcolors.WARNING + str(len(self.outbox))  + " Sent Messages: " + bcolors.ENDC
                if len(self.outbox) == 0:
                        print "You didnt send any message yet.\n"
                i = 0
                for mail in self.outbox:
                    aux = mail.split('_')
                    i = i + 1
                    print str(i) +"- Message " +  str(aux[1]) + " sent to user " +  self.getUUID(str(aux[0]))
                print "\n"
                print "\n"
                print "    ------------------------------------------------"
                print bcolors.HEADER + bcolors.BOLD + "     Commands: " + bcolors.ENDC
                print bcolors.WARNING +"        (/send  <user> <text>)" + bcolors.ENDC + "  Send a Message"
                print bcolors.WARNING +"        (/recv   <msg_number>)" + bcolors.ENDC + "  Read message"
                print bcolors.WARNING +"        (/status <msg_number>)" + bcolors.ENDC + "  Check Receipt Status"
                print bcolors.WARNING +"        (<)                   " + bcolors.ENDC + "  Main Menu"
                print "    ------------------------------------------------"

                # inbox, outbox
                self.mail = dict(zip(range(1,len(self.mailBox)+1), self.mailBox))
                self.outmail = dict(zip(range(1,len(self.outbox)+1), self.outbox))

                return

            if 'resultStatus' in req:
                os.system('clear')
                msg = req['resultStatus']['msg']
                msg = json.loads(msg)

                # parsing arguments to decipher message content, real text
                messageCiphered2 = base64.b64decode(msg['messageCiphered2'])
                symKeyCiphered2 = base64.b64decode(msg['symKeyCiphered2'])

                # parse signed receipt
                receiptDict =  json.loads(req['resultStatus']['receipts'][0]['receipt'])
                receiptSigned = base64.b64decode(receiptDict['receiptSigned'])
                receiptCleartext = base64.b64decode(receiptDict['receiptCleartext'])
                message = base64.b64decode(receiptDict['message'])

                # source username, certificate
                source = self.getUUID(req['resultStatus']['receipts'][0]['id'])
                source_cert = self.getCert(username=source)

                # timestamp
                timestamp = req['resultStatus']['receipts'][0]['date']

                # decipher msg
                msg = self.hybrid(operation='decipher', data=str(messageCiphered2), data_key=str(symKeyCiphered2))

                print bcolors.HEADER + bcolors.BOLD + "                 Receipt Status " + bcolors.ENDC
                if req['resultStatus']['receipts'] != []: # mensagem lida
                    print bcolors.OKGREEN + bcolors.BOLD + "Sent to: " + bcolors.ENDC + str(self.getUUID(req['resultStatus']['receipts'][0]['id']))
                    print bcolors.WARNING + bcolors.BOLD + "Your Message: " + bcolors.ENDC
                    print str(msg)
                    print "\n" 
                    if cc.verify(cert=source_cert, data= message, sign= receiptSigned) and cc.signatureValidity(cert=source_cert, timestamp=timestamp):
                        print bcolors.OKGREEN + bcolors.BOLD + "Signed and Verified! (Read at "+ str(time.ctime(int(timestamp) / 1000)) +")\n" + bcolors.ENDC
                        print bcolors.WARNING + bcolors.BOLD + "Signature: " +bcolors.ENDC
                        print str(receiptCleartext)
                        print "\n"
                    else:
                        print bcolors.FAIL + bcolors.BOLD + "Unreliable Message! (Forging attempt at "+ str(time.ctime(int(timestamp) / 1000)) +")\n" + bcolors.ENDC
                else:
                    print bcolors.WARNING + bcolors.BOLD + "Your Message: " + bcolors.ENDC
                    print str(msg)
                    print "\n" 
                    print bcolors.WARNING + bcolors.FAIL + "The message has not been read yet! " +bcolors.ENDC
                print "\n"
                print "    ------------------------------------------------"
                print bcolors.HEADER + bcolors.BOLD + "     Commands: " + bcolors.ENDC
                print bcolors.WARNING +"        (/all)    " + bcolors.ENDC + "Return to Message Box"
                print bcolors.WARNING +"        (<)       " + bcolors.ENDC + "Main Menu"
                print "    ------------------------------------------------"

                return

            if 'resultDH' in req:       
                #connect to server, calculate shared/session key
                self.serverPubNum = int(req['resultDH']['Server_pubNum'])
                self.serverPubKey = req['server_pubkey']
                self.sharedKey = int(pow(self.serverPubNum,self.privNum, self.modulus_prime))

                # state changed to connected
                self.state = CONNECTED

                # load keys and data registered on server(id, name), passphrase is checked
                if self.loadKeys():
                    self.id = req['id']
                    self.name = req['name']
                    print bcolors.OKBLUE+"Sucessfully Connected!"+bcolors.ENDC
                    # synchronizing users details
                    self.listUserMsgBox()
                    time.sleep(1)
                    os.system('clear')
                    self.show_menu() 
                else:
                    print bcolors.FAIL+"Connection Denied!"+bcolors.ENDC  
                return

            if 'resultRecv' in req:
                os.system('clear')
                source = req['resultRecv'][0]
                msg = req['resultRecv'][1]
                msg = json.loads(msg)

                # parsing arguments to decipher
                messageCiphered = base64.b64decode(msg['messageCiphered'])
                symKeyCiphered = base64.b64decode(msg['symKeyCiphered'])
                sent_timestamp = base64.b64decode(msg['timestamp'])
                signature_dict = json.loads(base64.b64decode(msg['signature']))

                signature = base64.b64decode(signature_dict['signature'])
                sign_cleartext = base64.b64decode(signature_dict['cleartext'])

                # decipher msg
                msg = self.hybrid(operation='decipher', data=str(messageCiphered), data_key=str(symKeyCiphered))
                
                # username and cert
                source = self.getUUID(str(source))
                source_cert = self.getCert(username=source)

                msg_nr = str(req['resultRecv'][2])
                dict_id = self.getKeyByValue(msg_nr)  # indicates message in self.mail
                print bcolors.OKGREEN + bcolors.BOLD + "Source: " + bcolors.ENDC + str(source)
                print bcolors.WARNING + bcolors.BOLD + "Message: " +bcolors.ENDC
                print msg
                print "\n"
                if cc.verify(cert=source_cert, data= msg, sign= signature) and cc.signatureValidity(cert=source_cert, timestamp=sent_timestamp):
                    print bcolors.OKGREEN + bcolors.BOLD + "Signed and Verified!\n" + bcolors.ENDC
                else:
                    print bcolors.FAIL + bcolors.BOLD + "Unreliable Message!\n" + bcolors.ENDC

                print "\n"
                print "    ------------------------------------------------"
                print bcolors.HEADER + bcolors.BOLD + "     Commands: " + bcolors.ENDC
                print bcolors.WARNING +"        (/all)    " + bcolors.ENDC + "      Return to Message Box"
                print bcolors.WARNING +"        (<)       " + bcolors.ENDC + "      Main Menu"
                print "    ------------------------------------------------"

               
                if self.to_receipt:        # mandar receipt se for primeira leitura
                    # Verificar estado do certificado
                    self.auth_certificate, self.session = cc.certificate(mode="AUTHENTICATION")
                    timestamp = str(int(time.time() * 1000))
                    if not cc.retrieveStatus(cert= self.auth_certificate, mode="AUTHENTICATION"):
                        print "Your Certificate is revoked! Sorry, aborting ..."
                        return
                    
                    if not cc.signatureValidity(cert=self.auth_certificate, timestamp=timestamp):
                        print "Your Signature isn't valid!"
                        return
                    # assinar
                    signature, cleartext = cc.sign(data=msg, session=self.session, mode="AUTHENTICATION")

                    receipt = json.dumps({
                            "receiptSigned": base64.b64encode(signature),
                            "receiptCleartext": base64.b64encode(cleartext),
                            "message" : base64.b64encode(msg),
                    })      
                    self.receipt(int(dict_id), receipt)

                return               

            if 'resultList' in req:
                arrayAux = []
                if self.sync == False:
                    os.system('clear')
                    print bcolors.OKGREEN + bcolors.BOLD + "\tMessageBoxes List (users): \n" + bcolors.ENDC
                    print bcolors.FAIL + "Hi "+ bcolors.WARNING + str(self.uuid) + bcolors.FAIL+", this is a list of users which you can exchange messages! \n"+bcolors.ENDC
                    print bcolors.OKGREEN + bcolors.BOLD + "Available Users:" + bcolors.ENDC
                for x in req['resultList']:
                    aux = {}
                    aux['id'] = x['id']
                    aux['description'] = x['description']
                    arrayAux.append(aux)
                    if self.sync == False:
                        if (x['description']['uuid'] != (self.uuid)):
                            print bcolors.WARNING +'Username: ' +bcolors.ENDC + str(x['description']['uuid']) + " \t " + bcolors.WARNING +'Nome: ' +bcolors.ENDC+(x['description']['name']).encode('utf-8')
                if self.sync == False:
                    print "\n"
                    print bcolors.HEADER + bcolors.BOLD + "Commands: " + bcolors.ENDC
                    print bcolors.WARNING +"(<)    " + bcolors.ENDC + " go back to main menu"
                self.Users = arrayAux
                self.sync = False
                return

            if 'resultCreate' in req:
                self.id =  req['resultCreate']
                print bcolors.OKGREEN + "You may connect now! (/connect)" + bcolors.ENDC
                return

            if 'type' not in req:
                return

        except Exception, e:
            logging.exception("Could not handle request")

    def handleInput(self, input):
        """
        Faz o handle do input(teclado)
        e redireciona para a funcao correcta
        de modo a fazer um pedido correcto ao servidor
        """
        fields = input.split()

        if fields[0] == '/list':
            self.listUserMsgBox()
            return
        if fields[0] == '/create':
            if self.id != None:
                print "You already created at least one MessageBox"
                return
            self.createUserMsgBox()
            return
        if fields[0] == '/all':
            self.listAllMessages()
            return
        if fields[0] == '/send':
            usernameDst = str(fields[1])
            if self.checkUser(usernameDst):
                self.sendMessage(str(fields[1]), fields[2:])
                return
            print bcolors.FAIL + "Username not found! Try another one ..." + bcolors.ENDC            
            return
        if fields[0] == '/recv':
            self.recvMessage(int(fields[1]))
            return
        if fields[0] == '<':
            os.system('clear')
            self.show_menu()
            return
        if fields[0] == '/connect':
            if self.state == NOT_CONNECTED:
                self.startDH(1)
            else:
                print "You are already Connected!"
                return
            return
        if fields[0] == '/status':
            self.status(int(fields[1]))
            return
        else:
            logging.error("Invalid input")
            return

    def processSecure(self, req):
        req = json.loads(req)
        salt = self.salt
        kdf_key = self.kdf_key
        content = req['content'] #mensagem
        content_decoded = base64.b64decode(content)

        # Read HMAC
        HMAC_msg = base64.b64decode(req['HMAC'])

        # Conteudo da mensagem
        dataFinal = security.D_AES(message= content_decoded, symKey= kdf_key) 
        
        # Creating new HMAC
        HMAC_new = (HMAC.new(key=kdf_key, msg=dataFinal, digestmod=SHA512)).hexdigest() # Criar novo HMAC com o texto recebido e comparar integridade

        # Checking Integrity
        if (HMAC_new == HMAC_msg) :
            #print bcolors.OKBLUE + "Integrity Checked Sucessfully" + bcolors.ENDC
            return dataFinal
        else:
            #print bcolors.FAIL + "Message forged! Sorry! Aborting ..." + bcolors.ENDC
            return

    def retrieveCCData(self):
        try:
            self.auth_certificate, self.session = cc.certificate(mode="AUTHENTICATION")
            self.sign_certificate, self.session = cc.certificate(mode="SIGNATURE")

            self.name, self.serialnumber = cc.getUserDetails(self.auth_certificate)
            print bcolors.OKBLUE + "Citizen Card loaded!" + bcolors.ENDC

            if not (cc.retrieveStatus(cert= self.auth_certificate, mode="AUTHENTICATION") or cc.retrieveStatus(cert= self.sign_certificate, mode="SIGNATURE")):
                print bcolors.FAIL + "Citizen Card revoked!" + bcolors.ENDC
                return False
            print bcolors.OKBLUE + "Citizen Card not revoked!" + bcolors.ENDC
            time.sleep(1)
            return True
        except:
            print bcolors.FAIL + "Failed loading Citizen Card!" + bcolors.ENDC
            return False
        return False

    def loop(self):
        """
        Ciclo de vida, handle de requests do servidor
        e pedidos do cliente ao servidor, em loop
        """
        os.system('clear')
        self.show_initmenu()
        while 1:
            socks = select.select([self.ss, sys.stdin, ], [], [])[0]
            for sock in socks:
                if sock == self.ss:
                    # information received from server
                    data = self.ss.recv(MAX_BUFSIZE)
                    if len(data) > 0:
                        reqs = self.parseReqs(data)
                        for req in reqs:
                            #print req
                            if 'secure' in req:
                                req = self.processSecure(req)
                            self.handleRequest(req)
                elif sock == sys.stdin:
                    # Information from keyboard input
                    input = raw_input()
                    if len(input) > 0:
                        self.handleInput(input)
    
    ################################################################################ Client Messages ################################################################################
    #Start DiffieHelman key exchange
    def startDH(self, phase):
        self.primitive_root = PRIMITIVE_ROOT
        self.modulus_prime = MODULUS_PRIME
        self.privNum = privateNumber()
        self.pubNum =  get_pubNum(self.primitive_root, self.privNum, self.modulus_prime)
        data = {
                "type" : "dh",
                "phase": int(phase),
                "uuid"   : self.uuid,
                "primitive_root" : self.primitive_root,
                "modulus_prime"  : self.modulus_prime,
                "Client_pubNum"  : int(self.pubNum),
        }
        self.send(data)

    # Message status
    def status(self, msgNr):
        data = {
                "type" : "status",
                "id"   : self.uuid,
                "msg"  : self.outmail[msgNr],
        }
        self.send(data)

    # Message receipt
    def receipt(self, msgNr, receipt):
        data = {
                "type" : "receipt",
                "id"   : self.uuid,
                "msg"  : self.mail[int(msgNr)],
                "receipt": receipt,
        }
        print bcolors.OKBLUE + "Receipt Sent Sucessfully!" + bcolors.ENDC
        self.send(data)

    # Create User Message Box
    def createUserMsgBox(self):
        if self.retrieveCCData():
            self.saveKeys()
            data = {
                    "type": "create",
                    "uuid": self.uuid,
                    "name": self.name,
                    "Client_pubKey"  : self.pubKey,
                    "auth_certificate" : self.auth_certificate,
                    "sign_certificate" : self.sign_certificate,
                    "serialnumber" : self.serialnumber,
                    }
            self.send(data)

    # Read a message
    def recvMessage(self, msgNr):

        if self.mail[int(msgNr)] in self.newMails:
            self.to_receipt = True
        else:
            self.to_receipt = False


        data = {
                "type": "recv",
                "uuid"  : self.uuid,
                "msg" : self.mail[int(msgNr)],
                }
        self.send(data)

    # List all messages in boxes, sent and recvd
    def listAllMessages(self):
        data = {
                "type": "all",
                "uuid": self.uuid,
                }
        self.send(data)

    # List users with details
    def listUserMsgBox(self):
        data = {
                "type": "list",
                }
        self.send(data)

    # Send a message to another user/client
    def sendMessage(self, dst, txt):
        sending = ""
        for t in txt:
            sending += (str(t))
            sending += " "
        
        dstId = int(self.getID(dst)) - 1  # dict comeca em 0

        # respectiva public key
        dstPubKey = self.Users[dstId]['description']['Client_pubKey']
        #print self.Users[dstId]['description']

        # cifra hibrida destino
        messageCiphered, symKeyCiphered = self.hybrid('cipher', sending, dstPubKey)

        # cifra hibrida para mim
        messageCiphered2, symKeyCiphered2 = self.hybrid('cipher', sending, self.pubKey)


        # registar envio
        timestamp = str(int(time.time() * 1000))

        # Verificar estado do certificado
        self.auth_certificate, self.session = cc.certificate(mode="AUTHENTICATION")

        if not cc.retrieveStatus(cert= self.auth_certificate, mode="AUTHENTICATION"):
            print "Your Certificate is revoked! Sorry, aborting ..."
            return
        
        if not cc.signatureValidity(cert=self.auth_certificate, timestamp=timestamp):
            print "Your Signature isn't valid!"
            return
        # assinar
        signature, cleartext = cc.sign(data=sending, session=self.session, mode="AUTHENTICATION")

        # signed stuff
        signed = json.dumps({
                "signature": base64.b64encode(signature),
                "cleartext" : base64.b64encode(cleartext),
        })

        # encapsulamento destino
        dstMessage = json.dumps({
                "messageCiphered": base64.b64encode(messageCiphered),
                "symKeyCiphered" : base64.b64encode(symKeyCiphered),
                "timestamp": base64.b64encode(timestamp),
                "signature": base64.b64encode(signed),
        })

        # encapsulamento para mim
        srcMessage = json.dumps({
                "messageCiphered2": base64.b64encode(messageCiphered2),
                "symKeyCiphered2" : base64.b64encode(symKeyCiphered2),
                "timestamp": base64.b64encode(timestamp),
        })


        data = {
                "type": "send",
                "src": self.uuid,
                "dst": dst,
                "msg": dstMessage,
                "copy": srcMessage,        # para mim, receipt
                }
        self.send(data)

    ##################################################################################################################################################################################

    # Verificacao do tipo de mensagem e envio (socket.send)
    def send(self, dict_):
        if self.state == NOT_CONNECTED:
            if dict_['type'] == 'dh' or dict_['type'] == 'create':          # Connect e Create
                try:
                    self.ss.send((json.dumps(dict_))+TERMINATOR)
                except Exception:
                    pass
            else:
                print "Error! Not connected!"

        if self.state == CONNECTED:
            # Secure Messages with Session Key
            if dict_['type'] == 'list' or dict_['type'] == 'send' \
                or dict_['type'] == 'getMyId' or dict_['type'] == 'all' or dict_['type'] == 'new' \
                or dict_['type'] == 'recv' or dict_['type'] == 'dh' or dict_['type'] == 'status' or dict_['type'] == 'receipt':
                try:
                    # Pronto para encapsular
                    message = (json.dumps(dict_))   

                    # Calcular nova chave derivada
                    # salt
                    salt = security.get_symmetricKey(256)
                    self.salt = salt
                    # Gerar derivada baseada no salt
                    kdf_key = security.kdf(str(self.sharedKey), self.salt, 32, 4096, lambda p, s: HMAC.new(p, s, SHA512).digest())
                    self.kdf_key = kdf_key

                    # Cifrar conteudo
                    sending =  security.AES(message, kdf_key)

                    # Gerar HMAC (mensagem, derivated key)
                    HMAC_msg = (HMAC.new(key=kdf_key, msg=message, digestmod=SHA512)).hexdigest()
                    # Encapsulamento
                    data = {
                            "type"          : "secure",
                            "content"       : base64.b64encode(sending),
                            "salt"          : base64.b64encode(salt),
                            "HMAC"          : base64.b64encode(HMAC_msg),
                            "client_pubkey" : base64.b64encode(self.pubKey)
                        }

                    self.ss.send(json.dumps(data)+TERMINATOR)
                except Exception:
                    pass
            else:
                print "Error while securing your message! Sorry! Quitting Client ..."
            
    # Disconnects
    def stop(self):
        try:
            self.disconnect_client("Client Stopped for some reason. Sorry...", client)
        except:
            print "Erro!"
        logging.info("Stopping Client")
        try:
            self.ss.close()
        except:
            logging.exception("Client.stop")
        logging.info("Client Stopped!")
    
    
    # Menu inicial
    def show_initmenu(self):
        print bcolors.HEADER + bcolors.BOLD + "             Secure Messaging Repository System\n" + bcolors.ENDC

        print bcolors.WARNING + "       (/create)                 " + bcolors.ENDC + "Create Account\n" + \
              bcolors.WARNING + "       (/connect)                " + bcolors.ENDC + "Connect to Message Repository\n" + \
              bcolors.HEADER + bcolors.BOLD + "\n"+ "Command:" + bcolors.ENDC
        return

    # Menu principal
    def show_menu(self):
        print bcolors.HEADER + bcolors.BOLD + "             Secure Messaging Repository System\n" + bcolors.ENDC
        print "     ---------------------------------------------------"
        print bcolors.WARNING + "       (/list)                   " + bcolors.ENDC + "List Connected Users\n" + \
              bcolors.WARNING + "       (/all)                    " + bcolors.ENDC + "My Message Box\n" +\
              bcolors.WARNING + "       (/send  <user> <text>)    " + bcolors.ENDC + "Send a Message"
        print "     ---------------------------------------------------"
        print bcolors.HEADER + bcolors.BOLD + "\n"+ "Command:" + bcolors.OKGREEN + "                                        Connected as "+ bcolors.ENDC + str(self.uuid)
        return

if __name__ == "__main__":
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, formatter=logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

    clnt = None
    try:
        logging.info(bcolors.OKBLUE+"Starting Client"+bcolors.ENDC)
        clnt = Client(HOST, PORT)
        clnt.loop()
    except KeyboardInterrupt:
        clnt.stop()
        try:
            logging.info(bcolors.OKBLUE+"Press CTRL-C again within 2 sec to quit"+bcolors.ENDC)
            time.sleep(2)
        except KeyboardInterrupt:
            logging.info(bcolors.OKBLUE+"CTRL-C pressed twice: Quitting!"+bcolors.ENDC)
    except:
        logging.exception(bcolors.FAIL+"Client ERROR"+bcolors.ENDC)
        if clnt is not (None):
            clnt.stop()
        time.sleep(10)











