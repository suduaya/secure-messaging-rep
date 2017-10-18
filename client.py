import select, socket, sys
import json
import time, base64
import random
import logging, socket, datetime
import os



HOST = "localhost"   # All available interfaces
PORT = 8080          # The server port

sys.tracebacklimit = 30

TERMINATOR = "\r\n"
MAX_BUFSIZE = 64 * 1024

taskNumber = 0

#Colours
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'    # Colours

# Randomizer
def get_id(length):
    a = "1"
    while len(a) != int(length) and a[0]!='0':
        a = ''.join([str(random.randint(0, 9)) for i in range(8)])
    return int(a)




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
        self.myConnections = {}
        self.inputs = []        # Sockets from which we expect to read
        self.uuid = 20
        self.id = 2
        self.bufin = ""
        self.bufout = ""
        self.usersLists = []
        self.tasks = []     # request ordenados
        self.mail = {}

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
            logging.info("HANDLING message from server: %r", repr(request))

            try:
                req = json.loads(request)
            except:
                return

            if not isinstance(req, dict):
                return

            if 'resultSend' in req:
                print req['resultSend']
                return

            if 'resultAll' in req:
                i=0
                os.system('clear')

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


                self.mailBox = self.newMails + self.inbox   # ordered

                #print self.mailBox
                print bcolors.OKGREEN + bcolors.BOLD + "        Mensagens (Enviadas/Recebidas): " + bcolors.ENDC
                print bcolors.WARNING + str(len(self.mailBox)) + " Mensagens Recebidas: " + bcolors.ENDC
                if len(self.mailBox) == 0:
                        print "Voce nao tem mensagens disponiveis\n"
                for mail in self.mailBox:
                    if mail[0] == '_':
                        i = i + 1
                        aux = mail.split('_')
                        print str(i) + "- Message " +  str(aux[2]) + " from user " +  str(aux[1])
                    else:
                        i = i + 1
                        aux = mail.split('_')
                        print str(i) + "- Message " +  str(aux[1]) + " from user " +  str(aux[0]) + bcolors.FAIL +" (NEW!)"+bcolors.ENDC

                print "\n"
                print bcolors.WARNING + str(len(self.outbox))  + " Mensagens Enviadas: " + bcolors.ENDC
                if len(self.outbox) == 0:
                        print "Voce nao tem mensagens enviadas\n"
                for mail in self.outbox:
                    aux = mail.split('_')
                    i = i + 1
                    print str(i) +"- Message " +  str(aux[1]) + " sent to user " +  str(aux[0])

                print "\n"
                print bcolors.HEADER + bcolors.BOLD + "Commands: " + bcolors.ENDC
                print bcolors.WARNING +"(/recv <msg_number> <src_user>)" + bcolors.ENDC + " Read message"
                print bcolors.WARNING +"(<)                            " + bcolors.ENDC + " go back to main menu"
         
                self.mail = dict(zip(range(1,len(self.mailBox)+1), self.mailBox))

                #print self.mail
                return

            if 'resultNew' in req:
                return

            if 'resultRecv' in req:
                os.system('clear')
                source = req['resultRecv'][0]
                msg = req['resultRecv'][1]
                print bcolors.OKGREEN + bcolors.BOLD + "Source: " + bcolors.ENDC + str(source) 
                print bcolors.WARNING + bcolors.BOLD + "Message: " +bcolors.ENDC
                print msg
                print "\n"
                print bcolors.HEADER + bcolors.BOLD + "Commands: " + bcolors.ENDC
                print bcolors.WARNING +"(<)    " + bcolors.ENDC + " go back to main menu"
                return               

            if 'resultList' in req:
                aux = []
                os.system('clear')
                print bcolors.OKGREEN + bcolors.BOLD + "        Lista de MessageBoxes (users): \n" + bcolors.ENDC
                print bcolors.WARNING+"Hello Mr." + str(self.uuid) +"! This is a list of users which you can communicate!"+bcolors.ENDC+"\n"
                for x in req['resultList']:
                    aux.append(x['id'])
                    if int(x['id'] != self.id):
                        print '         -> id: '+bcolors.WARNING+str(x['id'])+bcolors.ENDC +"      (I'm Mr." +bcolors.WARNING + str(x['description']['uuid']) + bcolors.ENDC+ " !)"
                print "\n"
                print bcolors.HEADER + bcolors.BOLD + "Commands: " + bcolors.ENDC
                print bcolors.WARNING +"(<)    " + bcolors.ENDC + " go back to main menu"
                self.usersLists = aux
                return

            if 'resultCreate' in req:
                self.id =  req['resultCreate']
                return

            if 'type' not in req:
                return

            if req['type'] == 'connect':
                return

            elif req['type'] == 'secure':
            	return
                #self.processSecure(server, req)

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
            self.createUserMsgBox()
            return
        if fields[0] == '/all':
            self.listAllMessages()
            return
        if fields[0] == '/send':
            self.sendMessage(int(fields[1]), str(fields[2]))
            return
        if fields[0] == '/recv':
            self.recvMessage(int(fields[1]))
            return
        if fields[0] == '<':
            os.system('clear')
            self.show_menu()
            return
        else:
            logging.error("Invalid input")
            return

    def loop(self):
        """
        Ciclo de vida, handle de requests do servidor
        e pedidos do cliente ao servidor, em loop
        """
        os.system('clear')
        self.show_menu()
        while 1:
            socks = select.select([self.ss, sys.stdin, ], [], [])[0]
            for sock in socks:
                if sock == self.ss:
                    # information received from server
                    data = self.ss.recv(MAX_BUFSIZE)
                    if len(data) > 0:
                        reqs = self.parseReqs(data)
                        for req in reqs:
                            self.handleRequest(req)
                elif sock == sys.stdin:
                    # Information from keyboard input
                    input = raw_input()
                    if len(input) > 0:
                        self.handleInput(input)
    
    ## Funcoes Listadas
    # Get do Id interno do cliente no servidor
    def getMyId(self):
    	data = {
    			"type" : "getMyId",
    			"id"   : self.uuid,
    	}
    	self.send(data)

    # Create User Message Box
    def createUserMsgBox(self):
        data = {
                "type": "create",
                "uuid": self.uuid,
                }
        self.send(data)

    # Leitura de uma mensagem
    def recvMessage(self, msgNr):
        data = {
                "type": "recv",
                "id"  : self.id,
                "msg" : self.mail[msgNr],
                }
        self.send(data)

    # Listar todas as mensagens de um user
    def listAllMessages(self):
        data = {
                "type": "all",
                "id": self.id,
                }
        self.send(data)

    # Listar User Message Box
    def listUserMsgBox(self):
        data = {
                "type": "list",
                }
        self.send(data)

    # Listar User Message Box
    def sendMessage(self, dst, txt):
        data = {
                "type": "send",
                "src": self.id,
                "dst": dst,
                "msg": txt,
                "copy": txt,
                }
        self.send(data)

    # Verificacao do tipo de mensagem e envio (socket.send)
    def send(self, dict_, client=None):
        if dict_['type'] == 'create' or dict_['type'] == 'list' or dict_['type'] == 'send' \
            or dict_['type'] == 'getMyId' or dict_['type'] == 'all' or dict_['type'] == 'new' \
            or dict_['type'] == 'recv':
            try:
                self.ss.send((json.dumps(dict_))+TERMINATOR)
            except Exception:
                pass

    # Disconnects
    def stop(self):
        for client in self.myConnections.keys():
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
    def show_menu(self):
        print bcolors.HEADER + bcolors.BOLD + "     Secure Messaging Repository System\n" + bcolors.ENDC
        print bcolors.WARNING + "(/create)                 " + bcolors.ENDC + "Create a User Message Box (dup)\n" + \
              bcolors.WARNING + "(/list)                   " + bcolors.ENDC + "List All Users\n" + \
              bcolors.WARNING + "(/all)                    " + bcolors.ENDC + "List All Messages\n" + \
              bcolors.WARNING + "(/send <user> <text>)     " + bcolors.ENDC + "Send a Message\n"
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











