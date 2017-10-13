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
        self.uuid = 10
        self.id = -1
        self.bufin = ""
        self.bufout = ""
        self.usersLists = []
        self.tasks = []     # request ordenados

    def parseReqs(self, data):
        print "Parsing"
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
        print "handling"


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
                return

            if 'resultNew' in req:
                return

            if 'resultList' in req:
                aux = []
                os.system('clear')
                print bcolors.OKGREEN + bcolors.BOLD + "Lista de MessageBoxes (users): " + bcolors.ENDC
                for x in req['resultList']:
                    aux.append(x['uuid'])
                    print '  -> '+str(x['uuid'])
                print "\n"
                print "/r  (go back to main menu)"
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
        fields = input.split()


        if fields[0] == 'list':
            self.listUserMsgBox()
            return
        if fields[0] == 'create':
            self.createUserMsgBox()
            return

        if fields[0] == 'all':
            self.listAllMessages()
            return
        if fields[0] == 'send':
            self.sendMessage()
            return
        if fields[0] == '/r':
            os.system('clear')
            self.show_menu()
            return
        else:
            logging.error("Invalid input")
            return

    # Processamento
    def loop(self):
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

    # Listar todas as mensagens de um user
    def listAllMessages(self):
        data = {
                "type": "all",
                "uuid": self.uuid,
                }
        self.send(data)

    # Listar User Message Box
    def listUserMsgBox(self):
        data = {
                "type": "list",
                }
        self.send(data)

    # Listar User Message Box
    def sendMessage(self):
    	idd= 20
    	msg= 'hello'
        data = {
                "type": "send",
                "src": 1,
                "dst": idd,
                "msg": msg,
                "copy": msg,
                }
        self.send(data)

    # enviar socket 
    def send(self, dict_, client=None):
        if dict_['type'] == 'create' or dict_['type'] == 'list' or dict_['type'] == 'send' or dict_['type'] == 'getMyId' or dict_['type'] == 'all' or dict_['type'] == 'new':
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
        print bcolors.HEADER + bcolors.BOLD + "Secure Messaging Repository System\n" + bcolors.ENDC
        print bcolors.WARNING + "1- " + bcolors.ENDC + "Create a User Message Box\n" + \
              bcolors.WARNING + "2- " + bcolors.ENDC + "List Users' Message Box\n"
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











