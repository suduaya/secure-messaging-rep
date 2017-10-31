import time, base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA,SHA224,SHA256, SHA384, SHA512, HMAC
from Crypto.Random import random
from Crypto import Random
from string import ascii_lowercase
from Crypto.Cipher import PKCS1_v1_5,AES
from Crypto.Protocol.KDF import PBKDF2

BlockSize = 16
pad = lambda s: s + (BlockSize - len(s) % BlockSize) * chr(BlockSize - len(s) % BlockSize)
unpad = lambda s : s[:-ord(s[len(s)-1:])]

class Security:
    ###############################################SYMMETRIC############################################################
    def AES(self, message, key):
        #key = self.get_symmetricKey(keyBits)
        #iv = Random.new().read(AES.block_size)  # initial vector to sum to 1 text block
        message_b = bytes(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        msg = iv + cipher.encrypt(pad(message_b))
        return msg

    def get_symmetricKey(self, bits):
        bits = int(bits)
        if bits == 64:
            key = bytes(''.join(random.choice(ascii_lowercase) for i in range(8)))  # random string 64 bits
            return key
        if bits == 128:
            key = bytes(''.join(random.choice(ascii_lowercase) for i in range(16)))  # random string 128 bits no parity bit 3*5+1
            return key
        if bits == 192:
            key = bytes(''.join(random.choice(ascii_lowercase) for i in range(24)))  # random string 192 bits
            return key
        if bits == 256:
            key = bytes(''.join(random.choice(ascii_lowercase) for i in range(32)))  # random string 256 bits
            return key

    def D_AES(self, symKey, message):
        message_b = bytes(message)
        cipher = AES.new(symKey, AES.MODE_CBC, message_b[:AES.block_size])
        msg = cipher.decrypt(message_b[AES.block_size:])
        return unpad(msg)

    ################################################ASSYMETRIC##########################################################
    # https://stackoverflow.com/questions/5244129/use-rsa-private-key-to-generate-public-key
    def get_keys(self):
        new_key = RSA.generate(2048)
        return (new_key.publickey().exportKey('PEM'),new_key.exportKey('PEM'))

    ## https://www.dlitz.net/software/pycrypto/api/2.6/
    def rsaCipher(self, message, key):
        h = SHA.new(message)
        cipher = PKCS1_v1_5.new(key)        #instance
        ciphered_text = cipher.encrypt(message + h.digest())
        return base64.b64encode(ciphered_text)

    def rsaDecipher(self, message, key):
        dsize = SHA.digest_size
        ciphered_key = base64.b64decode(message)
        sentinel = Random.new().read(len(ciphered_key) / 2 + dsize)  # Let's assume that average data length is 15
        cipher = PKCS1_v1_5.new(key)
        symmetric_key = cipher.decrypt(ciphered_key, sentinel)
        return symmetric_key[:-dsize]

    ##################################################HASH##############################################################
    # gerar novo [hmac(key, message) + mensagem]
    def HMAC_SHA(self, key, message, digestSize):   # estamos a usar digestsize = 64 => SHA512
        message_b = bytes(message)
        digestSize = int(digestSize)
        if digestSize == 20:
            hash = (HMAC.new(key=key, msg=message_b, digestmod=SHA)).hexdigest() + message_b
            return hash
        if digestSize == 28:
            hash = (HMAC.new(key=key, msg=message_b, digestmod=SHA224)).hexdigest() + message_b
            return hash
        if digestSize == 32:
            hash = (HMAC.new(key=key, msg=message_b, digestmod=SHA256)).hexdigest() + message_b
            return hash
        if digestSize == 48:
            hash = (HMAC.new(key=key, msg=message_b, digestmod=SHA384)).hexdigest() + message_b
            return hash
        if digestSize == 64:
            hash = (HMAC.new(key=key, msg=message_b, digestmod=SHA512)).hexdigest() + message_b
            return hash

    def check_HMAC(self, key, message, digestSize):
        # https://stackoverflow.com/questions/46311990/hmac-in-message-vs-hmac-in-digest
        #a[0] = [:h.digestSize*2] = get the hmac
        #a[1] = [h.digestSize*2:] = get the data message
        digestSize = int(digestSize)
        msg = bytes(message)
        if digestSize == 64:
            a = [msg[i:i + (digestSize*2)] for i in range(0, len(msg), (digestSize*2))] # split into hmac and text
            fullmsg = ''
            for i in a[1:]: # build message
                fullmsg += str(i)
            return (True, fullmsg) if a[0] == ((HMAC.new(key=key, msg=str(fullmsg), digestmod=SHA512)).hexdigest()) else (
                False, [])
        if digestSize == 48:
            a = [msg[i:i + (digestSize*2)] for i in range(0, len(msg), (digestSize*2))]
            fullmsg = ''
            for i in a[1:]:
                fullmsg += str(i)
            return (True, fullmsg) if a[0] == ((HMAC.new(key=key, msg=str(fullmsg), digestmod=SHA384)).hexdigest()) else (
                False, [])
        if digestSize == 32:
            a = [msg[i:i + (digestSize*2)] for i in range(0, len(msg), (digestSize*2))]
            fullmsg = ''
            for i in a[1:]:
                fullmsg += str(i)
            return (True, fullmsg) if a[0] == ((HMAC.new(key=key, msg=str(fullmsg), digestmod=SHA256)).hexdigest()) else (
                False, [])
        if digestSize == 28:
            a = [msg[i:i + (digestSize*2)] for i in range(0, len(msg), (digestSize*2))]
            fullmsg = ''
            for i in a[1:]:
                fullmsg += str(i)
            return (True, fullmsg) if a[0] == ((HMAC.new(key=key, msg=str(fullmsg), digestmod=SHA224)).hexdigest()) else (
                False, [])
        if digestSize == 20:
            a = [msg[i:i + (digestSize*2)] for i in range(0, len(msg), (digestSize*2))]
            fullmsg = ''
            for i in a[1:]:
                fullmsg += str(i)
            return (True, fullmsg) if a[0] == ((HMAC.new(key=key, msg=str(fullmsg), digestmod=SHA)).hexdigest()) else (
                False, [])

    # gera apenas o HMAC retornado de um request
    def HMAC_ONLY(self, key, message, digestSize):  # estamos a usar digestsize = 64 => SHA512
        message_b = bytes(message)
        digestSize = int(digestSize)
        if digestSize == 20:
            hash = (HMAC.new(key=key, msg=message_b, digestmod=SHA)).hexdigest()
            return hash
        if digestSize == 28:
            hash = (HMAC.new(key=key, msg=message_b, digestmod=SHA224)).hexdigest()
            return hash
        if digestSize == 32:
            hash = (HMAC.new(key=key, msg=message_b, digestmod=SHA256)).hexdigest()
            return hash
        if digestSize == 48:
            hash = (HMAC.new(key=key, msg=message_b, digestmod=SHA384)).hexdigest()
            return hash
        if digestSize == 64:
            hash = (HMAC.new(key=key, msg=message_b, digestmod=SHA512)).hexdigest()
            return hash

    # key derivation function check
    def check_kdf(self, key, message, bits):
        msg = bytes(message)
        #a = [msg[i:i + int(bits)/4] for i in range(0, len(msg), int(bits)/4)]
        hmac=msg[:int(bits)/4]
        salt=msg[int(bits)/4:]
        kdf_key = self.kdf(str(key), salt, 8, 4096, lambda p, s: HMAC.new(p, s, SHA512).digest())
        if bits=='512':
            return (True, salt, kdf_key) if hmac == ((HMAC.new(key=str(kdf_key), msg=str(salt), digestmod=SHA512)).hexdigest()) else (False,[], "")
        if bits=='384':
            return (True, salt, kdf_key) if hmac == ((HMAC.new(key=str(kdf_key), msg=str(salt), digestmod=SHA384)).hexdigest()) else (False,[], "")
        if bits=='256':
            return (True, salt, kdf_key) if hmac == ((HMAC.new(key=str(kdf_key), msg=str(salt), digestmod=SHA256)).hexdigest()) else (False,[], "")
        if bits=='224':
            return (True, salt, kdf_key) if hmac == ((HMAC.new(key=str(kdf_key), msg=str(salt), digestmod=SHA224)).hexdigest()) else (False,[], "")
        if bits=='1':
            return (True, salt, kdf_key) if hmac == ((HMAC.new(key=str(kdf_key), msg=str(salt), digestmod=SHA)).hexdigest()) else (False,[], "")


    # funcoes de sintese sha256 e sha512
    def SHA256(self, message):
        return SHA256.new(message).digest()
    def SHA512(self, message):
        return SHA512.new(message).digest()+message

    # key derivation function
    def kdf(self, pw, salt, klen, count, prf=None):
        key = PBKDF2(password=pw, salt=salt, dkLen=klen, count=count,prf=prf)
        return key