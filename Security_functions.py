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
    def SHA256(self, message):
        return SHA256.new(message).digest()
        
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
        if bits == 32:
            key = bytes(''.join(random.choice(ascii_lowercase) for i in range(4)))  # random string 64 bits
            return key
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
    def get_keys(self, passphrase=None):     # RSA Key Pairs
        new_key = RSA.generate(2048)
        return (new_key.publickey().exportKey(format='PEM'),new_key.exportKey(format='PEM', passphrase=passphrase))

    ## https://www.dlitz.net/software/pycrypto/api/2.6/
    def rsaCipher(self, message, key):
        h = SHA.new(message)
        cipher = PKCS1_v1_5.new(key)        #instance
        ciphered_text = cipher.encrypt(message + h.digest())
        return base64.b64encode(ciphered_text)

    def rsaDecipher(self, message, key):
        dsize = SHA.digest_size
        ciphered_key = base64.b64decode(message)
        flag = Random.new().read(len(ciphered_key) / 2 + dsize)  # Let's assume that average data length is 15
        cipher = PKCS1_v1_5.new(key)
        symmetric_key = cipher.decrypt(ciphered_key, flag)
        return symmetric_key[:-dsize]

    # key derivation function
    #https://www.dlitz.net/software/pycrypto/api/2.6/Crypto.Protocol.KDF-module.html
    def kdf(self, pw, salt, klen, count, prf=None):
        key = PBKDF2(password=pw, salt=salt, dkLen=klen, count=count,prf=prf)
        return key


