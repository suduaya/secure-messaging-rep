import time, base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA,SHA224,SHA256, SHA384, SHA512, HMAC
from Crypto.Random import random
from Crypto import Random
from string import ascii_lowercase
from Crypto.Cipher import PKCS1_v1_5,AES
from Crypto.Protocol.KDF import PBKDF2
from Security_functions import Security
from Crypto.Protocol.KDF import PBKDF1
import json

security = Security()

def secureMessage_Chiper(operation, data, data_key=None):
    if operation == 'cipher':
        symKey = security.get_symmetricKey(256)
        instance = RSA.importKey(data_key)

        a = security.AES(message=data, key=symKey)
        b = security.rsaCipher(message=symKey, key=instance)

        return a, b  # data ciphered with symKey, symKey ciphered with server pubKey

    if operation == 'decipher':
        instance = RSA.importKey(serverpriv)

        b = security.rsaDecipher(message=data_key, key=instance)
        a = security.D_AES(symKey=b, message=data)

        return a

# assymetric keys
clientpub, clientpriv = security.get_keys()
serverpub, serverpriv = security.get_keys()


# msg sample
message= {
            "content" : "hello",
        }
print json.dumps(message)


#cifra
a, b = secureMessage_Chiper('cipher', json.dumps(message), data_key=serverpub)


#decifra
dataFinal =  secureMessage_Chiper('decipher', data=a, data_key=b)
print dataFinal











