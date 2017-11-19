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

def get_keys(pw=None):     # RSA Key Pairs
    new_key = RSA.generate(2048)
    return (new_key.publickey().exportKey(format='PEM', passphrase= pw),new_key.exportKey(format='PEM', passphrase= pw))


pub, priv = get_keys("password")

print pub
print priv

instance = RSA.importKey(externKey= priv, passphrase= "password")












