
import requests as req
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher      import PKCS1_OAEP
import base64


f = open("test_key", 'r')
key = RSA.importKey( f.read() )

get_salt = {"pubkey" : key.exportKey('OpenSSH')}

print("start request")
#r = req.get("http://127.0.0.1:4567/block/10")




{'data' : "secret message",
 }

r = req.get("http://127.0.0.1:4567/salt", json=get_salt)

json = r.json()

crypt_salt = base64.b64decode(json['encrypt_salt'])

cipher = PKCS1_OAEP.new(key)

salt = cipher.decrypt(crypt_salt)

print(salt)


print("done")

#f = open('mykey.pem','r')
#key = RSA.importKey(f.read())
