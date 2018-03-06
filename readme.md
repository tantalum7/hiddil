
server -> server.py

client -> client.py


Creating a new testkey:

````python
from Crypto.Public import RSA
key = RSA.generate_key(1024)
with open("test_key", "w") as fp:
    fp.write(key.exportKey('PEM').decode("utf-8"))
````