from Crypto.PublicKey import RSA
from hashlib import sha256

print("Generate keys...")
server_keys = RSA.generate(1024)
client_keys = RSA.generate(1024)

pub_key = server_keys.publickey().exportKey()
print("Server public key:", pub_key.decode())
pub_key = client_keys.publickey().exportKey()
print("Client public key:", pub_key.decode())

mess = "hello"
print("Message:", mess)

# hashing and signed message
message_hash = sha256(mess.encode()).digest()
signature, = server_keys.sign(message_hash, '')
new_mess, = client_keys.publickey().encrypt(signature, 32)
print("Signed message hash:", str(new_mess))

# decrypt sign
sign = (client_keys.decrypt(new_mess), )
# verify sign
verify = server_keys.publickey().verify(message_hash, sign)
print("Check sign:", verify)
