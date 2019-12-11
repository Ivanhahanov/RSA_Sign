from config import *

key = RSA.generate(1024)

with socket(AF_INET, SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()

    with conn:
        c_key = RSA.importKey(conn.recv(1024))
        conn.send(key.publickey().exportKey())  # send key

        data = conn.recv(1024)
        mess = key.decrypt(data)
        print(mess)

        message_hash = sha256(mess).digest()
        signature, = key.sign(message_hash, '')
        new_mess, = c_key.encrypt(signature, 32)
        conn.send(str(new_mess).encode())  # send sign
        data = conn.recv(1024)
