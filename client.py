from config import *
import sys
key = RSA.generate(1024)

if sys.argv[1] == 'hello':
    message = 'hello'.encode()
else:
    message = input('Enter message: ').encode()

with socket(AF_INET, SOCK_STREAM) as tcp_socket:
    tcp_socket.connect((HOST, PORT))
    tcp_socket.send(key.publickey().exportKey())  # send key

    s_key = RSA.importKey(tcp_socket.recv(1024))
    data, = s_key.encrypt(message, 32)
    tcp_socket.send(data)  # send message

    data = tcp_socket.recv(1024)
    sign = (key.decrypt(int(data.decode())), )
    message_hash = sha256(message).digest()
    verify = s_key.verify(message_hash, sign)
    print(verify)

    data, = s_key.encrypt(b'end:)', 32)
    tcp_socket.send(data)
