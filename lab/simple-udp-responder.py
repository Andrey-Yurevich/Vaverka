import socket

HOST = '0.0.0.0'
PORT = 65534      

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.bind((HOST, PORT))
    print(f'UDP server is listening on {HOST}:{PORT}...')

    while True:
        data, addr = s.recvfrom(1024)
        print(f'Received message from {addr}')

        s.sendto(b'Hello i am UDP, scan me deeper!', addr)
        