import socket

HOST = '0.0.0.0'
PORT = 65535

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()

    print(f'Server is listening on {HOST}:{PORT}...')

    while True:
        
        conn, addr = s.accept()
        with conn:
            print(f'Connected by {addr}')
            conn.sendall(b'Hello i am TCP, scan me deeper!')