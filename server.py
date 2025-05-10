import socket
import subprocess

# Configurações do servidor
HOST = '127.0.0.1'  # Endereço IP do servidor (localhost)
PORT = 65432        # Porta que o servidor irá escutar

# Criando socket TCP
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"Servidor escutando em {HOST}:{PORT}")
    
    conn, addr = s.accept()
    with conn:
        print(f"Conectado por {addr}")
        data = conn.recv(1024)
        while data.decode() != '-1':
            velocidade = data.decode()  # isso eh string
            #tcpreplay -i veth0 -K --loop 3000000 --mbps 2000 1pkt.pcap
            process = subprocess.Popen(["tcpreplay", "-i", "amor", "-K", "--loop", "1000000", "--mbps", velocidade, "1pkt.pcap"])
            process.wait()

            conn.sendall(b'done')
            data = conn.recv(1024)

