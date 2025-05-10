import socket
import subprocess
import signal

#velocidades = [1000,2000,3000,4000,5000,6000,7000,8000,9000,10000, -1]
velocidades = [1000,2000, -1]

# Configurações do servidor para conectar
HOST = '127.0.0.1'  # Endereço IP do servidor
PORT = 65432        # Porta usada pelo servidor

IFACE = "amor"

# Criando socket TCP
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    for velocidade in velocidades:

        process = subprocess.Popen(["./remove_maps.sh", IFACE])
        process.wait()

        process = subprocess.Popen(["./bola", "--force", "--progsec", "xdp_ids_func", "--dev", IFACE], stdout=subprocess.PIPE, text=True)

        s.sendall(str(velocidade).encode())

        data = s.recv(1024)
        if data.decode() == "done":
            process.send_signal(signal.SIGINT)
            #process.wait()
            saida, erro = process.communicate()
            #print(saida)
            with open("resultado.txt", 'a') as f:
                f.write(f"\nVelocidade: {velocidade}\n")
                f.write(saida)


