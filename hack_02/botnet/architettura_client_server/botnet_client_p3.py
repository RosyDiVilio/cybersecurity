# -*- coding: utf-8 -*-
# Compatibile con Python 3

import socket
import sys

def connect_to_server(server_ip, server_port):
    try:
        # Crea un socket TCP/IP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = (server_ip, server_port)

        print("Connessione a {} porta {}".format(server_ip, server_port))

        # Connette il socket al server
        sock.connect(server_address)

        try:
            while True:
                # Usa input() in Python 3
                message = input("Inserisci un messaggio da inviare (o 'exit' per uscire): ")

                if message.lower() == 'exit':
                    print("Chiusura connessione...")
                    break

                print("Invio: {}".format(message))

                # Converte la stringa in bytes
                sock.sendall(message.encode('utf-8'))

                # Ricezione della risposta dal server
                while True:
                    data = sock.recv(1024)

                    if not data:
                        print("Connessione chiusa dal server.")
                        return

                    # Decodifica i bytes ricevuti in stringa
                    print("Risposta dal server: {}".format(data.decode('utf-8')))

                    # Se il messaggio ricevuto è inferiore a 1024 byte, non ci sono altri dati
                    if len(data) < 1024:
                        break
        finally:
            sock.close()
            print("Connessione chiusa.")

    except Exception as e:
        print("Errore: {}".format(e))
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python3 client.py [indirizzo_ip_server] [porta_server]")
        sys.exit(1)

    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])

    connect_to_server(server_ip, server_port)

