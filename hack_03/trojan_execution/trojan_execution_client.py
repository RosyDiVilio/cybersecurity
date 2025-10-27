#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import sys
import subprocess
import tempfile
import os

def start_client(server_ip: str, server_port: int) -> None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            print(f"Tentativo di connessione a {server_ip} porta {server_port}...")
            sock.connect((server_ip, server_port))
            print("Connessione stabilita. Ricezione script...")

            # Riceve lo script (presumibilmente piccolo, altrimenti si dovrebbe usare delimitatori)
            response_data = b''
            while True:
                data_chunk = sock.recv(4096)
                if not data_chunk:
                    break
                response_data += data_chunk
                if len(data_chunk) < 4096:
                    break

            script_content = response_data.decode('utf-8')

            if script_content.strip() == "SCRIPT_NOT_FOUND":
                print("Il server non ha fornito alcuno script.")
                return

            # Salva lo script in un file temporaneo
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".sh") as script_file:
                script_file.write(script_content)
                temp_script_path = script_file.name

            # Rende lo script eseguibile
            os.chmod(temp_script_path, 0o755)

            print(f"Eseguo lo script ricevuto ({temp_script_path})...\n")
            # Esegue lo script
            subprocess.run([temp_script_path], check=False)

            # Opzionale: elimina lo script dopo l'esecuzione
            os.remove(temp_script_path)
            print("Script eseguito e rimosso.")

    except ConnectionRefusedError:
        print(f"Errore: Connessione rifiutata. Assicurati che il server sia in ascolto su {server_ip}:{server_port}.")
    except socket.gaierror:
        print(f"Errore: L'indirizzo IP '{server_ip}' non è valido o non risolvibile.")
    except socket.error as e:
        print(f"Errore del socket: {e}")
    except KeyboardInterrupt:
        print("\nClient interrotto dall'utente.")
    finally:
        print("Client terminato.")
