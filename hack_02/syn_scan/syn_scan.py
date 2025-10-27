#!/usr/bin/env python3
"""
SYN scanner robusto (fix per TypeError su RandShort + fallback)

Uso:
  sudo python3 syn_scan_fixed.py <IP> <PORTA|p1,p2,...|start-end|all>
Opzioni utili (help):
  sudo python3 syn_scan_fixed.py -h

Principali migliorie:
 - usa int(RandShort()) per sport (fix TypeError)
 - fallback: se sr() genera eccezione, prova a scansionare porta-per-porta con sr1()
 - opzioni CLI per batch/timeout/delay e debug
 - commenti e output più verboso per debugging
"""
import argparse
import sys
import time
from scapy.all import IP, ICMP, TCP, sr, sr1, send, conf, RandShort

conf.verb = 0  # disabilita output verboso di Scapy

# -------------------------
# Utility
# -------------------------
def color(text, code):
    return f"\033[{code}m{text}\033[0m"

def parse_ports(arg, max_ports=50000, exclude_unused=False):
    """Parse dell'argomento porte: 'all', 'x-y', 'p1,p2,...' o singola.
       Restituisce lista di interi (limitata a max_ports)."""
    arg = arg.strip().lower()
    if arg == 'all':
        ports = list(range(1, 65536))
    elif '-' in arg:
        start, end = arg.split('-', 1)
        ports = list(range(int(start), int(end) + 1))
    elif ',' in arg:
        ports = sorted({int(p.strip()) for p in arg.split(',') if p.strip()})
    else:
        ports = [int(arg)]

    if exclude_unused:
        COMMON_UNUSED_PORTS = set(range(0, 20)) | set(range(1000, 1025)) | {
            135, 137, 138, 139, 445, 593, 1434, 1900, 2869, 5357, 17500
        }
        ports = [p for p in ports if p not in COMMON_UNUSED_PORTS]

    if len(ports) > max_ports:
        print(color(f"[!] Troppe porte ({len(ports)}). Limite applicato: {max_ports}.", "91"))
        ports = ports[:max_ports]

    return ports

def icmp_probe(ip, timeout=2):
    """Ping ICMP opzionale per controllare reachability."""
    try:
        pkt = IP(dst=ip)/ICMP()
        r = sr1(pkt, timeout=timeout, verbose=0)
        return r is not None
    except Exception:
        # non fallire se ICMP genera eccezione (ad es. permessi)
        return False

# -------------------------
# Scanner
# -------------------------
def syn_scan_batch(ip, ports, batch_size=200, timeout=4, delay_between_batches=0.5, debug=False):
    """
    Scansione con invio in batch di pacchetti SYN usando sr().
    - usa int(RandShort()) per sport (fix TypeError).
    - se sr() lancia un'eccezione, ritorna None per indicare fallback.
    Restituisce dict {porta: stato}
    """
    results = {}
    total = len(ports)
    start = time.time()

    try:
        for i in range(0, total, batch_size):
            batch = ports[i:i+batch_size]
            # IMPORTANT: convertire RandShort() in int per evitare TypeError
            pkts = [IP(dst=ip)/TCP(sport=int(RandShort()), dport=p, flags='S') for p in batch]

            if debug:
                print(f"[debug] Inviando batch {i//batch + 1}: porte {batch[0]}-{batch[-1]} (size {len(batch)})")

            # invia e ricevi
            answered, unanswered = sr(pkts, timeout=timeout, verbose=0)

            # default filtered
            for p in batch:
                results[p] = 'filtered'

            for sent_pkt, resp in answered:
                try:
                    dst_port = int(sent_pkt[TCP].dport)
                    src_sport = int(sent_pkt[TCP].sport)
                except Exception:
                    continue

                if resp is None:
                    results[dst_port] = 'filtered'
                    if debug:
                        print(f"[?] {dst_port}: no response")
                    continue

                if not resp.haslayer(TCP):
                    results[dst_port] = 'filtered'
                    if debug:
                        print(f"[?] {dst_port}: risposta non-TCP")
                    continue

                flags = int(resp[TCP].flags)
                # SYN-ACK (mask check)
                if (flags & 0x12) == 0x12:
                    results[dst_port] = 'open'
                    print(color(f"[+] {dst_port}: OPEN (SYN-ACK, flags={hex(flags)})", "92"))
                    # invia RST coerente
                    rst = IP(dst=ip)/TCP(sport=src_sport, dport=dst_port, flags='R')
                    send(rst, verbose=0)
                elif (flags & 0x04) != 0:
                    results[dst_port] = 'closed'
                    if debug:
                        print(color(f"[-] {dst_port}: CLOSED (RST, flags={hex(flags)})", "91"))
                else:
                    results[dst_port] = 'filtered'
                    if debug:
                        print(f"[?] {dst_port}: TCP non-standard flags={hex(flags)} -> filtered")

            scanned = min(i + batch_size, total)
            elapsed = time.time() - start
            rate = scanned / elapsed if elapsed > 0 else 0
            print(f"  Scansionate {scanned}/{total} porte — velocità ~{rate:.1f} p/s", end='\r')

            if delay_between_batches > 0:
                time.sleep(delay_between_batches)

        print()  # newline progresso
        return results

    except Exception as e:
        # Se sr() o altro fallisce, ritorniamo None per indicare fallback a modalità più conservativa
        print(f"\nERROR: durante sr() è avvenuta un'eccezione: {e}")
        return None

def syn_scan_fallback_per_port(ip, ports, timeout=6, delay_between=0.2, debug=False):
    """
    Fallback conservativo: usa sr1() porta per porta (più lento ma affidabile).
    Restituisce dict {porta: stato}
    """
    results = {}
    start = time.time()
    for idx, p in enumerate(ports, 1):
        try:
            sport = int(RandShort())
            pkt = IP(dst=ip)/TCP(sport=sport, dport=p, flags='S')
            if debug:
                print(f"[debug] sr1 -> porta {p} (sport {sport})")
            resp = sr1(pkt, timeout=timeout, verbose=0)
        except Exception as e:
            if debug:
                print(f"[debug] Errore sr1 porta {p}: {e}")
            resp = None

        if resp is None:
            results[p] = 'filtered'
            if debug:
                print(f"[?] {p}: no response -> filtered")
        elif not resp.haslayer(TCP):
            results[p] = 'filtered'
            if debug:
                print(f"[?] {p}: risposta non-TCP -> filtered")
        else:
            flags = int(resp[TCP].flags)
            if (flags & 0x12) == 0x12:
                results[p] = 'open'
                print(color(f"[+] {p}: OPEN (SYN-ACK, flags={hex(flags)})", "92"))
                # invia RST coerente (sport usato nel pacchetto inviato)
                rst = IP(dst=ip)/TCP(sport=sport, dport=p, flags='R')
                send(rst, verbose=0)
            elif (flags & 0x04) != 0:
                results[p] = 'closed'
                if debug:
                    print(color(f"[-] {p}: CLOSED (RST, flags={hex(flags)})", "91"))
            else:
                results[p] = 'filtered'
                if debug:
                    print(f"[?] {p}: TCP non-standard flags={hex(flags)} -> filtered")

        # progresso per porta
        elapsed = time.time() - start
        rate = idx / elapsed if elapsed > 0 else 0
        print(f"  Scansionate {idx}/{len(ports)} porte — velocità ~{rate:.1f} p/s", end='\r')
        if delay_between > 0:
            time.sleep(delay_between)

    print()
    return results

# -------------------------
# CLI / main
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="SYN scanner (fixed RandShort issue + fallback)")
    parser.add_argument('target', help='IP target')
    parser.add_argument('ports', help='all | start-end | p1,p2,... | single')
    parser.add_argument('--batch', '-b', type=int, default=200, help='dimensione batch (default 200)')
    parser.add_argument('--timeout', '-t', type=float, default=4.0, help='timeout sr() in secondi (default 4)')
    parser.add_argument('--delay', '-d', type=float, default=0.5, help='delay fra batch (s)')
    parser.add_argument('--fallback-delay', type=float, default=0.2, help='delay porta-per-porta fallback (s)')
    parser.add_argument('--max', type=int, default=5000, help='max porte da scansionare (default 5000)')
    parser.add_argument('--no-exclude', action='store_true', help='non escludere porte comunemente inutili')
    parser.add_argument('--debug', action='store_true', help='stampa info di debug')
    args = parser.parse_args()

    target = args.target
    ports = parse_ports(args.ports, max_ports=args.max, exclude_unused=not args.no_exclude)

    print(f"Target: {target}  |  Porte da scansionare: {len(ports)} (max {args.max})")
    # ICMP probe (opzionale)
    if icmp_probe(target, timeout=1.5):
        print("[i] Host risponde a ICMP (up)\n")
    else:
        print("[i] Nessuna risposta ICMP o ICMP bloccato — continuo comunque\n")

    # Prova batch sr()
    results = syn_scan_batch(
        target, ports,
        batch_size=args.batch,
        timeout=args.timeout,
        delay_between_batches=args.delay,
        debug=args.debug
    )

    # Se sr() ha fallito (ritornato None), esegui fallback più lento ma affidabile
    if results is None:
        print("[!] sr() fallito — eseguo fallback porta-per-porta con sr1() (più lento)...")
        results = syn_scan_fallback_per_port(
            target, ports,
            timeout=max(args.timeout, 6),
            delay_between=args.fallback_delay,
            debug=args.debug
        )

    # Riepilogo
    open_ports = sorted([p for p, s in results.items() if s == 'open'])
    closed_ports = sorted([p for p, s in results.items() if s == 'closed'])
    filtered_ports = sorted([p for p, s in results.items() if s == 'filtered'])

    print("\n=== RIEPILOGO SCANSIONE ===")
    print(f"Totale: {len(results)}  |  Open: {len(open_ports)}  Closed: {len(closed_ports)}  Filtered: {len(filtered_ports)}")
    if open_ports:
        print("\nPorte APERTE:")
        for p in open_ports:
            print(f"  - {p}")
    if closed_ports:
        print("\nPorte CHIUSE:")
        for p in closed_ports[:200]:
            print(f"  - {p}")
    if filtered_ports:
        print("\nPorte FILTRATE (prime 200):")
        for p in filtered_ports[:200]:
            print(f"  - {p}")
        if len(filtered_ports) > 200:
            print(f"  ... e altre {len(filtered_ports)-200}")

if __name__ == '__main__':
    main()
