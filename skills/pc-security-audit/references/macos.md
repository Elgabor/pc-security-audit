# Audit macOS

## Baseline e protezioni

Usare `scripts/audit.py collect`: versione, architettura, stato SIP/Gatekeeper/
FileVault/firewall, spazio, pressione memoria, snapshot processi senza argomenti,
metadati di LaunchAgents/Daemons e cartelle di estensioni agentiche. Il helper
non interroga la keychain, non fa scansioni AV e non certifica l'assenza di malware.
Eseguire con `python3 -I -S -B` da una copia fidata, senza elevazione. La home
proviene dal database account del sistema; un utente/elevazione ambiguo rende
NOT RUN l'inventario personale. Seguire [checks.md](checks.md) per i
controlli completi e [incident.md](incident.md) in caso d'incidente.

Verificare poi i domini mancanti con le superfici native:

- Aggiornamenti: versione/build e release di sicurezza Apple applicabile, stato
  del riavvio e aggiornamenti delle app/runtime realmente usati. Consultare web
  solo per fonti pubbliche; ricerca di patch non autorizza installazione.
- Protezioni: interpretare gli output, non l'exit code. `spctl --status` non
  equivale a una scansione XProtect né a controllo di ogni app o script.
- FileVault: controllare lo stato e chiedere se il recupero è stato provato;
  non richiedere di mostrare o copiare la chiave. Cifratura hardware e FileVault
  sono livelli distinti su Apple silicon/T2.
- Privacy: Impostazioni > Privacy e sicurezza; Accesso completo al disco,
  Accessibilità, Registrazione schermo e Automazione per terminale, editor,
  harness, scanner e applicazioni remote. Registrare nomi/scopo, non dati utente.
- Login e background: Impostazioni > Generali > Elementi login ed estensioni;
  confrontare con i metadati di `~/Library/LaunchAgents`, `/Library/LaunchAgents`
  e `/Library/LaunchDaemons`. Non caricare né scaricare job durante l'audit.
  Verificare anche helper privilegiati, cron/periodic, avvio shell ed estensioni
  IDE quando pertinenti: nel collector restano esplicitamente NOT RUN.
- Gestione dispositivo: profili, estensioni di sistema/rete, VPN/proxy e
  condivisioni. Profilo sconosciuto non significa malevolo; verificare proprietà
  aziendale e origine prima di proporre rimozione.
- Rete: firewall in ingresso, servizi in ascolto e traffico in uscita sono
  controlli distinti. Correlare PID e immagine; limitare IP/domini nel report.
- Browser: estensioni, permessi, criteri e sincronizzazione; non aprire database,
  cookie, password o profili completi. Usare soltanto UI autorizzata.
- Identità e cloud: applicare [checks.md](checks.md) agli account pertinenti;
  login e verifiche con dati sensibili restano privati all'utente. Non dedurre
  la sicurezza degli account dall'esito delle protezioni del Mac.

## Indagini mirate

Per un sospetto identificato correlare rilevamento AV/EDR, percorso, firma,
origine, processo padre, connessioni, persistenza e danno. Non cercare segreti o
ispezionare dump di memoria. La firma valida non prova innocuità; un programma
non firmato, un nuovo job o CPU alta non prova compromissione.

KnockKnock/BlockBlock/LuLu, se già presenti e autorizzati, coprono inventario
persistenza, nuovi eventi e rete in uscita rispettivamente. L'avvio può
richiedere FDA o altre autorizzazioni e lookup esterni: non concederli
implicitamente. Nessuna installazione o upload di campioni durante l'audit.

## Backup e recupero

Controllare disponibilità, separazione, cifratura e data della copia senza
leggere contenuti personali. Una prova di ripristino usa file campione scelti
dall'utente e una destinazione autorizzata. Una cartella iCloud sincronizzata
non dimostra recupero indipendente da cancellazione/ransomware. In caso di
ricostruzione non ripristinare indiscriminatamente hook, profili e sessioni.

Fonti: [Apple Platform Security](https://support.apple.com/guide/security/welcome/web),
[Malware](https://support.apple.com/guide/security/protecting-against-malware-sec469d47bd8/web),
[FileVault](https://support.apple.com/guide/mac-help/protect-data-on-your-mac-with-filevault-mh11785/mac),
[profili](https://support.apple.com/guide/personal-safety/review-and-delete-configuration-profiles-ips327569a75/web).
