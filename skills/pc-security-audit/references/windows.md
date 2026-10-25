# Audit Windows

Usare PowerShell nativo (5.1+ o 7+) senza profili, bypass di execution policy,
installazione moduli o elevazione automatica. `scripts/windows_collect.ps1`
restituisce metadati locali; i controlli non disponibili sono NOT RUN, non
false prove di protezione assente. Dall'harness applicare un timeout ragionevole
alla chiamata (per esempio 150 secondi) e segnalare un risultato incompleto.
Il collector usa job propri con timeout per controllo (default 8 secondi),
budget di raccolta complessivo (default 110 secondi) e stream diagnostici
non mischiati al JSON. Stop/Remove riguarda solo i job da lui creati. Un arresto
esterno può comunque impedire l'output finale: segnalare run incompleto.
Usa moduli dei percorsi di sistema ed enum serializzati come testo. Un timeout
non ferma processi dell'utente. Exit 1 indica controlli falliti, 2 copertura
incompleta. Se la policy blocca il file, dichiarare NOT RUN: usare soltanto
controlli interattivi consentiti dall'amministratore, senza bypass della policy.
PowerShell presente in WSL/Linux non dimostra accesso al vero host Windows.
Leggere anche [checks.md](checks.md) e [incident.md](incident.md) se
sono richiesti prevenzione completa o recupero da un incidente.

## Domini

- **Sistema:** versione/build/architettura e supporto effettivo della release;
  confrontare gli aggiornamenti con documentazione Microsoft corrente. Un elenco
  di hotfix non prova che tutto il software sia aggiornato. Nessun update o
  riavvio durante l'audit.
- **Defender:** interpretare `Get-MpComputerStatus`; engine, firme, protezione
  real-time, cloud e tamper protection. Modalità passiva può derivare da altro
  antivirus: verificare la protezione reale, senza avviarne due simultaneamente.
- **Esclusioni:** il collector restituisce conteggi, non percorsi/processi o
  altri valori potenzialmente privati. Se serve una verifica puntuale, usare
  la UI autorizzata e riportare soltanto l'esito rispetto al target sospetto.
- **Firewall:** `Get-NetFirewallProfile`; distinguere profili e regole da
  policy effettiva (`-PolicyStore ActiveStore`) e da
  traffico effettivamente raggiungibile. `Get-NetTCPConnection` espone una
  fotografia delle connessioni, non la storia della macchina.
  Considerare bind locale e UDP; il campione del collector non prova completezza.
- **Hardware:** Secure Boot, Memory Integrity/HVCI e requisiti driver. Un check
  UEFI non disponibile è NOT RUN; non proporre di disabilitare una protezione
  per nascondere incompatibilità o warning.
- **Cifratura:** `Get-BitLockerVolume` con selezione di MountPoint,
  VolumeStatus, ProtectionStatus, EncryptionMethod, EncryptionPercentage.
  Non enumerare KeyProtector, RecoveryPassword o `manage-bde -protectors -get`.
  Verificare con l'utente che il recupero sia accessibile, senza leggerne la
  chiave. Distinguere Device Encryption da disponibilità delle UI BitLocker.
- **Persistenza:** task (`Get-ScheduledTask`), servizi (`Get-Service`) e WMI
  (`Get-CimInstance` locale in `root/subscription`). Nomi/conteggi non bastano
  a giudicare target e azioni; usare native UI/Autoruns già disponibile e
  autorizzato per verifiche puntuali. Non stampare Actions, CommandLineTemplate,
  ScriptText o righe di comando integrali che possono contenere segreti.
  Per i soli conteggi, il collector richiede `Get-CimInstance -KeyOnly`: evitare
  di acquisire corpi di script o template anche quando non vengono stampati.
- **Avvio e browser:** Startup, Run/RunOnce, estensioni, criteri, servizi remoti,
  utenti/gruppi e applicazioni amministrative. Un consumer WMI non è di per sé
  malevolo; non assumere un numero universale di consumer legittimi.
  Verificare in modo mirato anche UAC, RDP/SMB, SmartScreen/PUA, Credential Guard,
  application control e ASR quando pertinenti. I corrispondenti NOT RUN del
  collector richiedono verifiche native: non sono controlli già eseguiti.
- **Identità e cloud:** applicare [checks.md](checks.md) agli account
  pertinenti, usando superfici autorizzate e conferme non segrete dell'utente.
  Nessun accesso agli store locali di password/cookie.
- **Backup:** verificare disponibilità, separazione, cifratura e recupero con
  campioni scelti dall'utente e destinazione autorizzata. Ripristino dei dati
  e recupero/revoca delle sessioni sono controlli separati.

## Scansioni

Una scansione AV può mettere file in quarantena e modificare stato. Se non è
già autorizzata, includerla nel piano con effetti/riavvii. Non confondere una
query sullo stato con una scansione eseguita.

Defender Offline usa un ambiente esterno al normale kernel; verificare requisiti
Microsoft aggiornati, WinRE, architettura e antivirus attivo. La documentazione
consultata esclude Windows ARM e Windows Server: non dichiarare compatibilità
universale. Può richiedere riavvio e gestione del recupero BitLocker: pianificare
questi effetti senza leggere la chiave né sospendere cifratura implicitamente.
Un risultato negativo non esclude furto storico di credenziali o persistenza cloud.

## Candidati di pulizia

Per una directory assoluta scelta dall'utente, usare `Get-Item -LiteralPath`
e `Get-ChildItem -LiteralPath <directory> -Force` con output limitato a nome,
dimensione, attributi e LastWriteTimeUtc. Escludere nomi sensibili e reparse
point prima di scendere. Evitare `-Recurse` su un intero profilo: non comprende
automaticamente né tutti i permessi né i confini di riservatezza. I nomi sono
privati; minimizzare la condivisione e applicare [workflow.md](workflow.md) prima di proporre
qualsiasi rimozione. Storage Sense, file temporanei e pulizia app sono proposte
con target/effetti dichiarati, non un bottone generico per liberare spazio.

Fonti: [Defender status](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus),
[Defender Offline](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-offline),
[BitLocker status](https://learn.microsoft.com/en-us/powershell/module/bitlocker/get-bitlockervolume),
[Get-ScheduledTask](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/get-scheduledtask),
[WMI persistence](https://learn.microsoft.com/en-us/windows/win32/wmisdk/receiving-events-at-all-times),
[revoca accessi](https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access).
