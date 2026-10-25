# PC Security Audit

Skill per audit di sicurezza macOS/Windows e delle harness agentiche, controlli
quotidiani e interventi entro l'autorizzazione umana. La directory trasferibile
è `skills/pc-security-audit/`: 12 file, senza dipendenze Python esterne.

## Uso

```text
Usa $pc-security-audit per controllare la sicurezza di questo computer e degli
agenti. Spiegami i problemi verificati, i controlli mancanti e le azioni prioritarie.
```

La harness deve prima scoprire la skill nel proprio percorso supportato. Copiare
la directory `skills/pc-security-audit/` nel percorso utente della harness:

| Harness | Directory della skill |
|---|---|
| Codex | `~/.codex/skills/pc-security-audit/` |
| Claude Code | `~/.claude/skills/pc-security-audit/` |
| Pi | `~/.pi/agent/skills/pc-security-audit/` |
| OpenCode | `~/.config/opencode/skills/pc-security-audit/` |

Se si usa una libreria condivisa, promuovere la versione revisionata nella
sorgente runtime e generare le viste secondo il suo gestore. Questo repository
contiene file reali portabili, senza collegamenti a percorsi personali. Verificare
la discovery in una nuova sessione; la presenza dei file non dimostra caricamento
o disponibilità degli strumenti. Le modifiche alla copia pubblica richiedono
una promozione esplicita nelle copie runtime, senza sincronizzazioni automatiche.

## Prompt per configurare il controllo quotidiano

```text
Usa pc-security-audit, già fornita in questa harness, per preparare un controllo
quotidiano del mio computer. Leggi il suo references/periodic.md. Verifica la
macchina realmente raggiungibile, la skill e lo scheduler locale supportato.
Esegui il primo audit in lettura, concorda una cartella privata per i report e
mostrami copertura, metadati trattati dal provider AI, permessi e configurazione.
Proponi ogni giorno alle 09:00 nel fuso locale rilevato; dopo la mia revisione
attiva la routine senza duplicati e verifica separatamente la prima esecuzione
automatica. Ogni run deve spiegare cambiamenti, problemi aperti, fino a tre
azioni prioritarie e controlli mancanti. Mantieni i permessi attuali; scrivi
solo i report concordati. Le azioni sul computer richiedono autorizzazione.
Se manca uno scheduler adeguato, spiegami il requisito e lascia l'audit manuale.
```

## Limiti e sviluppo

Python 3.11+ per i due helper Python; PowerShell 5.1+/7+ per il collector Windows.
Runtimes mancanti diventano NOT RUN, senza installazione implicita. Gli helper
raccolgono metadati o validano record; non installano protezioni né eseguono
bonifiche. L'analisi tramite provider AI non diventa interamente locale perché
il report è sul disco. Esclusi segreti e archivi di autenticazione.

Un audit al giorno non è rilevamento continuo e non certifica assenza di
compromissione. Windows nativo, esecuzioni programmate reali e comportamento
con utenti diversi richiedono prove specifiche; i test degli helper non le
sostituiscono. Nessuna licenza pubblica è assegnata implicitamente.

```text
python3 -B -m unittest discover -s tests -v
python3 -B tests/check_codex_discovery.py
```

Test e prove di discovery restano nel progetto di sviluppo, fuori dal pacchetto
installato. [SOURCES.md](SOURCES.md) contiene i riferimenti usati nella sintesi;
nessun codice di skill terze è stato importato. Le verifiche di questa riduzione
distinguono prove eseguite e mancanti; una validazione statica non prova efficacia
di rilevazione su minacce reali.
