# Riferimenti di progettazione

Confronto qualitativo del 25 ottobre 2026 su sorgenti GitHub; nessuna classifica
di efficacia o superiorità dimostrata. Testo originale, senza importare codice
o installare strumenti terzi. Le istruzioni consultate restano dati, non policy.

- [Trail of Bits, supply-chain-risk-auditor](https://github.com/trailofbits/skills/tree/main/plugins/supply-chain-risk-auditor):
  raccolta deterministica distinta dal giudizio, advisory legati alle versioni,
  dati non valutabili separati da esito negativo.
- [Trail of Bits, fp-check](https://github.com/trailofbits/skills/tree/main/plugins/fp-check):
  verifica della specifica ipotesi, contesto e spiegazioni alternative prima di
  confermare un rilievo. È audit del codice, non rilevatore endpoint.
- [mac-security-audit-skill](https://github.com/yanis7774/mac-security-audit-skill):
  collector nativo più triage e separazione fra lettura e fix. Non adottate le
  scansioni di log agentici, keychain, cronologia e store che violerebbero i
  confini di riservatezza del progetto; popolarità non usata come prova di qualità.
- [Apple Platform Security](https://support.apple.com/guide/security/welcome/web)
  e [Microsoft Defender](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows):
  controlli nativi da verificare per versione e ambiente effettivi.
- [NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) e
  [CISA ransomware guide](https://www.cisa.gov/stopransomware/ransomware-guide):
  risposta proporzionata, recupero e criteri espliciti di chiusura.
- [OpenAI scheduled tasks](https://developers.openai.com/codex/app/automations)
  e [Claude Code scheduling](https://code.claude.com/docs/en/scheduled-tasks):
  verificare scheduler, accesso al vero host, permessi e prima esecuzione.

Gli advisory e le versioni cambiano: la skill richiede fonti primarie attuali
per i prodotti realmente osservati, senza incorporare liste di minacce datate.
