# Sigma Rules

Reguły w formacie [Sigma](https://github.com/SigmaHQ/sigma) — generycznym, vendor-agnostycznym standardzie zapisu detekcji. Można je konwertować na Wazuh XML, Splunk SPL, Elastic EQL, KQL, itp.

## Konwersja do Wazuh

```bash
pip install sigma-cli pysigma-backend-elasticsearch pysigma-pipeline-windows

# Pojedyncza reguła:
sigma convert -t opensearch \
    -p windows-audit \
    -f json \
    powershell-empire-stager.yml

# Wszystkie reguły z folderu:
sigma convert -t opensearch \
    -p windows-audit \
    -f json \
    -o sigma-converted.json \
    ./
```

## Konwencja nazewnictwa pól MITRE

Wszystkie reguły mają w `tags` co najmniej:
- `attack.<tactic>` — np. `attack.credential_access`
- `attack.<technique>` — np. `attack.t1003.001`

To pozwala filtrować w SIEM-ie i budować dashboardy mapowane na MITRE.

## Reguły w tym katalogu

| Plik | Opis | MITRE |
|---|---|---|
| [`lsass-access-mimikatz.yml`](lsass-access-mimikatz.yml) | Dostęp do pamięci LSASS z podejrzaną maską | T1003.001 |
| [`powershell-empire-stager.yml`](powershell-empire-stager.yml) | Charakterystyczny stager PowerShell Empire | T1059.001 |
| [`mshta-lolbas-execution.yml`](mshta-lolbas-execution.yml) | mshta.exe uruchamiający kod (lokalnie lub zdalnie) | T1218.005 |
| [`suspicious-scheduled-task.yml`](suspicious-scheduled-task.yml) | Persistence przez schtasks z command line | T1053.005 |
