# Docker Quick Start — walidacja reguł Wazuh

Lekka alternatywa dla pełnego labu Vagrant. **Stawia tylko Wazuh manager** w kontenerze, do walidacji reguł detekcji bez konieczności pełnej infrastruktury (4 VM, AD, Sysmon).

---

## Po co to jest

Pełen lab (`infrastructure/vagrant/`) wymaga:
- 32 GB RAM (4 VM-y na raz)
- VirtualBox + Vagrant
- ~25 min build time

Docker setup wymaga:
- ~4 GB RAM
- Docker (Linux containers)
- ~3 min do uruchomienia

**Trade-off:** Docker nie postawi Active Directory, Windows 10 ofiary ani Sysmona — bo to elementy Windowsowe, których Linuxowy kontener nie pomieści. Dostajesz **sam silnik SIEM-a**.

### Co realnie zyskujesz

| Walidacja | Sam parser XML | Docker (Wazuh manager) | Pełen Vagrant lab |
|---|---|---|---|
| XML well-formed | ✅ | ✅ | ✅ |
| Sam Wazuh ładuje reguły bez błędu | ❌ | ✅ | ✅ |
| Regex PCRE2 poprawnie się kompiluje | ❌ | ✅ | ✅ |
| Łańcuchy `if_sid` wskazują na istniejące reguły | ❌ | ✅ | ✅ |
| Reguła faktycznie strzela na syntetyczne zdarzenie | ❌ | ✅ | ✅ |
| Pełen pipeline (agent → manager → indexer → alert) | ❌ | ❌ | ✅ |
| Detekcja realnego ataku na realnym Windowsie | ❌ | ❌ | ✅ |

Docker daje 5 z 7 walidacji za ułamek kosztu zasobów — perfekcyjne dla portfolio.

---

## Wymagania

- Docker (Linux containers) w wersji ≥ 20.10
- Na Windows: Docker Desktop z włączonym **WSL2 backend** lub **Hyper-V**
- ~4 GB wolnego RAM
- ~3 GB dysku na obraz `wazuh/wazuh-manager:4.7.5`

Sprawdź:

```bash
docker version
docker info --format '{{.MemTotal}} bytes RAM'
```

---

## Uruchomienie

```bash
cd infrastructure/docker
docker compose up -d

# Czekaj ~60s na healthcheck:
docker compose ps
# Powinno pokazac STATUS = healthy
```

## Walidacja reguł — `wazuh-logtest`

Najprostsza droga: interaktywne testowanie pojedynczych zdarzeń.

```bash
docker exec -it wazuh-manager /var/ossec/bin/wazuh-logtest
```

Wkleisz JSON zdarzenia (jedna linia), `wazuh-logtest` zwróci:
1. Który decoder rozpoznał zdarzenie
2. Która reguła (rule.id) strzeliła
3. Level i opis alertu

### Przykład: test reguły 100210 (LSASS dump)

```bash
docker exec -i wazuh-manager /var/ossec/bin/wazuh-logtest < test-events/02-lsass-access.json
```

Spodziewany output (skrót):

```
**Phase 3: Completed filtering (rules).
        Rule id: '100210'
        Level: '14'
        Description: 'Possible LSASS memory access (Mimikatz-like)...'
        MITRE: ['T1003.001']
```

### Wszystkie scenariusze testowe

Każdy plik w `test-events/` to jeden syntetyczne zdarzenie, oczekuje, że **trafi w konkretną regułę**:

| Plik | Zdarzenie | Oczekiwana reguła | Level |
|---|---|---|---|
| `01-ssh-bruteforce.log` | sshd Failed password z 192.168.30.30 | 5710 (potem 100110 po 8 próbach) | 5/12 |
| `02-lsass-access.json` | Sysmon EID 10, lsass.exe, GrantedAccess=0x1410 | **100210** | 14 |
| `03-lsass-comsvcs.json` | Sysmon EID 1, rundll32 + comsvcs + MiniDump | **100211** | 13 |
| `04-ps-encoded.json` | Sysmon EID 1, powershell.exe -Enc <długi base64> | **100212** | 11 |
| `05-ps-network.json` | Sysmon EID 3, powershell → 192.168.30.30:8080 | **100213** | 10 |
| `06-ps-iex-download.json` | EventLog 4104, IEX + DownloadString w ScriptBlock | **100214** | 12 |
| `07-mshta-remote.json` | Sysmon EID 1, mshta + http URL | **100220** | 12 |
| `08-mshta-child.json` | Sysmon EID 1, parent=mshta, image=powershell | **100221** | 13 |
| `09-archive-temp.json` | Sysmon EID 11, FileCreate `.zip` w `Temp` | **100232** | 6 |
| `10-registry-run.json` | Sysmon EID 13, RegistryValueSet w `\Run\` | **100240** | 9 |

### Skrypt batch — przepuść wszystkie scenariusze

Po starcie kontenera:

```bash
# Z folderu infrastructure/docker:
for f in test-events/*.json test-events/*.log; do
  echo "=== $f ==="
  docker exec -i wazuh-manager /var/ossec/bin/wazuh-logtest < "$f" 2>&1 | grep -E "Rule id|Level|Description" | head -3
  echo
done
```

---

## Diagnostyka

### Kontener nie startuje

```bash
docker compose logs wazuh-manager
# Najczęstsze błędy:
# - "ERROR ossec-syscheckd: ..." — błąd składni reguły, sprawdź <field type=pcre2>
# - "wazuh-analysisd:" — często wskazuje konkretną linię w local_rules.xml
```

### Reguła nie strzela mimo, że event powinien pasować

```bash
# Wlej event recznie, wlacz verbose:
docker exec -it wazuh-manager /var/ossec/bin/wazuh-logtest -v
```

Verbose pokazuje **fazy dopasowania**: decoder → pre-decoder → rule. Jeśli decoder nie złapał zdarzenia, reguły go nigdy nie zobaczą — zwykle to literówka w polu `eventID`, `providerName` itp.

### "Rule 5710 didn't match" mimo prawidłowego SSH

`wazuh-logtest` testuje pojedyncze zdarzenia. Reguła 100110 (brute force) wymaga **8 zdarzeń w 120 s** — nie wystrzeli na jedno. Zobacz `01-ssh-bruteforce-batch.sh` (jeśli istnieje) który puszcza 10 takich w pętli.

---

## Czyszczenie

```bash
docker compose down -v
# -v usuwa tez wolumeny (logi, kolejki)
# Jesli chcesz zachowac stan, uzyj samo: docker compose down
```

---

## Co ten setup NIE robi (świadomie)

- Brak Wazuh Indexer + Dashboard — ten compose to **lightweight rule validator**. Pełna paczka SIEM (z UI do screenshotów na portfolio) wymaga generowania certyfikatów. Patrz `docker-compose.full-stack.yml` (jeśli/kiedy zostanie dodany).
- Brak agentów. Manager nasłuchuje na 1514, ale w tym setupie nikt do niego nie pisze. To OK — `wazuh-logtest` testuje reguły wstrzykując zdarzenia bezpośrednio w pipeline manager-a.
- Brak Active Response — wymaga konfiguracji firewall hosta, w kontenerze nie ma sensu.
- Brak FIM (File Integrity Monitoring) ani SCA — same działają, ale wymagają agentów na realnych systemach.

---

## Następny krok

Jeśli reguły strzelają poprawnie tutaj — możesz iść dalej z czystym sumieniem:
1. Wrzuć repo na GitHub.
2. W rozmowach o pracę pokaż: "Mam custom rules zwalidowane przeciwko Wazuh 4.7 manager. Tu output `wazuh-logtest`."
3. Pełen lab z AD/Windows postawisz na maszynie z 32+ GB RAM, jeśli kiedyś chcesz pokazać end-to-end detekcję.
