# 01 — Architektura laboratorium

Dokument opisuje fizyczną i logiczną topologię SOC Home Lab, plan adresacji IP, podział na VLAN-y oraz przepływ logów. Jest punktem wyjścia dla dokumentu [02-installation.md](02-installation.md).

---

## 1. Założenia projektowe

| Obszar | Założenie |
|---|---|
| **Cel** | Demonstracja umiejętności analityka SOC: detekcja, triage, IR |
| **Skala** | 4 maszyny wirtualne na jednej stacji roboczej (16 GB RAM, SSD 100 GB wolnego miejsca) |
| **Izolacja** | Trzy oddzielne sieci wewnętrzne (host-only) — brak dostępu z internetu do segmentu ofiar |
| **Reprodukowalność** | Całe środowisko stawia się komendą `vagrant up`, agenci wdrażani Ansible |
| **Realizm** | Topologia naśladuje typową małą firmę: kontroler domeny, stacja robocza, segment zarządzania, segment napastnika |

---

## 2. Topologia logiczna

```
                  ┌─────────────────────────────────────────────────────────┐
                  │                    SOC HOME LAB                         │
                  └─────────────────────────────────────────────────────────┘

  VLAN 10 — MGMT (192.168.10.0/24)   VLAN 20 — LAN (192.168.20.0/24)   VLAN 30 — ATTACKER (192.168.30.0/24)
  ┌─────────────────────────┐         ┌─────────────────────────┐         ┌─────────────────────────┐
  │                         │         │                         │         │                         │
  │   ┌─────────────────┐   │         │   ┌─────────────────┐   │         │   ┌─────────────────┐   │
  │   │  WAZUH-SRV      │   │         │   │  DC01           │   │         │   │  KALI           │   │
  │   │  Ubuntu 22.04   │   │         │   │  Win Server 2019│   │         │   │  Kali 2024.x    │   │
  │   │  192.168.10.10  │◄──┼─────────┼───┤  192.168.20.10  │   │         │   │  192.168.30.30  │   │
  │   │                 │   │         │   │  AD DS / DNS    │   │         │   │                 │   │
  │   │  Manager 4.7    │   │         │   └─────────────────┘   │         │   └─────────────────┘   │
  │   │  Indexer        │   │         │                         │         │            │            │
  │   │  Dashboard      │◄──┼─────────┼───┌─────────────────┐   │         │            │            │
  │   │                 │   │         │   │  WS01           │   │         │            │            │
  │   └─────────────────┘   │         │   │  Windows 10 22H2│   │◄────────┼────────────┘            │
  │                         │         │   │  192.168.20.20  │   │  ataki  │                         │
  │                         │         │   │  Sysmon + Agent │   │         │                         │
  │                         │         │   └─────────────────┘   │         │                         │
  └─────────────────────────┘         └─────────────────────────┘         └─────────────────────────┘
            ▲                                                                          ▲
            │ log flow (1514/TCP TLS)                                                  │ ataki
            └──────────────────────────────────────────────────────────────────────────┘
```

> **Uwaga implementacyjna:** w środowisku domowym opartym o VirtualBox VLAN-y nie istnieją w sensie 802.1Q — są symulowane przez trzy odrębne sieci typu `host-only` (`vboxnet0`, `vboxnet1`, `vboxnet2`). W dokumentacji używam słowa "VLAN" dla zgodności z nomenklaturą produkcyjną.

---

## 3. Plan adresacji IP

### VLAN 10 — Management (192.168.10.0/24)

Segment serwerowy, oddzielony od stacji końcowych. W produkcji byłby chroniony jump-hostem; w labie dostęp z hosta jest bezpośredni dla wygody.

| Host | IP | OS | Rola | Otwarte porty |
|---|---|---|---|---|
| `wazuh-srv` | 192.168.10.10 | Ubuntu 22.04 LTS | Wazuh Manager + Indexer + Dashboard | 443 (UI), 1514 (agenci TLS), 1515 (enrollment), 55000 (API) |
| Brama (gateway) | 192.168.10.1 | — | Wirtualna brama VirtualBox | — |

### VLAN 20 — Internal LAN (192.168.20.0/24)

Segment "biurowy" — wszystko, co byłoby w prawdziwej organizacji za firewallem.

| Host | IP | OS | Rola | Otwarte porty |
|---|---|---|---|---|
| `dc01` | 192.168.20.10 | Win Server 2019 | AD DS, DNS, KDC | 53, 88, 135, 389, 445, 464, 636, 3268, 3269, 9389 |
| `ws01` | 192.168.20.20 | Windows 10 Pro 22H2 | Stacja robocza domenowa | 135, 139, 445, 3389 (RDP — celowo otwarty dla scenariusza brute-force) |
| Brama | 192.168.20.1 | — | — | — |

DNS dla całego segmentu wskazuje na DC01 (192.168.20.10). Domena AD: `soclab.local`.

### VLAN 30 — Attacker (192.168.30.0/24)

Segment napastnika. W normalnym środowisku byłby zewnętrzny (internet); tutaj wymuszamy routing przez bramę między 30 a 20.

| Host | IP | OS | Rola |
|---|---|---|---|
| `kali` | 192.168.30.30 | Kali Linux 2024.x | Stacja atakującego — Hydra, CrackMapExec, Mimikatz (port), Empire/Starkiller |

### Routing między segmentami

| Z | Do | Dozwolone | Powód |
|---|---|---|---|
| VLAN 30 → VLAN 20 | TCP/22, 445, 3389, 5985, 80, 443 | Tak | Symulacja perimetru z ekspozycją RDP/SMB (typowy błąd konfiguracji) |
| VLAN 20 → VLAN 10 | TCP/1514, 1515, 55000 | Tak | Logi i enrollment agentów |
| VLAN 10 → VLAN 20 | TCP/22, 5985 | Tak | Zarządzanie (Ansible) |
| VLAN 30 → VLAN 10 | ❌ | Nie | Wazuh nie powinien być widoczny dla napastnika |

W labie egzekwowane przez VirtualBox NAT + reguły `iptables` na maszynie hostującej (skrypt `infrastructure/vagrant/firewall.sh`).

---

## 4. Specyfikacja sprzętowa VM

| VM | vCPU | RAM | Dysk | Adapter sieciowy |
|---|---|---|---|---|
| `wazuh-srv` | 4 | 6 GB | 50 GB (dynamic) | vboxnet0 (VLAN 10) + NAT (do paczek apt) |
| `dc01` | 2 | 3 GB | 40 GB (dynamic) | vboxnet1 (VLAN 20) |
| `ws01` | 2 | 3 GB | 40 GB (dynamic) | vboxnet1 (VLAN 20) |
| `kali` | 2 | 3 GB | 30 GB (dynamic) | vboxnet2 (VLAN 30) |

**Łącznie: 10 vCPU, 15 GB RAM, ~160 GB dysku.** Działa na laptopie z 16 GB RAM, ale Wazuh Indexer jest wrażliwy na RAM — przy 8 GB host-RAM należy ograniczyć JVM heap w `/etc/wazuh-indexer/jvm.options` do 1g.

---

## 5. Przepływ logów

```
┌──────────────────────┐    ┌────────────────────┐    ┌──────────────────────────┐
│ Źródła na endpointach│───▶│  Wazuh Agent       │───▶│  Wazuh Manager           │
│                      │    │  (na DC01, WS01)   │    │                          │
│ • Security.evtx      │    │                    │    │  1. Decoders             │
│ • System.evtx        │    │  • Lokalne reguły  │    │     (parse JSON/XML)     │
│ • Sysmon/Operational │    │  • Bufor lokalny   │    │  2. Rules                │
│ • PowerShell/Operat. │    │  • TLS 1.2+        │    │     (level, MITRE tag)   │
│ • Defender Operat.   │    │  • Compression     │    │  3. Alert engine         │
│ • IIS access log     │    │                    │    │     (level ≥ 7 → alert)  │
└──────────────────────┘    └─────────┬──────────┘    └──────────────┬───────────┘
                                      │                              │
                                  1514/TCP TLS              ┌────────▼──────────┐
                                                            │  Wazuh Indexer    │
                                                            │  (OpenSearch)     │
                                                            └────────┬──────────┘
                                                                     │
                                                            ┌────────▼──────────┐
                                                            │  Wazuh Dashboard  │
                                                            │  (analityk SOC)   │
                                                            └───────────────────┘
```

### Czas reakcji (orientacyjny, w labie)

| Etap | Czas |
|---|---|
| Wygenerowanie zdarzenia na endpoint | t = 0 |
| Sysmon zapisuje do EventLog | t + 50 ms |
| Wazuh agent wysyła do managera | t + 1–2 s |
| Manager przetwarza, dopasowuje regułę | t + 2 s |
| Alert widoczny w dashboardzie | t + 3–5 s |

W produkcji dochodzi opóźnienie indeksacji (5–30 s) i propagacja do SOAR.

---

## 6. Konfiguracja czasu i nazewnictwa

- **Strefa czasowa:** wszystkie maszyny ustawione na `Europe/Warsaw`. To **kluczowe** — korelacja zdarzeń wymaga zgodnego czasu. Wazuh Manager pełni rolę NTP-klienta `pool.ntp.org`, pozostałe hosty synchronizują się z DC01.
- **Nazwy hostów:** `wazuh-srv`, `dc01`, `ws01`, `kali` (krótko, jednoznacznie).
- **FQDN w domenie:** `dc01.soclab.local`, `ws01.soclab.local`. `wazuh-srv` jest poza domeną (osobny segment).

---

## 7. Decyzje projektowe (i dlaczego)

| Decyzja | Alternatywa | Dlaczego tak |
|---|---|---|
| Trzy segmenty zamiast jednego | Wszystko w jednej sieci | Realizm — produkcja ma minimum DMZ / LAN / Mgmt |
| Wazuh all-in-one (manager+indexer+dashboard) | Cluster | Lab — w prod oddzielne nody dla HA |
| Sysmon na endpointach | Sam Windows Event Log | Bez Sysmona nie wykryjemy 80% technik T1059, T1003, T1218 |
| Domena `soclab.local` (TLD `.local`) | `.lab`, `.test`, `corp.com` | `.local` nadal działa, choć formalnie kolizja z mDNS — celowo, bo wielu klientów to ma w produkcji i to też trzeba umieć obsłużyć |
| Brute-force RDP otwarty z VLAN 30 | Zamknięty RDP | Świadomy błąd konfiguracji do detekcji T1110 |

Następny krok: [02-installation.md](02-installation.md) — instalacja krok po kroku.
