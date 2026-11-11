# SOC Home Lab — Wazuh SIEM with Active Directory

> A Security Operations Center home laboratory project designed to demonstrate practical detection engineering, incident response, and threat hunting skills for a junior SOC Analyst role.

[![Wazuh](https://img.shields.io/badge/SIEM-Wazuh%204.7-blue)](https://wazuh.com/)
[![MITRE](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)](https://attack.mitre.org/)
[![Lab](https://img.shields.io/badge/Type-Home%20Lab-green)](#)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Walidacja detekcji](https://github.com/Pawel123j/SOC-Home-Lab-Wazuh-AD-/actions/workflows/validate.yml/badge.svg)](https://github.com/Pawel123j/SOC-Home-Lab-Wazuh-AD-/actions/workflows/validate.yml)

---

> ⚠️ **Skrypty w `attacks/` symulują ofensywne techniki MITRE ATT&CK**
> (brute force, zrzut poświadczeń, eksfiltracja) po to, żeby sprawdzić, czy reguły
> detekcyjne działają. Uruchamiaj je wyłącznie na maszynach, które kontrolujesz.
> Goście Vagranta mają interfejs NAT do pobierania pakietów; wspólna sieć
> host-only nie filtruje ruchu między nimi ani nie gwarantuje braku wyjścia
> gości do internetu. Uruchamianie skryptów w sieci, której nie
> jesteś właścicielem lub na którą nie masz pisemnej zgody, jest nielegalne
> w wielu jurysdykcjach. Szczegóły i ograniczenia są w
> [architekturze](docs/01-architecture.md).

## Weryfikacja w CI

Repozytorium zawiera reguły detekcyjne, scenariusze i infrastrukturę jako kod.
Bramka CI sprawdza ich strukturę, spójność lokalnych łańcuchów i treść dokumentacji:

| Sprawdzenie | Zakres |
|---|---|
| Reguły Wazuh | poprawność XML, unikalność ID, zakres ID własnych, `level`, `description`, mapowanie MITRE, spójność łańcuchów `if_sid` |
| Reguły Sigma | poprawność YAML i pola wymagane przez specyfikację |
| Zdarzenia testowe | poprawny JSON i struktura, której oczekuje dekoder Wazuha |
| Ansible / compose | parsowanie YAML, składnia skryptów powłoki, `docker compose config` |

```bash
python3 scripts/validate_detections.py
```

**Czego CI nie robi:** nie uruchamia Wazuha ani Windows Event Channel, więc nie
potwierdza, że reguła *strzeli* na prawdziwym zdarzeniu. Fixture JSON sprawdza
strukturę testową, nie pełny tor dekodera/agenta. Walidacja wymaga managera oraz
gościa Windows.

## Detection catalogue

Nine detection scenarios in [`docs/detections/`](docs/detections/) — one file per
scenario, covering all 18 custom Wazuh rules. Each documents the attack technique,
log source, detection logic, the rule itself, MITRE mapping, expected alert,
**false positives and limitations**.

The limitations are written honestly: rule `100297` correlates an SSH brute force
with Windows reconnaissance commands without a shared key, so the two events can
come from different hosts. That is documented as a known weakness with a proposed
fix, not presented as working.

> **On evidence:** no document in this repository reports alert counts or TP/FP
> rates from an attack run. The lab uses four VMs and cannot run in CI. What CI
> does verify on every push: rule syntax, unique IDs, `if_sid` chain integrity,
> MITRE tag validity, and that the alert levels quoted in the documentation match
> the rule definitions.

## Project Purpose

This repository documents a SOC home lab designed to demonstrate Tier 1 / Tier 2 analyst workflows. Its intended detection lifecycle is:

1. Deploy a realistic enterprise-like environment (domain controller, workstation, attacker host).
2. Onboard endpoints into a centralized log pipeline (Wazuh + Sysmon).
3. Execute representative adversary techniques mapped to **MITRE ATT&CK**.
4. Write and tune **custom detection rules** (Wazuh XML + Sigma).
5. Triage the generated alerts and produce an **incident report** as a real analyst would.

Docelowe środowisko składa się z czterech VM Vagrant: managera Wazuh, kontrolera
domeny, stacji Windows i Kali. Vagrantfile używa wspólnej sieci host-only
`192.168.0.0/16` oraz domyślnego NAT do pobierania pakietów. To demonstracja,
nie izolowana topologia VLAN; potrzeba około 32 GiB RAM, a pełne uruchomienie VM
nie było walidowane w bieżącym środowisku.

---

## Technology Stack

| Layer | Component | Version | Role |
|---|---|---|---|
| Hypervisor | VirtualBox 7.0+ | Configured Vagrant provider; VMware has not been validated |
| Provisioning | Vagrant + Ansible | 2.4 / 2.15 | Reproducible builds |
| SIEM | Wazuh Manager + Indexer + Dashboard | 4.7.x | Central log analysis |
| Server OS | Ubuntu Server | 22.04 LTS | Wazuh host |
| Domain | Windows Server | 2019 | Active Directory DC |
| Endpoint | Windows 10 Pro | 22H2 | Victim workstation |
| Telemetry | Sysmon + SwiftOnSecurity config | 15.x | Deep Windows event logging |
| Attacker | Kali Linux | 2024.x | Offensive tooling |
| Detection | Sigma | latest | Vendor-neutral rules |

---

## Architecture & Log Flow

```mermaid
flowchart LR
    subgraph HOSTONLY["Wspólna sieć host-only 192.168.0.0/16 — bez izolacji między rolami"]
        KALI["Kali<br/>192.168.30.30"]
        DC["DC01 · AD DS / DNS<br/>192.168.20.10"]
        WS["WS01 · Sysmon<br/>192.168.20.20"]
        WAZUH["Wazuh · Manager / Indexer / Dashboard<br/>192.168.10.10"]
    end
    NAT["Domyślny NAT Vagranta<br/>pobieranie pakietów / możliwe wyjście"]
    KALI -->|kontrolowane scenariusze| DC
    KALI -->|kontrolowane scenariusze| WS
    DC -->|logi Windows · TCP/1514| WAZUH
    WS -->|Sysmon · TCP/1514| WAZUH
    WAZUH --> ALERTS["Wazuh Dashboard · triage"]
    NAT -. interfejs każdej VM .-> HOSTONLY
```

### How a log becomes an alert

```mermaid
sequenceDiagram
    participant A as Attacker (Kali)
    participant V as Victim (WS01)
    participant S as Sysmon
    participant W as Wazuh Agent
    participant M as Wazuh Manager
    participant D as Dashboard

    A->>V: Run an authorized simulation
    V->>S: Write a Windows event
    S->>W: Write to Microsoft-Windows-Sysmon/Operational
    W->>M: Forward over TCP 1514
    M->>M: Decoder parses event
    M->>M: Rule engine evaluates the event
    M->>D: Matching alert, if the decoder and rule conditions match
```

---

## Repository Layout

```
soc-home-lab/
├── README.md                            ← you are here
├── docs/
│   ├── 01-architecture.md               implemented topology and limits
│   ├── 02-installation.md               Wazuh manager + agent install guide (PL)
│   ├── 03-attack-scenarios.md           5 scenarios × MITRE ATT&CK
│   ├── 04-detection-results.md          expected alerts, derived from the rules
│   └── detections/                      9 detection scenarios, one per file
├── infrastructure/
│   ├── vagrant/Vagrantfile              4 VMs orchestrated as code
│   └── ansible/                         playbooks for agent rollout
├── attacks/
│   ├── 01-brute-force-ssh.sh            T1110.001 — password guessing
│   ├── 02-mimikatz-simulation.ps1       T1003.001 — LSASS memory
│   ├── 03-powershell-empire.md          T1059.001 — PowerShell C2
│   ├── 04-suspicious-process.ps1        T1218 — signed binary proxy exec
│   └── 05-data-exfiltration.py          T1041 — exfil over C2
├── detection-rules/
│   ├── custom-wazuh-rules.xml           18 custom rules with comments
│   └── sigma-rules/                     4 portable Sigma rules
└── reports/
    └── incident-report-template.md      IR write-up template
```

---

## Quick Start

```bash
# 1. Bring up all four VMs (first run may take considerably longer)
cd infrastructure/vagrant
vagrant up

# 2. Configure the Windows endpoints with Ansible
cd ../ansible
ansible-playbook -i inventory.yml site.yml

# 3. Log in to the Wazuh dashboard
#    https://192.168.10.10
#    user: admin   password: generated in /etc/wazuh-passwords.txt on wazuh-srv

# 4. Run only an authorized scenario from Kali
vagrant ssh kali
bash /root/attacks/01-brute-force-ssh.sh

# 5. Watch the alerts appear in the dashboard
```

---

## What This Lab Demonstrates

- **Detection Engineering** — tuning custom rules against event samples, not just enabling vendor content.
- **MITRE ATT&CK literacy** — every scenario is mapped to a specific technique ID with kill-chain context.
- **Triage & IR fundamentals** — a structured incident report template aligned with NIST SP 800-61.
- **Infrastructure as Code** — Vagrant and Ansible describe a reproducible local lab; setup time depends on the hypervisor and downloads.
- **Tool fluency** — Wazuh, Sigma, Sysmon, Hydra, Ansible, PowerShell, Linux, Active Directory.

---

## Lessons Learned (what I'd change in production)

These are the gaps between a home lab and a real production SOC — items I would treat as P1 follow-ups on day one of a real job:

1. **Log retention is fake here.** The lab keeps everything on one indexer node. In production I'd front Wazuh's indexer with hot/warm/cold ILM in OpenSearch and ship to immutable cold storage (e.g. S3 with object lock) for the regulator-mandated retention period (12–24 months depending on jurisdiction).
2. **No high availability.** A single Wazuh manager is a single point of failure. Production deployment requires a cluster (master + 2 workers minimum) behind a load balancer, and a multi-node indexer cluster with a quorum.
3. **Detection coverage is shallow.** 12 rules is a portfolio piece, not a baseline. The next step is mapping coverage against MITRE ATT&CK using DeTT&CT and tracking which sub-techniques have zero detections.
4. **No tuning loop.** In production I'd track every alert by analyst disposition (TP / FP / B-TP) in a ticketing system and feed FP rates back into rule tuning weekly. Rules without an owner get deprecated.
5. **No SOAR / playbooks.** Manual triage scales to ~50 alerts/day per analyst. Anything above that requires automated enrichment (AbuseIPDB, VT, internal CMDB) and one-click containment — I'd integrate Shuffle or TheHive + Cortex.
6. **Threat intelligence is missing.** No MISP feed, no automated IoC matching, no STIX/TAXII ingestion. The CDB lists in Wazuh are an okay starting point but they don't replace a real TIP.
7. **The "attacker" runs from inside the perimeter.** Real adversaries come through email, exposed RDP, supply chain. The lab would benefit from a simulated email gateway (e.g. an attacker mailbox + GoPhish) to test the full intrusion chain.
8. **No DFIR-ready endpoint.** Wazuh File Integrity Monitoring is useful but I'd add Velociraptor for hunt-time forensic collection, and EDR (Defender for Endpoint or CrowdStrike) for kernel-level visibility that Sysmon cannot give.
9. **AD is a single forest with default GPOs.** Production AD needs a tiering model (Tier 0/1/2), LAPS, gMSA for service accounts, and at minimum a hardened baseline (CIS L1).
10. **No purple team cadence.** Detections drift. I'd run quarterly purple-team exercises using Atomic Red Team / Caldera and measure mean-time-to-detect (MTTD) per technique.

---

## Author

Built as a portfolio project for a junior SOC Analyst role. Feedback and PRs are welcome.

**Licence:** MIT — feel free to fork, adapt, and use any part of this for your own learning.

## Weryfikacja środowiska — 2026-10-17

Walidatory przeszły: 18 reguł Wazuh, 4 Sigma, 10 plików zdarzeń i zgodność 16 dokumentów z 18 regułami. `docker compose -f infrastructure/docker/docker-compose.yml config -q` także przeszedł. Uruchomiono wyłącznie walidację statyczną, bez symulacji ataków.

Pełny lab Windows/Active Directory/Wazuh nie został uruchomiony. Nie ma nowych wyników TP/FP, korelacji między hostami ani alertów z prawdziwego managera. Przed użyciem operacyjnym wykonaj opisany harness i zachowaj rzeczywiste zdarzenia oraz alerty jako dowody; sama poprawność składni reguł tego nie zastępuje. Nie wdrożono infrastruktury.
