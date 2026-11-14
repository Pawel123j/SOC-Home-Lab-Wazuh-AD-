# Ansible — provisioning agentów Wazuh

Playbook do automatycznego wdrożenia agentów Wazuh na hostach z labu po tym, jak Vagrant postawi maszyny.

## Wymagania na maszynie sterującej

```bash
# Linux/macOS lub WSL na Windows, Python 3.11+
cd infrastructure/ansible
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements-controller.txt
ansible-galaxy collection install -r requirements.yml

# Sprawdzenie składni i modułów bez połączenia z hostami:
ansible-playbook -i inventory.yml site.yml --syntax-check
```

## Uruchomienie

```bash
cd infrastructure/ansible

# 1. Sprawdź łączność (Windows wymaga win_ping)
ansible -i inventory.yml wazuh_servers:linux_agents -m ansible.builtin.ping
ansible -i inventory.yml windows_agents -m ansible.windows.win_ping

# 2. Wdróż agentów
ansible-playbook -i inventory.yml site.yml

# Tylko Windows:
ansible-playbook -i inventory.yml site.yml --tags windows

# Tryb dry-run (sprawdza, co by zrobił, bez wprowadzania zmian):
ansible-playbook -i inventory.yml site.yml --check --diff
```

## Struktura

```
ansible/
├── inventory.yml            ← hosty + zmienne połączenia
├── site.yml                 ← główny playbook
├── group_vars/
│   └── all.yml              ← wersja agenta, IP managera
└── roles/
    ├── wazuh-agent-windows/
    │   ├── tasks/main.yml
    │   └── handlers/main.yml
    └── wazuh-agent-linux/tasks/main.yml
```

## Co playbook robi

1. Sprawdza, że Wazuh Manager nasłuchuje na `192.168.10.10:1514` i API odpowiada.
2. Na każdym hoście Windows:
   - pobiera MSI agenta z oficjalnego repozytorium Wazuh,
   - instaluje z parametrami enrollment (manager IP, group, name),
   - dopisuje do `ossec.conf` lokalizacje logów Sysmon i PowerShell Operational,
   - restartuje usługę `WazuhSvc`.
3. Na końcu pyta managera o status agentów — wymaga, żeby `dc01` i `ws01` były `Active`.

## Troubleshooting

| Błąd | Rozwiązanie |
|---|---|
| `winrm: error 401` | Vagrant box ma wyłączone autoryzacje basic — uruchom `vagrant winrm-config <host>` i porównaj |
| `agent not connecting` | Firewall na hoście blokuje 1514 wychodzące — zobacz reguły w `dc01-setup.ps1` |
| Wersja agenta ≠ wersja managera | Edytuj `group_vars/all.yml` → `wazuh_agent_version` |
