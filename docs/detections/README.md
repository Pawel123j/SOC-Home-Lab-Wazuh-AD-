# Scenariusze detekcji

Każdy dokument opisuje jedną detekcję: technikę, źródło logu, logikę reguły,
oczekiwany alert, fałszywe alarmy i ograniczenia.

> Reguły w tych dokumentach są wklejone wprost z
> [`detection-rules/custom-wazuh-rules.xml`](../../detection-rules/custom-wazuh-rules.xml),
> a zgodność poziomów alertów i tagów MITRE z definicjami pilnuje
> `scripts/validate_docs_against_rules.py` przy każdym pushu.
>
> **Sekcje „Fałszywe alarmy" opisują przewidywania wynikające z konstrukcji
> reguł, nie zmierzone wskaźniki.** Laboratorium wymaga trzech maszyn
> wirtualnych i nie da się go uruchomić w CI — procedura pomiaru jest
> w [04-detection-results.md](../04-detection-results.md).

| Scenariusz | Reguły | Poziom | Technika MITRE |
|---|---|---|---|
| [Brute force SSH zakończony udanym logowaniem](brute-force-ssh.md) | `100110`, `100111` | 12, 14 | `T1078`, `T1110.001` |
| [Brute force na Windows (RDP / SMB)](brute-force-windows-rdp-smb.md) | `100120` | 11 | `T1021.001`, `T1110.001` |
| [Dostęp do pamięci LSASS (zrzut poświadczeń)](credential-access-lsass.md) | `100210`, `100211` | 13, 14 | `T1003.001`, `T1218.011` |
| [Łańcuch PowerShell C2 (korelacja trzech wskaźników)](powershell-c2-chain.md) | `100212`, `100213`, `100214`, `100299` | 10, 11, 12, 14 | `T1027`, `T1059.001`, `T1071.001`, `T1105` |
| [mshta.exe jako proxy wykonania (LOLBAS)](lolbas-mshta.md) | `100220`, `100221` | 12, 13 | `T1059`, `T1218.005` |
| [Eksfiltracja danych przez HTTP](data-exfiltration-http.md) | `100232`, `100230`, `100231` | 6, 10, 12 | `T1030`, `T1041`, `T1560.001` |
| [Utrwalenie przez klucz Run w rejestrze](persistence-registry-run.md) | `100240` | 9 | `T1547.001` |
| [Polecenia rozpoznania środowiska](discovery-commands.md) | `100250` | 7 | `T1018`, `T1069.002`, `T1087.002` |
| [Korelacja: brute force poprzedzający rozpoznanie](account-compromise-correlation.md) | `100297` | 13 | `T1087.002`, `T1110.001` |

Scenariusze pokrywają **17 z 17** reguł własnych.

## Reguły Sigma

W [`detection-rules/sigma-rules/`](../../detection-rules/sigma-rules/) są cztery
reguły w formacie Sigma, przenośnym między systemami SIEM. Trzy odpowiadają
scenariuszom powyżej (`lsass-access-mimikatz`, `mshta-lolbas-execution`,
`powershell-empire-stager`).

Czwarta, `suspicious-scheduled-task.yml`, **nie ma odpowiednika w regułach
Wazuha** — zadania zaplanowane jako technika utrwalenia nie są obecnie pokryte
po stronie Wazuha. Pozycja w roadmapie poniżej.

## Roadmap detekcji

Techniki nieobsługiwane obecnym laboratorium, z powodem:

| Technika | Czego brakuje |
|---|---|
| Utrwalenie przez zadania zaplanowane | Reguła Wazuha odpowiadająca istniejącej regule Sigma (Sysmon EID 1 + dziennik Task Scheduler) |
| Password spraying | Odwrotne zliczanie: wiele kont z jednego źródła zamiast wielu prób na konto |
| Eksfiltracja przez DNS | Zbieranie logów zapytań DNS i analiza entropii nazw |
| Nadużycie Kerberosa (Kerberoasting) | Audyt EID 4769 na kontrolerze domeny |
| Ruch boczny przez WMI / WinRM | Sysmon EID 19–21 oraz logi WinRM na hostach docelowych |
| Zbieranie danych przez LDAP (BloodHound) | Logowanie zapytań LDAP na kontrolerze domeny |
| Poprawa korelacji `100297` | Wspólny klucz korelacji (konto) między światem SSH a Windows |
