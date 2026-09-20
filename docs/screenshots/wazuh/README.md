# Zrzuty z dashboardu Wazuh

Ten katalog jest **celowo pusty**.

Cała wartość tego repozytorium opiera się na twierdzeniu „te reguły strzelają
na tych atakach". Zrzut ekranu z alertem jest jedynym dowodem, jaki da się
pokazać w README — i właśnie dlatego **nie wolno go wygenerować ani zmontować**.
Sfabrykowany alert w portfolio z obszaru bezpieczeństwa jest gorszy niż brak
alertu: podważa wszystko inne w repozytorium.

Zrzuty musi zrobić człowiek, po uruchomieniu laboratorium. Procedura:
[`HUMAN_ACTION_REQUIRED.md`](../../../HUMAN_ACTION_REQUIRED.md).

## Oczekiwane pliki

| Plik | Skąd | Co musi pokazywać |
| ---- | ---- | ----------------- |
| `01-brute-force-alert.png` | Wazuh Dashboard → Security events | Alert reguły **100110/100111** po `attacks/01-brute-force-ssh.sh` — widoczny źródłowy IP 192.168.30.30 i liczba prób |
| `02-lsass-access-alert.png` | Wazuh Dashboard → Security events | Alert reguły **100210** (dostęp do LSASS) z `grantedAccess` i obrazem procesu źródłowego |
| `03-mitre-view.png` | Wazuh Dashboard → MITRE ATT&CK | Mapa technik z trafieniami z przeprowadzonych scenariuszy |
| `04-rule-detail.png` | Wazuh Dashboard → Management → Rules | Szczegóły jednej reguły własnej z `custom-wazuh-rules.xml` załadowanej przez managera |
| `05-agents.png` | Wazuh Dashboard → Agents | `dc01` i `ws01` w stanie *Active* — dowód, że pipeline agent → manager działa |

## Zasady

- PNG, pełna szerokość okna przeglądarki, bez chromu przeglądarki.
- **Nie retuszuj alertów.** Jeśli reguła nie strzeliła — to jest wynik do
  naprawienia w regule, nie do poprawienia w edytorze graficznym.
- Adresy 192.168.x i nazwy `soclab.local` są laboratoryjne, więc nie wymagają
  anonimizacji. Jeśli lab postawisz w innej sieci — zamaż adresy publiczne.
- Do ~500 KB na plik.
