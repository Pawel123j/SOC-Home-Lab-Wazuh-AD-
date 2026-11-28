# Pozostałe walidacje SOC Home Lab

## Stan na 28 listopada 2026

Walidacja statyczna reguł XML, Sigma, fixtures i dokumentacji przechodzi.

**Reguły zostały sprawdzone na prawdziwym managerze Wazuh 4.7.5.** Workflow CI
(job „Prawdziwy Wazuh manager") i lokalnie
`scripts/start_wazuh_test_manager.sh` stawiają izolowany kontener z tymi
regułami, a `scripts/run_wazuh_fixtures.py --transport eventchannel` wysyła do
niego każdą fiksturę i jej próbkę neutralną w formacie agenta Windows. Zdarzenie
przechodzi przez prawdziwy dekoder `windows_eventchannel` i wbudowany łańcuch
reguł Sysmon/PowerShell; każde musi mieć wpis w `archives.json`. Wynik: wszystkie
11 reguł jednozdarzeniowych strzela na swojej fiksturze i żadna nie strzela na
próbce neutralnej.

Co ten test wykazał i co poprawiono (przed poprawką 4 z 11 reguł nie strzelało):

- `wazuh-logtest` w 4.7 **nigdy** nie używa dekodera EventChannel (zawsze buduje
  komunikat `1:<location>:<log>`), dlatego wcześniej fixtures były widziane jako
  `json`. To ograniczenie narzędzia, nie fixtures.
- `100210` wskazywała `if_sid 61609` (Sysmon EID 7); EID 10 to `61612`.
- `100213` i `100240` były przesłaniane przez wbudowane reguły `92101` i
  `92300`/`92302`, które Wazuh sprawdza przed naszymi; teraz wiszą także pod nimi.
- Wazuh przechowuje w `win.eventdata.*` każdy `\` podwojony, `"` jako `\"`,
  a `&<>` jako encje XML. Wzorce `100232`, `100240`, `100241`, `100220` i `100250`
  zakładały pojedyncze `\` i zwykły `"`; poprawione, a testy PCRE2 używają tego
  samego modelu (`wazuh_decoded`).
- Reguła bazowa `61600` wymaga `severityValue`, które Wazuh wylicza tylko z pary
  `Level` + `Keywords`; fixtures Sysmona ich nie miały. Walidator to teraz sprawdza.

Czego ten test **nie** pokrywa: zbierania zdarzenia przez agenta i Sysmona na
prawdziwym Windowsie, Active Directory, Indexera/Dashboardu oraz reguł
korelacyjnych (`100110`, `100111`, `100120`, `100230`, `100231`, `100297`,
`100299`), które wymagają sekwencji zdarzeń. Archiwum tworzone przez PowerShell
trafia do wbudowanej `92212` zamiast `100232` (patrz
[data-exfiltration-http.md](docs/detections/data-exfiltration-http.md)).

## Wymagany test z prawdziwym kanałem Windows Event Channel

Na hoście z VirtualBox, Vagrant i około 32 GiB RAM:

1. Uruchom cztery VM zgodnie z [README](README.md) i zainstaluj agentów przez
   Ansible.
2. W Windows sprawdź, że Sysmon, agent Wazuh i kanał
   `Microsoft-Windows-Sysmon/Operational` są aktywne.
3. Wygeneruj **benign** zdarzenie procesu PowerShell, aby sprawdzić regułę
   100212 bez wykonywania pobierania ani modyfikacji systemu:

   ```powershell
   $command = 'Get-Date'
   $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
   & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
       -NoProfile -EncodedCommand $encoded
   ```

4. Zapisz surowe zdarzenie po stronie Windows oraz alert z Dashboardu; sprawdź
   ID reguły, agenta i timestamp. Potem uruchom zwykłe `powershell.exe -NoProfile
   -Command Get-Date` jako próbkę negatywną.
5. Zapisz wynik pozytywny i negatywny wraz z wersją managera, konfiguracją
   dekodera i reguły. Powtórz osobno dla każdej reguły, zanim zadeklarujesz
   pokrycie scenariuszy. Reguły korelacyjne wymagają odpowiedniej sekwencji i
   nie są dowiedzione pojedynczym zdarzeniem.

Nie uruchamiaj innych scenariuszy ofensywnych poza maszynami, które kontrolujesz.
Brak alertu jest wynikiem testu do diagnozy, a nie powodem do wpisania
oczekiwanego ID jako wyniku.

## Screenshoty i pełny provisioning

Do portfolio nadal brakuje zrzutów z prawdziwego Dashboardu z alertami z hostów
Windows. Instrukcje wymaganych obrazów znajdują się w
[`docs/screenshots/wazuh/README.md`](docs/screenshots/wazuh/README.md). Nie
zastępuj ich mockupami ani zrzutami z syntetycznego tekstu.

Kontener w `infrastructure/docker/` służy do lokalnego testu konfiguracji i
ładowania reguł. Nie zawiera agenta Windows, Active Directory, Indexera ani
Dashboardu. Nie stanowi odpowiednika pełnego wdrożenia VM.

## Poświadczenia

`ansible_password: vagrant` jest publicznym domyślnym hasłem tymczasowych boxów
Vagranta, a nie sekretem produkcyjnym. Używaj inwentarza wyłącznie z tymi
jednorazowymi VM-ami; przed innym użyciem skonfiguruj poświadczenia przez
Ansible Vault. `WAZUH_API_PASSWORD` w Compose jest wymagane z prywatnego
środowiska i nie ma domyślnej wartości w pliku.
