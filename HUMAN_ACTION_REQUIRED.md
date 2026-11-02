# Pozostałe walidacje SOC Home Lab

## Stan na 2 listopada 2026

Walidacja statyczna reguł XML, Sigma, fixtures i dokumentacji przechodzi.
Uruchomiony manager Wazuh 4.7.5 zwrócił kod `0` dla
`/var/ossec/bin/wazuh-analysisd -t`, czyli przyjął konfigurację. W tym
kontenerze pojawił się też komunikat o ograniczeniu limitu deskryptorów przez
hosta; nie zmienił kodu wyjścia.

Test `wazuh-logtest` **nie potwierdził** reguł Sysmon z fixtures. Narzędzie
przetworzyło ich JSON dekoderem `json`, a nie `windows_eventchannel`, który jest
przodkiem reguł 100210–100214 i pozostałych reguł Sysmon. Nie pojawiła się faza
3 ani wynik dopasowania. Wcześniejsza instrukcja, że samo wklejenie fixtures do
kontenera potwierdza detekcję, była błędna i została wycofana z dokumentacji.
Nie raportuj wyników FP/FN z tych fixtures jako potwierdzenia detekcji.

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
