# Docker — walidacja konfiguracji Wazuh

Compose uruchamia wyłącznie Wazuh Manager. Ułatwia lokalne sprawdzenie, czy
manager przyjmuje konfigurację i reguły; nie zapewnia pełnego toru zdarzeń
Windows.

## Stan i zakres

- Obraz `wazuh/wazuh-manager:4.7.5` jest przypięty jawnie. To starsza wersja;
  przed użyciem poza jednorazowym labem sprawdź wspieraną wersję i poprawki
  bezpieczeństwa.
- W bieżącej sesji kontener był `healthy`, a
  `/var/ossec/bin/wazuh-analysisd -t` zwrócił kod `0`. Wystąpił niekrytyczny
  komunikat hosta o limicie deskryptorów plików.
- `wazuh-logtest` w 4.7 nie używa dekodera `windows_eventchannel`, więc fixtures
  Windows przez logtest kończą się błędem. Reguły Windows sprawdza się przez
  kolejkę analysisd w formacie agenta — sekcja niżej. Stan i ograniczenia:
  [`HUMAN_ACTION_REQUIRED.md`](../../HUMAN_ACTION_REQUIRED.md).

Kontener nie zawiera Windows, agenta, Active Directory, Indexera ani Dashboardu.
Nie uruchamia też skryptów z `attacks/`.

## Uruchomienie

Ustaw prywatne hasło API; nie wpisuj go do repozytorium ani historii poleceń:

```bash
cd infrastructure/docker
read -r -s -p 'Wazuh API password: ' WAZUH_API_PASSWORD
printf '\n'
export WAZUH_API_PASSWORD
docker compose config -q
docker compose up -d
docker compose ps
```

Poczekaj, aż healthcheck pokaże `healthy`, a następnie sprawdź konfigurację:

```bash
docker exec wazuh-manager /var/ossec/bin/wazuh-analysisd -t
```

Ten test weryfikuje ładowanie konfiguracji managera. Nie dowodzi, że reguła
pasuje do syntetycznego zdarzenia ani że alert dotarł do Dashboardu.

Wszystkie opublikowane porty są ograniczone do `127.0.0.1`. Zmienne API,
poświadczenia, porty i trwałe wolumeny są zdefiniowane w
[`docker-compose.yml`](docker-compose.yml). Używaj osobnego projektu Compose,
jeśli na hoście działa inny Wazuh o stałej nazwie kontenera.

## Test reguł na prawdziwym managerze (EventChannel)

To samo, co job „Prawdziwy Wazuh manager" w CI. Z katalogu głównego:

```bash
scripts/start_wazuh_test_manager.sh wazuh-fixtures
python3 scripts/run_wazuh_fixtures.py --container wazuh-fixtures \
    --transport eventchannel --output /tmp/wazuh-eventchannel.json
docker rm -f wazuh-fixtures
```

Skrypt startowy stawia osobny kontener `wazuh/wazuh-manager:4.7.5` bez
opublikowanych portów i bez hasła API, montuje reguły i włącza w nim
`<logall_json>`. Runner wysyła każdą fiksturę i jej próbkę neutralną jako
zdarzenie agenta Windows, potwierdza wpis w `archives.json` z dekoderem
`windows_eventchannel` i kończy się `FN=0; FP=0; 22 cases` oraz kodem `0`, gdy
wszystkie reguły jednozdarzeniowe działają. Raport nie zawiera surowych logów.

W środowisku, które nie pozwala na `memlock: -1` (np. kontener w kontenerze),
`docker compose up` kończy się błędem `error setting rlimit type 8`; skrypt
startowy nie ustawia tego limitu.

## Walidacja statyczna repozytorium

Z katalogu głównego:

```bash
python3 scripts/validate_detections.py
python3 -m pytest -q tests
python3 scripts/validate_docs_against_rules.py
```

Walidatory sprawdzają m.in. strukturę XML/YAML/JSON, regex PCRE2, lokalne
łańcuchy SID oraz zgodność części dokumentacji z regułami. Reguły zależne od
wbudowanych SID Wazuha i poprawność dopasowania Windows Event Channel wymagają
testu z odpowiednim silnikiem oraz agentem.

## Zatrzymanie

```bash
docker compose down
```

Ta komenda zachowuje wolumeny. `docker compose down -v` usuwa stan managera;
używaj jej wyłącznie wtedy, gdy świadomie chcesz skasować dane tego projektu.
