# Human action required — SOC Home Lab

Ten projekt z natury wymaga uruchomionego laboratorium: hypervisora, kilku
maszyn wirtualnych i przeglądarki. Poniższe kroki są rozpisane dokładnie,
zamiast być pominięte albo udane.

CI nie jest tym zablokowane: walidacja reguł Wazuh, reguł Sigma, zdarzeń
testowych, YAML-a infrastruktury i pliku compose przechodzi bez żadnej z tych
czynności.

---

## 1. Postaw harness Docker i potwierdź, że 9 zdarzeń wyzwala reguły

To jest **najważniejszy** punkt tej listy: CI potwierdza, że reguły są
poprawne składniowo i że łańcuchy `if_sid` się spinają, ale **nie uruchamia
Wazuha**, więc nie potwierdza, że reguła faktycznie strzeli.

Wariant dockerowy wystarczy — nie potrzeba pełnego labu na VM-ach (4 GB RAM
zamiast 32 GB):

```bash
cd infrastructure/docker
docker compose up -d
docker compose logs -f wazuh-manager   # poczekaj na "Started wazuh-manager"

# Sprawdź, że manager załadował reguły własne bez błędu:
docker exec -it wazuh-manager /var/ossec/bin/wazuh-logtest -t

# Przepuść każde z 9 syntetycznych zdarzeń przez silnik reguł:
for f in test-events/*.json; do
  echo "=== $f"
  docker exec -i wazuh-manager /var/ossec/bin/wazuh-logtest < "$f"
done
```

**Czego szukać:** dla każdego zdarzenia `wazuh-logtest` powinien wypisać
`Rule id: 1002xx` z zakresu reguł własnych. Zdarzenie, które nie trafia w żadną
regułę własną, oznacza lukę w detekcji — to realne znalezisko, warte poprawki
w regule, a nie zignorowania.

Wyniki warto zapisać do `docs/04-detection-results.md`, który dziś opisuje
oczekiwane zachowanie.

---

## 2. Zrób zrzuty z dashboardu

Wymaga pełnego labu (dashboard nie wchodzi w skład wariantu dockerowego):

```bash
cd infrastructure/vagrant
vagrant up                      # ~25 min, 4 VM-y
cd ../ansible
ansible-playbook -i inventory.yml site.yml

# Przeprowadź scenariusze z maszyny Kali:
bash attacks/01-brute-force-ssh.sh
powershell -File attacks/02-mimikatz-simulation.ps1
```

Następnie zrób 5 zrzutów opisanych w
[`docs/screenshots/wazuh/README.md`](docs/screenshots/wazuh/README.md).

**Nie fabrykuj tych obrazków.** Całe repozytorium opiera się na twierdzeniu, że
te reguły wykrywają te ataki — sfabrykowany alert podważyłby wszystko inne.
Jeśli reguła nie strzeli, to jest wynik do naprawienia w regule.

---

## 3. Opcjonalnie: nagranie „atak → alert"

Dwu-, trzyminutowe wideo (terminal Kali po lewej, dashboard Wazuh po prawej)
pokazuje ten projekt lepiej niż jakikolwiek zrzut. To jedyny format, w którym
widać opóźnienie między atakiem a alertem.

---

## Uwagi o poświadczeniach

Dwa hasła w repozytorium są **celowe i nie są wyciekiem**:

- `ansible_password: vagrant` w `infrastructure/ansible/inventory.yml` — publicznie
  znane domyślne dane logowania obrazów bazowych Vagranta.
- `API_PASSWORD` w `infrastructure/docker/docker-compose.yml` — domyślne hasło
  API z dokumentacji Wazuha.

Oba są opatrzone komentarzem w miejscu użycia, wraz z tym, co należy zmienić
przy jakimkolwiek trwałym wdrożeniu. `.gitignore` wyklucza `secrets/`
i `wazuh-passwords.txt`, czyli pliki generowane przez instalator.
