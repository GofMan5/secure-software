# Secure Software

`Secure Software` — open-source Codex plugin для adversarial-аудита сайтов, API, сервисов, desktop/mobile приложений, cloud/IAM, CI/CD, контейнеров, ОС, зависимостей, игр, firmware и OT/ICS.

Он не превращает чек-лист или совпадение CVE в готовую уязвимость. Для каждого серьёзного finding требуется доказать цепочку:

```text
вход атакующего -> контролируемые данные или identity -> security control
-> примитив обхода -> привилегированный sink -> реальный impact
```

## Установка

```bash
codex plugin marketplace add GofMan5/secure-software
codex plugin add secure-software@secure-software
```

После установки открой новую сессию Codex:

```text
$secure-software проведи глубокий аудит репозитория, докажи полные attack chains и оставь только подтверждённые findings
```

Прямая установка одного скилла:

```text
$skill-installer install https://github.com/GofMan5/secure-software/tree/main/plugins/secure-software/skills/secure-software
```

## Что отличает скилл

- reverse engineering, exploit reconstruction, binary/protocol и IPC-анализ;
- строгие discovery, validation, attack-path и remediation фазы;
- поиск tenant escape, identity pivot, artifact poisoning, signed-update abuse и sibling bypass;
- актуальные MITRE ATT&CK и CISA KEV с проверкой целостности и provenance;
- исправление корневой trust boundary вместо локального фильтра;
- честные `reportable`, `suppressed`, `not_applicable` и `deferred` dispositions;
- совместимость с Codex Security executors и Ponytail full.

Подробности, команды и доказательства находятся в [основном README](../README.md) и [evaluation report](EVALUATION.md).
