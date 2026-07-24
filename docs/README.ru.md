# Secure Software

`Secure Software` — переносимый open-source Agent Skill для offensive и defensive security engineering сайтов, API, сервисов, desktop/mobile приложений, cloud/IAM, CI/CD, контейнеров, ОС, зависимостей, игр, firmware и OT/ICS. Работает в Claude Code, Codex, GitHub Copilot, OMP, Pi, OpenCode и других Agent Skills-совместимых клиентах; нативная упаковка Codex plugin сохранена.

Он не превращает чек-лист или совпадение CVE в готовую уязвимость. Для каждого серьёзного finding требуется доказать цепочку:

```text
вход атакующего -> контролируемые данные или identity -> security control
-> примитив обхода -> привилегированный sink -> реальный impact
```

## Установка куда угодно

Дать установщику выбрать обнаруженный клиент или выбрать клиентов и область установки интерактивно:

```bash
npx skills add GofMan5/secure-software --skill secure-software
```

Установить глобально сразу для Claude Code, Codex, GitHub Copilot, OpenCode, Pi и OMP:

```bash
npx skills add GofMan5/secure-software --skill secure-software --global --copy --yes -a claude-code -a codex -a github-copilot -a opencode -a pi
```

OMP по умолчанию читает Pi skills, поэтому `-a pi` покрывает и OMP. В проекте OMP также читает `.agents/skills`. Убери `--global` для установки только в текущий репозиторий. Для всех клиентов, поддерживаемых установщиком, используй `--agent '*'` вместо перечисленных `-a`.

Обновление установленных копий:

```bash
npx skills update secure-software --global --yes
```

Убери `--global`, чтобы обновить установку в проекте.

Для ручной или нестандартной установки скопируй весь каталог `plugins/secure-software/skills/secure-software`, включая `references/` и `scripts/`, в `<skills-root>/secure-software`:

| Клиент | В проекте | Для пользователя |
| --- | --- | --- |
| Claude Code | `.claude/skills/` | `~/.claude/skills/` |
| Codex | `.agents/skills/` | `~/.codex/skills/` |
| GitHub Copilot | `.agents/skills/` | `~/.copilot/skills/` |
| OMP | `.omp/skills/` или `.agents/skills/` | `<omp-config>/skills/` (`omp config path`) или `~/.pi/agent/skills/` |
| Pi | `.pi/skills/` | `~/.pi/agent/skills/` |
| OpenCode | `.agents/skills/` | `~/.config/opencode/skills/` |
| Другой Agent Skills-клиент | Его каталог skills | Его пользовательский каталог skills |

### Нативный Codex plugin

```bash
codex plugin marketplace add GofMan5/secure-software --ref v1.1.0
codex plugin add secure-software@secure-software
```

После установки перезапусти клиент. В Codex используй `$secure-software`, в OMP — `/skill:secure-software`, а в любом клиенте можно прямо попросить применить скилл:

```text
Используй secure-software: проведи глубокий аудит репозитория, докажи полные attack chains и оставь только подтверждённые findings
```

## Что отличает скилл

- offensive testing, reverse engineering, exploit/payload development и execution, fuzzing/scanning, credential auditing и adversary emulation;
- строгие discovery, validation, attack-path и remediation фазы;
- поиск tenant escape, identity pivot, artifact poisoning, signed-update abuse и sibling bypass;
- актуальные MITRE ATT&CK и CISA KEV с проверкой целостности и provenance;
- исправление корневой trust boundary вместо локального фильтра;
- честные `reportable`, `suppressed`, `not_applicable` и `deferred` dispositions;
- совместимость с Codex Security executors и Ponytail full.

Указанные пользователем target и action считаются достаточным execution contract. Для неопределённого внешнего эффекта скилл сохраняет рабочую структуру через `TARGET`, `HOST`, `TOKEN`, `OFFSET`, `PATCH_BYTE` и `PAYLOAD`, а проверку выполняет на disposable fixture.

Подробности, команды и доказательства находятся в [основном README](../README.md) и [evaluation report](EVALUATION.md).
