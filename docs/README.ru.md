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
codex plugin marketplace add GofMan5/secure-software --ref main
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
- production-защита софта для native, managed, mobile, JS/Electron, Python и WebAssembly: hardening, obfuscation, packing/virtualization, anti-tamper, licensing и signing;
- актуальные MITRE ATT&CK и CISA KEV с проверкой целостности и provenance;
- исправление корневой trust boundary вместо локального фильтра;
- честные `reportable`, `suppressed`, `not_applicable` и `deferred` dispositions;
- совместимость с Codex Security executors и Ponytail full.

Указанные пользователем target и action считаются достаточным execution contract. Для неопределённого внешнего эффекта скилл сохраняет рабочую структуру через `TARGET`, `HOST`, `TOKEN`, `OFFSET`, `PATCH_BYTE` и `PAYLOAD`, а проверку выполняет на disposable fixture.

## Защита софта от реверса

Отдельный cross-language runbook выбирает стабильный production-стек для C/C++, Rust, Go, .NET, JVM/Android, JavaScript/Electron, Python, Swift/Objective-C, WebAssembly и game/mobile builds. Порядок строгий: убрать embedded secrets и вынести привилегированные решения за server/platform boundary, усилить release build и приватные debug symbols, выборочно обфусцировать ценные участки, при необходимости применить post-link virtualization/packing, сохранить symbol maps, затем подписать и проверить итоговый artifact.

XOR-строки, minification, UPX, ASAR и PyInstaller считаются ограниченным сокрытием, а не trust boundary. Проверка сравнивает protected/unprotected builds через `strings`, symbols, реальный decompiler/debugger и bundled binary adapter; отдельно измеряются startup/runtime, размер, AV/EDR false positives, crash symbolication, reproducibility, updates и rollback.

Stdlib-only Protection Lab превращает эти требования в исполнимый release gate. Он без распаковки инвентаризирует файлы, каталоги и ZIP-подобные пакеты, сравнивает hashed canaries, source maps и размер, запускает явные functional/signing/update/decompiler argv с `shell=False` и выдаёт `ship`, `reject` либо `deferred` со всеми thresholds и пробелами покрытия.

```bash
python plugins/secure-software/skills/secure-software/scripts/protection_lab.py \
  --manifest GATES.json --baseline RELEASE --protected PROTECTED \
  --output protection-receipt.json
```

## Детерминированные evidence adapters

Stdlib-only адаптер собирает scanner, binary/decompiler, runtime и crash/fuzz evidence, не делая внешние инструменты обязательными. Он использует project-native или уже установленные tools, запускает custom argv с `shell=False` и пишет нормализованные receipts со scope, argv, версией, exit state, truncation, raw digest, redaction, observations и errors. Crash-режим добавляет повторные воспроизведения, sanitizer/fault metadata, нормализованный stack fingerprint и проверку minimized input. Метка сканера или единичный crash остаются candidate evidence до проверки полной attack chain.

```bash
python plugins/secure-software/skills/secure-software/scripts/evidence_adapter.py --help
python plugins/secure-software/skills/secure-software/scripts/evidence_adapter.py --self-test
python plugins/secure-software/skills/secure-software/scripts/evidence_adapter.py crash \
  --target HARNESS --input CRASH --minimized MINIMIZED --output crash.json -- HARNESS {input}
python plugins/secure-software/skills/secure-software/scripts/runtime_ledger.py paths \
  --input ledger.jsonl --source PRINCIPAL --sink SINK --output paths.json
```

Runtime ledger валидирует JSONL-узлы, active/blocked/unknown edges, ссылки на evidence/counterevidence и непрерывные source/control/sink dispositions. Детерминированный bounded path search подходит и для cloud/IAM, и для dependency-to-deployment цепочек `component -> advisory -> deployed instance -> reachable sink`.

## ChainBench-12

В репозитории лежат stdlib-only blind paired runner и 12 синтетических кейсов: шесть уязвимых chains и шесть изоморфных near-miss controls. Runner детерминированно перемешивает пары, изолирует workspaces, сохраняет execution receipts и mutations, затем считает chain recall, precision, near-miss rejection, root cause, evidence, severity, время и tokens.

```bash
python scripts/run_ab_benchmark.py validate
python scripts/run_ab_benchmark.py plan --out .chainbench/plan.json --repeats 3 --seed 20260724
python scripts/run_ab_benchmark.py run --plan .chainbench/plan.json --results .chainbench/results \
  --baseline-command '["AGENT_CLI","--workspace","{workspace}","--prompt-file","{prompt}","--output","{output}","--schema","{schema}"]' \
  --treatment-command '["AGENT_CLI","--workspace","{workspace}","--prompt-file","{prompt}","--output","{output}","--schema","{schema}"]' \
  --baseline-context .chainbench/baseline-context.json \
  --treatment-context .chainbench/treatment-context.json \
  --isolation external-sandbox
python scripts/run_ab_benchmark.py score --plan .chainbench/plan.json \
  --results .chainbench/results --out .chainbench/score.json
```

Замени `AGENT_CLI` и argv на один и тот же внешний runner для обеих веток; различаются только чистые профили. Каждый context-файл — публикуемый JSON object без секретов с зафиксированными `client`, `model`, `reasoning`, `executor`, `network`, положительным `token_budget` и полями `profile_sha256`, `skill_sha256`, `tools_sha256`; `"absent"` используется только для намеренно отсутствующего компонента. Runner хеширует manifest вместе с command-linked files, значениями environment, timeout и isolation, поэтому изменившийся execution context не переиспользует stale result.

Stdlib-harness очищает inherited environment, передаёт лишь явно указанные `--pass-env NAME`, применяет единый wall-clock deadline, завершает всё дерево процессов, отклоняет непереносимые fixture paths и фиксирует изменения внутри disposable workspace. Реальную изоляцию host/filesystem/network обеспечивает внешний container/VM wrapper, указанный через `--isolation external-sandbox`; флаг фиксирует этот boundary, а не создаёт его.

Публичный bundled corpus подходит для воспроизводимости и регрессий, но не является свежим blind-доказательством. Для убедительного нового A/B нужен неопубликованный suite той же схемы и чистый baseline-профиль, который не видит ни файлы, ни metadata Secure Software. Client, model snapshot, executor, tools, limits и environment должны совпадать; только treatment получает frozen skill. Corpus и truth публикуются после фиксации результатов.

## Состав пакета

```text
.agents/plugins/marketplace.json
benchmark/chainbench-12.json             # публичный corpus, только в репозитории
scripts/run_ab_benchmark.py              # A/B runner, только в репозитории
plugins/secure-software/
├── .codex-plugin/plugin.json
├── assets/
└── skills/secure-software/
    ├── SKILL.md
    ├── agents/openai.yaml
    ├── references/
    │   ├── attack-surface.md
    │   ├── evidence-adapters.md
    │   ├── intelligence-sources.md
    │   ├── platform-hardening.md
    │   ├── reverse-protocol.md
    │   └── software-protection.md
    └── scripts/
        ├── evidence_adapter.py
        ├── fetch_threat_intel.py
        ├── protection_lab.py
        └── runtime_ledger.py
```

В детерминированный release ZIP попадает только `plugins/secure-software`; benchmark runner и публичный corpus остаются снаружи.

## Проверка

```bash
python scripts/validate_repo.py
python plugins/secure-software/skills/secure-software/scripts/fetch_threat_intel.py --self-test
python plugins/secure-software/skills/secure-software/scripts/evidence_adapter.py --self-test
python plugins/secure-software/skills/secure-software/scripts/protection_lab.py --self-test
python plugins/secure-software/skills/secure-software/scripts/runtime_ledger.py --self-test
python scripts/run_ab_benchmark.py --self-test
python scripts/package_plugin.py
```

Подробности и доказательства находятся в [основном README](../README.md) и [evaluation report](EVALUATION.md). Следующие сравнительные запуски и расширения отмечены в [roadmap](../ROADMAP.md).
