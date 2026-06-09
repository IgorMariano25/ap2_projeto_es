# TOOLS_VERSIONS.md — Versões das ferramentas (reprodutibilidade)

Registre aqui as versões **exatas** usadas na coleta, junto com a data e o SO.
As ferramentas externas pesadas ficam fora do repositório, em `E:\developer-tools`
(ver `.gitignore`); as libs Python ficam no `venv/` a partir do `requirements.txt`.

- **Data da coleta:** AAAA-MM-DD
- **Sistema operacional:** _(ex.: Windows 11 / Ubuntu 22.04)_
- **Python (`python --version`):** _____

## Ferramentas externas (`E:\developer-tools`)

| Ferramenta | Versão | Como verificar | Observações |
| --- | --- | --- | --- |
| SonarQube (servidor) | | UI → Administration → System, ou `docker images sonarqube` | Community Edition |
| SonarScanner CLI | | `sonar-scanner --version` | precisa estar no `PATH` |
| Semgrep | | `semgrep --version` | fallback do alvo |
| CodeQL | | `codeql version` | opcional |
| CK (metrics) | | release/jar | opcional (métricas OO) |
| OSV-Scanner | | `osv-scanner --version` | opcional (SCA de dependências) |
| Gitleaks | | `gitleaks version` | opcional (segredos) |

## Bibliotecas Python (do `requirements.txt`)

Gere o snapshot com `pip freeze > pip_freeze.txt` e registre as principais:

| Pacote | Versão |
| --- | --- |
| pandas | |
| scikit-learn | |
| numpy | |
| matplotlib | |
| requests | |

## Comandos e parâmetros relevantes

Registre aqui qualquer parâmetro não trivial usado (ex.: `sonar.java.binaries`,
inclusões/exclusões, quality profile aplicado), para tornar o estudo reprodutível.
