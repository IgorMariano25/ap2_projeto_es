# DATA_DICTIONARY.md — Dicionário de dados (`data/dataset.csv`)

**Unidade de análise:** um arquivo `.java` (uma linha por arquivo).
**Origem das métricas:** SonarQube, via `GET /api/measures/component_tree`
(`qualifiers=FIL`), extraídas por `extract_sonar_csv.py`.

| Coluna | Origem | Papel | Descrição |
| --- | --- | --- | --- |
| `repo` | extração | identificador / grupo | Nome do repositório. É o **grupo** do GroupKFold. |
| `file_path` | extração | identificador | Caminho do arquivo `.java` dentro do repositório. |
| `ncloc` | SonarQube | **feature** | Linhas de código (non-comment lines of code). |
| `complexity` | SonarQube | **feature** | Complexidade ciclomática. |
| `cognitive_complexity` | SonarQube | **feature** | Complexidade cognitiva. |
| `code_smells` | SonarQube | **feature** | Nº de *code smells* (manutenibilidade). |
| `duplicated_lines_density` | SonarQube | **feature** | % de linhas duplicadas. |
| `comment_lines_density` | SonarQube | **feature** | % de linhas de comentário. |
| `functions` | SonarQube | **feature** | Nº de funções/métodos. |
| `classes` | SonarQube | **feature** | Nº de classes. |
| `violations` | SonarQube | **feature** | Nº total de *issues* (regras violadas). |
| `security_hotspots` | SonarQube | **define o alvo** | Pontos quentes de segurança. **NÃO é feature.** |
| `vulnerabilities` | SonarQube | **define o alvo** | Vulnerabilidades detectadas. **NÃO é feature.** |
| `has_security_risk` | derivada (`train_model.py`) | **alvo** | `1` se `security_hotspots + vulnerabilities > 0`, senão `0`. |
| `semgrep_findings` | `semgrep_target.py` (opcional) | alvo alternativo | Nº de achados Semgrep por arquivo (fallback do alvo). |

## Observações metodológicas

- **SonarQube omite a métrica quando o valor é 0.** Por isso o ML faz coerção
  numérica + `fillna(0)` ao carregar o dataset.
- **Sem vazamento (decisões 5 e 6 do prompt):** `security_hotspots` e
  `vulnerabilities` **só definem o alvo**; nunca entram em `FEATURE_METRICS`.
- **Modo "só clone" (sem build):** os sinais de segurança do SonarQube podem vir
  vazios. Nesse caso, derive o alvo de `semgrep_findings` (ver `semgrep_target.py`).
- **Identificadores não são features:** `repo` e `file_path` servem para
  rastreabilidade e para o agrupamento por repositório na validação cruzada.
