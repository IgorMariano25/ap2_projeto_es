# NSA Java · SonarQube · Machine Learning

Estudo empírico de **postura de segurança** em repositórios Java da
organização `NationalSecurityAgency` (GitHub), fundamentado na **ISO/IEC 25010**.
O pipeline analisa código-fonte **sem build** (apenas clone), extrai métricas
estruturais **por arquivo `.java`** com o SonarQube e treina um modelo de
Machine Learning que prevê arquivos propensos a **risco de segurança**.

> **Pergunta de pesquisa:** métricas de qualidade de código (complexidade,
> duplicação, code smells, violações) predizem arquivos Java propensos a riscos
> de segurança?

## Decisões fixas do desenho

- **Modo estático, sem build:** os projetos são apenas clonados, nunca compilados.
- **Unidade de análise = arquivo `.java`** (uma linha por arquivo no dataset).
- **Alvo:** `has_security_risk = 1` se `security_hotspots + vulnerabilities > 0`.
- **Features = só métricas estruturais/qualidade.** As métricas de segurança
  **nunca** são features — apenas definem o alvo (**sem vazamento**).
- **Modelos:** Random Forest (principal) + Regressão Logística (baseline).
- **Avaliação:** Accuracy, Precision, Recall, F1, ROC-AUC, Matriz de Confusão.
  RMSE/MAE **não se aplicam** (é classificação).

## Estrutura

| Arquivo | Papel |
| --- | --- |
| `config.py` | Configuração central: repos, `project_key`, features × segurança. |
| `run_sonarqube_nsa.py` | Clona e analisa cada repo no SonarQube. |
| `extract_sonar_csv.py` | Extrai métricas **por arquivo** → `data/<repo>.csv` + `data/dataset.csv`. |
| `train_model.py` | Deriva o alvo, treina RF + LogReg, avalia e salva figuras. |
| `descriptive_report.py` | Estatística descritiva por repo (tabela + gráfico para o artigo). |
| `semgrep_target.py` | Fallback do alvo via Semgrep quando os hotspots vêm vazios. |
| `DATA_DICTIONARY.md` | Dicionário de colunas do `dataset.csv`. |
| `TOOLS_VERSIONS.md` | Versões das ferramentas (reprodutibilidade). |

## Pré-requisitos

1. **SonarQube** (servidor). Caminho mais simples, via Docker:
   ```
   docker run -d --name sonarqube -p 9000:9000 sonarqube:community
   ```
   Aguarde subir (~1–2 min), acesse <http://localhost:9000> (admin/admin),
   troque a senha e gere um token em *My Account → Security → Generate Tokens*.
2. **SonarScanner CLI** no `PATH` (comando `sonar-scanner`).
3. **git** e **Python 3.9+**.
4. Ferramentas externas pesadas em `E:\developer-tools` (ver `TOOLS_VERSIONS.md`).

> **Aviso (Java sem build):** o analisador Java do SonarQube usa bytecode. No
> modo "só clone", as métricas **estruturais** vêm confiáveis (features), mas os
> sinais de **segurança** podem vir vazios. Se isso ocorrer, derive o alvo com
> `semgrep_target.py`.

## Instalação

```powershell
# Windows (PowerShell)
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:SONAR_TOKEN = "<seu_token>"
# opcional: $env:SONAR_HOST = "http://localhost:9000"
```

```bash
# Linux / macOS
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
export SONAR_TOKEN=<seu_token>
# opcional: export SONAR_HOST=http://localhost:9000
```

## Ordem de execução

```bash
# PILOTO (obrigatório antes dos 10) — valida o desenho em 1 repositório:
python run_sonarqube_nsa.py --only ghidra
python extract_sonar_csv.py --repos ghidra     # confira se security_hotspots tem valores
python train_model.py                          # se "classe única", acione semgrep_target.py

# COMPLETO — os 10 repositórios:
python run_sonarqube_nsa.py
python extract_sonar_csv.py
python train_model.py
python descriptive_report.py
```

## Saídas

- `data/dataset.csv` — dataset unificado (uma linha por `.java`). **Versionado.**
- `data/<repo>.csv` — métricas por arquivo de cada repo (não versionado).
- `data/confusion_matrix_rf.png`, `data/feature_importance_rf.png` — figuras do ML.
- `data/repo_summary.csv` / `data/repo_summary.png` — tabela e gráfico descritivos.
