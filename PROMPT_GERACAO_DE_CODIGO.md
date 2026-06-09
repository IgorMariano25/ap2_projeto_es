# PROMPT — Geração de Todo o Código do Projeto (NSA Java · SonarQube · Machine Learning)

> **Como usar:** cole este prompt em um agente de código (Claude Code, etc.). Ele deve **gerar todo o código do projeto**, funcional e simples, conforme as especificações abaixo. Use em conjunto com o documento de metodologia `PROMPT_Analise_Seguranca_NSA_Java.md` (fonte da verdade para o "porquê"); este prompt define o "o quê" e o "como" do código.

---

## 0. Objetivo

Gerar um projeto Python completo e **executável de ponta a ponta** que: (1) analisa 10 repositórios Java da NSA com SonarQube; (2) extrai métricas **por arquivo** para CSVs; (3) treina e avalia um modelo de Machine Learning que prevê arquivos propensos a risco de segurança; e (4) produz artefatos para o artigo SBC (tabelas/figuras). Prioridade absoluta: **simplicidade + funcionar sem grandes correções**.

---

## 1. Decisões FIXAS que o código deve respeitar (não alterar o desenho)

1. **Modo estático, sem build:** os projetos são **apenas clonados**; nunca compilados/executados. Toda ferramenta opera sobre código-fonte ou histórico Git.
2. **SonarQube-cêntrico:** o SonarQube fornece **as features (métricas estruturais) e o sinal de segurança que define o alvo**.
3. **Unidade de análise = arquivo `.java`** (uma linha por arquivo no dataset), não o repositório.
4. **Alvo (target):** `has_security_risk = 1` se `security_hotspots > 0` **ou** `vulnerabilities > 0`; senão `0`.
5. **Features = métricas estruturais/qualidade** apenas: `ncloc, complexity, cognitive_complexity, code_smells, duplicated_lines_density, comment_lines_density, functions, classes, violations`.
6. **SEM VAZAMENTO:** `security_hotspots`, `vulnerabilities` (e qualquer métrica de segurança) **nunca** são features — só definem o alvo.
7. **Modelos:** Random Forest (principal) + Regressão Logística (baseline). XGBoost/LightGBM opcionais, atrás de import protegido (não quebrar se não instalados).
8. **Avaliação:** Accuracy, Precision, Recall, F1, ROC-AUC, Matriz de Confusão. **RMSE/MAE NÃO se aplicam** (é classificação). Sob desbalanceamento, focar Recall/F1 e usar `class_weight="balanced"`.
9. **Validação:** divisão treino/teste estratificada (principal) + GroupKFold por repositório (secundária, robusta a exceções).
10. **Separação de dependências:** libs Python no projeto (`requirements.txt`, `venv/` no `.gitignore`); ferramentas externas pesadas (SonarQube, SonarScanner, CodeQL, CK, OSV-Scanner, Gitleaks) em `E:\developer-tools`, versões registradas em `TOOLS_VERSIONS.md`.

---

## 2. Regras de comportamento do agente

- **Entenda antes de alterar:** leia a estrutura existente antes de criar/editar arquivos; não sobrescreva trabalho sem necessidade.
- **Não fabrique dados nem resultados.** Métrica ausente vira nulo/0 documentado, nunca valor inventado.
- **Verifique antes de afirmar:** nomes de repositório, existência de endpoints, versões. Não invente.
- **Piloto primeiro:** o código deve permitir rodar em 1 repositório (`--repos ghidra`) antes dos 10.
- **Código simples, comentado e idempotente** (reexecutável sem efeitos colaterais). Tratar erros por repositório sem derrubar o pipeline inteiro.

---

## 3. Estrutura de pastas a criar

```
nsa-java-security/
├── README.md
├── requirements.txt
├── .gitignore
├── TOOLS_VERSIONS.md
├── DATA_DICTIONARY.md
├── config.py                  # lista de repos, chaves, env (SONAR_HOST/TOKEN)
├── run_sonarqube_nsa.py       # 1) clona + analisa no SonarQube
├── extract_sonar_csv.py       # 2) extrai métricas por arquivo -> CSVs
├── train_model.py             # 3) treina e avalia o ML
├── descriptive_report.py      # 4) estatística descritiva p/ o artigo (opcional-recomendado)
├── semgrep_target.py          # fallback: alvo via Semgrep se hotspots vierem vazios
└── data/                      # saídas (no .gitignore, exceto dataset final)
    ├── <repo>.csv
    ├── dataset.csv
    ├── confusion_matrix_rf.png
    └── feature_importance_rf.png
```

---

## 4. Especificação de cada arquivo

### `config.py`
- `SONAR_HOST` (env, default `http://localhost:9000`) e `SONAR_TOKEN` (env, obrigatório).
- `REPOS`: lista dos 10 nomes — `ghidra, emissary, timely, qonduit, datawave, fractalrabbit, datawave-query-service, datawave-audit-service, datawave-authorization-service, ghidra-lisa`. Comentar que tamanhos devem ser verificados e os pequenos descartados.
- Convenção de chave: `project_key = f"nsa_{repo}"`.
- `FEATURE_METRICS` e `SECURITY_METRICS` (listas das decisões 5 e 6).

### `run_sonarqube_nsa.py`
- Para cada repo: clone raso (`git clone --depth 1`), rodar `sonar-scanner` com `-Dsonar.projectKey=nsa_<repo>`, `-Dsonar.sources=.`, `-Dsonar.inclusions=**/*.java`, e `-Dsonar.java.binaries=.` (modo source-only).
- Capturar o `ceTaskId` em `.scannerwork/report-task.txt` e **aguardar o Compute Engine** via `GET /api/ce/task?id=...` até `SUCCESS/FAILED`.
- Flag `--only <repo>` para o piloto. Tratar falha de um repo sem parar os demais.
- **Comentar honestamente:** se o analisador Java exigir bytecode e abortar, o usuário decide (compilar mínimo, ou usar `semgrep_target.py`).

### `extract_sonar_csv.py`  ← núcleo do pedido "gerar os CSVs"
- Para cada `project_key`, paginar `GET /api/measures/component_tree` com `qualifiers=FIL`, `metricKeys=` (FEATURE_METRICS+SECURITY_METRICS), `ps=500`.
- Filtrar componentes cujo `path` termina em `.java`. Uma linha por arquivo.
- Escrever **`data/<repo>.csv`** e acumular em **`data/dataset.csv`**.
- Colunas: `repo, file_path, <FEATURE_METRICS>, <SECURITY_METRICS>`.
- Flag `--repos` para subconjunto/piloto. Tratar `HTTPError` por repo sem abortar.

### `train_model.py`  ← núcleo do ML
- Ler `data/dataset.csv`. Converter métricas para numérico com `fillna(0)` (SonarQube omite métrica zero).
- Derivar `has_security_risk` (decisão 4). Se **uma única classe**, **parar com mensagem clara** sugerindo o fallback Semgrep.
- `X = FEATURE_METRICS` (decisão 5/6, sem vazamento), `y = has_security_risk`, `groups = repo`.
- `train_test_split(test_size=0.25, stratify=y, random_state=42)`.
- **Random Forest** (`n_estimators=300, class_weight="balanced", min_samples_leaf=2, n_jobs=-1`) + **Regressão Logística** (com `StandardScaler`, `class_weight="balanced"`).
- Imprimir, para cada modelo: Accuracy, Precision, Recall, F1, ROC-AUC (try/except p/ classe única), Matriz de Confusão.
- Salvar `data/confusion_matrix_rf.png` e `data/feature_importance_rf.png`; imprimir ranking de importância (gancho da discussão ISO 25010).
- Bloco final: **GroupKFold por repositório** (`n_splits=min(5, n_repos)`) com `cross_val_predict(method="predict_proba")`, dentro de try/except para nunca quebrar o script.
- Imprimir aviso: "RMSE/MAE não se aplicam (classificação)".
- XGBoost/LightGBM: opcionais, dentro de `try: import ...` — se ausentes, ignorar sem erro.

### `semgrep_target.py`  (fallback do alvo)
- Para cada repo clonado, rodar `semgrep --config p/java --json` e parsear `results` → contagem de achados por arquivo.
- Produzir uma coluna alternativa de alvo (`semgrep_findings`) e mesclar ao `dataset.csv`. Usar quando os hotspots do SonarQube vierem vazios (cenário sem build).

### `descriptive_report.py`  (para a seção Resultados do artigo)
- A partir dos `data/<repo>.csv`, agregar por repositório: `ncloc` total, nº de arquivos, total de hotspots/vulnerabilidades, e **densidade por KLOC**.
- Gerar uma tabela `data/repo_summary.csv` e um gráfico de barras comparativo. Mapear, em comentários/saída, cada indicador à sub-característica ISO 25010 correspondente (Integridade/Confidencialidade etc.).

### Arquivos de suporte
- **`requirements.txt`**: `pandas, scikit-learn, numpy, matplotlib, requests` (mínimo viável); `pydriller, lizard, semgrep` (se usar fallback/extras); `xgboost, lightgbm, imbalanced-learn, shap` (opcionais). Comentar o mínimo viável.
- **`.gitignore`**: `venv/`, `repos/`, `data/*.png`, saídas brutas, `developer-tools/`, caches; **manter** `data/dataset.csv`, scripts, configs.
- **`TOOLS_VERSIONS.md`**: modelo para registrar versões de SonarQube, SonarScanner, Semgrep, etc.
- **`DATA_DICTIONARY.md`**: descrição de cada coluna do `dataset.csv`, origem (SonarQube/derivada) e papel (feature/alvo/identificador).
- **`README.md`**: pré-requisitos (E:\developer-tools, SonarQube via Docker, token), e a ordem de execução abaixo.

---

## 5. Contrato de dados (`dataset.csv`)

| Coluna | Origem | Papel |
| --- | --- | --- |
| `repo`, `file_path` | extração | identificador (e grupo do GroupKFold) |
| `ncloc, complexity, cognitive_complexity, code_smells, duplicated_lines_density, comment_lines_density, functions, classes, violations` | SonarQube (component_tree) | **features** |
| `security_hotspots, vulnerabilities` | SonarQube | definem o **alvo** (não são features) |
| `has_security_risk` | derivada em `train_model.py` | **alvo** |

---

## 6. Ordem de execução (documentar no README)

```bash
python -m venv venv && pip install -r requirements.txt
export SONAR_TOKEN=<token>          # Windows: set SONAR_TOKEN=...

# PILOTO (obrigatório antes dos 10):
python run_sonarqube_nsa.py --only ghidra
python extract_sonar_csv.py --repos ghidra      # checar se security_hotspots tem valores
python train_model.py                            # se "classe única", acionar semgrep_target.py

# COMPLETO:
python run_sonarqube_nsa.py
python extract_sonar_csv.py
python train_model.py
python descriptive_report.py
```

---

## 7. Critérios de aceitação (o código só está pronto se)

- [ ] Roda de ponta a ponta nos 3 comandos principais, sem erros, partindo de um SonarQube populado.
- [ ] `extract_sonar_csv.py` gera um CSV por repositório **e** o `dataset.csv` unificado, uma linha por `.java`.
- [ ] `train_model.py` deriva `has_security_risk`, treina RF + LogReg, e imprime Accuracy/Precision/Recall/F1/ROC-AUC/Matriz de Confusão + importância de features, salvando as figuras.
- [ ] Nenhuma métrica de segurança aparece em `FEATURE_METRICS` (sem vazamento).
- [ ] GroupKFold roda sem quebrar mesmo com fold de classe única (try/except).
- [ ] Suporta piloto (`--only` / `--repos`).
- [ ] Falha de um repositório não derruba o processamento dos demais.
- [ ] XGBoost/LightGBM são opcionais e não quebram o script se ausentes.
- [ ] `requirements.txt`, `.gitignore`, `README.md`, `DATA_DICTIONARY.md` e `TOOLS_VERSIONS.md` gerados e coerentes.
- [ ] Mensagens e comentários honestos sobre a limitação do SonarQube sem build (hotspots como sinal principal; fallback Semgrep documentado).
