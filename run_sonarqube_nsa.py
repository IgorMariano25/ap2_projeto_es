#!/usr/bin/env python3
"""
Orquestrador SonarQube — 10 repositórios Java da NSA
====================================================

Executa o fluxo pedido no projeto:
  1) roda o SonarQube no `ghidra` (use --only ghidra),
  2) você inspeciona o CSV / o relatório de "métricas preenchidas",
  3) roda nos outros 9 repositórios Java públicos da NSA.

IMPORTANTE: este script NÃO roda em sandbox sem rede/Docker. Execute na SUA
máquina (ou num servidor seu) com os pré-requisitos abaixo.

------------------------------------------------------------------------------
PRÉ-REQUISITOS (no seu ambiente)
------------------------------------------------------------------------------
1) Servidor SonarQube. Caminho mais simples, via Docker:
       docker run -d --name sonarqube -p 9000:9000 sonarqube:community
   Aguarde subir (~1-2 min), acesse http://localhost:9000 (admin / admin),
   troque a senha e gere um token em:
       My Account > Security > Generate Tokens
2) SonarScanner CLI no PATH (comando `sonar-scanner`):
       https://docs.sonarsource.com/sonarqube-server/latest/analyzing-source-code/scanners/sonarscanner/
3) git, e Python 3.9+ com `requests`:
       pip install requests

------------------------------------------------------------------------------
USO
------------------------------------------------------------------------------
   export SONAR_TOKEN=<seu_token>
   # opcional: export SONAR_HOST=http://localhost:9000
   python run_sonarqube_nsa.py --only ghidra      # PASSO 1: só o Ghidra
   python run_sonarqube_nsa.py                     # PASSO 3: todos os 10

------------------------------------------------------------------------------
AVISO CRÍTICO — Java SEM build (decisão do projeto: apenas clonar, não buildar)
------------------------------------------------------------------------------
O analisador Java do SonarQube usa bytecode (propriedade `sonar.java.binaries`).
Consequências do modo SEM build:
  * Métricas ESTRUTURAIS (tamanho, complexidade, duplicação, comentários) vêm
    confiáveis -> são as FEATURES do seu ML.
  * SEGURANÇA (`vulnerabilities`) e parte de BUGS vêm quase vazias -> por isso o
    rótulo `has_security_risk` do ML deve vir de Semgrep/CodeQL, não do SonarQube.
  * COBERTURA fica vazia (não há execução de testes).

ATENÇÃO: dependendo da versão, o SonarScanner pode EXIGIR `sonar.java.binaries`
e ABORTAR a análise Java se não encontrar classes compiladas. Se isso ocorrer,
você tem três opções (escolha consciente, e documente no artigo):
  (a) compilar apenas para gerar bytecode (contraria a decisão de não buildar);
  (b) apontar SONAR_JAVA_BINARIES para classes que você já tenha;
  (c) abandonar o SonarQube para Java e obter as métricas estruturais por
      ferramentas nativas de fonte (cloc + lizard + CK), mantendo o SonarQube
      fora — opção mais coerente com o pipeline "só clone".
Este script tenta o modo source-only por padrão (sonar.java.binaries=.).
"""

import argparse
import csv
import os
import subprocess
import sys
import time
from pathlib import Path

import requests

# ----------------------------------------------------------------------------
# Configuração
# ----------------------------------------------------------------------------
SONAR_HOST = os.environ.get("SONAR_HOST", "http://localhost:9000")
SONAR_TOKEN = os.environ.get("SONAR_TOKEN")  # obrigatório
SONAR_JAVA_BINARIES = os.environ.get("SONAR_JAVA_BINARIES", "")  # ver AVISO

ORG = "NationalSecurityAgency"

# Lista verificada de candidatos Java (confirme tamanho/linguagem antes de fixar;
# descarte os pequenos demais conforme os critérios do prompt do projeto).
REPOS = {
    "ghidra":                         f"https://github.com/{ORG}/ghidra.git",
    "emissary":                       f"https://github.com/{ORG}/emissary.git",
    "timely":                         f"https://github.com/{ORG}/timely.git",
    "qonduit":                        f"https://github.com/{ORG}/qonduit.git",
    "datawave":                       f"https://github.com/{ORG}/datawave.git",
    "fractalrabbit":                  f"https://github.com/{ORG}/fractalrabbit.git",
    "datawave-query-service":         f"https://github.com/{ORG}/datawave-query-service.git",
    "datawave-audit-service":         f"https://github.com/{ORG}/datawave-audit-service.git",
    "datawave-authorization-service": f"https://github.com/{ORG}/datawave-authorization-service.git",
    "ghidra-lisa":                    f"https://github.com/{ORG}/ghidra-lisa.git",
}

# Métricas consultadas. O script reporta, por repo, quais voltaram preenchidas
# (= "consistentes"). Agrupadas por confiabilidade no modo SEM build.
METRIC_KEYS = [
    # --- Tamanho/estrutura (confiáveis -> FEATURES) ---
    "ncloc", "lines", "statements", "files", "classes", "functions",
    "comment_lines", "comment_lines_density",
    # --- Complexidade (confiáveis -> FEATURES) ---
    "complexity", "cognitive_complexity",
    # --- Duplicação (confiáveis -> FEATURES) ---
    "duplicated_lines", "duplicated_lines_density", "duplicated_blocks", "duplicated_files",
    # --- Manutenibilidade/issues (parciais sem build) ---
    "code_smells", "sqale_index", "sqale_debt_ratio", "sqale_rating",
    "violations", "blocker_violations", "critical_violations",
    "major_violations", "minor_violations",
    # --- Confiabilidade (parciais sem bytecode) ---
    "bugs", "reliability_rating", "reliability_remediation_effort",
    # --- Segurança (NÃO confiável sem bytecode -> não usar como target) ---
    "vulnerabilities", "security_rating", "security_remediation_effort",
    "security_hotspots", "security_hotspots_reviewed", "security_review_rating",
    # --- Cobertura (vazia sem rodar testes) ---
    "coverage", "line_coverage", "branch_coverage", "uncovered_lines",
    "tests", "test_success_density",
]

# Métricas que NÃO devem ser features do ML (vazamento) — referência p/ a etapa seguinte.
LEAKAGE_METRICS = {
    "vulnerabilities", "security_rating", "security_remediation_effort",
    "security_hotspots", "security_hotspots_reviewed", "security_review_rating",
}

WORKDIR = Path("repos")
OUT_CSV = Path("sonar_metrics_nsa.csv")


# ----------------------------------------------------------------------------
# Funções
# ----------------------------------------------------------------------------
def run(cmd, cwd=None):
    print("    $", " ".join(cmd))
    subprocess.run(cmd, cwd=cwd, check=True)


def clone(name: str, url: str) -> Path:
    """Clone raso (rápido) — suficiente para o SonarQube.
    Obs.: PyDriller/CK (etapas separadas) precisam do histórico completo;
    para essas, clone SEM --depth."""
    dest = WORKDIR / name
    if dest.exists():
        print(f"[{name}] já clonado em {dest}")
        return dest
    print(f"[{name}] clonando…")
    run(["git", "clone", "--depth", "1", url, str(dest)])
    return dest


def scan(name: str, path: Path) -> str:
    """Roda o sonar-scanner. Retorna o ceTaskId (para aguardar o processamento)."""
    props = [
        "sonar-scanner",
        f"-Dsonar.host.url={SONAR_HOST}",
        f"-Dsonar.token={SONAR_TOKEN}",
        f"-Dsonar.projectKey=nsa_{name}",
        f"-Dsonar.projectName={name}",
        "-Dsonar.sources=.",
        "-Dsonar.inclusions=**/*.java",  # foca no Java (ignora ex.: C++ do decompilador do Ghidra)
    ]
    # Modo source-only por padrão; ver AVISO no cabeçalho.
    props.append(f"-Dsonar.java.binaries={SONAR_JAVA_BINARIES or '.'}")

    print(f"[{name}] analisando (sonar-scanner)…")
    run(props, cwd=path)

    # O scanner grava o ceTaskId em .scannerwork/report-task.txt
    task_file = path / ".scannerwork" / "report-task.txt"
    if task_file.exists():
        for line in task_file.read_text().splitlines():
            if line.startswith("ceTaskId="):
                return line.split("=", 1)[1]
    return ""


def wait_for_ce(ce_task_id: str, timeout: int = 600) -> None:
    """Aguarda o Compute Engine concluir; a Web API de measures só reflete
    resultados após o processamento terminar."""
    if not ce_task_id:
        time.sleep(8)
        return
    url = f"{SONAR_HOST}/api/ce/task"
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = requests.get(url, params={"id": ce_task_id}, auth=(SONAR_TOKEN, ""))
        r.raise_for_status()
        status = r.json().get("task", {}).get("status", "")
        if status in ("SUCCESS", "FAILED", "CANCELED"):
            print(f"    Compute Engine: {status}")
            return
        time.sleep(5)
    print("    AVISO: timeout aguardando o Compute Engine.")


def fetch_measures(name: str) -> dict:
    url = f"{SONAR_HOST}/api/measures/component"
    params = {"component": f"nsa_{name}", "metricKeys": ",".join(METRIC_KEYS)}
    r = requests.get(url, params=params, auth=(SONAR_TOKEN, ""))
    r.raise_for_status()
    measures = r.json().get("component", {}).get("measures", [])
    return {m["metric"]: m.get("value", "") for m in measures}


def main() -> None:
    if not SONAR_TOKEN:
        sys.exit("ERRO: defina SONAR_TOKEN (token gerado no SonarQube).")

    ap = argparse.ArgumentParser(description="Roda SonarQube nos repos Java da NSA.")
    ap.add_argument("--only", help="rodar apenas um repositório (ex.: ghidra)")
    args = ap.parse_args()

    if args.only and args.only not in REPOS:
        sys.exit(f"ERRO: '{args.only}' não está na lista. Opções: {', '.join(REPOS)}")

    WORKDIR.mkdir(exist_ok=True)
    targets = {args.only: REPOS[args.only]} if args.only else dict(REPOS)

    rows: dict[str, dict] = {}
    for name, url in targets.items():
        print(f"\n===== {name} =====")
        try:
            path = clone(name, url)
            ce_task_id = scan(name, path)
            wait_for_ce(ce_task_id)
            rows[name] = fetch_measures(name)
        except subprocess.CalledProcessError as e:
            print(f"[{name}] ERRO na análise (provável falta de bytecode): {e}")
            rows[name] = {}
        except requests.HTTPError as e:
            print(f"[{name}] ERRO na Web API: {e}")
            rows[name] = {}

    # --- CSV: uma linha por repo, colunas = métricas ---
    with OUT_CSV.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["repo"] + METRIC_KEYS)
        for name in targets:
            m = rows.get(name, {})
            w.writerow([name] + [m.get(k, "") for k in METRIC_KEYS])
    print(f"\nCSV salvo em: {OUT_CSV.resolve()}")

    # --- Relatório de consistência: quais métricas voltaram preenchidas ---
    print("\n=== Métricas preenchidas por repositório (= 'consistentes') ===")
    for name in targets:
        m = rows.get(name, {})
        filled = [k for k in METRIC_KEYS if m.get(k) not in (None, "")]
        print(f"\n{name}: {len(filled)}/{len(METRIC_KEYS)} métricas preenchidas")
        # destaque das que tipicamente ficam vazias sem build/testes
        for k in ("vulnerabilities", "security_hotspots", "bugs", "coverage"):
            val = m.get(k, "")
            flag = "OK" if val not in (None, "") else "VAZIO (esperado sem build/test)"
            print(f"    {k:22s} = {val!r:>10}  [{flag}]")

    print(
        "\nLembrete p/ a próxima etapa (ML): NÃO use como feature -> "
        + ", ".join(sorted(LEAKAGE_METRICS))
        + ".\nO target (has_security_risk) deve vir de Semgrep/CodeQL, não do SonarQube."
    )


if __name__ == "__main__":
    main()
