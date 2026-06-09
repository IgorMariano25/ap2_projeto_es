#!/usr/bin/env python3
"""
extract_sonar_csv.py
====================
Extrai metricas POR ARQUIVO do SonarQube e gera:
  - um CSV por repositorio:  data/<repo>.csv
  - um dataset unificado:    data/dataset.csv   (base para o ML)

PRE-REQUISITO: projetos ja analisados no SonarQube, com projectKey = nsa_<repo>
(rode antes o run_sonarqube_nsa.py, ou analise manualmente). Servidor em
SONAR_HOST e token em SONAR_TOKEN.

USO:
  export SONAR_TOKEN=<seu_token>
  # opcional: export SONAR_HOST=http://localhost:9000
  python extract_sonar_csv.py                          # todos os repos
  python extract_sonar_csv.py --repos ghidra emissary  # subconjunto

Usa /api/measures/component_tree (qualifiers=FIL) -> uma linha por arquivo .java.
As metricas de seguranca (security_hotspots, vulnerabilities) sao coletadas para
DEFINIR O ALVO no ML, nao como features.
"""
import argparse
import csv
import os
import sys
from pathlib import Path

import requests

SONAR_HOST = os.environ.get("SONAR_HOST", "http://localhost:9000")
SONAR_TOKEN = os.environ.get("SONAR_TOKEN")

# Lista padrao (ajuste conforme a verificacao de tamanho da Secao 4 do prompt).
REPOS = [
    "ghidra", "emissary", "timely", "qonduit", "datawave", "fractalrabbit",
    "datawave-query-service", "datawave-audit-service",
    "datawave-authorization-service", "ghidra-lisa",
]

# Features estruturais (confiaveis sem build) -> entram no modelo.
FEATURE_METRICS = [
    "ncloc", "complexity", "cognitive_complexity", "code_smells",
    "duplicated_lines_density", "comment_lines_density",
    "functions", "classes", "violations",
]
# Sinais de seguranca -> definem o ALVO (nao sao features).
SECURITY_METRICS = ["security_hotspots", "vulnerabilities"]
ALL_METRICS = FEATURE_METRICS + SECURITY_METRICS

OUT = Path("data")


def pull_files(project_key):
    """Retorna lista de dicts (um por arquivo .java) com as metricas."""
    rows, page = [], 1
    while True:
        r = requests.get(
            f"{SONAR_HOST}/api/measures/component_tree",
            params={
                "component": project_key,
                "qualifiers": "FIL",
                "metricKeys": ",".join(ALL_METRICS),
                "ps": 500,
                "p": page,
            },
            auth=(SONAR_TOKEN, ""),
            timeout=60,
        )
        r.raise_for_status()
        data = r.json()
        for comp in data.get("components", []):
            path = comp.get("path", "")
            if not path.endswith(".java"):
                continue
            measures = {m["metric"]: m.get("value", "") for m in comp.get("measures", [])}
            row = {"repo": project_key.replace("nsa_", ""), "file_path": path}
            for k in ALL_METRICS:
                row[k] = measures.get(k, "")
            rows.append(row)
        paging = data.get("paging", {})
        if page * paging.get("pageSize", 500) >= paging.get("total", 0):
            break
        page += 1
    return rows


def main():
    if not SONAR_TOKEN:
        sys.exit("ERRO: defina SONAR_TOKEN (token gerado no SonarQube).")
    ap = argparse.ArgumentParser()
    ap.add_argument("--repos", nargs="*", default=REPOS)
    args = ap.parse_args()

    OUT.mkdir(exist_ok=True)
    cols = ["repo", "file_path"] + ALL_METRICS
    all_rows = []

    for repo in args.repos:
        key = f"nsa_{repo}"
        print(f"[{repo}] puxando metricas por arquivo...")
        try:
            rows = pull_files(key)
        except requests.HTTPError as e:
            print(f"[{repo}] ERRO na API ({e}); pulando.")
            continue
        print(f"[{repo}] {len(rows)} arquivos .java")
        with (OUT / f"{repo}.csv").open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            w.writerows(rows)
        all_rows.extend(rows)

    with (OUT / "dataset.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(all_rows)

    print(f"\nOK: {len(all_rows)} arquivos no total -> {OUT / 'dataset.csv'}")
    print("Proximo passo: python train_model.py")


if __name__ == "__main__":
    main()
