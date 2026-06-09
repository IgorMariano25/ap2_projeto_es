#!/usr/bin/env python3
"""
semgrep_target.py
=================
FALLBACK DO ALVO. No modo "so clone" (sem build/bytecode), os security_hotspots
e vulnerabilities do SonarQube costumam vir vazios. Quando isso acontece, o alvo
do ML pode ser derivado de uma analise SAST que NAO precisa de build: o Semgrep.

Para cada repo clonado em repos/<repo>, roda:
    semgrep --config p/java --json --quiet repos/<repo>
conta os achados por arquivo .java e mescla a coluna `semgrep_findings` ao
data/dataset.csv (chave de juncao: repo + file_path).

No train_model.py, use `semgrep_findings > 0` como ALVO alternativo a
`has_security_risk` quando os hotspots do SonarQube vierem vazios.

PRE-REQUISITOS: semgrep instalado (pip install semgrep) e repos ja clonados
(rode antes run_sonarqube_nsa.py, que faz o clone) + extract_sonar_csv.py
(que gera o dataset.csv a ser enriquecido).

USO:
  python semgrep_target.py                          # todos os repos em repos/
  python semgrep_target.py --repos ghidra emissary  # subconjunto
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

import pandas as pd

REPOS_DIR = Path("repos")
DATASET = Path("data/dataset.csv")


def run_semgrep(repo_path: Path) -> dict:
    """Retorna {caminho_relativo_ao_repo: numero_de_achados} para um repo."""
    cmd = ["semgrep", "--config", "p/java", "--json", "--quiet", str(repo_path)]
    print(f"    $ {' '.join(cmd)}")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if not proc.stdout.strip():
        print(f"    [aviso] semgrep nao retornou JSON. stderr: {proc.stderr[:200]}")
        return {}
    data = json.loads(proc.stdout)
    counts: dict[str, int] = {}
    for res in data.get("results", []):
        p = Path(res.get("path", ""))
        try:
            rel = p.relative_to(repo_path)
        except ValueError:
            rel = p  # ja relativo / fora do repo
        key = rel.as_posix()
        counts[key] = counts.get(key, 0) + 1
    return counts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repos", nargs="*",
                    help="subconjunto; padrao = todas as subpastas de repos/")
    args = ap.parse_args()

    if not REPOS_DIR.exists():
        sys.exit(f"{REPOS_DIR} nao existe. Clone os repos (run_sonarqube_nsa.py) antes.")
    repos = args.repos or [p.name for p in REPOS_DIR.iterdir() if p.is_dir()]
    if not repos:
        sys.exit("Nenhum repositorio clonado em repos/.")

    findings: dict[tuple, int] = {}  # (repo, file_path) -> contagem
    for repo in repos:
        repo_path = REPOS_DIR / repo
        if not repo_path.exists():
            print(f"[{repo}] nao encontrado em {repo_path}; pulando.")
            continue
        print(f"[{repo}] rodando semgrep...")
        try:
            counts = run_semgrep(repo_path)
        except (subprocess.SubprocessError, json.JSONDecodeError) as e:
            print(f"[{repo}] ERRO no semgrep ({e}); pulando.")
            continue
        for path, n in counts.items():
            findings[(repo, path)] = n
        print(f"[{repo}] {sum(counts.values())} achados em {len(counts)} arquivos")

    if not DATASET.exists():
        sys.exit(f"{DATASET} nao encontrado. Rode extract_sonar_csv.py antes de mesclar.")
    df = pd.read_csv(DATASET)
    df["semgrep_findings"] = [
        findings.get((r, fp), 0) for r, fp in zip(df["repo"], df["file_path"])
    ]
    df.to_csv(DATASET, index=False)

    pos = int((df["semgrep_findings"] > 0).sum())
    pct = 100 * pos / len(df) if len(df) else 0.0
    print(f"\nOK: coluna 'semgrep_findings' mesclada em {DATASET}.")
    print(f"Arquivos com >=1 achado Semgrep: {pos} ({pct:.1f}%).")
    print("Observacao: a juncao usa caminhos relativos ao repo; se SonarQube e "
          "Semgrep divergirem na raiz, confira alguns file_path manualmente.")


if __name__ == "__main__":
    main()
