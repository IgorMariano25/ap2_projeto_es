#!/usr/bin/env python3
"""
descriptive_report.py
=====================
Estatistica descritiva POR REPOSITORIO para a secao de Resultados do artigo.

A partir dos CSVs por arquivo (data/<repo>.csv) gerados por extract_sonar_csv.py,
agrega por repositorio:
  - ncloc total e numero de arquivos .java;
  - total de security_hotspots e vulnerabilities;
  - densidade por KLOC (achados por 1.000 linhas de codigo).

Saidas:
  - data/repo_summary.csv  (tabela para o artigo)
  - data/repo_summary.png  (grafico de barras comparativo)

Mapa ISO/IEC 25010 (Seguranca): a densidade de hotspots/vulnerabilities serve de
indicador empirico para as sub-caracteristicas Integridade e Confidencialidade.

USO:  python descriptive_report.py
"""
import sys
from pathlib import Path

import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

DATA = Path("data")
SECURITY_METRICS = ["security_hotspots", "vulnerabilities"]
# CSVs agregados/derivados que NAO sao "um repo": excluir do varredura.
SKIP = {"dataset.csv", "repo_summary.csv"}


def main():
    csvs = sorted(p for p in DATA.glob("*.csv") if p.name not in SKIP)
    if not csvs:
        sys.exit("Nenhum data/<repo>.csv encontrado. Rode extract_sonar_csv.py antes.")

    rows = []
    for csv_path in csvs:
        df = pd.read_csv(csv_path)
        # SonarQube omite a metrica quando o valor e 0 -> coercao + fillna(0).
        for c in ["ncloc"] + SECURITY_METRICS:
            df[c] = pd.to_numeric(df.get(c), errors="coerce").fillna(0)
        ncloc = float(df["ncloc"].sum())
        hotspots = float(df["security_hotspots"].sum())
        vulns = float(df["vulnerabilities"].sum())
        kloc = ncloc / 1000.0
        rows.append({
            "repo": csv_path.stem,
            "arquivos_java": len(df),
            "ncloc": int(ncloc),
            "security_hotspots": int(hotspots),
            "vulnerabilities": int(vulns),
            "hotspots_por_kloc": round(hotspots / kloc, 3) if kloc else 0.0,
            "vulns_por_kloc": round(vulns / kloc, 3) if kloc else 0.0,
        })

    summary = pd.DataFrame(rows).sort_values("ncloc", ascending=False)
    out_csv = DATA / "repo_summary.csv"
    summary.to_csv(out_csv, index=False)
    print(summary.to_string(index=False))
    print(f"\nTabela salva em {out_csv}")

    # --- grafico: densidade de sinais de seguranca por KLOC ---
    ax = summary.set_index("repo")[["hotspots_por_kloc", "vulns_por_kloc"]].plot.bar(
        figsize=(10, 5)
    )
    ax.set_ylabel("achados por KLOC")
    ax.set_xlabel("repositorio")
    ax.set_title("Densidade de sinais de seguranca por repositorio\n"
                 "(ISO/IEC 25010 - Seguranca: Integridade & Confidencialidade)")
    plt.tight_layout()
    out_png = DATA / "repo_summary.png"
    plt.savefig(out_png, dpi=150)
    plt.close()
    print(f"Grafico salvo em {out_png}")

    print("\nMapa ISO/IEC 25010 (Seguranca): hotspots e vulnerabilities -> "
          "indicadores de Integridade e Confidencialidade.")


if __name__ == "__main__":
    main()
