#!/usr/bin/env python3
"""
config.py
=========
Configuracao central do projeto (NSA Java - SonarQube - Machine Learning).

Fonte unica da verdade para: servidor SonarQube, lista de repositorios,
convencao de project_key e a separacao features/seguranca (SEM VAZAMENTO).

Os scripts do pipeline podem importar daqui para manter coerencia:
    from config import REPOS, FEATURE_METRICS, SECURITY_METRICS, project_key

Decisoes fixas respeitadas (ver PROMPT_GERACAO_DE_CODIGO.md, secao 1):
  - unidade de analise = arquivo .java;
  - alvo derivado de seguranca (hotspots/vulnerabilities), nunca usado como feature;
  - features = somente metricas estruturais/qualidade.
"""
import os

# ---------------------------------------------------------------------------
# Servidor SonarQube
# ---------------------------------------------------------------------------
SONAR_HOST = os.environ.get("SONAR_HOST", "http://localhost:9000")
SONAR_TOKEN = os.environ.get("SONAR_TOKEN")  # obrigatorio (gerado no SonarQube)

ORG = "NationalSecurityAgency"

# ---------------------------------------------------------------------------
# 10 repositorios Java escolhidos (verificados na API do GitHub em 2026-06-09;
# selecao "substancial p/ ML": prioriza codigo real, evita examples/*-utils/
# *-in-memory). Estrelas e tamanho aproximado em comentario.
# ---------------------------------------------------------------------------
REPOS = [
    "ghidra",                        # 69412 estrelas, ~399 MB
    "datawave",                      # 699, ~126 MB
    "timely",                        # 392, ~145 MB
    "datawave-ingest-services",      # 10,  ~84 MB
    "emissary",                      # 297, ~45 MB
    "fractalrabbit",                 # 173, ~9 MB
    "lemongrenade",                  # 320, ~1.3 MB
    "qonduit",                       # 67,  ~0.1 MB (pequeno)
    "datawave-dictionary-service",   # 25,  ~1.2 MB
    "datawave-query-metric-service", # 8,   ~1.3 MB
]

# URLs de clone derivadas da organizacao.
REPO_URLS = {name: f"https://github.com/{ORG}/{name}.git" for name in REPOS}


def project_key(repo: str) -> str:
    """Convencao fixa de chave de projeto no SonarQube."""
    return f"nsa_{repo}"


# ---------------------------------------------------------------------------
# Features estruturais/qualidade (decisao 5): ENTRAM no modelo.
# ---------------------------------------------------------------------------
FEATURE_METRICS = [
    "ncloc", "complexity", "cognitive_complexity", "code_smells",
    "duplicated_lines_density", "comment_lines_density",
    "functions", "classes", "violations",
]

# ---------------------------------------------------------------------------
# Sinais de seguranca (decisao 6): definem o ALVO, NUNCA sao features.
# ---------------------------------------------------------------------------
SECURITY_METRICS = ["security_hotspots", "vulnerabilities"]

ALL_METRICS = FEATURE_METRICS + SECURITY_METRICS

# Guarda anti-vazamento: nenhuma metrica de seguranca pode estar nas features.
assert not (set(FEATURE_METRICS) & set(SECURITY_METRICS)), (
    "VAZAMENTO: metrica de seguranca encontrada em FEATURE_METRICS"
)
