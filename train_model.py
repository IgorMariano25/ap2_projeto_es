#!/usr/bin/env python3
"""
train_model.py
==============
Treina e avalia um modelo de ML para prever ARQUIVOS Java propensos a risco de
seguranca, a partir do dataset.csv gerado por extract_sonar_csv.py.

ALVO   : has_security_risk = 1 se (security_hotspots + vulnerabilities) > 0
FEATURES: metricas estruturais do SonarQube (NAO usa metricas de seguranca -> sem vazamento)
MODELOS : Random Forest (principal) + Regressao Logistica (baseline)
AVALIACAO: Accuracy, Precision, Recall, F1, ROC-AUC, Matriz de Confusao
          (RMSE/MAE NAO se aplicam: isto e classificacao, nao regressao)

USO:  python train_model.py            (le data/dataset.csv)
"""
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split, GroupKFold, cross_val_predict
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, ConfusionMatrixDisplay,
)

# XGBoost/LightGBM sao OPCIONAIS (decisao 7): se nao estiverem instalados, o
# script ignora sem erro, atras de import protegido.
try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except ImportError:
    HAS_XGB = False
try:
    from lightgbm import LGBMClassifier
    HAS_LGBM = True
except ImportError:
    HAS_LGBM = False

DATA = Path("data/dataset.csv")
FEATURES = [
    "ncloc", "complexity", "cognitive_complexity", "code_smells",
    "duplicated_lines_density", "comment_lines_density",
    "functions", "classes", "violations",
]
SECURITY = ["security_hotspots", "vulnerabilities"]


def load():
    df = pd.read_csv(DATA)
    # SonarQube costuma OMITIR a metrica quando o valor e 0 -> coercao + fillna(0)
    for c in FEATURES + SECURITY:
        df[c] = pd.to_numeric(df.get(c), errors="coerce").fillna(0)
    df["has_security_risk"] = ((df["security_hotspots"] + df["vulnerabilities"]) > 0).astype(int)
    return df


def evaluate(name, y_true, y_pred, y_proba):
    print(f"\n=== {name} ===")
    print(f"Accuracy : {accuracy_score(y_true, y_pred):.3f}")
    print(f"Precision: {precision_score(y_true, y_pred, zero_division=0):.3f}")
    print(f"Recall   : {recall_score(y_true, y_pred, zero_division=0):.3f}")
    print(f"F1-Score : {f1_score(y_true, y_pred, zero_division=0):.3f}")
    try:
        print(f"ROC-AUC  : {roc_auc_score(y_true, y_proba):.3f}")
    except ValueError:
        print("ROC-AUC  : n/d (classe unica no conjunto de teste)")
    print("Matriz de confusao [[TN FP][FN TP]]:")
    print(confusion_matrix(y_true, y_pred))


def main():
    if not DATA.exists():
        sys.exit(f"{DATA} nao encontrado. Rode extract_sonar_csv.py antes.")
    df = load()
    pos = int(df["has_security_risk"].sum())
    print(f"Arquivos: {len(df)} | positivos (risco): {pos} "
          f"({100 * df['has_security_risk'].mean():.1f}%)")
    if df["has_security_risk"].nunique() < 2:
        sys.exit("Apenas uma classe presente (provavel: hotspots/vulnerabilities vazios "
                 "no modo sem build).\nRode 'python semgrep_target.py' para gerar o alvo "
                 "alternativo (semgrep_findings) e use-o como rotulo antes de treinar.")

    X, y, groups = df[FEATURES], df["has_security_risk"], df["repo"]

    # --- divisao treino/teste estratificada (simples e robusta) ---
    Xtr, Xte, ytr, yte = train_test_split(
        X, y, test_size=0.25, stratify=y, random_state=42
    )

    # Modelo principal: Random Forest (tabular, desbalanceado, da importancia de features)
    rf = RandomForestClassifier(
        n_estimators=300, class_weight="balanced",
        min_samples_leaf=2, random_state=42, n_jobs=-1,
    )
    rf.fit(Xtr, ytr)
    evaluate("Random Forest (principal)", yte, rf.predict(Xte), rf.predict_proba(Xte)[:, 1])

    # Baseline: Regressao Logistica (precisa de padronizacao)
    lr = make_pipeline(
        StandardScaler(),
        LogisticRegression(class_weight="balanced", max_iter=1000),
    )
    lr.fit(Xtr, ytr)
    evaluate("Regressao Logistica (baseline)", yte, lr.predict(Xte), lr.predict_proba(Xte)[:, 1])

    # --- modelos opcionais: so rodam se instalados (decisao 7); nunca quebram ---
    extra = {}
    if HAS_XGB:
        pos = max(int(ytr.sum()), 1)
        scale_pos_weight = (len(ytr) - pos) / pos  # trata desbalanceamento no XGBoost
        extra["XGBoost (opcional)"] = XGBClassifier(
            n_estimators=300, random_state=42, n_jobs=-1,
            eval_metric="logloss", scale_pos_weight=scale_pos_weight,
        )
    if HAS_LGBM:
        extra["LightGBM (opcional)"] = LGBMClassifier(
            n_estimators=300, random_state=42, n_jobs=-1,
            class_weight="balanced", verbose=-1,
        )
    for name, model in extra.items():
        model.fit(Xtr, ytr)
        evaluate(name, yte, model.predict(Xte), model.predict_proba(Xte)[:, 1])
    if not extra:
        print("\n[XGBoost/LightGBM nao instalados: etapa opcional ignorada (ok).]")

    # --- figura: matriz de confusao do RF ---
    ConfusionMatrixDisplay(
        confusion_matrix(yte, rf.predict(Xte)),
        display_labels=["sem risco", "com risco"],
    ).plot(cmap="Blues")
    plt.title("Random Forest - Matriz de Confusao")
    plt.tight_layout()
    plt.savefig("data/confusion_matrix_rf.png", dpi=150)
    plt.close()

    # --- importancia das features (liga com a discussao ISO 25010) ---
    imp = pd.Series(rf.feature_importances_, index=FEATURES).sort_values(ascending=False)
    print("\n=== Importancia das features (Random Forest) ===")
    print(imp.to_string())
    imp.sort_values().plot.barh()
    plt.title("Importancia das features (Random Forest)")
    plt.tight_layout()
    plt.savefig("data/feature_importance_rf.png", dpi=150)
    plt.close()

    # --- validacao cruzada por repositorio (mais rigorosa; nao quebra o script) ---
    try:
        n = groups.nunique()
        if n >= 2:
            gkf = GroupKFold(n_splits=min(5, n))
            proba = cross_val_predict(
                rf, X, y, groups=groups, cv=gkf, method="predict_proba", n_jobs=-1
            )[:, 1]
            evaluate("Random Forest - GroupKFold por repositorio",
                     y, (proba >= 0.5).astype(int), proba)
    except Exception as e:
        print(f"\n[GroupKFold pulado: {e}]")

    print("\nFiguras salvas em data/. RMSE/MAE NAO se aplicam (classificacao, nao regressao).")


if __name__ == "__main__":
    main()
