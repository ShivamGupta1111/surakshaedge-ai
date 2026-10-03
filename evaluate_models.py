"""Evaluate saved local models against CSV datasets."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

from src.config import PROJECT_ROOT
from src.security import load_trusted_joblib
from train_models import _url_row, train_network


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", default=str(PROJECT_ROOT / "data"))
    parser.add_argument("--model-dir", default=str(PROJECT_ROOT / "models"))
    args = parser.parse_args()
    data_dir = Path(args.data_dir)
    model_dir = Path(args.model_dir)
    meta_path = model_dir / "model_metadata.json"
    if meta_path.is_file():
        print(meta_path.read_text(encoding="utf-8"))

    sms_file = model_dir / "sms_model.joblib"
    if sms_file.is_file():
        model = load_trusted_joblib(sms_file, model_dir=model_dir)
        df = pd.read_csv(data_dir / "sms_spam.csv")
        pred = model.predict(df["text"].astype(str))
        print("SMS eval\n", classification_report(df["label"].astype(str), pred, zero_division=0))
        print(confusion_matrix(df["label"].astype(str), pred))

    url_file = model_dir / "url_model.joblib"
    if url_file.is_file():
        model = load_trusted_joblib(url_file, model_dir=model_dir)
        df = pd.read_csv(data_dir / "url_dataset.csv")
        rows, labels = [], []
        for url, label in zip(df["url"].astype(str), df["label"].astype(str)):
            vec = _url_row(url)
            if vec:
                rows.append(vec)
                labels.append(label)
        pred = model.predict(rows)
        print("URL eval\n", classification_report(labels, pred, zero_division=0))

    net_file = model_dir / "network_model.joblib"
    if net_file.is_file():
        print("Network model present:", net_file)
        _ = train_network  # reused helpers live in train_models


if __name__ == "__main__":
    main()
