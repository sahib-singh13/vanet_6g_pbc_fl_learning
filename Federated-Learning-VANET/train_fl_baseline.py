#!/usr/bin/env python3
"""Reproducible FL baseline for the VANET attack-classification dataset.

This script keeps the real ML experiment outside ns-3.  The ns-3 integration
simulates communication/security/power, while this baseline trains the MLP from
main.ipynb and exports round-level FL metrics for accuracy comparisons.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelBinarizer, StandardScaler

try:
    import tensorflow as tf
    from tensorflow.keras import Sequential
    from tensorflow.keras.layers import Dense
    from tensorflow.keras.optimizers import SGD
except ImportError as exc:  # pragma: no cover - clear runtime error for users
    raise SystemExit(
        "TensorFlow is required. Run: pip install -r requirements.txt"
    ) from exc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train VANET FL and centralized SGD baselines.")
    parser.add_argument("--data", default="Main_data_shuffled.csv", help="Input CSV path")
    parser.add_argument("--rounds", type=int, default=50, help="Federated communication rounds")
    parser.add_argument("--clients", type=int, default=10, help="Number of FL clients")
    parser.add_argument("--epochs", type=int, default=1, help="Local epochs per FL round")
    parser.add_argument("--batch-size", type=int, default=32, help="Training batch size")
    parser.add_argument("--lr", type=float, default=0.01, help="SGD learning rate")
    parser.add_argument("--momentum", type=float, default=0.9, help="SGD momentum")
    parser.add_argument("--test-size", type=float, default=0.1, help="Test split fraction")
    parser.add_argument("--seed", type=int, default=105, help="Random seed")
    parser.add_argument("--out", default="results/fl_baseline_metrics.csv", help="Metrics CSV output")
    return parser.parse_args()


def build_model(input_dim: int, classes: int, lr: float, momentum: float) -> Sequential:
    model = Sequential(
        [
            Dense(200, activation="relu", input_shape=(input_dim,)),
            Dense(200, activation="relu"),
            Dense(classes, activation="softmax"),
        ]
    )
    model.compile(
        loss="categorical_crossentropy",
        optimizer=SGD(learning_rate=lr, momentum=momentum),
        metrics=["accuracy"],
    )
    return model


def split_clients(x: np.ndarray, y: np.ndarray, clients: int, seed: int) -> List[Tuple[np.ndarray, np.ndarray]]:
    rng = np.random.default_rng(seed)
    indices = np.arange(len(x))
    rng.shuffle(indices)
    shards = np.array_split(indices, clients)
    return [(x[shard], y[shard]) for shard in shards if len(shard) > 0]


def scale_weights(weights: Sequence[np.ndarray], scale: float) -> List[np.ndarray]:
    return [layer * scale for layer in weights]


def sum_weights(weight_sets: Iterable[Sequence[np.ndarray]]) -> List[np.ndarray]:
    weight_sets = list(weight_sets)
    return [np.sum(layer_group, axis=0) for layer_group in zip(*weight_sets)]


def evaluate(model: Sequential, x_test: np.ndarray, y_test: np.ndarray) -> Tuple[float, float, float, float]:
    loss, _ = model.evaluate(x_test, y_test, verbose=0)
    pred = np.argmax(model.predict(x_test, verbose=0), axis=1)
    truth = np.argmax(y_test, axis=1)
    return (
        float(loss),
        float(accuracy_score(truth, pred)),
        float(precision_score(truth, pred, average="weighted", zero_division=0)),
        float(recall_score(truth, pred, average="weighted", zero_division=0)),
    )


def main() -> None:
    args = parse_args()
    np.random.seed(args.seed)
    tf.random.set_seed(args.seed)

    data_path = Path(args.data)
    df = pd.read_csv(data_path)
    x = df.iloc[:, :4].to_numpy(dtype=np.float32)
    y_raw = df.iloc[:, 4].to_numpy()

    x = StandardScaler().fit_transform(x).astype(np.float32)
    y = LabelBinarizer().fit_transform(y_raw).astype(np.float32)
    if y.ndim == 1:
      y = np.expand_dims(y, axis=1)

    x_train, x_test, y_train, y_test = train_test_split(
        x, y, test_size=args.test_size, random_state=args.seed, stratify=y_raw
    )
    clients = split_clients(x_train, y_train, args.clients, args.seed)
    total_samples = sum(len(cx) for cx, _ in clients)

    global_model = build_model(x_train.shape[1], y_train.shape[1], args.lr, args.momentum)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with out_path.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["round", "loss", "accuracy", "precision", "recall", "clients", "samples"])
        for round_id in range(args.rounds):
            global_weights = global_model.get_weights()
            scaled = []
            for client_x, client_y in clients:
                local_model = build_model(x_train.shape[1], y_train.shape[1], args.lr, args.momentum)
                local_model.set_weights(global_weights)
                local_model.fit(client_x, client_y, epochs=args.epochs, batch_size=args.batch_size, verbose=0)
                scaled.append(scale_weights(local_model.get_weights(), len(client_x) / total_samples))
                tf.keras.backend.clear_session()
            global_model.set_weights(sum_weights(scaled))
            loss, acc, precision, recall = evaluate(global_model, x_test, y_test)
            writer.writerow([round_id, loss, acc, precision, recall, len(clients), total_samples])
            print(f"round={round_id} loss={loss:.4f} acc={acc:.4f} precision={precision:.4f} recall={recall:.4f}")


if __name__ == "__main__":
    main()
