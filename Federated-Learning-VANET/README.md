# Federated-Learning-VANET

This folder contains the real ML baseline for VANET attack classification using the VeReMi-style CSV data in this directory. The ns-3 simulator integrates a lightweight model-vector FL protocol for communication, PBC/ECC security, latency, and power measurement; this Python baseline keeps the actual TensorFlow training experiment reproducible outside ns-3.

## Dataset

`Main_data_shuffled.csv` uses these columns:

```text
velocity_x,velocity_y,constant_offset_check,total_displacement,attacktype
```

The first four columns are features and `attacktype` is the class label.

## Run The Baseline

```bash
cd /home/sahib/vanet_ns3_security_research/Federated-Learning-VANET
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python train_fl_baseline.py --rounds 5 --clients 10
```

The default output is:

```text
results/fl_baseline_metrics.csv
```

## Relationship To ns-3

The Python code trains the actual MLP model and reports accuracy, precision, recall, and loss. The ns-3 code simulates the FL network protocol: vehicles upload local model vectors, RSUs perform edge aggregation, the BS performs global aggregation, and PBC/ECC security plus communication power are measured.
