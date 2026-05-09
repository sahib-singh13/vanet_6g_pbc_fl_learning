# VANET ns-3 Security Research (Wi‑Fi, LTE, NR/5G‑LENA)

This repo contains an ns‑3 VANET security simulation with Wi‑Fi (802.11p), LTE (LENA), and NR (5G‑LENA) scenarios plus per‑second delay logging for V2V, V2I, and security backhaul (KGC/TA).

**Overview**
- Mobility: SUMO ns‑2 trace (`mobility_trace.tcl`)
- Core roles: Vehicle, RSU, BS (core), TA (trusted authority), KGC (key generation center)
- Security: ECDSA registration + key/cert exchange
- Outputs: per‑second CSV metrics for V2V, V2I, registration, KGC RTT, TA RTT

**Layout**
- ns‑3 tree: `simulation_workspace/ns-allinone-3.44/ns-3.44`
- Security module: `simulation_workspace/ns-allinone-3.44/ns-3.44/src/vanet-security`
- Scenarios:
  - Wi‑Fi 802.11p: `simulation_workspace/ns-allinone-3.44/ns-3.44/scratch/vanet-security-sumo.cc`
  - LTE (LENA): `simulation_workspace/ns-allinone-3.44/ns-3.44/scratch/vanet-security-lte.cc`
  - NR (5G‑LENA, “6G‑proxy”): `simulation_workspace/ns-allinone-3.44/ns-3.44/scratch/vanet-security-nr.cc`
- Trace inputs: `simulation_workspace/integration_test/mobility_trace.tcl` (default)

**Prerequisites (typical Ubuntu/Debian)**
1. `sudo apt update`
2. `sudo apt install -y build-essential cmake ninja-build python3 pkg-config libsqlite3-dev libgsl-dev libssl-dev`

Optional plotting:
1. `sudo apt install -y python3-venv`
2. `python3 -m venv .venv`
3. `. .venv/bin/activate`
4. `python -m pip install matplotlib`

**Build**
1. `cd /home/sahib/vanet_ns3_security_research/simulation_workspace/ns-allinone-3.44/ns-3.44`
2. `./ns3 configure --enable-examples`
3. `./ns3 build -j $(nproc)`

**Run Scenarios**
All commands below are run from:
`/home/sahib/vanet_ns3_security_research/simulation_workspace/ns-allinone-3.44/ns-3.44`

Wi‑Fi (802.11p baseline):
```
./ns3 run scratch/vanet-security-sumo -- \
  --trace=../../integration_test/mobility_trace.tcl \
  --simTime=150 \
  --msgInterval=1.0 \
  --verifySignatures=true \
  --commRange=300 \
  --rsuCount=2 \
  --outCsv=vanet-security-metrics-wifi.csv
```

LTE (LENA baseline):
```
./ns3 run scratch/vanet-security-lte -- \
  --trace=../../integration_test/mobility_trace.tcl \
  --simTime=150 \
  --msgInterval=1.0 \
  --verifySignatures=true \
  --rsuCount=2 \
  --securityMode=pbc \
  --outCsv=vanet-security-metrics-lte.csv
```

NR (5G‑LENA “6G‑proxy”):
```
./ns3 run scratch/vanet-security-nr -- \
  --trace=../../integration_test/mobility_trace.tcl \
  --simTime=150 \
  --msgInterval=1.0 \
  --verifySignatures=true \
  --rsuCount=2 \
  --nrFreq=60e9 \
  --nrBw=400e6 \
  --nrMu=3 \
  --v2vMode=relay \
  --securityMode=pbc \
  --outCsv=vanet-security-metrics-nr.csv
```

Short smoke test (7 seconds):
```
./ns3 run scratch/vanet-security-lte -- \
  --trace=../../integration_test/mobility_trace.tcl \
  --simTime=7 \
  --msgInterval=1.0 \
  --verifySignatures=true \
  --rsuCount=2 \
  --securityMode=pbc \
  --outCsv=vanet-security-metrics-lte.csv
```

**Security Comparison Matrix (Manual Separate Runs)**
Run from:
`/home/sahib/vanet_ns3_security_research/simulation_workspace/ns-allinone-3.44/ns-3.44`

Create output folder once:
```
mkdir -p results
```

Set verbose security logging once (recommended for professor demo):
```
export NS_LOG="KgcApp=level_info:TaApp=level_info:VehicleApp=level_info:BsRelayApp=level_info"
export ASAN_OPTIONS=detect_leaks=0
```

1. LTE PBC (`lte_pbc`)
```
./ns3 run "scratch/vanet-security-lte --trace=mobility_trace.tcl --simTime=7 --msgInterval=1.0 --verifySignatures=true --rsuCount=2 --securityMode=pbc --progressLog=1 --outCsv=results/lte_pbc.csv" 2>&1 | tee /tmp/lte_pbc.log
```

2. LTE ECC baseline (`lte_ecc`)
```
./ns3 run "scratch/vanet-security-lte --trace=mobility_trace.tcl --simTime=7 --msgInterval=1.0 --verifySignatures=true --rsuCount=2 --securityMode=ecc --progressLog=1 --outCsv=results/lte_ecc.csv" 2>&1 | tee /tmp/lte_ecc.log
```

3. NR max PBC (`nr_max_pbc`)
```
./ns3 run "scratch/vanet-security-nr --trace=mobility_trace.tcl --simTime=7 --msgInterval=1.0 --verifySignatures=true --rsuCount=2 --nrFreq=60e9 --nrBw=400e6 --nrMu=3 --v2vMode=relay --securityMode=pbc --progressLog=1 --outCsv=results/nr_max_pbc.csv" 2>&1 | tee /tmp/nr_max_pbc.log
```

4. NR max ECC baseline (`nr_max_ecc`)
```
./ns3 run "scratch/vanet-security-nr --trace=mobility_trace.tcl --simTime=7 --msgInterval=1.0 --verifySignatures=true --rsuCount=2 --nrFreq=60e9 --nrBw=400e6 --nrMu=3 --v2vMode=relay --securityMode=ecc --progressLog=1 --outCsv=results/nr_max_ecc.csv" 2>&1 | tee /tmp/nr_max_ecc.log
```

5. NR min PBC (`nr_min_pbc`)
```
./ns3 run "scratch/vanet-security-nr --trace=mobility_trace.tcl --simTime=7 --msgInterval=1.0 --verifySignatures=true --rsuCount=2 --nrFreq=3.5e9 --nrBw=20e6 --nrMu=0 --v2vMode=relay --securityMode=pbc --progressLog=1 --outCsv=results/nr_min_pbc.csv" 2>&1 | tee /tmp/nr_min_pbc.log
```

6. NR min ECC baseline (`nr_min_ecc`)
```
./ns3 run "scratch/vanet-security-nr --trace=mobility_trace.tcl --simTime=7 --msgInterval=1.0 --verifySignatures=true --rsuCount=2 --nrFreq=3.5e9 --nrBw=20e6 --nrMu=0 --v2vMode=relay --securityMode=ecc --progressLog=1 --outCsv=results/nr_min_ecc.csv" 2>&1 | tee /tmp/nr_min_ecc.log
```

Per-case latency logs (full time-series from CSV):

1. LTE PBC latency log
```
awk -F, 'NR==1{print "time,avg_v2v_delay_ms,avg_v2i_uplink_ms,avg_v2i_downlink_ms,avg_v2i_rtt_ms,avg_reg_delay_ms,avg_kgc_rtt_ms,avg_ta_rtt_ms";next}{print $1","$5","$6","$7","$8","$9","$10","$11}' results/lte_pbc.csv | tee /tmp/lte_pbc_latency.log
```

2. LTE ECC latency log
```
awk -F, 'NR==1{print "time,avg_v2v_delay_ms,avg_v2i_uplink_ms,avg_v2i_downlink_ms,avg_v2i_rtt_ms,avg_reg_delay_ms,avg_kgc_rtt_ms,avg_ta_rtt_ms";next}{print $1","$5","$6","$7","$8","$9","$10","$11}' results/lte_ecc.csv | tee /tmp/lte_ecc_latency.log
```

3. NR max PBC latency log
```
awk -F, 'NR==1{print "time,avg_v2v_delay_ms,avg_v2i_uplink_ms,avg_v2i_downlink_ms,avg_v2i_rtt_ms,avg_reg_delay_ms,avg_kgc_rtt_ms,avg_ta_rtt_ms";next}{print $1","$5","$6","$7","$8","$9","$10","$11}' results/nr_max_pbc.csv | tee /tmp/nr_max_pbc_latency.log
```

4. NR max ECC latency log
```
awk -F, 'NR==1{print "time,avg_v2v_delay_ms,avg_v2i_uplink_ms,avg_v2i_downlink_ms,avg_v2i_rtt_ms,avg_reg_delay_ms,avg_kgc_rtt_ms,avg_ta_rtt_ms";next}{print $1","$5","$6","$7","$8","$9","$10","$11}' results/nr_max_ecc.csv | tee /tmp/nr_max_ecc_latency.log
```

5. NR min PBC latency log
```
awk -F, 'NR==1{print "time,avg_v2v_delay_ms,avg_v2i_uplink_ms,avg_v2i_downlink_ms,avg_v2i_rtt_ms,avg_reg_delay_ms,avg_kgc_rtt_ms,avg_ta_rtt_ms";next}{print $1","$5","$6","$7","$8","$9","$10","$11}' results/nr_min_pbc.csv | tee /tmp/nr_min_pbc_latency.log
```

6. NR min ECC latency log
```
awk -F, 'NR==1{print "time,avg_v2v_delay_ms,avg_v2i_uplink_ms,avg_v2i_downlink_ms,avg_v2i_rtt_ms,avg_reg_delay_ms,avg_kgc_rtt_ms,avg_ta_rtt_ms";next}{print $1","$5","$6","$7","$8","$9","$10","$11}' results/nr_min_ecc.csv | tee /tmp/nr_min_ecc_latency.log
```

Quick matrix summary from CSV final rows:
```
printf "case,infected_ratio,verification_failures,avg_v2v_delay_ms,avg_v2i_rtt_ms,avg_reg_delay_ms,avg_kgc_rtt_ms,avg_ta_rtt_ms\n"
for c in lte_pbc lte_ecc nr_max_pbc nr_max_ecc nr_min_pbc nr_min_ecc; do
  awk -F, -v case="$c" 'NR>1{last=$0} END{split(last,a,","); printf "%s,%s,%s,%s,%s,%s,%s,%s\n", case,a[2],a[4],a[5],a[8],a[9],a[10],a[11]}' "results/${c}.csv"
done
```

**PBC Power And Latency Runs**
Use this section when comparing the current PBC security model across LTE,
6G minimum, and 6G maximum profiles. The recommended workflow is to run
one case, inspect its output, then run the next case.

Run from the repository root:
```
cd /home/sahib/vanet_ns3_security_research
```

Build and run only LTE PBC:
```
./scripts/run_pbc_power_tests.sh lte
```

Build and run only 6G minimum PBC:
```
./scripts/run_pbc_power_tests.sh nr-min
```

Build and run only 6G maximum PBC:
```
./scripts/run_pbc_power_tests.sh nr-max
```

Quick smoke-test version for any one case:
```
SIM_TIME=20 ./scripts/run_pbc_power_tests.sh lte
SIM_TIME=20 ./scripts/run_pbc_power_tests.sh nr-min
SIM_TIME=20 ./scripts/run_pbc_power_tests.sh nr-max
```

Run all three only if you explicitly want the full batch:
```
./scripts/run_pbc_power_tests.sh all
```

The script prints the final periodic CSV row and important PBC stage rows after
each selected run. It also creates readable structured outputs for each case.

LTE output files:
```
simulation_workspace/ns-allinone-3.44/ns-3.44/results/power_pbc/lte_pbc_power.csv
simulation_workspace/ns-allinone-3.44/ns-3.44/results/power_pbc/lte_pbc_stages.csv
simulation_workspace/ns-allinone-3.44/ns-3.44/results/power_pbc/lte_pbc_structured.csv
simulation_workspace/ns-allinone-3.44/ns-3.44/results/power_pbc/lte_pbc_report.md
```

6G minimum output files:
```
simulation_workspace/ns-allinone-3.44/ns-3.44/results/power_pbc/nr_min_pbc_power.csv
simulation_workspace/ns-allinone-3.44/ns-3.44/results/power_pbc/nr_min_pbc_stages.csv
simulation_workspace/ns-allinone-3.44/ns-3.44/results/power_pbc/nr_min_pbc_structured.csv
simulation_workspace/ns-allinone-3.44/ns-3.44/results/power_pbc/nr_min_pbc_report.md
```

6G maximum output files:
```
simulation_workspace/ns-allinone-3.44/ns-3.44/results/power_pbc/nr_max_pbc_power.csv
simulation_workspace/ns-allinone-3.44/ns-3.44/results/power_pbc/nr_max_pbc_stages.csv
simulation_workspace/ns-allinone-3.44/ns-3.44/results/power_pbc/nr_max_pbc_structured.csv
simulation_workspace/ns-allinone-3.44/ns-3.44/results/power_pbc/nr_max_pbc_report.md
```

Final comparison summary, generated from whichever case files already exist:
```
simulation_workspace/ns-allinone-3.44/ns-3.44/results/power_pbc/final_pbc_power_summary.csv
```

Open/check the latest LTE outputs after running `lte`:
```
cat simulation_workspace/ns-allinone-3.44/ns-3.44/results/power_pbc/lte_pbc_report.md
awk 'NR==1{print "HEADER:", $0} {last=$0} END{print "LAST:", last}' simulation_workspace/ns-allinone-3.44/ns-3.44/results/power_pbc/lte_pbc_power.csv
```

Open/check the latest 6G minimum outputs after running `nr-min`:
```
cat simulation_workspace/ns-allinone-3.44/ns-3.44/results/power_pbc/nr_min_pbc_report.md
awk 'NR==1{print "HEADER:", $0} {last=$0} END{print "LAST:", last}' simulation_workspace/ns-allinone-3.44/ns-3.44/results/power_pbc/nr_min_pbc_power.csv
```

Open/check the latest 6G maximum outputs after running `nr-max`:
```
cat simulation_workspace/ns-allinone-3.44/ns-3.44/results/power_pbc/nr_max_pbc_report.md
awk 'NR==1{print "HEADER:", $0} {last=$0} END{print "LAST:", last}' simulation_workspace/ns-allinone-3.44/ns-3.44/results/power_pbc/nr_max_pbc_power.csv
```

Manual one-by-one ns-3 commands are still available if you do not want to use
the helper script. Run from the ns-3 directory:
```
cd /home/sahib/vanet_ns3_security_research/simulation_workspace/ns-allinone-3.44/ns-3.44
mkdir -p results/power_pbc
./ns3 build vanet-security-lte vanet-security-nr
```

Manual LTE PBC:
```
LSAN_OPTIONS=detect_leaks=0 ./ns3 run "vanet-security-lte --securityMode=pbc --networkLabel=5g_lte --effectiveRateMbps=100 --simTime=150 --progressLog=true --outCsv=results/power_pbc/lte_pbc_power.csv --stageCsv=results/power_pbc/lte_pbc_stages.csv"
```

Manual 6G minimum PBC:
```
LSAN_OPTIONS=detect_leaks=0 ./ns3 run "vanet-security-nr --securityMode=pbc --radioProfile=6g_nr_min --simTime=150 --progressLog=true --outCsv=results/power_pbc/nr_min_pbc_power.csv --stageCsv=results/power_pbc/nr_min_pbc_stages.csv"
```

Manual 6G maximum PBC:
```
LSAN_OPTIONS=detect_leaks=0 ./ns3 run "vanet-security-nr --securityMode=pbc --radioProfile=6g_nr_max --simTime=150 --progressLog=true --outCsv=results/power_pbc/nr_max_pbc_power.csv --stageCsv=results/power_pbc/nr_max_pbc_stages.csv"
```

Create a readable report manually for an existing raw CSV pair:
```
cd /home/sahib/vanet_ns3_security_research
python3 scripts/format_pbc_power_results.py \
  --stage-csv simulation_workspace/ns-allinone-3.44/ns-3.44/results/power_pbc/lte_pbc_stages.csv \
  --power-csv simulation_workspace/ns-allinone-3.44/ns-3.44/results/power_pbc/lte_pbc_power.csv \
  --out-prefix simulation_workspace/ns-allinone-3.44/ns-3.44/results/power_pbc/lte_pbc
```

**PBC vs ECC Power/Latency Increment**
Use this section to compare PBC security against the non-PBC ECC baseline.
Here, "without PBC" means `--securityMode=ecc`, so ECDSA signing and
verification are still active, but pairing-based pseudonym/signature operations
are disabled.

Run from the repository root:
```
cd /home/sahib/vanet_ns3_security_research
```

Run LTE with PBC, then inspect:
```
./scripts/run_security_power_compare.sh lte-pbc
cat simulation_workspace/ns-allinone-3.44/ns-3.44/results/security_compare/lte_pbc_report.md
```

Run LTE without PBC/ECC baseline, then inspect the comparison:
```
./scripts/run_security_power_compare.sh lte-ecc
cat simulation_workspace/ns-allinone-3.44/ns-3.44/results/security_compare/lte_ecc_report.md
cat simulation_workspace/ns-allinone-3.44/ns-3.44/results/security_compare/lte_comparison.md
```

Run 6G minimum with PBC, then inspect:
```
./scripts/run_security_power_compare.sh nr-min-pbc
cat simulation_workspace/ns-allinone-3.44/ns-3.44/results/security_compare/nr_min_pbc_report.md
```

Run 6G minimum without PBC/ECC baseline, then inspect the comparison:
```
./scripts/run_security_power_compare.sh nr-min-ecc
cat simulation_workspace/ns-allinone-3.44/ns-3.44/results/security_compare/nr_min_ecc_report.md
cat simulation_workspace/ns-allinone-3.44/ns-3.44/results/security_compare/nr_min_comparison.md
```

Shortcut commands if you want each pair in one run:
```
./scripts/run_security_power_compare.sh lte
./scripts/run_security_power_compare.sh nr-min
```

Quick smoke-test versions:
```
SIM_TIME=20 ./scripts/run_security_power_compare.sh lte
SIM_TIME=20 ./scripts/run_security_power_compare.sh nr-min
```

The comparison files contain the increment formulas:
```
increment_abs = pbc_value - ecc_value
increment_percent = 100 * (pbc_value - ecc_value) / ecc_value
```

**Scenario Options**
Wi‑Fi (`scratch/vanet-security-sumo`):

| Option | Description | Default |
|---|---|---|
| `--trace` | SUMO ns‑2 mobility trace | `../../integration_test/mobility_trace.tcl` |
| `--simTime` | Simulation time (s) | `150` |
| `--msgInterval` | Message interval (s) | `1.0` |
| `--verifySignatures` | Enable ECDSA verification | `true` |
| `--commRange` | Wi‑Fi comm range (m) | `300` |
| `--rsuCount` | Number of RSUs | `2` |
| `--outCsv` | Output CSV path | `vanet-security-metrics-wifi.csv` |

LTE (`scratch/vanet-security-lte`):

| Option | Description | Default |
|---|---|---|
| `--trace` | SUMO ns‑2 mobility trace | `../../integration_test/mobility_trace.tcl` |
| `--simTime` | Simulation time (s) | `150` |
| `--msgInterval` | Message interval (s) | `1.0` |
| `--verifySignatures` | Enable ECDSA verification | `true` |
| `--rsuCount` | Number of RSU/eNB nodes | `2` |
| `--securityMode` | Security mode: `pbc` or `ecc` | `pbc` |
| `--outCsv` | Output CSV path | `vanet-security-metrics-lte.csv` |
| `--progressLog` | Print `SimTime X s` | `true` |

NR (`scratch/vanet-security-nr`):

| Option | Description | Default |
|---|---|---|
| `--trace` | SUMO ns‑2 mobility trace | `../../integration_test/mobility_trace.tcl` |
| `--simTime` | Simulation time (s) | `150` |
| `--msgInterval` | Message interval (s) | `1.0` |
| `--verifySignatures` | Enable ECDSA verification | `true` |
| `--rsuCount` | Number of RSU/gNB nodes | `2` |
| `--nrFreq` | NR carrier frequency (Hz) | `60e9` |
| `--nrBw` | NR bandwidth (Hz) | `400e6` |
| `--nrMu` | NR numerology (mu) | `3` |
| `--v2vMode` | `relay` or `sidelink` | `sidelink` |
| `--securityMode` | Security mode: `pbc` or `ecc` | `pbc` |
| `--outCsv` | Output CSV path | `vanet-security-metrics-nr.csv` |
| `--progressLog` | Print `SimTime X s` | `true` |

**Note on NR V2V**
`--v2vMode=sidelink` currently falls back to BS relay in this branch. The code logs a warning and uses relay mode.

**CSV Output Columns**
Each scenario writes one row per simulated second:
```
time,infected_ratio,propagation_distance,verification_failures,
avg_v2v_delay_ms,avg_v2i_uplink_ms,avg_v2i_downlink_ms,avg_v2i_rtt_ms,
avg_reg_delay_ms,avg_kgc_rtt_ms,avg_ta_rtt_ms,
security_energy_j,comm_energy_j,total_energy_j,
avg_security_power_w,avg_comm_power_w,avg_total_power_w,
avg_sign_ms,avg_aggregate_ms,avg_verify_ms,avg_partial_key_ms
```

The final per-stage power CSV uses:
```
network_label,security_mode,stage,role,count,
avg_latency_ms,total_latency_ms,total_energy_j,avg_energy_mj_per_op
```

**Quick CSV Summary (no external deps)**
```
python3 - <<'PY'
import csv, statistics

def summarize(path):
    with open(path) as f:
        rows = list(csv.DictReader(f))
    if not rows:
        print(f"\n{path}\n(no rows)")
        return
    cols = [
        "avg_v2v_delay_ms",
        "avg_v2i_uplink_ms",
        "avg_v2i_downlink_ms",
        "avg_v2i_rtt_ms",
        "avg_reg_delay_ms",
        "avg_kgc_rtt_ms",
        "avg_ta_rtt_ms",
    ]
    last = rows[-1]
    print(f"\n{path}")
    print("FINAL (last row):")
    for c in cols:
        print(f"{c:22s} {float(last[c]):.3f} ms")
    print("MEAN / MIN / MAX:")
    for c in cols:
        vals = [float(r[c]) for r in rows if r[c] != ""]
        print(f"{c:22s} mean={statistics.fmean(vals):.3f}  min={min(vals):.3f}  max={max(vals):.3f}")

summarize("vanet-security-metrics-wifi.csv")
summarize("vanet-security-metrics-lte.csv")
summarize("vanet-security-metrics-nr.csv")
PY
```

**Plot Delay Curves (optional, matplotlib)**
```
python - <<'PY'
import csv
import matplotlib.pyplot as plt

def plot(path, out):
    t=[]; v2v=[]; up=[]; down=[]; rtt=[]
    with open(path) as f:
        r = csv.DictReader(f)
        for row in r:
            t.append(float(row["time"]))
            v2v.append(float(row["avg_v2v_delay_ms"]))
            up.append(float(row["avg_v2i_uplink_ms"]))
            down.append(float(row["avg_v2i_downlink_ms"]))
            rtt.append(float(row["avg_v2i_rtt_ms"]))
    plt.figure(figsize=(10,6))
    plt.plot(t, v2v, label="V2V end-to-end")
    plt.plot(t, up, label="V2I uplink")
    plt.plot(t, down, label="V2I downlink")
    plt.plot(t, rtt, label="V2I RTT")
    plt.xlabel("Time (s)")
    plt.ylabel("Delay (ms)")
    plt.legend()
    plt.tight_layout()
    plt.savefig(out, dpi=150)
    print(f"Saved: {out}")

plot("vanet-security-metrics-wifi.csv", "vanet-delay-wifi.png")
plot("vanet-security-metrics-lte.csv", "vanet-delay-lte.png")
plot("vanet-security-metrics-nr.csv", "vanet-delay-nr.png")
PY
```

**What “6G‑proxy” means here**
The NR scenario is configured as a high‑frequency, high‑bandwidth 5G‑NR profile (e.g., 60 GHz, 400 MHz, µ=3). This is a **proxy** for 6G‑like conditions, not a true 6G PHY/MAC.
