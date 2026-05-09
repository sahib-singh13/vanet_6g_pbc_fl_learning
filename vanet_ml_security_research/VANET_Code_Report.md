# VANET Code Report (vanet-code)

Date: 2026-03-28
Project root: /home/sahib/vanet_ml_security_research/vanet-code

## 1. Overview
This report documents the "vanet-code" folder. The code is a **minimal, local TCP socket demo** that models a simple authentication-style workflow between:

- **TA (Trusted Authority)**: generates keys and sends them to RSU
- **RSU (Road Side Unit)**: requests keys from TA and serves cars
- **Car**: connects to RSU and receives a response (ticket-like data)

This is **not** a full VANET stack and it **does not** implement V2X radio, TLS, or an actual KGC/BS. It is a toy prototype intended to show basic request/response logic between TA -> RSU -> Car on localhost.

## 2. Folder Contents

- `server_TA.py`  
  Runs the TA server. Creates RSA keys and shared keys, then sends them to the RSU on request.

- `Client_RSU.py`  
  Acts as a client to the TA, then becomes a server for cars. It forwards a response back to each car.

- `car.py`  
  Acts as a car client. Sends a car ID to the RSU and prints what it receives.

- `assets/`  
  Contains screenshots used in the README.

- `README.md`  
  Quick usage instructions and screenshots.

## 3. How the Code Works (Protocol Flow)

### 3.1 TA (server_TA.py)
- Starts a TCP server on `127.0.0.1:12345`.
- Generates:
  - RSA public/private keys
  - a shared key
  - an RSU0 key
- When the RSU connects, TA sends a serialized list using `pickle`:
  ```
  [public_key, shared_key, private_key, IDta, RSU0]
  ```
- The TA rotates its internal keys after each request.

### 3.2 RSU (Client_RSU.py)
- Connects to TA at `127.0.0.1:12345` and requests data.
- Receives the TA list and stores it locally.
- Starts its own TCP server on `127.0.0.1:12346`.
- For each car connection, it sends:
  ```
  [car_id, RSU0]
  ```

### 3.3 Car (car.py)
- Generates a random ID using `Fernet.generate_key()`.
- Connects to RSU at `127.0.0.1:12346`.
- Receives and prints the two values:
  - the car ID (same one it sent)
  - the RSU0 key

## 4. Dependencies
The code uses these Python packages:
- `cryptography`
- `rsa`
- `pycryptodome` (for `Crypto.PublicKey`)

Install them (inside the virtual environment):
```bash
python -m pip install cryptography rsa pycryptodome
```

## 5. How I Ran the Code

I activated the virtual environment and ran the components in the correct order:

### 5.1 Activate venv
```bash
cd /home/sahib/vanet_ml_security_research
source /home/sahib/vanet_ml_security_research/venv/bin/activate
```

### 5.2 Run TA server (Terminal 1)
```bash
cd /home/sahib/vanet_ml_security_research/vanet-code
python3 server_TA.py
```

### 5.3 Run RSU server (Terminal 2)
```bash
cd /home/sahib/vanet_ml_security_research/vanet-code
python3 Client_RSU.py
```

### 5.4 Run Car client (Terminal 3)
```bash
cd /home/sahib/vanet_ml_security_research/vanet-code
python3 car.py
```

## 6. Observed Output and What It Means
When running `car.py`, the output looked like:

```
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Receive from RSU .............................................
----[encoded] pQne1Y43SGLywzAkHbmPYV2nlKR-nn0oic-7RBS4OWQ=
----[encoded] B-3KvHBJqCcL8gbF_ZrUEYj0ImpKxM2xSpnhC9UKytM=
```

Interpretation:
- **First line**: the car ID generated at runtime (changes each run)
- **Second line**: RSU0 key received from the TA (stays the same unless TA/RSU restarts)

Running `car.py` multiple times shows a new car ID each run, but the same RSU0 value (while TA/RSU stay up).

## 7. What This Code Is About (Summary)
This code is a **local demonstration** of a basic TA -> RSU -> Car exchange:

- TA generates keys
- RSU fetches them once and stores them
- Cars connect and receive a response containing their ID plus RSU0

It models **the direction of trust and key distribution**, but it does not implement:
- actual V2V/V2I radio links
- TLS or secure transport
- signature verification
- message encryption
- revocation or pseudonym systems

## 8. Limitations and Notes
- Uses `pickle`, which is unsafe over untrusted networks.
- Hard-coded to localhost and fixed ports.
- No real cryptographic validation.
- Minimal error handling.

## 9. Troubleshooting
- If you see `ModuleNotFoundError: No module named 'Crypto'`, install `pycryptodome`.
- If car connects but RSU is not running, the connection will fail.
- If RSU connects but TA is not running, RSU will fail.

## 10. Next Steps (Optional Improvements)
- Add digital signatures and verification.
- Replace `pickle` with a safe serialization format (e.g., JSON + base64 for keys).
- Add TLS for TA and RSU servers.
- Integrate this handshake into the mobility simulation.

