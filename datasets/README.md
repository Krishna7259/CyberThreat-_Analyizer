# CyberShield AI Datasets

## Primary Supported Dataset: UNSW-NB15

CyberShield AI is designed and benchmarked against the **UNSW-NB15 dataset**, created by the Cyber Range Lab of the Australian Centre for Cyber Security (ACCS) at the University of New South Wales (UNSW Canberra).

### Citation
> Moustafa, Nour, and Jill Slay. "UNSW-NB15: a comprehensive data set for network intrusion detection systems (UNSW-NB15 network data set)." 2015 Military Communications and Information Systems Conference (MilCIS). IEEE, 2015.

---

## Dataset Schema

The system extracts and analyzes key flow-level features across packet headers and payload metrics:

### 1. Numerical Features
- `dur`: Record total duration (seconds)
- `spkts`: Source to destination packet count
- `dpkts`: Destination to source packet count
- `sbytes`: Source to destination transaction bytes
- `dbytes`: Destination to source transaction bytes
- `rate`: Packet transmission rate (packets per second)
- `sttl`: Source to destination time-to-live value
- `dttl`: Destination to source time-to-live value
- `sload`: Source bits per second
- `dload`: Destination bits per second
- `sloss`: Source packets dropped/retransmitted
- `dloss`: Destination packets dropped/retransmitted
- `sinpkt`: Source interpacket arrival time (msec)
- `dinpkt`: Destination interpacket arrival time (msec)
- `sjit`: Source jitter (msec)
- `djit`: Destination jitter (msec)
- `swin`: Source TCP window advertisement value
- `stcpb`: Source TCP base sequence number
- `dtcpb`: Destination TCP base sequence number
- `dwin`: Destination TCP window advertisement value
- `tcprtt`: TCP round-trip time (`synack` + `ackdat`)
- `synack`: Time between TCP SYN and SYN-ACK
- `ackdat`: Time between TCP SYN-ACK and ACK
- `smean`: Mean packet size transmitted by source
- `dmean`: Mean packet size transmitted by destination
- `trans_depth`: Pipelined HTTP request depth
- `response_body_len`: Actual uncompressed content size of HTTP response

### 2. Categorical Features
- `proto`: Transaction protocol (e.g., `tcp`, `udp`, `icmp`)
- `service`: Network service (e.g., `http`, `dns`, `ftp`, `ssh`, `ssl`, `-`)
- `state`: State of the connection (e.g., `FIN`, `CON`, `INT`, `REQ`, `RST`)

### 3. Classification Targets
- `label`: Binary classification target (`0` = Normal, `1` = Attack / Suspicious)
- `attack_cat`: Multi-class threat taxonomy (`Normal`, `Generic`, `Exploits`, `Fuzzers`, `DoS`, `Reconnaissance`, `Analysis`, `Backdoor`, `Shellcode`, `Worms`)

---

## Included Files

- `unsw_nb15_sample.csv`: A representative 600-record dataset containing balanced normal flows and diverse cyber attacks (DoS, Exploits, Reconnaissance, Generic, Fuzzers) for model training, benchmarking, and demonstration.
- `test_stream.csv`: A 120-record dataset formatted for simulated real-time packet stream replay and dataset upload testing.

### Ready-to-Use Scenario Datasets (7 CSV Files)
1. **`01_normal_office_traffic.csv`** (250 records): 100% Benign enterprise baseline traffic (HTTPS, DNS, SMTP, SSH). Ideal for testing false-positive rates.
2. **`02_ddos_syn_flood.csv`** (300 records): High-volume SYN & UDP denial-of-service attack traffic with elevated packet rates and abnormal drop losses.
3. **`03_port_scan_reconnaissance.csv`** (260 records): Stealthy TCP/UDP port sweeps and network reconnaissance probes.
4. **`04_web_application_exploits.csv`** (250 records): Web exploit traffic (SQL injection, XSS, command injection) with high transaction depths and HTTP response bodies.
5. **`05_zero_day_anomalies.csv`** (250 records): Subtle statistical outliers and unknown protocol behaviors designed for Isolation Forest anomaly detection.
6. **`06_botnet_c2_exfiltration.csv`** (250 records): Botnet command-and-control beaconing with persistent sessions and asymmetric outbound data transfers.
7. **`07_enterprise_mixed_threats.csv`** (530 records): End-to-end multi-vector attack benchmark dataset containing a realistic SOC mix of normal operations and diverse threat vectors.

---

## Obtaining the Full Dataset

To train against the full raw 100k+ record UNSW-NB15 dataset:
1. Download `UNSW-NB15_1.csv` through `UNSW-NB15_4.csv` from the official repository:
   https://research.unsw.edu.au/projects/unsw-nb15-dataset
2. Place the downloaded CSV inside this `datasets/` folder.
3. Run the training script:
   ```powershell
   python ml/train_model.py --dataset datasets/UNSW-NB15_1.csv
   ```
