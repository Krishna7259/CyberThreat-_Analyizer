import random
import csv
from pathlib import Path

random.seed(42)

BASE_DIR = Path(__file__).resolve().parent.parent
DATASETS_DIR = BASE_DIR / 'datasets'
DATASETS_DIR.mkdir(parents=True, exist_ok=True)

COLUMNS = [
    'dur', 'proto', 'service', 'state', 'spkts', 'dpkts',
    'sbytes', 'dbytes', 'rate', 'sttl', 'dttl', 'sload', 'dload',
    'sloss', 'dloss', 'sinpkt', 'dinpkt', 'sjit', 'djit',
    'swin', 'stcpb', 'dtcpb', 'dwin', 'tcprtt', 'synack', 'ackdat',
    'smean', 'dmean', 'trans_depth', 'response_body_len',
    'attack_cat', 'label'
]

PROTOCOLS = ['tcp', 'udp', 'icmp', 'ospf', 'sctp']
SERVICES = ['http', 'dns', 'ftp', 'smtp', 'ssh', 'ssl', '-']
STATES = ['FIN', 'CON', 'INT', 'REQ', 'RST']

def generate_record(attack_type='Normal'):
    if attack_type == 'Normal':
        label = 0
        cat = 'Normal'
        dur = round(random.uniform(0.01, 2.5), 6)
        proto = random.choices(['tcp', 'udp', 'icmp'], weights=[0.6, 0.35, 0.05])[0]
        service = random.choices(['http', 'dns', 'ssl', '-'], weights=[0.4, 0.3, 0.2, 0.1])[0]
        state = random.choice(['FIN', 'CON'])
        spkts = random.randint(2, 40)
        dpkts = random.randint(2, 60)
        sbytes = spkts * random.randint(60, 250)
        dbytes = dpkts * random.randint(80, 1400)
        rate = round(random.uniform(5.0, 1200.0), 4)
        sttl = random.choice([31, 62, 64, 254])
        dttl = random.choice([29, 60, 62, 252])
        sload = round(sbytes * 8.0 / max(dur, 0.001), 2)
        dload = round(dbytes * 8.0 / max(dur, 0.001), 2)
        sloss = random.randint(0, 1)
        dloss = random.randint(0, 2)
        sinpkt = round(random.uniform(0.01, 25.0), 3)
        dinpkt = round(random.uniform(0.01, 20.0), 3)
        sjit = round(random.uniform(0.0, 50.0), 2)
        djit = round(random.uniform(0.0, 45.0), 2)
        swin = 255 if proto == 'tcp' else 0
        dwin = 255 if proto == 'tcp' else 0
        stcpb = random.randint(100000000, 999999999) if proto == 'tcp' else 0
        dtcpb = random.randint(100000000, 999999999) if proto == 'tcp' else 0
        tcprtt = round(random.uniform(0.0005, 0.05), 6) if proto == 'tcp' else 0.0
        synack = round(random.uniform(0.0002, 0.02), 6) if proto == 'tcp' else 0.0
        ackdat = round(random.uniform(0.0002, 0.02), 6) if proto == 'tcp' else 0.0
        smean = round(sbytes / max(spkts, 1), 1)
        dmean = round(dbytes / max(dpkts, 1), 1)
        trans_depth = 1 if service == 'http' else 0
        response_body_len = random.randint(200, 4000) if service == 'http' else 0

    elif attack_type == 'DoS':
        label = 1
        cat = 'DoS'
        dur = round(random.uniform(0.00001, 0.5), 6)
        proto = random.choices(['tcp', 'udp', 'icmp'], weights=[0.7, 0.2, 0.1])[0]
        service = random.choices(['-', 'http', 'dns'], weights=[0.7, 0.2, 0.1])[0]
        state = random.choice(['INT', 'REQ', 'RST'])
        spkts = random.randint(200, 2000)
        dpkts = random.randint(0, 10)
        sbytes = spkts * random.randint(40, 120)
        dbytes = dpkts * random.randint(0, 60)
        rate = round(random.uniform(15000.0, 120000.0), 4)
        sttl = 254
        dttl = 0 if dpkts == 0 else random.choice([29, 60])
        sload = round(sbytes * 8.0 / max(dur, 0.0001), 2)
        dload = round(dbytes * 8.0 / max(dur, 0.0001), 2)
        sloss = random.randint(20, 150)
        dloss = random.randint(0, 5)
        sinpkt = round(random.uniform(0.0001, 0.01), 4)
        dinpkt = 0.0
        sjit = round(random.uniform(0.0, 5.0), 2)
        djit = 0.0
        swin = 0
        dwin = 0
        stcpb = random.randint(100000000, 999999999) if proto == 'tcp' else 0
        dtcpb = 0
        tcprtt = 0.0
        synack = 0.0
        ackdat = 0.0
        smean = round(sbytes / max(spkts, 1), 1)
        dmean = 0.0
        trans_depth = 0
        response_body_len = 0

    elif attack_type == 'Exploits':
        label = 1
        cat = 'Exploits'
        dur = round(random.uniform(0.05, 1.8), 6)
        proto = 'tcp'
        service = random.choice(['http', 'ftp', 'ssh', '-'])
        state = 'FIN'
        spkts = random.randint(10, 80)
        dpkts = random.randint(8, 70)
        sbytes = random.randint(1500, 18000)
        dbytes = random.randint(300, 8000)
        rate = round(random.uniform(10.0, 500.0), 4)
        sttl = 64
        dttl = 60
        sload = round(sbytes * 8.0 / max(dur, 0.001), 2)
        dload = round(dbytes * 8.0 / max(dur, 0.001), 2)
        sloss = random.randint(1, 10)
        dloss = random.randint(1, 8)
        sinpkt = round(random.uniform(0.01, 10.0), 3)
        dinpkt = round(random.uniform(0.01, 8.0), 3)
        sjit = round(random.uniform(5.0, 100.0), 2)
        djit = round(random.uniform(4.0, 80.0), 2)
        swin = 255
        dwin = 255
        stcpb = random.randint(100000000, 999999999)
        dtcpb = random.randint(100000000, 999999999)
        tcprtt = round(random.uniform(0.001, 0.08), 6)
        synack = round(random.uniform(0.0005, 0.03), 6)
        ackdat = round(random.uniform(0.0005, 0.03), 6)
        smean = round(sbytes / max(spkts, 1), 1)
        dmean = round(dbytes / max(dpkts, 1), 1)
        trans_depth = 1 if service == 'http' else 0
        response_body_len = random.randint(0, 1500) if service == 'http' else 0

    elif attack_type == 'Reconnaissance':
        label = 1
        cat = 'Reconnaissance'
        dur = round(random.uniform(0.0001, 0.1), 6)
        proto = random.choice(['tcp', 'udp', 'icmp'])
        service = '-'
        state = random.choice(['INT', 'CON', 'REQ'])
        spkts = random.randint(2, 6)
        dpkts = random.randint(0, 2)
        sbytes = spkts * random.randint(40, 70)
        dbytes = dpkts * random.randint(0, 60)
        rate = round(random.uniform(500.0, 8000.0), 4)
        sttl = 64
        dttl = 0 if dpkts == 0 else 60
        sload = round(sbytes * 8.0 / max(dur, 0.0001), 2)
        dload = round(dbytes * 8.0 / max(dur, 0.0001), 2)
        sloss = 0
        dloss = 0
        sinpkt = round(random.uniform(0.001, 1.0), 4)
        dinpkt = 0.0
        sjit = round(random.uniform(0.0, 2.0), 2)
        djit = 0.0
        swin = 0
        dwin = 0
        stcpb = random.randint(100000000, 999999999) if proto == 'tcp' else 0
        dtcpb = 0
        tcprtt = 0.0
        synack = 0.0
        ackdat = 0.0
        smean = round(sbytes / max(spkts, 1), 1)
        dmean = round(dbytes / max(dpkts, 1), 1) if dpkts > 0 else 0.0
        trans_depth = 0
        response_body_len = 0

    else:  # Generic / Fuzzers
        label = 1
        cat = attack_type
        dur = round(random.uniform(0.01, 1.2), 6)
        proto = random.choice(['tcp', 'udp'])
        service = random.choice(['dns', 'http', '-'])
        state = random.choice(['CON', 'INT', 'FIN'])
        spkts = random.randint(4, 50)
        dpkts = random.randint(2, 30)
        sbytes = spkts * random.randint(50, 400)
        dbytes = dpkts * random.randint(40, 300)
        rate = round(random.uniform(50.0, 3000.0), 4)
        sttl = 254
        dttl = 252
        sload = round(sbytes * 8.0 / max(dur, 0.001), 2)
        dload = round(dbytes * 8.0 / max(dur, 0.001), 2)
        sloss = random.randint(0, 5)
        dloss = random.randint(0, 3)
        sinpkt = round(random.uniform(0.01, 5.0), 3)
        dinpkt = round(random.uniform(0.01, 5.0), 3)
        sjit = round(random.uniform(0.0, 30.0), 2)
        djit = round(random.uniform(0.0, 25.0), 2)
        swin = 255 if proto == 'tcp' else 0
        dwin = 255 if proto == 'tcp' else 0
        stcpb = random.randint(100000000, 999999999) if proto == 'tcp' else 0
        dtcpb = random.randint(100000000, 999999999) if proto == 'tcp' else 0
        tcprtt = round(random.uniform(0.0005, 0.04), 6) if proto == 'tcp' else 0.0
        synack = round(random.uniform(0.0002, 0.02), 6) if proto == 'tcp' else 0.0
        ackdat = round(random.uniform(0.0002, 0.02), 6) if proto == 'tcp' else 0.0
        smean = round(sbytes / max(spkts, 1), 1)
        dmean = round(dbytes / max(dpkts, 1), 1)
        trans_depth = 0
        response_body_len = 0

    return [
        dur, proto, service, state, spkts, dpkts,
        sbytes, dbytes, rate, sttl, dttl, sload, dload,
        sloss, dloss, sinpkt, dinpkt, sjit, djit,
        swin, stcpb, dtcpb, dwin, tcprtt, synack, ackdat,
        smean, dmean, trans_depth, response_body_len,
        cat, label
    ]

# Generate Training Sample (600 records: 360 Normal, 240 Attacks)
train_rows = []
for _ in range(360):
    train_rows.append(generate_record('Normal'))
for _ in range(70):
    train_rows.append(generate_record('DoS'))
for _ in range(60):
    train_rows.append(generate_record('Exploits'))
for _ in range(50):
    train_rows.append(generate_record('Reconnaissance'))
for _ in range(35):
    train_rows.append(generate_record('Generic'))
for _ in range(25):
    train_rows.append(generate_record('Fuzzers'))

random.shuffle(train_rows)

sample_file = DATASETS_DIR / 'unsw_nb15_sample.csv'
with open(sample_file, 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(COLUMNS)
    writer.writerows(train_rows)

print(f"[+] Wrote {len(train_rows)} records to {sample_file}")

# Generate Test Stream Sample (120 records for simulation / test uploads)
stream_rows = []
for _ in range(70):
    stream_rows.append(generate_record('Normal'))
for _ in range(15):
    stream_rows.append(generate_record('DoS'))
for _ in range(15):
    stream_rows.append(generate_record('Exploits'))
for _ in range(10):
    stream_rows.append(generate_record('Reconnaissance'))
for _ in range(10):
    stream_rows.append(generate_record('Generic'))

random.shuffle(stream_rows)

stream_file = DATASETS_DIR / 'test_stream.csv'
with open(stream_file, 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(COLUMNS)
    writer.writerows(stream_rows)

print(f"[+] Wrote {len(stream_rows)} records to {stream_file}")
