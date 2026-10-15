import csv
import random
from pathlib import Path

# Fix seed for reproducible, high quality datasets
random.seed(1337)

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

def make_normal_record():
    proto = random.choices(['tcp', 'udp', 'icmp'], weights=[0.65, 0.30, 0.05])[0]
    service = random.choices(['http', 'dns', 'ssl', 'smtp', 'ssh', '-'], weights=[0.35, 0.25, 0.20, 0.08, 0.07, 0.05])[0]
    dur = round(random.uniform(0.02, 3.5), 6)
    state = random.choice(['FIN', 'CON'])
    spkts = random.randint(4, 50)
    dpkts = random.randint(3, 75)
    sbytes = spkts * random.randint(64, 300)
    dbytes = dpkts * random.randint(80, 1450)
    rate = round((spkts + dpkts) / max(dur, 0.001), 4)
    sttl = random.choice([64, 128, 62])
    dttl = random.choice([60, 124, 58])
    sload = round(sbytes * 8.0 / max(dur, 0.001), 2)
    dload = round(dbytes * 8.0 / max(dur, 0.001), 2)
    sloss = random.randint(0, 1)
    dloss = random.randint(0, 2)
    sinpkt = round(random.uniform(0.01, 15.0), 3)
    dinpkt = round(random.uniform(0.01, 12.0), 3)
    sjit = round(random.uniform(0.0, 35.0), 2)
    djit = round(random.uniform(0.0, 30.0), 2)
    swin = 255 if proto == 'tcp' else 0
    dwin = 255 if proto == 'tcp' else 0
    stcpb = random.randint(100000000, 999999999) if proto == 'tcp' else 0
    dtcpb = random.randint(100000000, 999999999) if proto == 'tcp' else 0
    tcprtt = round(random.uniform(0.001, 0.04), 6) if proto == 'tcp' else 0.0
    synack = round(random.uniform(0.0005, 0.02), 6) if proto == 'tcp' else 0.0
    ackdat = round(random.uniform(0.0005, 0.02), 6) if proto == 'tcp' else 0.0
    smean = round(sbytes / max(spkts, 1), 1)
    dmean = round(dbytes / max(dpkts, 1), 1)
    trans_depth = 1 if service in ['http', 'ssl'] else 0
    response_body_len = random.randint(250, 6000) if service == 'http' else 0
    return [
        dur, proto, service, state, spkts, dpkts,
        sbytes, dbytes, rate, sttl, dttl, sload, dload,
        sloss, dloss, sinpkt, dinpkt, sjit, djit,
        swin, stcpb, dtcpb, dwin, tcprtt, synack, ackdat,
        smean, dmean, trans_depth, response_body_len,
        'Normal', 0
    ]

def make_dos_record():
    proto = random.choices(['tcp', 'udp', 'icmp'], weights=[0.7, 0.2, 0.1])[0]
    service = random.choices(['-', 'http', 'dns'], weights=[0.75, 0.15, 0.10])[0]
    dur = round(random.uniform(0.00005, 0.4), 6)
    state = random.choice(['INT', 'REQ', 'RST'])
    spkts = random.randint(250, 3500)
    dpkts = random.randint(0, 8)
    sbytes = spkts * random.randint(40, 90)
    dbytes = dpkts * random.randint(0, 60)
    rate = round(float(spkts) / max(dur, 0.0001), 4)
    sttl = 254
    dttl = 0 if dpkts == 0 else random.choice([29, 60])
    sload = round(sbytes * 8.0 / max(dur, 0.0001), 2)
    dload = round(dbytes * 8.0 / max(dur, 0.0001), 2)
    sloss = random.randint(30, 300)
    dloss = random.randint(0, 4)
    sinpkt = round(random.uniform(0.00005, 0.005), 5)
    dinpkt = 0.0
    sjit = round(random.uniform(0.0, 3.0), 2)
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
    return [
        dur, proto, service, state, spkts, dpkts,
        sbytes, dbytes, rate, sttl, dttl, sload, dload,
        sloss, dloss, sinpkt, dinpkt, sjit, djit,
        swin, stcpb, dtcpb, dwin, tcprtt, synack, ackdat,
        smean, dmean, trans_depth, response_body_len,
        'DoS', 1
    ]

def make_recon_record():
    proto = random.choice(['tcp', 'udp', 'icmp'])
    service = '-'
    dur = round(random.uniform(0.00005, 0.08), 6)
    state = random.choice(['INT', 'REQ', 'RST'])
    spkts = random.randint(2, 6)
    dpkts = random.randint(0, 2)
    sbytes = spkts * random.randint(40, 68)
    dbytes = dpkts * random.randint(0, 52)
    rate = round(float(spkts) / max(dur, 0.0001), 4)
    sttl = 64
    dttl = 0 if dpkts == 0 else 60
    sload = round(sbytes * 8.0 / max(dur, 0.0001), 2)
    dload = round(dbytes * 8.0 / max(dur, 0.0001), 2)
    sloss = 0
    dloss = 0
    sinpkt = round(random.uniform(0.001, 0.8), 4)
    dinpkt = 0.0
    sjit = round(random.uniform(0.0, 1.5), 2)
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
    return [
        dur, proto, service, state, spkts, dpkts,
        sbytes, dbytes, rate, sttl, dttl, sload, dload,
        sloss, dloss, sinpkt, dinpkt, sjit, djit,
        swin, stcpb, dtcpb, dwin, tcprtt, synack, ackdat,
        smean, dmean, trans_depth, response_body_len,
        'Reconnaissance', 1
    ]

def make_exploit_record():
    proto = 'tcp'
    service = random.choices(['http', 'ftp', 'ssh', '-'], weights=[0.7, 0.15, 0.1, 0.05])[0]
    dur = round(random.uniform(0.08, 2.2), 6)
    state = 'FIN'
    spkts = random.randint(15, 120)
    dpkts = random.randint(10, 90)
    sbytes = random.randint(2500, 32000)
    dbytes = random.randint(500, 12000)
    rate = round((spkts + dpkts) / max(dur, 0.001), 4)
    sttl = 64
    dttl = 60
    sload = round(sbytes * 8.0 / max(dur, 0.001), 2)
    dload = round(dbytes * 8.0 / max(dur, 0.001), 2)
    sloss = random.randint(1, 12)
    dloss = random.randint(1, 9)
    sinpkt = round(random.uniform(0.01, 8.0), 3)
    dinpkt = round(random.uniform(0.01, 7.0), 3)
    sjit = round(random.uniform(8.0, 120.0), 2)
    djit = round(random.uniform(6.0, 90.0), 2)
    swin = 255
    dwin = 255
    stcpb = random.randint(100000000, 999999999)
    dtcpb = random.randint(100000000, 999999999)
    tcprtt = round(random.uniform(0.002, 0.09), 6)
    synack = round(random.uniform(0.001, 0.04), 6)
    ackdat = round(random.uniform(0.001, 0.04), 6)
    smean = round(sbytes / max(spkts, 1), 1)
    dmean = round(dbytes / max(dpkts, 1), 1)
    trans_depth = random.choice([1, 2, 3]) if service == 'http' else 0
    response_body_len = random.randint(800, 8500) if service == 'http' else 0
    return [
        dur, proto, service, state, spkts, dpkts,
        sbytes, dbytes, rate, sttl, dttl, sload, dload,
        sloss, dloss, sinpkt, dinpkt, sjit, djit,
        swin, stcpb, dtcpb, dwin, tcprtt, synack, ackdat,
        smean, dmean, trans_depth, response_body_len,
        'Exploits', 1
    ]

def make_anomaly_record():
    # Rare combination / statistical outlier for Isolation Forest
    proto = random.choice(['ospf', 'sctp', 'udp', 'tcp'])
    service = random.choice(['-', 'ssl', 'dns', 'http'])
    dur = round(random.uniform(0.0001, 12.0), 6)
    state = random.choice(['REQ', 'INT', 'RST'])
    spkts = random.randint(1, 500)
    dpkts = random.randint(0, 10)
    sbytes = spkts * random.randint(30, 1800)
    dbytes = dpkts * random.randint(0, 400)
    rate = round(float(spkts + dpkts) / max(dur, 0.001), 4)
    # Rare TTL deviation
    sttl = random.choice([17, 45, 99, 215, 240])
    dttl = random.choice([0, 15, 42, 90, 200])
    sload = round(sbytes * 8.0 / max(dur, 0.001), 2)
    dload = round(dbytes * 8.0 / max(dur, 0.001), 2)
    sloss = random.randint(0, 20)
    dloss = random.randint(0, 10)
    sinpkt = round(random.uniform(0.0001, 45.0), 4)
    dinpkt = round(random.uniform(0.0, 30.0), 4)
    sjit = round(random.uniform(15.0, 350.0), 2)
    djit = round(random.uniform(10.0, 250.0), 2)
    swin = random.choice([0, 64, 128, 255])
    dwin = random.choice([0, 64, 128, 255])
    stcpb = random.randint(100000000, 999999999) if proto == 'tcp' else 0
    dtcpb = random.randint(100000000, 999999999) if proto == 'tcp' else 0
    tcprtt = round(random.uniform(0.05, 0.45), 6) if proto == 'tcp' else 0.0
    synack = round(random.uniform(0.02, 0.20), 6) if proto == 'tcp' else 0.0
    ackdat = round(random.uniform(0.02, 0.20), 6) if proto == 'tcp' else 0.0
    smean = round(sbytes / max(spkts, 1), 1)
    dmean = round(dbytes / max(dpkts, 1), 1) if dpkts > 0 else 0.0
    trans_depth = 0
    response_body_len = 0
    return [
        dur, proto, service, state, spkts, dpkts,
        sbytes, dbytes, rate, sttl, dttl, sload, dload,
        sloss, dloss, sinpkt, dinpkt, sjit, djit,
        swin, stcpb, dtcpb, dwin, tcprtt, synack, ackdat,
        smean, dmean, trans_depth, response_body_len,
        'Fuzzers', 1
    ]

def make_botnet_record():
    # Covert C2 beaconing and exfiltration
    proto = 'tcp'
    service = random.choices(['ssl', 'http', '-'], weights=[0.6, 0.3, 0.1])[0]
    dur = round(random.uniform(4.0, 30.0), 6) # Long persistent flow
    state = 'CON'
    spkts = random.randint(40, 300)
    dpkts = random.randint(20, 100)
    # Exfiltration: disproportionately large outbound bytes
    sbytes = spkts * random.randint(400, 1500)
    dbytes = dpkts * random.randint(40, 120)
    rate = round(float(spkts + dpkts) / max(dur, 0.001), 4)
    sttl = 64
    dttl = 58
    sload = round(sbytes * 8.0 / max(dur, 0.001), 2)
    dload = round(dbytes * 8.0 / max(dur, 0.001), 2)
    sloss = random.randint(0, 3)
    dloss = random.randint(0, 2)
    # Regular beacon intervals
    sinpkt = round(random.uniform(0.8, 2.5), 3)
    dinpkt = round(random.uniform(0.8, 2.5), 3)
    sjit = round(random.uniform(0.1, 5.0), 2)
    djit = round(random.uniform(0.1, 4.0), 2)
    swin = 255
    dwin = 255
    stcpb = random.randint(100000000, 999999999)
    dtcpb = random.randint(100000000, 999999999)
    tcprtt = round(random.uniform(0.015, 0.06), 6)
    synack = round(random.uniform(0.008, 0.03), 6)
    ackdat = round(random.uniform(0.007, 0.03), 6)
    smean = round(sbytes / max(spkts, 1), 1)
    dmean = round(dbytes / max(dpkts, 1), 1)
    trans_depth = 1 if service == 'http' else 0
    response_body_len = random.randint(100, 800) if service == 'http' else 0
    return [
        dur, proto, service, state, spkts, dpkts,
        sbytes, dbytes, rate, sttl, dttl, sload, dload,
        sloss, dloss, sinpkt, dinpkt, sjit, djit,
        swin, stcpb, dtcpb, dwin, tcprtt, synack, ackdat,
        smean, dmean, trans_depth, response_body_len,
        'Generic', 1
    ]

def make_generic_attack_record():
    return [
        round(random.uniform(0.01, 1.2), 6),
        random.choice(['tcp', 'udp']),
        random.choice(['dns', 'http', '-']),
        random.choice(['CON', 'INT', 'FIN']),
        random.randint(4, 50),
        random.randint(2, 30),
        random.randint(200, 8000),
        random.randint(100, 4000),
        round(random.uniform(50.0, 3000.0), 4),
        254, 252,
        round(random.uniform(10000.0, 800000.0), 2),
        round(random.uniform(5000.0, 500000.0), 2),
        random.randint(0, 5), random.randint(0, 3),
        round(random.uniform(0.01, 5.0), 3),
        round(random.uniform(0.01, 5.0), 3),
        round(random.uniform(0.0, 30.0), 2),
        round(random.uniform(0.0, 25.0), 2),
        255, random.randint(100000000, 999999999), random.randint(100000000, 999999999), 255,
        round(random.uniform(0.0005, 0.04), 6),
        round(random.uniform(0.0002, 0.02), 6),
        round(random.uniform(0.0002, 0.02), 6),
        round(random.uniform(40.0, 500.0), 1),
        round(random.uniform(40.0, 400.0), 1),
        0, 0,
        'Generic', 1
    ]

# Spec for 7 datasets
DATASET_SPECS = [
    {
        'filename': '01_normal_office_traffic.csv',
        'title': 'Normal Office Network Traffic',
        'counts': {'normal': 250, 'dos': 0, 'recon': 0, 'exploit': 0, 'anomaly': 0, 'botnet': 0, 'generic': 0}
    },
    {
        'filename': '02_ddos_syn_flood.csv',
        'title': 'DDoS SYN & UDP Flood Attack',
        'counts': {'normal': 35, 'dos': 265, 'recon': 0, 'exploit': 0, 'anomaly': 0, 'botnet': 0, 'generic': 0}
    },
    {
        'filename': '03_port_scan_reconnaissance.csv',
        'title': 'Port Scan & Reconnaissance Probing',
        'counts': {'normal': 40, 'dos': 0, 'recon': 220, 'exploit': 0, 'anomaly': 0, 'botnet': 0, 'generic': 0}
    },
    {
        'filename': '04_web_application_exploits.csv',
        'title': 'Web Exploitation (SQLi & XSS)',
        'counts': {'normal': 50, 'dos': 0, 'recon': 0, 'exploit': 200, 'anomaly': 0, 'botnet': 0, 'generic': 0}
    },
    {
        'filename': '05_zero_day_anomalies.csv',
        'title': 'Zero-Day Anomalies & Lateral Movement',
        'counts': {'normal': 60, 'dos': 0, 'recon': 0, 'exploit': 0, 'anomaly': 190, 'botnet': 0, 'generic': 0}
    },
    {
        'filename': '06_botnet_c2_exfiltration.csv',
        'title': 'Botnet C2 Beaconing & Exfiltration',
        'counts': {'normal': 60, 'dos': 0, 'recon': 0, 'exploit': 0, 'anomaly': 0, 'botnet': 180, 'generic': 10}
    },
    {
        'filename': '07_enterprise_mixed_threats.csv',
        'title': 'Full Enterprise Mixed Threat Benchmark',
        'counts': {'normal': 280, 'dos': 65, 'recon': 55, 'exploit': 50, 'anomaly': 30, 'botnet': 30, 'generic': 20}
    }
]

def generate_all():
    generated_files = []
    for spec in DATASET_SPECS:
        rows = []
        for _ in range(spec['counts']['normal']):
            rows.append(make_normal_record())
        for _ in range(spec['counts']['dos']):
            rows.append(make_dos_record())
        for _ in range(spec['counts']['recon']):
            rows.append(make_recon_record())
        for _ in range(spec['counts']['exploit']):
            rows.append(make_exploit_record())
        for _ in range(spec['counts']['anomaly']):
            rows.append(make_anomaly_record())
        for _ in range(spec['counts']['botnet']):
            rows.append(make_botnet_record())
        for _ in range(spec['counts']['generic']):
            rows.append(make_generic_attack_record())

        random.shuffle(rows)
        target_path = DATASETS_DIR / spec['filename']
        with open(target_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(COLUMNS)
            writer.writerows(rows)

        print(f"[+] Successfully created {spec['filename']} ({len(rows)} records) -> {spec['title']}")
        generated_files.append((spec['filename'], len(rows), spec['title']))

    return generated_files

if __name__ == '__main__':
    generate_all()
