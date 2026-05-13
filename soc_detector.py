from scapy.all import *
import sqlite3
from datetime import datetime
import pytz

# Sri Lanka timezone
colombo = pytz.timezone("Asia/Colombo")

# Connect database
conn = sqlite3.connect("soc.db")
cursor = conn.cursor()

# Create table
cursor.execute("""
CREATE TABLE IF NOT EXISTS logs (
    time TEXT,
    src TEXT,
    dst TEXT,
    protocol TEXT,
    domain TEXT,
    size INTEGER,
    attack TEXT,
    category TEXT,
    suspicion TEXT
)
""")

# Read packets
packets = rdpcap("capture.pcap")

for pkt in packets:

    try:
        # Packet timestamp
        packet_time = datetime.fromtimestamp(float(pkt.time), tz=colombo)
        time_str = packet_time.strftime("%Y-%m-%d %H:%M:%S")

        # Packet info
        src = pkt[IP].src if pkt.haslayer(IP) else "-"
        dst = pkt[IP].dst if pkt.haslayer(IP) else "-"
        size = len(pkt)

        # Default classification
        protocol = "Other"
        domain = "-"

        attack = "Suspicious Network Activity"
        category = "Network"
        suspicion = "Medium"

        # ---------------- DNS DETECTION ----------------
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):

            protocol = "DNS"
            domain = pkt[DNSQR].qname.decode(errors="ignore")

            # DNS TUNNELING
            if domain.count('.') > 4:

                attack = "DNS Tunneling"
                category = "DNS"
                suspicion = "High"

            # DNS EXFILTRATION
            elif len(domain) > 40:

                attack = "DNS Exfiltration"
                category = "DNS"
                suspicion = "High"

            # Suspicious DNS
            else:

                attack = "Suspicious DNS Activity"
                category = "DNS"
                suspicion = "Medium"

        # ---------------- ICMP DETECTION ----------------
        elif pkt.haslayer(ICMP):

            protocol = "ICMP"

            attack = "ICMP Suspicious Communication"
            category = "Network"
            suspicion = "Medium"

        # ---------------- TCP DETECTION ----------------
        elif pkt.haslayer(TCP):

            protocol = "TCP"

            attack = "TCP Suspicious Communication"
            category = "Network"
            suspicion = "Medium"

        # Insert into database
        cursor.execute("""
        INSERT INTO logs VALUES (?,?,?,?,?,?,?,?,?)
        """, (
            time_str,
            src,
            dst,
            protocol,
            domain,
            size,
            attack,
            category,
            suspicion
        ))

    except Exception as e:
        print("Error processing packet:", e)

# Save database
conn.commit()
conn.close()

print("✅ SOC analysis completed successfully")
