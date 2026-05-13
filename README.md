# DNS_Covert_Channel_Project

## Project Overview

This project focuses on the detection and analysis of DNS covert channel activities within a controlled virtual laboratory environment. The implementation was developed using Python, Flask, Scapy, SQLite, tcpdump, and Wireshark technologies.

The system captures and analyzes DNS traffic in order to identify suspicious communication patterns such as DNS tunneling and DNS exfiltration activities. Detection results are stored inside an SQLite database and visualized through a Flask-based SOC monitoring dashboard.

---

## Features

- DNS traffic monitoring
- DNS tunneling detection
- DNS exfiltration detection
- Packet capture analysis
- SQLite database logging
- Flask-based SOC dashboard
- Python-based traffic analysis engine
- Packet inspection using Scapy
- Virtual laboratory implementation

---

## Technologies Used

- Python 3
- Flask
- Scapy
- SQLite3
- tcpdump
- Wireshark
- HTML/CSS
- VMware Workstation / VirtualBox

---

## Project Structure

```text
DNS_Covert_Channel_Project/
│
├── app.py
├── soc_detector.py
├── soc.db
├── simulator.html
└── templates/
    └── index.html
```

## Installation
Update Packages
sudo apt update
Install Python and Required Tools
sudo apt install python3 python3-pip sqlite3 tcpdump
pip install flask
pip install scapy
Running the Detection Engine
python3 soc_detector.py
Running the Flask Dashboard
python3 app.py

Open browser:

http://127.0.0.1:5000
Packet Capture Example
sudo tcpdump -i ens33 port 53
Simulation Environment

The project also includes an HTML-based simulation interface (simulator.html) that demonstrates the workflow of the DNS covert channel detection framework.

The simulation visualizes:

attacker environment,
packet capture process,
detection engine,
SQLite database,
SOC monitoring dashboard.
Database Access

Open SQLite database:

sqlite3 soc.db

Example commands:

.tables
SELECT * FROM logs;
Educational Purpose

This project was developed for academic and educational purposes as part of an undergraduate cybersecurity project.
