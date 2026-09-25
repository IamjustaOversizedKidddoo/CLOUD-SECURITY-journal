# 🔍 Automated TCP Port Scanner (Deliverable 1)

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Cloud: AWS EC2](https://img.shields.io/badge/AWS-EC2%20Security%20Audit-orange.svg)](https://aws.amazon.com/ec2/)

A high-performance, multi-threaded TCP port scanner and network audit utility built in Python using raw transport-layer sockets. Designed for cloud security engineers to audit exposed attack surfaces, validate AWS Security Group ingress configurations, and detect inadvertent service bindings.

---

## 🎯 Problem Statement & Cloud Security Context

In cloud infrastructure, misconfigured security boundaries (such as AWS Security Groups permitting `0.0.0.0/0` ingress) are among the leading root causes of cloud data breaches. 

Automated bots continuously scan the IPv4 address space for vulnerable ports (e.g., SSH `22`, Telnet `23`, RDP `3389`, MySQL `3306`, Redis `6379`). This tool provides cloud security teams with an automated, lightweight mechanism to proactively audit infrastructure from the outside in, validating that only authorized ports are reachable.

---

## ⚙️ How It Works (Transport Layer Mechanics)

The scanner operates at **Layer 4 (Transport)** using Python's native `socket` interface:

1. **Socket Instantiation:** Initializes an `AF_INET` (IPv4) `SOCK_STREAM` (TCP) socket.
2. **Three-Way Handshake (`connect_ex`):** Attempts to establish a full TCP connection (`SYN` $\to$ `SYN-ACK` $\to$ `ACK`):
   * **Return Code `0`:** Port is **OPEN** (target responded with `SYN-ACK`, completed handshake).
   * **Return Code `10061` (WSAECONNREFUSED) / `ECONNREFUSED`:** Port is **CLOSED** (target host replied with `RST-ACK`).
   * **Socket Timeout:** Port is **FILTERED** (packets silently dropped by an AWS Security Group or network firewall without returning a response).
3. **Concurrency:** Utilizes `concurrent.futures.ThreadPoolExecutor` to scan hundreds of ports concurrently without blocking the main event loop.

---

## 🚀 Features

- [x] **Zero External Dependencies:** Built entirely with Python's standard library (`socket`, `sys`, `argparse`, `concurrent.futures`, `datetime`).
- [x] **High-Throughput Threading:** Multi-threaded concurrency for scanning broad port ranges in seconds.
- [x] **Service Fingerprinting:** Automatic port-to-service resolution for common and well-known ports.
- [x] **Configurable Timeouts:** Tunable socket timeouts to prevent hanging on silently filtered ports.
- [x] **Clear Executive Summary:** Structured reporting detailing total scanned ports, scan duration, and open ports discovered.

---

## 📋 Installation & Prerequisites

* Python 3.8 or higher.
* No `pip install` required.

```bash
# Clone the repository
git clone https://github.com/IamjustaOversizedKidddoo/port-scanner.git
cd port-scanner
```

---

## 💻 Usage

```bash
python3 scanner.py <target_host_or_ip> <start_port> <end_port> [options]
```

### Options:
* `-t`, `--threads`: Number of concurrent worker threads (default: `50`).
* `-w`, `--timeout`: Socket timeout in seconds (default: `1.0`).

### Examples:

#### 1. Audit an AWS EC2 Instance (Well-Known Ports 1–1024):
```bash
python3 scanner.py 54.211.10.5 1 1024 -t 100 -w 1.0
```

#### 2. Scan Specific Application Ranges:
```bash
python3 scanner.py ec2-instance.compute-1.amazonaws.com 8000 8500
```

---

## 📊 Sample Output (EC2 Security Audit)

```text
======================================================================
  AUTOMATED TCP PORT SCANNER - CLOUD SECURITY AUDIT
======================================================================
  Target Host      : 54.211.10.5 (54.211.10.5)
  Port Range       : 1 - 1024 (1024 ports)
  Concurrency      : 50 worker threads
  Socket Timeout   : 1.0s
  Scan Initiated   : 2026-09-25 15:51:14
======================================================================

  [+] Port    22/TCP : OPEN  --> [SSH]

======================================================================
  SCAN REPORT SUMMARY
======================================================================
  Completed At     : 2026-09-25 15:51:28
  Total Ports      : 1024
  Open Ports Found : 1

  Exposed Ports List:
    - TCP 22 (SSH)
======================================================================
```

---

## 🛡️ Detection & SIEM Visibility

* **AWS GuardDuty Finding:** A rapid TCP connect scan across sequential ports triggers the finding `Recon:EC2/Portscan`.
* **VPC Flow Logs:** Generates thousands of short-lived sessions with `action = REJECT` (for closed/filtered ports) or `ACCEPT` (for open ports).
* **Stealth Note (TCP Connect vs. SYN Scan):**
  * This tool performs a full **TCP Connect Scan** via OS sockets, completing the handshake and creating an entry in target server connection tables.
  * In contrast, raw **SYN Scans** (`nmap -sS`) send `SYN`, wait for `SYN-ACK`, and immediately reply with `RST` to avoid opening a full connection, requiring raw root packet creation capabilities (`CAP_NET_RAW`).

---

## ⚖️ Authorized-Use-Only Disclaimer

> **IMPORTANT LEGAL & ETHICAL NOTICE:**  
> This software is intended strictly for authorized educational, defensive, and diagnostic auditing purposes. Scanning hosts or networks without explicit, documented permission from the asset owner is illegal and unethical under national cybercrime laws (e.g., Computer Fraud and Abuse Act, IT Act 2000).  
> The author assumes no liability for misuse, damages, or violations caused by this tool. Only test against systems you personally own or have written authorization to assess (such as your own AWS EC2 instances).
