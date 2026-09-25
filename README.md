# 🛡️ Cloud Security Engineering Journal

> **Target:** Cloud Security Engineer / DevSecOps Engineer (8–10 LPA)  
> **Roadmap:** 90-Day Zero to Job Ready  
> **Repository Purpose:** Documenting daily hands-on labs, packet analysis, infrastructure-as-code, detection engineering, and cloud security implementations.

---

## 🗺️ Roadmap Progress

### Phase 1: Core Foundations, AWS & Automation (Days 1–30)
- [x] **Week 1 (Days 1–10): Networking, Linux & Git**
  - [x] [Day 01: TCP/IP Fundamentals, 3-Way Handshake & Packet Inspection](notes/day01-tcpip.md)
  - [x] [Days 02–03: IPv4, Subnetting, CIDR Math & the OSI Model](notes/day02-03-subnetting-osi.md)
  - [x] [Days 04–05: Ports, Protocols (HTTP/S, SSH, DNS) & TLS Cryptography](notes/day04-05-protocols.md)
  - [x] [Days 06–07: Linux Security, File Permissions, Audit Logs & SSH Hardening](notes/day06-07-linux.md)
  - [x] [Days 08–09: Git Architecture, Commit Signing, SSH Keys & PR Workflows](notes/day08-09-git.md)
  - [x] [Day 10: AWS Ubuntu Provisioning & Network Diagnostic Tooling](notes/day10-aws-port-scanner.md)
  - **📌 Deliverable 1:** [Automated Port Scanner Script (Python)](projects/port-scanner/)
- [ ] **Week 2 (Days 11–20): AWS Core Security & Python Automation**
  - [ ] Days 11–12: AWS Global Infrastructure, IAM Access Keys & Security Controls
  - [ ] Days 13–14: EC2 Security Hardening & S3 Public Access Prevention
  - [ ] Days 15–16: IAM Policies Deep Dive (Evaluation Logic, Conditions, MFA Enforcement)
  - [ ] Days 17–18: Python Security Automation (Requests, JSON Parsing, OS Interaction)
  - [ ] Days 19–20: Automated AWS Auditing using Boto3
  - **📌 Deliverable 2:** *AWS Security Auditor (Boto3)*
- [ ] **Weeks 3–4 (Days 21–30): Cloud Networking (VPC) & Terraform IaC**
  - [ ] Days 21–22: Custom VPC Architecture, Route Tables, NAT Gateways & Subnets
  - [ ] Days 23–24: Stateful Security Groups vs Stateless NACLs, Bastions & SSM
  - [ ] Days 25–26: Terraform HCL Architecture, Remote State Locking & Providers
  - [ ] Days 27–28: Production Multi-Tier VPC Deployment with Terraform
  - [ ] Days 29–30: Security Architecture Validation & Documentation
  - **📌 Deliverable 3:** *Multi-Tier Production VPC (Terraform)*

---

### Phase 2: Cloud Defense & Security Services (Days 31–60)
- [ ] **Weeks 5–6 (Days 31–42): AWS Native Security Services** (KMS, GuardDuty, Security Hub, WAF, CloudTrail, Config)
- [ ] **Weeks 7–8 (Days 43–60): DevSecOps & Container Security** (Docker Hardening, Trivy, GitHub Actions CI/CD SAST/SCA)
- **📌 Deliverable 4:** *DevSecOps CI/CD Security Pipeline*

---

### Phase 3: SIEM, Capstone & Interview Preparation (Days 61–90)
- [ ] **Weeks 9–10 (Days 61–75): SIEM & SOC Automation** (Wazuh/Splunk, VPC Flow Logs, Custom Detection Rules, Lambda Auto-Remediation)
- [ ] **Weeks 11–12 (Days 76–90): Capstone & MNC Hiring Blitz**
- **📌 Deliverable 5:** *Automated Cloud Incident Detection & Response System*

---

## 🛠️ Security Tooling & Tech Stack
* **Networking & Packet Analysis:** `tcpdump`, `Wireshark`, `curl`, `dig`, `nmap`
* **Operating Systems:** Linux (Ubuntu/Debian), Bash scripting
* **Cloud Platform:** Amazon Web Services (AWS)
* **Automation & Scripting:** Python 3, `boto3`, Terraform
* **Security & Detection:** AWS GuardDuty, Security Hub, VPC Flow Logs, CloudTrail, AWS WAF, AWS KMS
