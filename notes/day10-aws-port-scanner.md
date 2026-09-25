# Day 10 — AWS Ubuntu Setup & Deliverable 1: Automated Port Scanner

## 1. Executive Summary & AWS Cloud Infrastructure

Day 10 marks the culmination of Week 1: moving from local network simulations to managing real internet-facing cloud compute resources and building **Deliverable 1 (Automated Port Scanner)**.

---

### 1. Amazon EC2 Architecture & `cloud-init`
* **EC2 (Elastic Compute Cloud):** Virtual machines running on AWS's hypervisor (Nitro System / Xen).
* **Automated Key Pair Provisioning:** When an EC2 instance launches, AWS does not install passwords. Instead, AWS uses **`cloud-init`** (an open-source multi-distribution package) to inject the selected public key into `/home/ubuntu/.ssh/authorized_keys` during the initial bootstrap cycle.
* **Workstation Key Permissions:** The private key downloaded from AWS (`mykey.pem`) must be restricted using `chmod 600 mykey.pem` before OpenSSH permits connection:
  ```bash
  chmod 600 mykey.pem
  ssh -i mykey.pem ubuntu@<EC2_PUBLIC_IP>
  ```

---

### 2. AWS Security Groups (Virtual Stateful Firewalls)
A **Security Group (SG)** is an instance-level virtual firewall operating at **Layer 4 (Transport)**:
* **Default-Deny Model:** All inbound traffic is blocked by default unless explicitly allowed by an ingress rule.
* **Stateful Filtering:** If an inbound connection is allowed (e.g., TCP 22 ingress from your IP), the corresponding outbound response packets are **automatically tracked and permitted**, regardless of outbound security group rules.
* **Critical Security Baseline:** Never allow `0.0.0.0/0` (the entire internet) on administrative ports like SSH (`22`) or RDP (`3389`). Ingress should always be locked down to `"My IP"` (`/32`) or corporate VPN CIDR blocks.

---

### 3. Cloud Cost Hygiene & Free Tier Checkpoint
* **Free-Tier Limits:** `t2.micro` or `t3.micro` allows 750 hours/month of compute for the first 12 months.
* **Hidden Cost Traps:**
  1. **Idle Elastic IPs:** AWS charges for public Elastic IPs allocated to an account that are not actively attached to a running EC2 instance.
  2. **Orphaned EBS Volumes:** Detaching an instance without terminating its root or secondary EBS volumes results in continued storage billing.
* **Stop vs. Terminate:**
  * **Stop:** Halts compute billing while preserving disk state and installed packages for subsequent labs.
  * **Terminate:** Permanently deletes the virtual machine and attached root storage.

---

## 2. Hands-on Lab: Real SSH Server Hardening

On the live Ubuntu instance, apply the hardening baseline learned on Days 6–7:

```bash
# 1. Edit the OpenSSH daemon configuration
sudo nano /etc/ssh/sshd_config

# 2. Enforce strict key-only access and disable anonymous root
PasswordAuthentication no
PermitRootLogin no

# 3. Reload daemon without dropping active sessions
sudo systemctl restart sshd

# 4. Confirm successful key authentication in audit log
sudo tail -20 /var/log/auth.log
```

---

## 3. Deliverable 1: Automated TCP Port Scanner

The standalone production project is located at:  
👉 **[`projects/port-scanner/`](../projects/port-scanner/)** (Repository: [`port-scanner`](https://github.com/IamjustaOversizedKidddoo/port-scanner))

### Core Transport-Layer Architecture (`socket`):
```python
import socket

def scan_port(target_ip, port, timeout=1.0):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        # connect_ex performs the full TCP 3-way handshake under the hood
        result = sock.connect_ex((target_ip, port))
        return result == 0  # 0 indicates connection succeeded (OPEN)
```

### Key Technical Mechanisms:
1. **`socket.AF_INET` & `socket.SOCK_STREAM`:** Directly constructs raw transport-layer TCP streams across IPv4.
2. **`sock.settimeout(1.0)`:** Essential for port scanning. When a port is **filtered** by an AWS Security Group or firewall, packets are silently dropped without generating an `RST`. Without an explicit timeout, socket calls would block and hang indefinitely.
3. **`connect_ex()` vs `connect()`:** `connect()` throws an unhandled `ConnectionRefusedError` exception on closed ports. `connect_ex()` returns a C-style integer error code (`0` for success, errno `111` / `10061` for refused), maximizing scanning speed and cleaner control flow.
4. **Concurrency (`ThreadPoolExecutor`):** Implements multi-threading across 50–100 workers, reducing scan time for 1,024 ports from ~15 minutes to under 15 seconds.

---

## 4. Break It Safely: Live Security Group State Changes

### The Experiment:
Validating that the port scanner accurately detects dynamic security group adjustments in real time:

1. **Baseline Scan:** Scan ports 8075–8085 against the host. Scanner reports:
   ```text
   Total Ports Scanned: 11 | Open Ports Found: 0
   ```
2. **Open Port in Security Group:** Add an inbound rule for TCP `8080` from your IP.
3. **Bind a Listener:** Run a test HTTP service:
   ```bash
   python3 -m http.server 8080
   ```
4. **Re-Scan:** Run the scanner again:
   ```text
   [+] Port 8080/TCP : OPEN  --> [HTTP-PROXY]
   Open Ports Found : 1
   ```
5. **Remediation & Closure:** Terminate the Python server and delete the temporary security group rule. Subsequent scans immediately revert to closed/filtered.

---

## 5. Interview Questions & Model Answers

### Beginner:
1. **What does "stateful" mean in the context of an AWS Security Group?**  
   *Answer:* "Stateful" means the security group automatically tracks the state of established connections. When an inbound connection is permitted by an ingress rule, return outbound response packets for that session are automatically allowed without needing an explicit egress rule (unlike stateless Network ACLs, which require rules for both directions).

2. **Why does a port scanner need a timeout on each connection attempt?**  
   *Answer:* When a port is filtered (e.g., protected by a firewall or Security Group that silently drops packets instead of sending an active rejection), the client socket will wait for the operating system's default TCP connection timeout (often 30–120 seconds). A configured timeout (e.g., 1 second) prevents the scanner from hanging on silent ports.

3. **What does `connect_ex()` return on a successful connection?**  
   *Answer:* It returns integer `0`, indicating that the three-way handshake (`SYN` $\to$ `SYN-ACK` $\to$ `ACK`) completed successfully.

### Intermediate:
4. **Why is opening SSH (port 22) to `0.0.0.0/0` considered a serious misconfiguration even with key-only auth enabled?**  
   *Answer:* While key-only auth prevents password brute-forcing, exposing port 22 to the world unnecessarily enlarges the instance's public attack surface. It exposes the OpenSSH daemon to zero-day vulnerabilities (e.g., regreSSHion / CVE-2024-6387), floods auth logs with millions of automated bot probes, and risks denial-of-service against the SSH daemon. Network access should always be restricted via least-privilege CIDR rules.

5. **What is the difference between a port showing as "closed" vs. "filtered"?**  
   *Answer:* A **closed** port means the packet reached the target operating system, but no process was listening on that port, causing the OS network stack to reply immediately with an active `RST` (Reset) packet. A **filtered** port means an intermediate firewall, NACL, or Security Group silently discarded the packet, returning no response at all and forcing the scanner to time out.

6. **Why does AWS inject public keys via `cloud-init` rather than requiring manual copying after boot?**  
   *Answer:* Manual post-boot key transfer presents a chicken-and-egg dilemma: you cannot access a secure, passwordless instance over SSH to paste a key without already having authentication. `cloud-init` solves this by consuming instance metadata provided by AWS at launch time and writing the public key directly into the root filesystem before enabling network daemon logins.

### Scenario-Based:
7. **You scan an EC2 instance and find port 3306 (MySQL) unexpectedly open to the internet. Walk through investigation and remediation.**  
   *Answer:*
   1. **Immediate Ingress Revocation:** Check the instance's Security Group and immediately remove or restrict the ingress rule permitting `0.0.0.0/0:3306`.
   2. **Inspect Process Binding:** SSH into the instance and run `ss -tulpn | grep 3306` to determine whether MySQL is bound to `0.0.0.0` or `127.0.0.1`. Update `my.cnf` to bind exclusively to `localhost` or private subnet interfaces.
   3. **Audit Database Logs:** Inspect MySQL authentication and query logs for brute-force attempts or unauthorized logins during the exposure period.
   4. **Audit CloudTrail:** Identify who created or modified the Security Group rule (`AuthorizeSecurityGroupIngress`) to identify root-cause human error or IAM compromise.

8. **A colleague says "we don't need to restrict SSH security group source IP because we have key-only auth enabled." How do you respond?**  
   *Answer:* I would explain the core cloud security principle of **defense-in-depth**. Relying on a single control creates a single point of failure. If a vulnerability is discovered in the SSH daemon, or if a developer's private key is leaked on an unsecured workstation, a network-level restriction (Security Group) serves as a critical secondary barrier that prevents exploitation from unauthorized IPs.

### Difficult:
9. **Explain why a TCP connect scan is easily detected, and how a SYN scan differs mechanically.**  
   *Answer:* A TCP connect scan uses standard operating system sockets to complete the full three-way handshake (`SYN` $\to$ `SYN-ACK` $\to$ `ACK`). Because the connection is formally established, the OS hands the connection to the application layer, which immediately logs the connection (or abort) in web server / system event logs. A **SYN scan (half-open scan)** sends a `SYN`, waits for the `SYN-ACK` to determine the port is open, and immediately terminates the exchange by sending a `RST` before the handshake completes. Because the connection is never established, it rarely appears in application logs. Implementing a SYN scan requires raw socket privileges (`SOCK_RAW` / `CAP_NET_RAW` / root) to manually craft IP and TCP headers.

---

## 6. Mini Assessment Self-Check
- [x] **Mechanism placing SSH key on new EC2:** `cloud-init` fetching the key from the AWS instance metadata service during first boot.
- [x] **Why `t3.micro` matters:** It is AWS Free-Tier eligible, providing 750 free hours/month while avoiding inadvertent compute charges.
- [x] **Port timing out meaning:** The port is **filtered**; packets are being silently dropped by an upstream firewall or Security Group without returning an `RST`.
- [x] **Why restrict SSH source IP:** Prevents zero-day vulnerability exploitation in OpenSSH, mitigates denial-of-service, eliminates automated bot scanning noise in logs, and enforces defense-in-depth.
- [x] **Port 22 showing filtered a week later explanations:**
  1. Your home/workstation public IP address changed (dynamic ISP IP), so your Security Group rule no longer matches your current IP.
  2. The EC2 instance was stopped, terminated, or its security group rules were altered.
  *Check:* Check your current public IP via `curl ifconfig.me` and compare against the Security Group ingress rule in the AWS console.

---

## 7. Lab Cleanup Checklist
- [x] Terminated or Stopped test EC2 instances in AWS Console.
- [x] Verified zero unassociated Elastic IPs (to avoid hourly idle billing).
- [x] Removed temporary test rules (e.g., port 8080 ingress).
