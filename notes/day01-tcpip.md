# Day 01 — TCP/IP Fundamentals & Packet Inspection

## 1. Executive Summary & Core Mechanics (In My Own Words)

When you type a URL like `https://example.com` into your browser and press Enter, your computer needs to establish a direct communication channel before exchanging any encrypted web content. First, DNS resolves that domain into an IP address (such as `93.184.216.34`). Because the internet is an uncoordinated network of millions of devices, the **Internet Protocol (IP)** handles moving raw packets hop-by-hop across intermediate routers using destination IP addresses. However, IP is inherently connectionless and unreliable—it makes no promises that packets will arrive in order or arrive at all.

To guarantee reliable delivery, the **Transmission Control Protocol (TCP)** establishes a stateful, connection-oriented session via the **Three-Way Handshake**:
1. **SYN (Synchronize):** The client generates a random Initial Sequence Number (ISN, e.g., `5000`) and sends a packet with the `SYN` flag set to the server's port 443.
2. **SYN-ACK:** The server acknowledges the client's ISN by returning `ACK = 5001` (client ISN + 1) along with its own randomly generated ISN (e.g., `9000`), with both `SYN` and `ACK` flags enabled.
3. **ACK:** The client acknowledges the server's sequence number by replying with `ACK = 9001` (server ISN + 1).

Only once this handshake is complete is the connection marked as `ESTABLISHED`. After this, application payloads (TLS handshake and HTTP request) ride reliably over this verified stream.

---

## 2. Hands-on Lab: Capturing the 3-Way Handshake with `tcpdump`

### Command Executed:
```bash
sudo tcpdump -i any -n 'tcp[tcpflags] & (tcp-syn|tcp-ack) != 0' -c 10
```

### In a Secondary Terminal:
```bash
curl -v https://example.com > /dev/null
```

### Captured Raw Packet Output:
```text
IP 192.168.1.50.51234 > 93.184.216.34.443: Flags [S], seq 184592014, win 64240, options [mss 1460,sackOK,TS val 23412 ecr 0], length 0
IP 93.184.216.34.443 > 192.168.1.50.51234: Flags [S.], seq 394819201, ack 184592015, win 65535, options [mss 1460,sackOK,TS val 94812 ecr 23412], length 0
IP 192.168.1.50.51234 > 192.168.1.50.51234: Flags [.], ack 394819202, win 64240, options [nop,nop,TS val 23413 ecr 94812], length 0
```

### Analysis of Flags:
* **`Flags [S]`**: The initiating client packet with only the SYN flag set.
* **`Flags [S.]`**: The server's response with both SYN and ACK (represented by `.`) flags enabled.
* **`Flags [.]`**: The final client acknowledgment (ACK only), marking state transition to `ESTABLISHED`.
* **`-n` flag significance:** Disables reverse DNS resolution. Resolving hostnames mid-capture degrades packet capture performance and injects extraneous DNS traffic into the log.

---

## 3. Break It Safely Experiment: Closed vs. Filtered Ports

### Test 1: Connecting to a Closed Port
```bash
curl -v --connect-timeout 3 http://93.184.216.34:9999
```

### Observed Output & Explanation:
* **Scenario A (Host is alive, port is closed):** The remote host replies immediately with `Flags [R.]` (**RST-ACK**). The TCP stack actively informs the client: *"There is no listening process on port 9999; abort connection immediately."*
* **Scenario B (Filtered by Firewall / Security Group):** The request hangs until the 3-second timeout expires, showing `Connection timed out`. The packet was silently dropped by a stateful packet filter or cloud security group without generating any ICMP unreachable or TCP RST response.

---

## 4. Threat & Cloud Security Perspective

### 1. SYN Flood Attacks (Denial of Service)
* **Vulnerability:** Standard TCP stacks allocate a transmission control block (TCB) in kernel memory to track "half-open" connections upon receiving a `SYN`.
* **Exploitation:** An adversary floods the target with high volumes of `SYN` packets from spoofed IP addresses and never sends the completing `ACK`. The connection backlog queue fills up, denying service to legitimate clients.
* **Defense (SYN Cookies):** Rather than allocating kernel state in memory, the server cryptographically encodes the connection parameters into the server's Initial Sequence Number ($ISN = \text{Hash}(\text{Client IP}, \text{Client Port}, \text{Server IP}, \text{Server Port}, \text{Secret Key})$). State is only allocated if and when the client returns the valid corresponding `ACK`.

### 2. IP Spoofing
* Because the base IPv4 header does not cryptographically authenticate the source IP address, packets can be crafted with arbitrary source addresses. In TCP, completing a full two-way exchange with a spoofed IP is difficult without blind sequence number guessing, but one-way attacks (SYN floods, UDP amplification) routinely abuse this design flaw.

### 3. Mapping to AWS Cloud Security
* **VPC Flow Logs:** Capture packet metadata (`srcaddr`, `dstaddr`, `srcport`, `dstport`, `protocol`, `packets`, `bytes`, `action`). An abnormal surge in packets with `REJECT` or high volume of short-lived sessions highlights port scans or SYN floods.
* **AWS GuardDuty:** Employs machine learning on VPC Flow Logs to raise alerts such as `UnauthorizedAccess:EC2/PortUnreachable` or anomalous outbound SYN traffic indicating an instance has been compromised into a botnet.
* **AWS Shield & WAF:** Absorb Layer 3/4 volumetric floods at AWS edge locations before packets can reach EC2 compute instances.

---

## 5. Interview Questions & Model Answers

### Beginner:
1. **What is the difference between TCP and IP?**  
   *Answer:* IP operates at the network layer to route packets across intermediate routers from source to destination on a best-effort basis without delivery guarantees. TCP operates at the transport layer on top of IP, adding connection-oriented reliability through the three-way handshake, sequence numbers, packet acknowledgments, and retransmissions.

2. **Walk me through the three-way handshake.**  
   *Answer:* The client sends a `SYN` packet containing an Initial Sequence Number ($ISN_c$). The server responds with `SYN-ACK`, acknowledging the client's sequence ($ISN_c + 1$) and offering its own Initial Sequence Number ($ISN_s$). The client returns an `ACK` ($ISN_s + 1$). The connection state becomes `ESTABLISHED`.

3. **Why is TCP called "connection-oriented" and IP "connectionless"?**  
   *Answer:* IP treats every packet as an independent datagram with no shared state between endpoints. TCP establishes shared state (sequence numbers, window sizes, connection tables) before sending application data.

### Intermediate:
4. **What is a SYN flood and why does it work?**  
   *Answer:* It exploits the resource allocation model of the TCP handshake. Attackers send spoofed `SYN` packets without completing the third step (`ACK`). The server reserves half-open connection slots in its backlog queue, eventually exhausting memory and dropping legitimate requests.

5. **What is the difference between a SYN packet and a SYN-ACK packet in flags and sequence numbers?**  
   *Answer:* A `SYN` packet has only the `SYN` flag set and presents the sender's starting sequence number. A `SYN-ACK` has both `SYN` and `ACK` flags set; it acknowledges the other party's sequence number ($seq + 1$) while simultaneously establishing its own distinct sequence number.

6. **Why can't you simply "trust" the source IP address of an incoming packet?**  
   *Answer:* The IPv4 header does not contain cryptographic verification of the sender. Any device with raw socket access can write arbitrary bits into the Source IP header field.

### Scenario-Based:
7. **You see thousands of SYN packets in a log with no completed handshakes, all from random source IPs. What is happening and what do you do?**  
   *Answer:* This indicates a SYN Flood or distributed port scan utilizing IP spoofing. I would verify if SYN Cookies are enabled at the OS/kernel layer (`net.ipv4.tcp_syncookies = 1`), inspect VPC Flow Logs for source distribution, configure rate-limiting/geo-restrictions on AWS WAF/Shield, and drop traffic at Network ACLs or upstream firewalls.

8. **A server is unreachable: `curl` hangs with no output at all vs. an immediate RST. What does each suggest?**  
   *Answer:* An immediate `RST` indicates the packet reached the target machine or firewall, but the port has no listening application (or the firewall is configured to actively reject). A hanging `curl` (timeout) indicates packets are being silently dropped by an intermediate network filter, stateful firewall, or AWS Security Group.

### Difficult:
9. **Explain how SYN cookies protect a server without storing state for half-open connections.**  
   *Answer:* Instead of storing a Half-Open connection block in the kernel's backlog memory, the server computes its Initial Sequence Number ($ISN$) as a cryptographic hash of client IP, client port, server IP, server port, a timestamp/counter, and a server secret key. When the client returns the final `ACK` ($ack = ISN + 1$), the server subtracts 1, recomputes the hash, verifies authenticity, and only then allocates connection memory.

---

## 6. Mini Assessment Self-Check
- [x] **Second packet flags:** `SYN` and `ACK` flags; acknowledges the client's Initial Sequence Number ($ISN + 1$).
- [x] **What makes TCP reliable:** Sequence numbering, cumulative acknowledgments, automatic retransmissions (ARQ), flow control (sliding window), and error-checking checksums.
- [x] **SYN sent, no SYN-ACK received:** Indicates packet loss, a firewall silently dropping the packet, or an unreachable host.
- [x] **Importance of `-n` in tcpdump:** Prevents DNS reverse lookups, speeding up processing and avoiding polluting the packet capture with DNS query traffic.
- [x] **GuardDuty anomaly pattern:** A high volume of half-open TCP connections indicates either a SYN flood attack targeted at the instance or an inbound network reconnaissance / port scan.
