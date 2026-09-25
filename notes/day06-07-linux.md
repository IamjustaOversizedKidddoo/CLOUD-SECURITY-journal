# Days 06–07 — Linux Permissions, Users, Audit Logs, Cron & SSH Hardening

## 1. Executive Summary & Core Mechanics

Every cloud compute instance (AWS EC2), serverless execution environment, container runtime, and SIEM collector runs on Linux. To secure cloud infrastructure, an engineer must understand how Linux enforces access controls, tracks security events in system logs, schedules automated jobs, and hardens remote access daemons.

---

### 1. Users, Groups, and the Root Problem
* **User Identity (UID):** Every account has a numerical ID. Standard users start at UID `1000+` on modern distributions.
* **Group Identity (GID):** Primary and supplementary groups used to manage collective permissions.
* **The Root Account (UID `0`):** Possesses unrestricted kernel privileges and bypasses standard DAC (Discretionary Access Control) file permission checks.
* **The Security Principle:** Never run operational workloads or interactive sessions directly as `root`. A remote code execution (RCE) vulnerability in a service running as root grants immediate, unconstrained system compromise. Always operate under an unprivileged user account and escalate via `sudo` so that every privileged command is individually authenticated and logged.

---

### 2. Discretionary Access Control (DAC): Permissions Decoded

Every file and directory possesses an owner, an assigned group, and a 10-character permission string:

```text
  -  r w x  r - x  r - -
  |  \___/  \___/  \___/
Type Owner  Group  Others (World)
```

* **Position 1 (File Type):** `-` (regular file), `d` (directory), `l` (symbolic link).
* **Owner Triplet (Positions 2–4):** Permissions for the specific owning user.
* **Group Triplet (Positions 5–7):** Permissions for members of the file's assigned group.
* **Others Triplet (Positions 8–10):** Permissions for all other local users on the operating system.

#### Octal Permission Math:
Each permission bit carries a fixed binary weight:
* **`r` (Read):** $4$ ($2^2$)
* **`w` (Write):** $2$ ($2^1$)
* **`x` (Execute):** $1$ ($2^0$)
* **`-` (None):** $0$

```text
r w x = 4 + 2 + 1 = 7  (Full control)
r w - = 4 + 2 + 0 = 6  (Read & Write)
r - x = 4 + 0 + 1 = 5  (Read & Execute)
r - - = 4 + 0 + 0 = 4  (Read-only)
- - - = 0 + 0 + 0 = 0  (No access)
```

#### Production Permission Standards:
* `chmod 600 key.pem` $\implies$ `rw-------` (Only the owner can read/write; group and others have zero access. Required for SSH private keys).
* `chmod 640 app.conf` $\implies$ `rw-r-----` (Owner can modify; application group can read; world cannot access).
* `chmod 750 /opt/scripts/` $\implies$ `rwxr-x---` (Owner full control; group execute/traverse; world locked out).

---

### 3. OpenSSH Strict Client-Side Key Enforcement
If you attempt to connect using an overly permissive private key (e.g., `chmod 644 id_rsa`), the OpenSSH client intentionally terminates the connection:
```text
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0644 for 'id_rsa' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
```
* **Why this control exists:** A private key readable by other local unprivileged accounts on a multi-user machine compromises the fundamental guarantee of asymmetric cryptography. OpenSSH treats this condition as a fatal security violation.

---

## 2. Linux Logging Architecture & Incident Investigation

System and security events are managed by `systemd-journald` and `rsyslog`, written to `/var/log/`.

### Key Security Log Locations:
* **Debian / Ubuntu:** `/var/log/auth.log`
* **RHEL / CentOS / Amazon Linux:** `/var/log/secure`
* **System Events:** `/var/log/syslog` or `/var/log/messages`

### Real Log Evidence (Captured from Live Ubuntu Lab):
```text
2026-09-25T10:09:06.343330+00:00 LAPTOP-8IAE4RB0 useradd[461]: new user: name=testuser, UID=1000, GID=1000, home=/home/testuser, shell=/bin/sh
2026-09-25T10:09:06.414867+00:00 LAPTOP-8IAE4RB0 useradd[470]: new user: name=otheruser, UID=1001, GID=1001, home=/home/otheruser, shell=/bin/sh
2026-09-25T10:09:06.458148+00:00 LAPTOP-8IAE4RB0 su[475]: (to otheruser) root on none
2026-09-25T10:09:06.458792+00:00 LAPTOP-8IAE4RB0 su[475]: pam_unix(su-l:session): session opened for user otheruser(uid=1001) by (uid=0)
2026-09-25T10:09:06.608661+00:00 LAPTOP-8IAE4RB0 su[475]: pam_unix(su-l:session): session closed for user otheruser
```

### The Log Tampering Threat & Centralized SIEM
* **Attacker Playbook:** Upon compromising a server (especially if escalating to root), an adversary often attempts to truncate or delete `/var/log/auth.log` (`shred -u /var/log/auth.log` or `cat /dev/null > /var/log/auth.log`) to eliminate forensic artifacts of their origin IP and hijacked credentials.
* **Architectural Defense:** **Centralized Log Forwarding.** Log shippers (AWS CloudWatch Agent, Wazuh Agent, or Fluentbit) stream log entries over TLS to an external repository or SIEM (Splunk, OpenSearch, S3) within milliseconds of generation. Even if the local operating system is formatted by an attacker, the immutable remote logs preserve the attack timeline.

---

## 3. Cron Scheduling: Administrative Automation vs. Attacker Persistence

### 1. The 5-Field Crontab Syntax:
```text
 *  *  *  *  *  command_to_execute
 |  |  |  |  |
 |  |  |  |  +----- Day of Week (0 - 6) (Sunday = 0 or 7)
 |  |  |  +-------- Month (1 - 12)
 |  |  +----------- Day of Month (1 - 31)
 |  +-------------- Hour (0 - 23)
 +----------------- Minute (0 - 59)
```

* **Example (Nightly Security Audit at 2:30 AM):**
  ```bash
  30 2 * * * /usr/local/bin/aws-security-audit.sh >> /var/log/audit.log 2>&1
  ```
* **Example (Every 5 Minutes):**
  ```bash
  */5 * * * * /usr/local/bin/check-health.sh
  ```

### 2. Cron as a Threat Persistence Vector
* When threat actors gain access, one of their primary objectives is maintaining **persistence** through reboots.
* Placing a reverse shell or beaconing script into a user's crontab or `/etc/cron.d/` ensures that malware automatically respawns on schedule.
* **Incident Response Audit Checklist:**
  ```bash
  crontab -l                    # Inspect current user's crontab
  sudo crontab -u root -l       # Inspect root's crontab
  ls -la /etc/cron.*            # Audit cron.hourly, daily, weekly, monthly
  cat /etc/crontab              # Audit system-wide schedule table
  ls -la /var/spool/cron/crontabs/ # Direct spool inspection
  ```

---

## 4. SSH Server Hardening: `/etc/ssh/sshd_config`

### Baseline Hardening Directives:

```ini
# Enforce modern cryptography and access control
Port 2222                          # Optional: Reduces automated bot scanning noise
Protocol 2                         # Prohibits vulnerable SSHv1
PermitRootLogin no                 # Forces interactive users to log in as named unprivileged users
PasswordAuthentication no          # Disables password brute-forcing entirely; forces SSH keys
PubkeyAuthentication yes           # Enforces asymmetric public/private key verification
MaxAuthTries 3                     # Drops connection after 3 failed attempts
ClientAliveInterval 300            # Terminates idle sessions after 5 minutes
ClientAliveCountMax 0
AllowUsers deployer security-admin # Strict whitelist of authorized accounts
```

* **Restart Daemon to Apply:**
  ```bash
  sudo systemctl restart sshd # or sudo service ssh restart
  ```

---

## 5. Hands-on Lab: Real Execution Evidence

### Test: Multi-User Isolation & File Permissions
1. Created users `testuser` (UID 1000) and `otheruser` (UID 1001).
2. Generated confidential file `/home/testuser/myfile.txt` owned by `testuser`.
3. Applied strict least-privilege permissions:
   ```bash
   chmod 600 /home/testuser/myfile.txt
   ls -l /home/testuser/myfile.txt
   ```
   **Output:**
   ```text
   -rw------- 1 testuser testuser 17 Sep 25 10:09 /home/testuser/myfile.txt
   ```
4. Attempted unauthorized read access as `otheruser`:
   ```bash
   su - otheruser -c "cat /home/testuser/myfile.txt"
   ```
   **Output:**
   ```text
   cat: /home/testuser/myfile.txt: Permission denied
   ```
* **Conclusion:** The kernel DAC engine successfully intercepted and blocked the unauthorized read request before any file descriptor was granted.

---

## 6. Break It Safely: The Danger of `chmod 777`

### The Scenario:
An engineer runs:
```bash
chmod 777 /home/testuser/myfile.txt
```

### Analysis of the Exposure:
* **Resulting Permissions:** `-rwxrwxrwx`
* **Triplets Evaluated:**
  * Owner: Read, Write, Execute ($4+2+1 = 7$)
  * Group: Read, Write, Execute ($4+2+1 = 7$)
  * Others (World): **Read, Write, Execute ($4+2+1 = 7$)**

### Why Lynis, CIS Benchmarks, and Security Auditors Flag 777:
1. **Total Loss of Confidentiality:** Any unprivileged user or compromised service account (e.g., `www-data`, `nobody`, database runner) on the server can read the contents.
2. **Total Loss of Integrity:** Any process on the machine can modify, truncate, or overwrite the file with malicious payloads or false data.
3. **Execution / Code Injection:** If the file is an executable or shell script, any local process can inject malicious commands that execute under the file owner's context.
4. **Vulnerability to Lateral Movement:** Even if no attacker currently exists on the box, the presence of world-writable files creates trivial privilege-escalation stepping stones. If a low-privilege web daemon is breached via Local File Inclusion (LFI) or RCE, it immediately pivots to control or exfiltrate all 777 files.

### The Fix:
* Secrets, private keys, database credentials: **`chmod 600`** (`rw-------`) or **`chmod 400`** (`r--------`).
* Shared configuration files: **`chmod 640`** (`rw-r-----`) owned by `root:<servicegroup>`.

---

## 7. Interview Questions & Model Answers

### Beginner:
1. **What do the `r`, `w`, and `x` permission bits mean, and for which three categories?**  
   *Answer:* `r` stands for Read (view file contents / list directory), `w` stands for Write (modify/delete file contents / create/remove files in directory), and `x` stands for Execute (run as binary or script / traverse into directory). They are evaluated across three distinct categories: **Owner** (the user owning the file), **Group** (members of the assigned group), and **Others/World** (all other local users).

2. **What is the octal value of `rw-r--r--`, and what does it mean?**  
   *Answer:* The octal value is **`644`** (Owner: $4+2=6$, Group: $4$, Others: $4$). It means the owner has read and write privileges, while the group and all other users have read-only access.

3. **Where does SSH-related authentication activity get logged on Ubuntu?**  
   *Answer:* On Ubuntu and Debian-based systems, it is logged in **`/var/log/auth.log`**. (On RHEL/CentOS/Amazon Linux, it is logged in `/var/log/secure`).

### Intermediate:
4. **Why does OpenSSH refuse to use a private key file with `644` permissions?**  
   *Answer:* A `644` permission mode allows any other local user account or process on the machine to read the private key. Because the security of public-key cryptography requires the private key to remain strictly confidential to the keyholder, OpenSSH rejects the key to prevent credential theft.

5. **Why is `PermitRootLogin no` considered a security best practice rather than an inconvenience?**  
   *Answer:* Direct root login obscures accountability because actions cannot be traced back to an identifiable individual in audit logs. Forcing engineers to log in with named accounts and elevate via `sudo` ensures non-repudiation, generates granular audit trails in `/var/log/auth.log`, and prevents automated internet-wide brute-force attacks against the universally known `root` username.

6. **What is the security risk of a world-writable (`666` or `777`) configuration file?**  
   *Answer:* Any unprivileged user or compromised background daemon (e.g., `www-data`) can alter configuration parameters, hijack execution paths, insert malicious directives, or disable security controls, leading directly to privilege escalation or denial of service.

### Scenario-Based:
7. **During an incident investigation, you find an unfamiliar cron entry on a production server. Walk through your investigation steps.**  
   *Answer:*
   1. **Document and Preserve Evidence:** Record the exact cron line, file timestamp, and user context before modifying it.
   2. **Analyze the Payload:** Inspect the targeted script, binary, or network destination (checking for reverse shell syntax like `bash -i >& /dev/tcp/...` or `curl | sh`).
   3. **Check Creation & Modification History:** Inspect file metadata with `stat`, check shell history (`~/.bash_history`), and search `/var/log/auth.log` or `/var/log/syslog` around that timestamp for `CRON` executions and `sudo crontab -e` events.
   4. **Containment:** Disable the cron entry by commenting it out, terminate any running child processes/PIDs spawned by that job, and isolate the host for forensic memory/disk imaging.

8. **You notice `/var/log/auth.log` on a suspected host looks unusually truncated or empty. What does that suggest, and what should have been in place?**  
   *Answer:* This strongly suggests that an adversary achieved root/privileged access and purged the log file (`log wiping`) to erase evidence of lateral movement and initial access. To prevent this, the architecture should enforce **immutable centralized log shipping** (e.g., CloudWatch Logs Agent, Wazuh, or remote Syslog over TLS), ensuring logs are transmitted off-host in near-real-time to an append-only external SIEM that an endpoint-level compromise cannot tamper with.

### Difficult:
9. **Explain the difference between authentication and authorization using Linux's user/permission model as a concrete example, and explain where `sudo` fits.**  
   *Answer:*
   * **Authentication (AuthN):** Verifying the identity of an entity (*"Are you who you say you are?"*). In Linux, this occurs via PAM (Pluggable Authentication Modules) when a user provides a valid password or matches a cryptographic SSH key pair.
   * **Authorization (AuthZ):** Determining what an authenticated entity is permitted to execute or access (*"Are you allowed to do this?"*). In Linux, the kernel checks the file's DAC bits (`rwx`), file ownership (UID/GID), and capabilities before allowing an open/exec call.
   * **Where `sudo` fits:** `sudo` bridges both concepts. First, it **re-authenticates** the user by prompting for their password. Second, it consults the `/etc/sudoers` policy file to **authorize** whether that specific user or group has permission to execute the requested command with elevated (`root`) privileges.

---

## 8. Mini Assessment Self-Check
- [x] **Octal representation of `rwxrwxr-x`:** $775$ (Owner: $4+2+1=7$, Group: $4+2+1=7$, Others: $4+0+1=5$).
- [x] **Why run services as dedicated low-privilege users:** Implements the Principle of Least Privilege. If the service is exploited via an application flaw, the attacker's execution context is restricted to an unprivileged account without access to raw system resources or other user files.
- [x] **Command to list scheduled cron jobs:** `crontab -l` (or `sudo crontab -u <username> -l` for another account).
- [x] **Private key with `644` permissions fix:** The file is readable by group and world. Remediation: `chmod 600 id_rsa` (or `chmod 400 id_rsa` for read-only).
- [x] **Deleted `/var/log/auth.log` analysis:** Indicates the attacker obtained **root / UID 0** privileges (or `syslog` group write access). Architectural prevention: configure remote log aggregation (e.g., AWS CloudWatch Agent or remote syslog server with write-only / append-only permissions) so logs exist off-host immediately upon generation.
