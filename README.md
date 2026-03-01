# Advanced Linux Security Audit Script

## Overview

This project provides a **comprehensive Linux security audit script** written in Bash.
It performs deep system inspection across users, services, kernel settings, networking, logging, firewall rules, SSH configuration, rootkit indicators, and more.

Designed for:

* System administrators
* DevOps engineers
* Security engineers
* Red team / blue team labs
* Hardening verification

---

## Features

### 🔐 Account & Authentication Security

* UID 0 user checks
* Empty / locked password detection
* Password policy validation
* PAM configuration audit
* Sudo configuration review
* Failed login & brute force detection

### 🖥 System Hardening Checks

* Kernel security (sysctl parameters)
* SSH hardening verification
* File permission validation
* World-writable file detection
* Rootkit indicators scan
* Suspicious process detection
* Crypto-miner behavior hints
* USB security checks

### 🌐 Network Security

* Open port inspection
* Suspicious connections
* Malicious port detection
* Firewall status (UFW / firewalld / iptables / nftables)
* IPtables policy check

### 📦 Package & Update Security

* Pending security updates
* Vulnerable service presence (Apache, Nginx, OpenSSH, etc.)

### 📝 Logging & Monitoring

* Audit daemon status
* Rsyslog validation
* Log rotation checks
* Large log file detection

### 🔑 SSL / TLS Review

* Certificate expiration checks

### 🧠 Rootkit & Integrity Checks

* Known rootkit file indicators
* Hidden processes
* Suspicious kernel modules

---

## Requirements

* Linux system (Debian, Ubuntu, RHEL, CentOS, etc.)
* Bash shell
* Root privileges recommended
* Common utilities:

  * `netstat` or `ss`
  * `systemctl`
  * `iptables` or `nft`
  * `openssl`
  * `auditctl` (optional)

---

## Installation

Clone or download the script:

```bash
git clone https://github.com/4n4rk135/linux-audit-security.git
cd linux-audit-security
```

Or simply download the script file directly.

Make it executable:

```bash
chmod +x linux_security_audit.sh
```

---

## Usage

Run with root privileges:

```bash
sudo ./linux_security_audit.sh
```

Optional: Save output to a file

```bash
sudo ./linux_security_audit.sh > audit_report.txt
```

---

## Output Format

The script uses colored output:

* 🟢 PASS – Secure configuration detected
* 🟡 WARN – Potential risk or needs review
* 🔴 FAIL – Security issue detected
* 🔵 INFO – Informational output

---

## Important Notes

* This is a **baseline security audit tool**, not a replacement for:

  * Lynis
  * OpenSCAP
  * CIS Benchmark scanners
  * Enterprise EDR solutions

* False positives are possible.

* Always review findings before making changes.

* Use only on systems you own or are authorized to assess.

---

## Recommended Improvements

Future enhancements could include:

* JSON output mode
* HTML report generation
* CIS benchmark scoring
* Email reporting
* Log integrity verification
* Malware hash scanning
* Docker/Kubernetes audit modules

---

## License

MIT License (or specify your preferred license)

---

## Author

Created by **aguskb**
* Security and Automation Enthusiast
* Father with 2 daughters (k4li and 3nigma)
