# CyberAudit: Linux Security Audit Tool

CyberAudit is a Python tool that audits a Linux system and produces a security report with a risk level (LOW, MEDIUM or HIGH).
It checks the firewall, open ports, user accounts, failed SSH logins and file integrity, then saves a text report. 

I built it while studying for the Red Hat RHCSA exam, to practice Linux administration and basic security monitoring

**Built and tested on** Rocky Linux 10.2 (a RHEL-compatible distribution) in a VirtualBox VM.

## Features
- **AREA:** WHAT IT CHECKS
- **System:** OS, kernel version, current user
- **Network:** firewall status, listening ports
- **Accounts:** extra root-level (UID 0) accounts, users who can log in
- **Authentication:** failed SSH logins, IPs with repeated failures
- **File integrity:** SHA-256 hashes of key files compared against a saved baseline
- **Report:** risk score (LOW / MEDIUM / HIGH) saved to a text file

## How to run
```
git clone https://github.com/annsunil/CyberAudit.git
cd CyberAudit
sudo python3 security_audit.py
```
- Requires Python 3 on a RHEL-based Linux system (Rocky, AlmaLinux, RHEL).
- Run it with `sudo` so it can read `sshd_config` and the system journal.
- The first run creates `baseline.json`, which stores the fingerprints of the monitored files. Later runs compare against it.
- To reset the baseline after a change you made on purpose, delete `baseline.json` and run again.

## How the risk score works
- Firewall not running = 3 
- Extra root-level account = 3 
- Suspicious IP (3+ failed logins) = 2 
- Monitored file changed = 2 

Total of 0 = **LOW**, 1-3 = **MEDIUM**, 4+ = **HIGH**

## What I learned
- How `/etc/passwd` is structured, and why a second UID 0 account is a warning sign.
- How SHA-256 hashing can detect that a file was modified.
- How to read authentication failures from the system journal and spot repeated attempts from one IP.
- How to turn raw system information into a simple risk score and report.

## Limitations and Future improvements
- Only checks IPv4/IPv6 TCP ports, not UDP
- Only reads SSH login failures
- Planned: interactive menu, HTML report, password policy checks, file permission checks

## Disclaimer
This tool is for learning and for auditing systems you own or have permission to audit. It only reads system information and does not change anything on the system (apart from writing its own baseline and report files).

## Author
Ann Sunil, Computer Science Engineering (Cybersecurity) student
[LinkedIn](https://www.linkedin.com/in/ann-sunil)
