import subprocess
import re
from collections import Counter
import platform
import getpass
import hashlib
import json
import os
from datetime import datetime

print("===SYSTEM==")
print("OS     :",platform.system())
print("Kernel :",platform.release())
print("User   :",getpass.getuser())

print()
print("=== NETWORK ===")

result = subprocess.run(["firewall-cmd", "--state"], capture_output=True, text=True)
firewall_active = (result.returncode == 0)
if result.returncode == 0:
    print("Firewall :","ACTIVE")
else:
    print("Firewall :", "NOT RUNNING")

result = subprocess.run(["ss", "-tln"], capture_output=True, text=True)
lines = result.stdout.strip().split("\n")
ports = lines[1:]

print("Open ports:", len(ports))
for line in ports:
    parts = line.split()
    print("  -",parts[3])

print()
print("===ACCOUNTS===")

uid0_users = []
login_users = []

with open("/etc/passwd") as f:
    for line in f:
        parts = line.strip().split(":")
        name = parts[0]
        uid = int(parts[2])
        shell = parts[6]
        if uid == 0:
            uid0_users.append(name)
        if uid >= 1000 and "nologin" not in shell:
            login_users.append(name)

print("Root-power accounts (UID 0):", uid0_users)
print("Normal users who can log in:", login_users)

if len(uid0_users) > 1:
    print("WARNING: extra root-level account found!")
else:
    print("OK: only root has root power")

print()
print("===AUTHENTICATION===")

result = subprocess.run(["journalctl", "-u", "sshd", "--no-pager"], capture_output=True, text=True)

failed_ips = []
for line in result.stdout.split("\n"):
    if "Failed password" in line:
        match = re.search(r"from (\S+) port", line)
        if match:
            failed_ips.append(match.group(1))

print("Failed logins:",len(failed_ips))

counts = Counter(failed_ips)
suspicious = []
for ip, count in counts.items():
    print("  ",ip, "->", count, "failed attempts")
    if count >= 3:
        suspicious.append(ip)

print("Suspicious IPs:", len(suspicious))

print()
print("=== FILE INTEGRITY ===")

files_to_watch = [
    "/etc/passwd",
    "etc/group",
    "/etc/hosts",
    "/etc/ssh/sshd_config",
]
baseline_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "baseline.json")

def get_hash(path):
    try:
        with open(path, "rb") as f:
           return hashlib.sha256(f.read()).hexdigest()
    except (PermissionError, FileNotFoundError):
        return "UNREADABLE"

current = {}
for path in files_to_watch:
    current[path] = get_hash(path)

changed_files = []

if not os.path.exists(baseline_path):
    with open(baseline_path, "w") as f:
       json.dump(current, f, indent=2)
    print("First run: fingerprints saved as the baseline.")
else:
    with open(baseline_path) as f:
        old = json.load(f)
    for path in files_to_watch:
        if current[path] == "UNREADABLE":
            print(path, ": cannot read (use sudo)")
        elif old.get(path) == current[path]:
            print(path, ": OK, no change")
        else:
            print(path, ":CHANGED!!!")
            changed_files.append(path)
    print("Changed files:",len(changed_files))

print()
print("=== SECURITY SUMMARY ===")

score = 0
findings = []

if firewall_active:
    findings.append("OK: Firewall is active")
else:
    score += 3
    findings.append("WARNING: Firewall is not running")

if len(uid0_users) > 1:
    score += 3
    findings.append("WARNING: Extra root-level account found")
else:
    findings.append("OK: Only root has root power")   

if len(suspicious) >0:
    score += 2
    findings.append("WARNING: " + str(len(suspicious)) + " suspicious IP(s) detected")
else:
    findings.append("OK: No suspicious IPs")

if len(changed_files) > 0:
    score += 2
    findings.append("WARNING: " + str(len(changed_files)) + "monitored file(s) changed")
else:
    findings.append("OK: No monitored files changed")

if score == 0:
    risk = "LOW"
elif score <= 3:
    risk = "MEDIUM"
else:
    risk = "HIGH"

print("Risk Level:", risk)
for item in findings:
    print("  ", item)

report_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
os.makedirs(report_dir, exist_ok=True)
report_path = os.path.join(report_dir, "security_report.txt")

with open(report_path, "w") as f:
    f.write("LINUX SECURITY AUDIT REPORT\n")
    f.write("Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n") 
    f.write("Risk Level: " + risk + "\n\n")
    f.write("Failed logins: " + str(len(failed_ips)) + "\n")
    f.write("Open ports: " + str(len(ports)) + "\n\n")
    for item in findings:
        f.write(item + "\n")

print("Report saved to:", report_path)
