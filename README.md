# TryHackMe Cybersecurity Write-ups

Welcome to my cybersecurity learning repository.

This repository contains my hands-on **TryHackMe penetration testing and cybersecurity write-ups**. I use this repository to document the techniques, commands, tools, troubleshooting steps, and lessons I learn while working through practical security labs.

The goal is not only to record the answers, but to understand **why each technique works, how vulnerabilities are identified, and how they can be exploited in an authorized lab environment.**

---

## 🎯 Purpose

I created this repository to:

- Document my cybersecurity learning journey
- Practice penetration testing techniques
- Improve Linux and Windows security knowledge
- Build practical privilege escalation skills
- Keep a personal reference of useful commands
- Practice documenting technical findings
- Create a portfolio of hands-on cybersecurity work

Each write-up focuses on the methodology and reasoning behind the techniques used during the lab.

---

## 📚 Write-ups

### 🐧 Linux Privilege Escalation

Write-ups covering techniques used to identify and exploit Linux privilege escalation vulnerabilities.

Topics include:

- Sudo misconfigurations
- SUID binaries
- SGID binaries
- PATH hijacking
- Linux capabilities
- Cron jobs
- Writable scripts
- NFS misconfigurations
- Enumeration
- Automated enumeration tools
- Privilege escalation through misconfigured applications

➡️ **[View Linux Privilege Escalation Write-ups](./Linux-Privilege-Escalation/)**

---

### 🪟 Windows Privilege Escalation

Write-ups covering Windows privilege escalation techniques and enumeration.

Topics include:

- Scheduled tasks
- Windows services
- Weak service permissions
- File and directory permissions
- Account and credential discovery
- Windows privilege enumeration
- Saved credentials
- `whoami`
- `icacls`
- `wmic`
- AccessChk
- winPEAS
- PrivescCheck

➡️ **[View Windows Privilege Escalation Write-ups](./Windows-Privilege-Escalation/)**

---

## 🛠️ Tools & Technologies

Throughout these labs, I practice working with tools and technologies such as:

### Reconnaissance & Enumeration

- Nmap
- Netcat
- FTP
- SSH
- DNS enumeration
- Service enumeration

### Linux

- Bash
- SSH
- Sudo
- SUID / SGID
- Cron
- Linux capabilities
- NFS
- LinPEAS
- pspy
- Linux Exploit Suggester

### Windows

- PowerShell
- Windows Command Prompt
- `whoami`
- `icacls`
- `wmic`
- `schtasks`
- `sc`
- AccessChk
- winPEAS
- PrivescCheck
- Impacket

### Web & Offensive Security

- Burp Suite
- Gobuster
- ffuf
- Nikto
- Metasploit
- Meterpreter

---

## 🧠 What My Write-ups Include

I try to structure my write-ups around the actual penetration testing process:

```text
Enumeration
     ↓
Identify potential vulnerability
     ↓
Analyze the misconfiguration
     ↓
Exploit the vulnerability
     ↓
Obtain access / escalate privileges
     ↓
Verify the result
     ↓
Document the technique
