# Brute Force Detection, Visualization & IP Blocking System

## 1. Project Overview
This is a small, local Python web app that watches login attempts on a test
`/login` endpoint, detects brute-force behavior (too many failed logins from
one IP in a short time), automatically blocks the offending IP, and shows
everything on a live dashboard with tables and charts. An administrator can
also block or unblock IPs manually from the dashboard.

Everything runs on `localhost` only. No cloud services, no paid APIs.

## 2. Architecture

```
Browser (dashboard)  <--HTTP-->  Flask app (app.py)  <--SQL-->  SQLite (security.db)
        |                              |
        |                              +-- /login          (test endpoint, gets attacked)
        |                              +-- /dashboard       (serves the HTML page)
        |                              +-- /api/*           (JSON data for tables & charts)
        |
simulate_attack.py  --HTTP-->  /login  (fires repeated fake failed logins)
```

Request flow for a login attempt:

```
Request → is IP already blocked? → yes → 403 Forbidden (stop here)
                                  → no  → check username/password
                                          → log attempt in SQLite
                                          → count failures for this IP in last 60s
                                          → over threshold? → block IP + log brute-force event
                                                             → return 403
                                                            → under threshold → normal 200/401 response
```

Three tables in SQLite:
- `login_attempts` — every attempt (timestamp, IP, username, success/fail)
- `brute_force_events` — every time the detection rule fires
- `blocked_ips` — current + historical block list (auto and manual)

## 3. Installation Instructions
Requires Python 3.9+.

```bash
cd brute-force-monitor
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## 4. How to Start the Server
```bash
python app.py
```
This also creates `database/security.db` automatically on first run
(via `init_db()`), so there's no separate setup step.

## 5. Dashboard URL
```
http://localhost:8000/dashboard
```
(`http://localhost:8000/` also redirects to the same page.)

## 6. Brute-Force Detection Logic
Rule (configurable at the top of `app.py`):

```
FAILED_THRESHOLD = 5          # failed attempts
TIME_WINDOW_SECONDS = 60      # within this many seconds
```

On every failed login, the app counts how many *other failed* attempts came
from the **same IP** in the last `TIME_WINDOW_SECONDS`. If that count reaches
`FAILED_THRESHOLD`, it's flagged as a brute-force attack:
- A row is written to `brute_force_events` (IP, time, failed count, reason).
- The IP is inserted into `blocked_ips`.

Successful logins are never blocked and don't need to "reset" anything
explicitly — the count only ever looks at *failures within the last minute*,
so once enough time passes without new failures, the count naturally drops
back below the threshold on its own.

## 7. Blocking Logic
Two block types, same table (`blocked_ips`), same enforcement path:

- **Automatic** — created by the detection rule above. Has an expiry
  (`BLOCK_DURATION_MINUTES`, default 15 min) after which the block is
  lifted automatically on the next check.
- **Manual** — created from the dashboard (`POST /api/block`), stays active
  until an admin unblocks it (`POST /api/unblock`), no expiry.

Enforcement happens at the very top of `/login`: before checking the
password, the app checks `blocked_ips` for an `ACTIVE` row for that IP. If
found (and not expired), it returns:
```
HTTP 403 Forbidden
{"message": "Your IP has been temporarily blocked."}
```
This is **application-level** blocking — it stops the request inside the
Flask app, not at the OS/network firewall.

## 8. How to Run the Local Simulation
With the server running in one terminal:
```bash
python simulate_attack.py
```
This script only ever talks to `http://localhost:8000/login`. It:
1. Sends one valid login (from a different IP) to prove success still works.
2. Sends repeated failed logins from a simulated attacker IP
   (`192.168.1.24`, set via a test-only `X-Test-IP` header) until the app
   returns 403.
3. Sends one more request from that IP to prove it stays blocked, even with
   the correct password.

Watch `/dashboard` update in real time (it polls every 3 seconds) while the
script runs.

> **Why a header for the IP?** Since everything runs on one machine,
> `request.remote_addr` would always be `127.0.0.1`. `X-Test-IP` lets the
> simulator pretend to be different source IPs purely for local testing —
> it is not a spoofing technique aimed at bypassing anything in production;
> see the limitations below.

## 9. Assumptions / Limitations
- **Single-machine testing IP header**: In production, IP should come from
  `request.remote_addr` or a *trusted* reverse-proxy header
  (e.g. `X-Forwarded-For` set by your own load balancer) — never from a
  client-supplied header, since that's trivially spoofable.
- **IP spoofing / proxies**: An attacker behind NAT, a VPN, or rotating
  proxies can appear as many different IPs and dodge a pure per-IP
  threshold. A production system would add per-account throttling, CAPTCHA
  after N fails, device fingerprinting, or rate limiting at the network
  edge (WAF/CDN) in addition to this application-level logic.
- **False positives**: Shared IPs (offices, campuses, carrier-grade NAT)
  can trip the threshold from legitimate users. Mitigate by combining
  IP-based rules with per-username/per-account tracking, and by keeping
  block durations short (here: 15 minutes) rather than permanent.
- **Application-level blocking only**: Blocking happens inside Flask, not
  in the OS firewall (`iptables`/Windows Firewall). A blocked IP can still
  reach other parts of the machine/network; it's only rejected on this
  app's `/login` (and would need to be applied to any other sensitive
  routes too).
- **Threshold tuning**: 5 fails / 60s is a reasonable demo default, but
  real thresholds should be tuned against real traffic to balance security
  vs. user friction.
- **No password hashing / real auth**: The "valid" credentials are hardcoded
  for demo purposes only — this is a monitoring exercise, not a production
  auth system.

## 10. Project Structure
```
brute-force-monitor/
├── app.py                 # Flask app: /login, detection, blocking, dashboard APIs
├── requirements.txt
├── templates/
│   └── dashboard.html
├── static/
│   ├── css/style.css
│   └── js/dashboard.js
├── database/
│   └── security.db        # created automatically on first run
├── simulate_attack.py
├── .gitignore
└── README.md
```
