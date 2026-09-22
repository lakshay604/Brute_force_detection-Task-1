"""
simulate_attack.py
-------------------
Safe local testing script. Sends login requests ONLY to the local app
created for this assignment (default: http://localhost:8000/login).

It demonstrates the full flow:
  normal login -> repeated failed logins -> threshold reached ->
  brute-force event logged -> IP blocked -> further requests get 403

Usage:
    python simulate_attack.py
"""

import requests
import time

TARGET_URL = "http://localhost:8000/login"

# A fake attacker IP, only used via a test header so everything still
# physically runs on localhost. See get_client_ip() in app.py.
ATTACKER_IP = "192.168.1.24"


def send_login(username, password, ip=ATTACKER_IP):
    headers = {"X-Test-IP": ip, "Content-Type": "application/json"}
    payload = {"username": username, "password": password}
    try:
        resp = requests.post(TARGET_URL, json=payload, headers=headers, timeout=5)
        return resp.status_code, resp.json()
    except requests.exceptions.ConnectionError:
        print("Could not reach the app. Is 'python app.py' running on port 8000?")
        raise SystemExit(1)


def main():
    print("=" * 60)
    print(" BRUTE FORCE SIMULATION")
    print(f" Target: {TARGET_URL}")
    print(f" Simulated attacker IP: {ATTACKER_IP}")
    print("=" * 60)

    # 1. One normal, legitimate login to show success path
    print("\n[1] Sending ONE valid login (should succeed)...")
    status, body = send_login("admin", "admin123", ip="192.168.1.99")
    print(f"    -> {status}: {body}")

    # 2. Repeated failed logins from the same IP, fast
    print("\n[2] Sending repeated FAILED logins from the attacker IP...")
    for i in range(1, 8):
        status, body = send_login("admin", "wrong-password")
        tag = "BLOCKED" if status == 403 else f"HTTP {status}"
        print(f"    Attempt {i}: {tag} -> {body}")
        if status == 403:
            print("\n    IP has been auto-blocked by the detection engine.")
            break
        time.sleep(1)

    # 3. Prove the block is actually enforced
    print("\n[3] Trying one more request from the blocked IP...")
    status, body = send_login("admin", "admin123")  # even correct creds should be rejected
    print(f"    -> {status}: {body}")
    if status == 403:
        print("    Confirmed: blocked IP is rejected even with correct credentials.")

    print("\nDone. Open http://localhost:8000/dashboard to see the event, "
          "the blocked IP, and the charts update.")


if __name__ == "__main__":
    main()
