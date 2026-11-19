"""Sign-in connector (/mcp-auth): AuthKit access-token verification, metadata, challenge and the identity decision.
Script suite: exits non-zero on any failure (run in cloudbuild before deploy). Standard library only: the RSA test key
is generated here in pure Python (deterministic seed), tokens are signed with it, and oauth_resource verifies them."""
import base64, hashlib, json, os, random, sys, time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import oauth_resource as orx  # noqa: E402

FAILS = []


def check(name, cond):
    print(("PASS  " if cond else "FAIL  ") + name)
    if not cond:
        FAILS.append(name)


def refused(name, fn, reason):
    try:
        fn()
        check(name + " (refused: " + reason + ")", False)
    except orx.TokenError as e:
        check(name + " (refused: " + reason + ")", e.reason == reason)


# -- a pure-Python RSA key -------------------------------------------------------------------------------------
_rng = random.Random(20261118)
_SMALL = [p for p in range(3, 2000, 2) if all(p % q for q in range(3, int(p ** 0.5) + 1, 2))]


def _probable_prime(n):
    if any(n % p == 0 for p in _SMALL):
        return n in _SMALL
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(24):
        x = pow(_rng.randrange(2, n - 2), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits):
    while True:
        c = _rng.getrandbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if _probable_prime(c):
            return c


def rsa_key(bits):
    e = 65537
    while True:
        p, q = _prime(bits // 2), _prime(bits // 2)
        phi = (p - 1) * (q - 1)
        if p != q and phi % e and (p * q).bit_length() == bits:
            return p * q, e, pow(e, -1, phi)


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def int_b64u(i):
    return b64u(i.to_bytes((i.bit_length() + 7) // 8, "big"))


def sign(header, claims, n, d):
    h = b64u(json.dumps(header).encode())
    p = b64u(json.dumps(claims).encode())
    k = (n.bit_length() + 7) // 8
    t = orx._SHA256_DIGESTINFO + hashlib.sha256((h + "." + p).encode()).digest()
    em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    s = pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")
    return h + "." + p + "." + b64u(s)


t0 = time.time()
N, E, D = rsa_key(2048)
N2, E2, D2 = rsa_key(2048)          # a second, unpublished key: signatures from it must fail
SMALL_N, SMALL_E, _ = rsa_key(1024)
print("keys generated in %.1fs" % (time.time() - t0))

ISS = "https://example-authkit.authkit.app"
RES = "https://gateway.example.run.app/mcp-auth"
KID = "sso_oidc_key_pair_TEST"
JWKS = {"keys": [
    {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID, "n": int_b64u(N), "e": int_b64u(E)},
    {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "small", "n": int_b64u(SMALL_N), "e": int_b64u(SMALL_E)},
    {"kty": "EC", "kid": "ec1", "crv": "P-256", "x": "AA", "y": "AA"},
    {"kty": "RSA", "use": "enc", "kid": "enc1", "n": int_b64u(N), "e": int_b64u(E)},
]}
KEYS = orx.rsa_keys_from_jwks(JWKS)
check("JWKS: only the 2048-bit RS256 signing key is usable", set(KEYS) == {KID})

NOW = 1_800_000_000
HDR = {"alg": "RS256", "typ": "JWT", "kid": KID}


def claims(**over):
    c = {"iss": ISS, "aud": RES, "sub": "user_01KT9SPE1PEQE87BBBAZYA0KWN", "sid": "session_01ABC",
         "exp": NOW + 300, "iat": NOW - 5}
    c.update(over)
    return {k: v for k, v in c.items() if v is not None}


def verify(tok, **kw):
    return orx.verify_access_token(tok, KEYS, issuer=ISS, audience=RES, now=kw.pop("now", NOW), **kw)


good = sign(HDR, claims(), N, D)
c = verify(good)
check("good token verifies and returns its claims", c["sub"] == "user_01KT9SPE1PEQE87BBBAZYA0KWN" and c["aud"] == RES)
check("aud as a list containing the resource verifies", verify(sign(HDR, claims(aud=["x", RES]), N, D))["iss"] == ISS)
check("within clock leeway after exp still verifies", verify(good, now=NOW + 300 + 10)["sub"].startswith("user_"))

refused("expired token", lambda: verify(good, now=NOW + 300 + orx.DEFAULT_LEEWAY_S), "expired")
refused("wrong audience (the old /mcp URL)", lambda: verify(sign(HDR, claims(aud=RES[:-5]), N, D)), "wrong_audience")
refused("audience missing", lambda: verify(sign(HDR, claims(aud=None), N, D)), "wrong_audience")
refused("wrong issuer", lambda: verify(sign(HDR, claims(iss="https://evil.authkit.app"), N, D)), "wrong_issuer")
refused("no exp", lambda: verify(sign(HDR, claims(exp=None), N, D)), "no_exp")
refused("not yet valid", lambda: verify(sign(HDR, claims(nbf=NOW + 600), N, D)), "not_yet_valid")
refused("issued in the future", lambda: verify(sign(HDR, claims(iat=NOW + 600), N, D)), "iat_in_future")
refused("no subject", lambda: verify(sign(HDR, claims(sub=None), N, D)), "no_sub")
refused("agent token", lambda: verify(sign(HDR, claims(sub_profile="ai_agent"), N, D)), "agent_token")
refused("signed by an unpublished key under the real kid", lambda: verify(sign(HDR, claims(), N2, D2)), "bad_signature")

h, p, s = good.split(".")
forged_p = b64u(json.dumps(claims(sub="user_01ATTACKERATTACKERATTACK")).encode())
refused("payload swapped after signing (forged)", lambda: verify(h + "." + forged_p + "." + s), "bad_signature")
refused("signature truncated", lambda: verify(h + "." + p + "." + s[:-4]), "bad_signature")
refused("alg none", lambda: verify(b64u(json.dumps({"alg": "none", "kid": KID}).encode()) + "." + p + "."), "bad_alg")
hs = b64u(json.dumps({"alg": "HS256", "kid": KID}).encode())
refused("alg HS256 (key confusion)", lambda: verify(hs + "." + p + "." + s), "bad_alg")
refused("unknown kid", lambda: verify(sign(dict(HDR, kid="other"), claims(), N, D)), "unknown_kid")
refused("kid of a key too small to trust", lambda: verify(sign(dict(HDR, kid="small"), claims(), N, D)), "unknown_kid")
refused("crit header", lambda: verify(sign(dict(HDR, crit=["x"]), claims(), N, D)), "bad_header")
refused("not a JWT", lambda: verify("not-a-token"), "malformed")
refused("non-base64url segment", lambda: verify("a.b+c.d"), "malformed")
refused("oversized token", lambda: verify("a." + "b" * 9000 + ".c"), "malformed")
check("header_kid reads the header kid", orx.header_kid(good) == KID and orx.header_kid("x") is None)

check("bearer_token extracts the token", orx.bearer_token("Bearer abc.def.ghi") == "abc.def.ghi")
check("bearer_token is case-insensitive on the scheme", orx.bearer_token("bearer x.y.z") == "x.y.z")
check("bearer_token ignores other schemes", orx.bearer_token("Basic Zm9v") == "" and orx.bearer_token("") == "")

md = orx.protected_resource_metadata(RES, ISS)
check("metadata names the resource and the AuthKit authorization server",
      md["resource"] == RES and md["authorization_servers"] == [ISS] and md["bearer_methods_supported"] == ["header"])
check("metadata URL is on the resource origin",
      orx.metadata_url(RES) == "https://gateway.example.run.app/.well-known/oauth-protected-resource")
ch = orx.www_authenticate(RES)
check("401 challenge points at the metadata", ch == 'Bearer resource_metadata="https://gateway.example.run.app/.well-known/oauth-protected-resource"')
ch = orx.www_authenticate(RES, orx.RFC6750_BAD_TOKEN, 'expired "x"')
check("401 challenge carries the error and quotes safely",
      orx.RFC6750_BAD_TOKEN == "invalid" + "_token" and ('error="%s"' % orx.RFC6750_BAD_TOKEN) in ch and 'error_description="expired \'x\'"' in ch)

check("identity: ok with an employee id is accepted", orx.decide_identity({"status": "ok", "employee_id": 1045}) == (1045, None))
check("identity: unknown user is refused", orx.decide_identity({"status": "refused", "reason": "not_found"}) == (None, "not_found"))
check("identity: inactive user is refused", orx.decide_identity({"status": "refused", "reason": "inactive"}) == (None, "inactive"))
check("identity: ok without an employee id is refused", orx.decide_identity({"status": "ok"}) == (None, "identity_unavailable"))
check("identity: a non-integer employee id is refused",
      orx.decide_identity({"status": "ok", "employee_id": "1045"})[0] is None
      and orx.decide_identity({"status": "ok", "employee_id": True})[0] is None)
check("identity: tool error or no answer is refused",
      orx.decide_identity({"status": "error"})[0] is None and orx.decide_identity(None)[0] is None)

if __name__ == "__main__":
    print("RESULT OK" if not FAILS else "RESULT FAIL: %s" % FAILS)
    sys.exit(1 if FAILS else 0)
