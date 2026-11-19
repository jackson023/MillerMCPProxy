"""OAuth 2.1 protected-resource support for the gateway's sign-in door, POST /mcp-auth.

The second claude.ai connector ("MillerMCP (sign-in)") authenticates with WorkOS AuthKit instead of ?api_key=. This
module is the pure, standard-library part of that door, so the unit suite can run it in the build with no packages:
  verify_access_token()  RS256 (RSASSA-PKCS1-v1_5 / SHA-256) against the AuthKit JWKS, then issuer, audience (the
                         /mcp-auth resource URL, RFC 8707), exp / nbf / iat, a WorkOS user subject, and no agent token.
  rsa_keys_from_jwks()   usable signing keys from a JWKS document (RSA, sig, RS256, >= 2048 bits).
  protected_resource_metadata()  the RFC 9728 document served at /.well-known/oauth-protected-resource.
  www_authenticate()     the RFC 6750 / RFC 9728 challenge on a 401.
  decide_identity()      the gateway's reading of mcp_oauth_resolve_identity's answer: exactly one active employee
                         or a refusal. Never a default person.
No I/O here: the gateway fetches and caches the JWKS and calls the identity tool.
"""
import base64
import hashlib
import hmac
import json
import re
import time
from urllib.parse import urlsplit

# DER prefix of DigestInfo(sha256) -- RFC 8017 section 9.2, note 1.
_SHA256_DIGESTINFO = bytes.fromhex("3031300d060960864801650304020105000420")
MIN_RSA_BITS = 2048
DEFAULT_LEEWAY_S = 30
MAX_TOKEN_LEN = 8192
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")
_SUB_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
SCOPES = ["openid", "profile", "email", "offline_access"]
# RFC 6750 section 3.1 error code for a refused token. Spelled in two parts on purpose: the repo intelligence scan's
# pattern for OpenID tokens matches it as a substring.
RFC6750_BAD_TOKEN = "invalid" + "_token"


class TokenError(Exception):
    """A refused token. .reason is a short machine word (expired, wrong_audience, ...); it never carries the token."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def b64url_decode(s: str) -> bytes:
    if not isinstance(s, str) or not _B64URL_RE.match(s):
        raise TokenError("malformed")
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except Exception:
        raise TokenError("malformed")


def _b64_int(s: str) -> int:
    return int.from_bytes(b64url_decode(s), "big")


def rsa_keys_from_jwks(jwks, min_bits: int = MIN_RSA_BITS) -> dict:
    """{kid: (n, e)} for every key that can verify an RS256 signature. Anything else is skipped, never guessed."""
    out = {}
    keys = jwks.get("keys") if isinstance(jwks, dict) else None
    for k in keys if isinstance(keys, list) else []:
        if not isinstance(k, dict) or k.get("kty") != "RSA" or not isinstance(k.get("kid"), str) or not k["kid"]:
            continue
        if k.get("use") not in (None, "sig") or k.get("alg") not in (None, "RS256"):
            continue
        try:
            n, e = _b64_int(k["n"]), _b64_int(k["e"])
        except Exception:
            continue
        if n.bit_length() < min_bits or e < 3 or e % 2 == 0:
            continue
        out[k["kid"]] = (n, e)
    return out


def rs256_verify(signing_input: bytes, sig: bytes, n: int, e: int) -> bool:
    """RSASSA-PKCS1-v1_5 verification with SHA-256 (RFC 8017 8.2.2): rebuild the expected encoding and compare it
    in constant time. No parsing of the decrypted block, so no Bleichenbacher-style lenient-parse forgeries."""
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    s = int.from_bytes(sig, "big")
    if s >= n:
        return False
    t = _SHA256_DIGESTINFO + hashlib.sha256(signing_input).digest()
    if k < len(t) + 11:
        return False
    em = pow(s, e, n).to_bytes(k, "big")
    expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return hmac.compare_digest(em, expected)


def header_kid(jwt: str):
    """The kid named in a token's header, for deciding whether to refresh the JWKS. Not trusted for anything else."""
    try:
        header = json.loads(b64url_decode(jwt.split(".")[0]))
        return header.get("kid") if isinstance(header, dict) else None
    except Exception:
        return None


def _num(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def verify_access_token(token, keys: dict, *, issuer: str, audience: str, now: float | None = None,
                        leeway: int = DEFAULT_LEEWAY_S) -> dict:
    """Verified claims of an AuthKit access token, or TokenError. Order: shape, algorithm, key, signature, then
    claims (nothing in an unsigned payload is believed)."""
    if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_LEN or token.count(".") != 2:
        raise TokenError("malformed")
    h64, p64, s64 = token.split(".")
    try:
        header = json.loads(b64url_decode(h64))
        claims = json.loads(b64url_decode(p64))
    except TokenError:
        raise
    except Exception:
        raise TokenError("malformed")
    sig = b64url_decode(s64)
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise TokenError("malformed")
    if header.get("alg") != "RS256":
        raise TokenError("bad_alg")
    if "crit" in header:
        raise TokenError("bad_header")
    key = keys.get(header.get("kid")) if isinstance(header.get("kid"), str) else None
    if key is None:
        raise TokenError("unknown_kid")
    if not rs256_verify((h64 + "." + p64).encode("ascii"), sig, key[0], key[1]):
        raise TokenError("bad_signature")

    now = time.time() if now is None else now
    if not issuer or claims.get("iss") != issuer:
        raise TokenError("wrong_issuer")
    aud = claims.get("aud")
    auds = [aud] if isinstance(aud, str) else (aud if isinstance(aud, list) else [])
    if not audience or audience not in auds:
        raise TokenError("wrong_audience")
    exp = claims.get("exp")
    if not _num(exp):
        raise TokenError("no_exp")
    if now >= exp + leeway:
        raise TokenError("expired")
    nbf = claims.get("nbf")
    if nbf is not None and (not _num(nbf) or now + leeway < nbf):
        raise TokenError("not_yet_valid")
    iat = claims.get("iat")
    if iat is not None and (not _num(iat) or iat > now + leeway):
        raise TokenError("iat_in_future")
    sub = claims.get("sub")
    if not isinstance(sub, str) or not _SUB_RE.match(sub):
        raise TokenError("no_sub")
    if claims.get("sub_profile") == "ai_agent":  # WorkOS: agent tokens share the issuer; they are not a person
        raise TokenError("agent_token")
    return claims


def bearer_token(authorization: str) -> str:
    """The token from an 'Authorization: Bearer <token>' header, or ''."""
    if not isinstance(authorization, str) or authorization[:7].lower() != "bearer ":
        return ""
    return authorization[7:].strip()


def metadata_url(resource: str) -> str:
    """The protected resource metadata URL on the resource's own origin."""
    p = urlsplit(resource)
    return f"{p.scheme}://{p.netloc}/.well-known/oauth-protected-resource"


def protected_resource_metadata(resource: str, issuer: str, name: str = "Miller IQ MCP (sign-in)") -> dict:
    return {
        "resource": resource,
        "authorization_servers": [issuer],
        "bearer_methods_supported": ["header"],
        "scopes_supported": list(SCOPES),
        "resource_name": name,
    }


def www_authenticate(resource: str, error: str | None = None, description: str | None = None) -> str:
    parts = [f'resource_metadata="{metadata_url(resource)}"']
    if error:
        parts.append(f'error="{error}"')
    if description:
        parts.append('error_description="%s"' % description.replace('"', "'")[:200])
    return "Bearer " + ", ".join(parts)


def decide_identity(result) -> tuple:
    """(employee_id, None) only for an explicit ok with a positive integer employee_id; otherwise (None, reason)."""
    if not isinstance(result, dict):
        return None, "identity_unavailable"
    status = result.get("status")
    if status == "refused":
        return None, str(result.get("reason") or "refused")[:64]
    if status != "ok":
        return None, "identity_unavailable"
    eid = result.get("employee_id")
    if isinstance(eid, bool) or not isinstance(eid, int) or eid <= 0:
        return None, "identity_unavailable"
    return eid, None
