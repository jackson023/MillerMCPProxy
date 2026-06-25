"""
miller_jwt_gateway.py — Cloudflare Zero Trust pattern, gateway side.

Replaces GCP metadata server OIDC mint (50-200ms, 3 failure points)
with in-memory HS256 JWT mint (0.03ms, zero external dependencies).

Usage in server.py:
    from miller_jwt_gateway import load_jwt_secret, build_auth_headers

    # At startup (after pool init):
    await load_jwt_secret(db_pool)

    # In /execute forward path (replace OIDC block):
    forward_headers.update(build_auth_headers())
"""
import jwt, time, json, logging, os

logger = logging.getLogger("miller.gateway.jwt")

_JWT_SECRET: str | None = None
_JWT_ISSUER   = "miller-mcp-gateway"
_JWT_TTL_S    = 300  # 5 min — same as Cloudflare JWT TTL


async def load_jwt_secret(db_pool) -> None:
    global _JWT_SECRET
    try:
        async with db_pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT value FROM platform_settings "
                "WHERE key = 'miller_gateway_jwt_secret'"
            )
        if row:
            val = row["value"]
            _JWT_SECRET = (json.loads(val)
                           if isinstance(val, str) and val.startswith('"')
                           else val)
            logger.info("JWT secret loaded from platform_settings (%d chars)",
                        len(_JWT_SECRET))
            return
    except Exception as e:
        logger.warning("DB secret load failed, trying env: %s", e)
    _JWT_SECRET = os.environ.get("MILLER_JWT_SECRET")
    if _JWT_SECRET:
        logger.info("JWT secret loaded from env var MILLER_JWT_SECRET")
    else:
        logger.error("FATAL: JWT secret not found — /execute calls will fail")


def mint_token(audience: str, caller: str = "gateway") -> str:
    if not _JWT_SECRET:
        raise RuntimeError("JWT secret not loaded — call load_jwt_secret() at startup")
    now = int(time.time())
    return jwt.encode(
        {"iss": _JWT_ISSUER, "sub": caller, "aud": audience,
         "iat": now, "exp": now + _JWT_TTL_S},
        _JWT_SECRET, algorithm="HS256",
    )


def build_auth_headers(audience: str = "miller-mcp-db-v3",
                        caller: str = "gateway") -> dict:
    """
    Drop-in replacement for the OIDC Authorization header block.
    Returns {"x-miller-assertion": "<jwt>"}.
    Starlette/FastAPI normalise all header keys to lowercase.
    """
    return {"x-miller-assertion": mint_token(audience, caller)}
