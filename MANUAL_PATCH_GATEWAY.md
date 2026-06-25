# Manual Gateway Patch Guide

## If auto-patch did not find the OIDC block, do this in server.py:

### ADD at top (after existing imports):
```python
from miller_jwt_gateway import load_jwt_secret, build_auth_headers
```

### ADD after db_pool creation in startup/lifespan:
```python
await load_jwt_secret(db_pool)
```

### FIND the OIDC identity token mint (looks like one of these):
```python
# urllib pattern:
token_url = "http://metadata.google.internal/.../identity"
resp = urllib.request.urlopen(...)
id_token = json.loads(resp.read())["access_token"]
headers["Authorization"] = f"Bearer {id_token}"

# OR requests pattern:
resp = requests.get(metadata_url, params={"audience": ...}, ...)
forward_headers["Authorization"] = f"Bearer {resp.text}"

# OR google-auth pattern:
from google.oauth2 import id_token
token = id_token.fetch_id_token(...)
```

### REPLACE the entire OIDC block with:
```python
forward_headers.update(build_auth_headers())
```
