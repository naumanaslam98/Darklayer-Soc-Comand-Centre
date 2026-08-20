import base64, hashlib, hmac, json, time
from fastapi import Header, HTTPException
from .config import ADMIN_USER, ADMIN_PASSWORD, SECRET

def _sign(payload: bytes) -> str:
    return hmac.new(SECRET.encode(), payload, hashlib.sha256).hexdigest()

def create_token(username: str) -> str:
    body = {"sub": username, "exp": int(time.time()) + 12 * 3600}
    raw = json.dumps(body, separators=(",", ":")).encode()
    enc = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    return f"{enc}.{_sign(enc.encode())}"

def verify_login(username: str, password: str) -> bool:
    return hmac.compare_digest(username, ADMIN_USER) and hmac.compare_digest(password, ADMIN_PASSWORD)

def verify_token(token: str) -> str:
    try:
        enc, sig = token.split(".", 1)
        if not hmac.compare_digest(sig, _sign(enc.encode())):
            raise ValueError("bad signature")
        raw = base64.urlsafe_b64decode(enc + "=" * (-len(enc) % 4))
        body = json.loads(raw)
        if int(body["exp"]) < int(time.time()):
            raise ValueError("expired")
        return body["sub"]
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

def require_auth(authorization: str | None = Header(default=None)) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    return verify_token(authorization.split(" ", 1)[1].strip())


def require_agent_key(x_agent_key: str | None = Header(default=None, alias="X-Agent-Key")) -> str:
    from .config import AGENT_API_KEY
    if not x_agent_key or not hmac.compare_digest(x_agent_key, AGENT_API_KEY):
        raise HTTPException(status_code=401, detail="Valid collector agent key required")
    return "collector"
