from app.db.redis_conn import redis_client

def blacklist_token(jti: str):
    redis_client.setex(f"bl:{jti}", 86400, "1")

def is_blacklisted(jti: str):
    return redis_client.get(f"bl:{jti}") == "1"
