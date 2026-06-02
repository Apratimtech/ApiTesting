import hashlib

def fingerprint(request):
    ua = request.headers.get("User-Agent", "")
    ip = request.client.host
    raw = ua + ip
    return hashlib.sha256(raw.encode()).hexdigest()
