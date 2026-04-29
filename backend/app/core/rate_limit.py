from fastapi import FastAPI, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from fastapi.responses import JSONResponse

# -------------------------------
# GLOBAL LIMITER
# -------------------------------
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="memory://"
)

app = FastAPI()

app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

@app.exception_handler(RateLimitExceeded)
async def ratelimit_error_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"success": False, "message": "Too many requests, slow down."}
    )


# -------------------------------
# 1️⃣ LOGIN — Match: frontend login tab
# -------------------------------
@app.post("/login")
@limiter.limit("5/minute")    # strong brute-force protection
async def login(request: Request):
    return {"message": "login success"}


# -------------------------------
# 2️⃣ REGISTER — Match: frontend register tab
# -------------------------------
@app.post("/register")
@limiter.limit("3/minute")   # avoid spam signups
async def register(request: Request):
    return {"message": "register success"}


# -------------------------------
# 3️⃣ SEND OTP for Forgot Password
# Match: when user clicks "Send OTP"
# -------------------------------
@app.post("/forgot-password/send-otp")
@limiter.limit("3/minute")
async def send_otp(request: Request):
    return {"message": "otp sent"}


# -------------------------------
# 4️⃣ VERIFY OTP
# Match: verifyOTP() in frontend
# -------------------------------
@app.post("/forgot-password/verify-otp")
@limiter.limit("5/minute")
async def verify_otp(request: Request):
    return {"message": "otp verified"}
