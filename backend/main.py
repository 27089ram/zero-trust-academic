from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uuid
import re

app = FastAPI(
    title="Academic Portal with Zero Trust Architecture",
    version="1.0"
)

# -----------------------------
# CORS CONFIGURATION
# -----------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# IN-MEMORY STORAGE
# -----------------------------
users_db = {}           # username -> {password, role}
active_sessions = {}    # username -> device_id
active_tokens = {}      # token -> {username, role}
pending_otps = {}       # username -> {otp, device_id, role}

# -----------------------------
# REQUEST MODELS
# -----------------------------
class SignupRequest(BaseModel):
    username: str
    password: str
    role: str

class LoginRequest(BaseModel):
    username: str
    password: str
    device_id: str

class OTPRequest(BaseModel):
    username: str
    otp: str

# -----------------------------
# PASSWORD POLICY
# -----------------------------
def validate_password(password: str) -> bool:
    if len(password) < 8 or len(password) > 14:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*]", password):
        return False
    return True

# -----------------------------
# SIGNUP API
# -----------------------------
@app.post("/signup")
def signup(data: SignupRequest):
    if data.username in users_db:
        raise HTTPException(status_code=400, detail="User already exists")

    if data.role not in ["student", "teacher"]:
        raise HTTPException(status_code=400, detail="Invalid role")

    if not validate_password(data.password):
        raise HTTPException(
            status_code=400,
            detail="Password must be 8–14 chars with uppercase, lowercase, number & special character"
        )

    users_db[data.username] = {
        "password": data.password,
        "role": data.role
    }

    return {
        "message": "Signup successful",
        "username": data.username,
        "role": data.role
    }

# -----------------------------
# LOGIN API (OTP STAGE)
# -----------------------------
@app.post("/login")
def login(data: LoginRequest):
    user = users_db.get(data.username)

    if not user or user["password"] != data.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if data.username in active_sessions:
        if active_sessions[data.username] != data.device_id:
            raise HTTPException(
                status_code=403,
                detail="User already logged in from another device"
            )

    otp = str(uuid.uuid4())[:6]
    pending_otps[data.username] = {
        "otp": otp,
        "device_id": data.device_id,
        "role": user["role"]
    }

    print(f"[OTP] OTP for {data.username}: {otp}")

    return {
        "message": "OTP sent for verification",
        "next_step": "verify-otp"
    }

# -----------------------------
# OTP VERIFICATION
# -----------------------------
@app.post("/verify-otp")
def verify_otp(data: OTPRequest):
    record = pending_otps.get(data.username)

    if not record or record["otp"] != data.otp:
        raise HTTPException(status_code=401, detail="Invalid OTP")

    token = str(uuid.uuid4())

    active_sessions[data.username] = record["device_id"]
    active_tokens[token] = {
        "username": data.username,
        "role": record["role"]
    }

    del pending_otps[data.username]

    return {
        "message": "OTP verified. Login successful",
        "token": token,
        "role": record["role"]
    }

# -----------------------------
# STUDENT DASHBOARD
# -----------------------------
@app.get("/student/dashboard")
def student_dashboard(token: str = Header(None)):
    session = active_tokens.get(token)

    if not session or session["role"] != "student":
        raise HTTPException(status_code=403, detail="Student access only")

    return {
        "dashboard": "Student",
        "user": session["username"]
    }

# -----------------------------
# TEACHER DASHBOARD
# -----------------------------
@app.get("/teacher/dashboard")
def teacher_dashboard(token: str = Header(None)):
    session = active_tokens.get(token)

    if not session or session["role"] != "teacher":
        raise HTTPException(status_code=403, detail="Teacher access only")

    return {
        "dashboard": "Teacher",
        "user": session["username"]
    }

# -----------------------------
# HEALTH CHECK
# -----------------------------
@app.get("/health")
def health():
    return {"status": "OK", "ZTA": "Active"}