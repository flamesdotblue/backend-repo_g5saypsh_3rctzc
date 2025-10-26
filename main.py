import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr

from database import db, create_document, get_documents
from schemas import User as UserSchema, Report as ReportSchema

APP_NAME = "Civic-Sense API"
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change")
JWT_ALG = "HS256"
JWT_EXPIRE_MINUTES = 60 * 24 * 14  # 14 days

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title=APP_NAME)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- Auth Helpers ----------

def create_token(email: str, role: str):
    payload = {
        "sub": email,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def verify_token(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    try:
        scheme, token = authorization.split(" ", 1)
        if scheme.lower() != "bearer":
            raise ValueError("Invalid auth scheme")
        data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        return {"email": data.get("sub"), "role": data.get("role")}
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


# ---------- Models for requests ----------
class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: str = "user"  # 'user' or 'municipal'


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ReportStatusUpdate(BaseModel):
    status: ReportSchema.model_fields["status"].annotation  # Literal values


# ---------- Basic routes ----------
@app.get("/")
def root():
    return {"message": f"{APP_NAME} running"}


@app.get("/test")
def test_database():
    info = {
        "backend": "running",
        "database": "disconnected",
        "collections": [],
    }
    try:
        if db is not None:
            info["database"] = "connected"
            info["collections"] = db.list_collection_names()[:10]
    except Exception as e:
        info["database"] = f"error: {str(e)[:80]}"
    return info


# ---------- Auth endpoints ----------
@app.post("/auth/register")
def register(req: RegisterRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    existing = db["user"].find_one({"email": req.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    password_hash = pwd_context.hash(req.password)
    user_doc = {
        "name": req.name,
        "email": req.email,
        "role": req.role if req.role in ["user", "municipal"] else "user",
        "password_hash": password_hash,
        "is_active": True,
    }
    create_document("user", user_doc)

    token = create_token(req.email, user_doc["role"])
    return {"token": token, "user": {"name": req.name, "email": req.email, "role": user_doc["role"]}}


@app.post("/auth/login")
def login(req: LoginRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    user = db["user"].find_one({"email": req.email})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not pwd_context.verify(req.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account disabled")

    token = create_token(user["email"], user.get("role", "user"))
    return {"token": token, "user": {"name": user.get("name"), "email": user.get("email"), "role": user.get("role", "user")}}


@app.get("/me")
def me(user=Depends(verify_token)):
    return {"email": user["email"], "role": user["role"]}


# ---------- Report endpoints ----------

def server_score_and_status(description: str):
    d = (description or "").lower()
    is_high_risk = any(k in d for k in ["flood", "bridge", "collapse", "electri", "fire", "gas", "sinkhole"])
    looks_fake = any(k in d for k in ["prank", "lol", "fake", "just testing"])
    if looks_fake:
        return "Rejected", -25
    if is_high_risk:
        return "Validated", 20
    return "In Review", 10


@app.post("/reports")
def create_report(report: ReportSchema, user=Depends(verify_token)):
    if user.get("role") != "user":
        raise HTTPException(status_code=403, detail="Only citizens can create reports")

    status, points = server_score_and_status(report.description)
    data = report.model_dump()
    data["status"] = status if report.status == "Submitted" else report.status
    data["pointsAwarded"] = points

    _id = create_document("report", data)
    return {"id": _id, **data}


@app.get("/reports")
def list_reports(limit: Optional[int] = None):
    docs = get_documents("report", {}, limit)
    out = []
    for d in docs:
        d["id"] = str(d.get("_id"))
        d.pop("_id", None)
        out.append(d)
    out.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
    return out


@app.patch("/reports/{report_id}")
def update_report_status(report_id: str, body: ReportStatusUpdate, user=Depends(verify_token)):
    if user.get("role") != "municipal":
        raise HTTPException(status_code=403, detail="Only municipal can update status")

    try:
        from bson import ObjectId
        oid = ObjectId(report_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid report id")

    res = db["report"].update_one({"_id": oid}, {"$set": {"status": body.status, "updated_at": datetime.now(timezone.utc)}})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"ok": True}


@app.delete("/reports/{report_id}")
def delete_report(report_id: str, user=Depends(verify_token)):
    if user.get("role") != "municipal":
        raise HTTPException(status_code=403, detail="Only municipal can remove reports")

    try:
        from bson import ObjectId
        oid = ObjectId(report_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid report id")

    res = db["report"].delete_one({"_id": oid})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"ok": True}
