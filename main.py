import os
import re
import json
import pickle
import socket
import datetime
from urllib.parse import urlsplit, urlunsplit

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session
import bcrypt

from database import engine, get_db
import models

models.Base.metadata.create_all(bind=engine)

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
import tensorflow as tf
try:
    from tensorflow.keras.preprocessing.sequence import pad_sequences
except (ImportError, ModuleNotFoundError):
    from keras.utils import pad_sequences

app = FastAPI(title="Phishing Detection API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = os.path.dirname(__file__)

CONFIG_PATH = os.path.join(BASE_DIR, "model_config.json")
if not os.path.exists(CONFIG_PATH):
    CONFIG_PATH = os.path.join(BASE_DIR, "..", "model_config.json")

with open(CONFIG_PATH, "r") as f:
    config = json.load(f)

MAX_LEN = config["max_len"]
THRESHOLD = config["threshold"]

TOKENIZER_PATH = os.path.join(BASE_DIR, "tokenizer_url_phishing.pkl")
if not os.path.exists(TOKENIZER_PATH):
    TOKENIZER_PATH = os.path.join(BASE_DIR, "..", "tokenizer_url_phishing.pkl")

with open(TOKENIZER_PATH, "rb") as f:
    tokenizer = pickle.load(f)

MODEL_PATH = os.path.join(BASE_DIR, "model_cnn_lstm_url_phishing.keras")
if not os.path.exists(MODEL_PATH):
    MODEL_PATH = os.path.join(BASE_DIR, "..", "model_cnn_lstm_url_phishing.keras")

model = tf.keras.models.load_model(MODEL_PATH)

class UserCreate(BaseModel):
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class URLRequest(BaseModel):
    url: str
    user_id: int = None

def normalize_url_prediction(url):
    url = str(url).strip()
    url = re.sub(r"\s+", "", url)
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        netloc = parts.netloc.lower().rstrip(".")
        path = "" if parts.path == "/" else parts.path
        query = parts.query
        return urlunsplit((scheme, netloc, path, query, ""))
    except Exception:
        return url

@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    if len(user.password) < 6:
        raise HTTPException(status_code=400, detail="Kata sandi minimal harus 6 karakter")

    if user.email.lower().startswith("admin"):
        raise HTTPException(status_code=403, detail="Pendaftaran akun admin dilarang demi keamanan")

    existing_user = db.query(models.User).filter(models.User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    salt = bcrypt.gensalt()
    hashed_pw = bcrypt.hashpw(user.password.encode('utf-8'), salt).decode('utf-8')
    
    db_user = models.User(email=user.email, password_hash=hashed_pw)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return {"id": db_user.id, "email": db_user.email}

@app.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    if user.email == "admin@kampus.ac.id" and user.password == "admin123":
        return {"id": 0, "email": user.email, "message": "Login admin berhasil"}

    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    
    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid email or password")
        
    is_valid = bcrypt.checkpw(user.password.encode('utf-8'), db_user.password_hash.encode('utf-8'))
    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid email or password")
    
    return {"id": db_user.id, "email": db_user.email, "message": "Login successful"}

def check_domain_exists(url: str) -> bool:
    try:
        parts = urlsplit(url if '://' in url else 'https://' + url)
        netloc = parts.netloc.split(':')[0].strip().lower()
        if not netloc:
            return False
        # If it's an IPv4 address
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", netloc):
            return True
        # Perform fast DNS resolution
        socket.setdefaulttimeout(3.0)
        socket.gethostbyname(netloc)
        return True
    except Exception:
        return False

@app.post("/predict")
def predict_url(request: URLRequest, db: Session = Depends(get_db)):
    original_url = request.url
    if not original_url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    norm_url = normalize_url_prediction(original_url)

    # 1. DNS Resolution Validation (Cek keberadaan domain di internet)
    if not check_domain_exists(norm_url):
        raise HTTPException(
            status_code=422,
            detail="Domain tidak ditemukan atau tidak terdaftar di internet. Harap periksa kembali alamat URL Anda."
        )
    
    seq = tokenizer.texts_to_sequences([norm_url])
    padded = pad_sequences(seq, maxlen=MAX_LEN, padding="post")
    
    pred_prob = model.predict(padded, verbose=0)[0][0]
    label = "PHISHING" if pred_prob > THRESHOLD else "LEGITIMATE"
    
    scan_record = models.Scan(
        url=original_url,
        prediction=label,
        probability=float(pred_prob),
        user_id=request.user_id
    )
    db.add(scan_record)
    db.commit()
    db.refresh(scan_record)

    return {
        "id": scan_record.id,
        "url": original_url,
        "normalized_url": norm_url,
        "probability": float(pred_prob),
        "label": label,
        "threshold_used": float(THRESHOLD)
    }

@app.get("/admin/stats")
def get_admin_stats(db: Session = Depends(get_db)):
    total_users = db.query(models.User).count()
    total_scanned = db.query(models.Scan).count()
    threats_blocked = db.query(models.Scan).filter(models.Scan.prediction == "PHISHING").count()
    
    recent_scans = db.query(models.Scan, models.User.email).outerjoin(
        models.User, models.Scan.user_id == models.User.id
    ).order_by(models.Scan.created_at.desc()).limit(10).all()
    
    history_list = []
    for scan, email in recent_scans:
        history_list.append({
            "id": str(scan.id),
            "url": scan.url,
            "prediction": scan.prediction,
            "probability": float(scan.probability) * 100,
            "date": scan.created_at.strftime("%m/%d/%Y"),
            "user": email if email else "Guest"
        })
        
    return {
        "totalUsers": total_users,
        "totalScanned": total_scanned,
        "threatsBlocked": threats_blocked,
        "monthlyRatio": {
            "phishing": threats_blocked,
            "legitimate": total_scanned - threats_blocked
        },
        "globalHistory": history_list
    }

@app.get("/admin/history")
def get_admin_history(db: Session = Depends(get_db)):
    all_scans = db.query(models.Scan, models.User.email).outerjoin(
        models.User, models.Scan.user_id == models.User.id
    ).order_by(models.Scan.created_at.desc()).all()
    
    history_list = []
    for scan, email in all_scans:
        history_list.append({
            "id": str(scan.id),
            "url": scan.url,
            "prediction": scan.prediction,
            "probability": float(scan.probability) * 100,
            "date": scan.created_at.strftime("%m/%d/%Y"),
            "user": email if email else "Guest"
        })
    return history_list

@app.get("/admin/users")
def get_admin_users(db: Session = Depends(get_db)):
    from sqlalchemy import func
    users_with_counts = db.query(
        models.User.id,
        models.User.email,
        func.count(models.Scan.id).label("scans")
    ).outerjoin(
        models.Scan, models.Scan.user_id == models.User.id
    ).group_by(models.User.id).all()
    
    user_list = []
    for uid, email, scans in users_with_counts:
        role = "Admin" if email.startswith("admin") else "User"
        user_list.append({
            "id": str(uid),
            "name": email.split("@")[0],
            "email": email,
            "role": role,
            "scans": scans,
            "status": "Active"
        })
    return user_list

@app.get("/history")
def get_history(user_id: int = None, db: Session = Depends(get_db)):
    if user_id:
        scans = db.query(models.Scan).filter(models.Scan.user_id == user_id).order_by(models.Scan.created_at.desc()).all()
    else:
        scans = db.query(models.Scan).order_by(models.Scan.created_at.desc()).all()
    return scans

@app.api_route("/", methods=["GET", "HEAD"])
def read_root():
    return {"message": "Phishing Detection API with DB is running!"}

