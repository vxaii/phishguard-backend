import bcrypt
from database import SessionLocal
import models
from passlib.context import CryptContext

db = SessionLocal()
try:
    user_email = "debug@test.com"
    existing_user = db.query(models.User).filter(models.User.email == user_email).first()
    print("existing_user query passed")
    salt = bcrypt.gensalt()
    hashed_pw = bcrypt.hashpw('12345'.encode('utf-8'), salt).decode('utf-8')
    print("bcrypt passed")
    db_user = models.User(email=user_email, password_hash=hashed_pw)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    print("DB commit passed, id:", db_user.id)
except Exception as e:
    import traceback
    traceback.print_exc()
finally:
    db.close()
