import bcrypt
salt = bcrypt.gensalt()
hashed_pw = bcrypt.hashpw('12345'.encode('utf-8'), salt).decode('utf-8')
print("HASHED:", hashed_pw)
