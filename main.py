from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

# Fake database (plain text for learning)
fake_user_db = {
    "sir": "1234"
}

# Request model
class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/login")
def login(data: LoginRequest):
    stored_password = fake_user_db.get(data.username)

    if stored_password is None:
        raise HTTPException(status_code=401, detail="User not found")

    if stored_password != data.password:
        raise HTTPException(status_code=401, detail="Incorrect password")

    return {"message": "Login successful"}
