from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Security
from fastapi.middleware.cors import CORSMiddleware


from .database import engine, SessionLocal
from .models import Base, User
from .schemas import UserCreate, UserLogin
from .auth import create_access_token, verify_token

app = FastAPI()
security = HTTPBearer()


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


Base.metadata.create_all(bind=engine)

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security)
):
    token = credentials.credentials

    payload = verify_token(token)

    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    return payload["sub"]


# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.post("/signup")
def signup(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.username == user.username).first()

    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_password = pwd_context.hash(user.password)

    new_user = User(
        username=user.username,
        hashed_password=hashed_password
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User created successfully"}


@app.post("/signin")
def signin(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()

    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not pwd_context.verify(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_access_token(
        data={"sub": db_user.username}
    )

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }

@app.get("/me")
def read_current_user(current_user: str = Depends(get_current_user)):
    return {"user": current_user}
