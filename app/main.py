from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Security
from fastapi.middleware.cors import CORSMiddleware


from .database import engine, SessionLocal
from .models import Base, User , Post
from .schemas import UserCreate, UserLogin, PostCreate, PostResponse
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


@app.post("/posts", response_model=PostResponse)
def create_post(
    post: PostCreate,
    db: Session = Depends(get_db),
    current_user: str = Depends(get_current_user)
):
    # Get user from database
    db_user = db.query(User).filter(User.username == current_user).first()

    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    new_post = Post(
        title=post.title,
        content=post.content,
        author_id=db_user.id
    )

    db.add(new_post)
    db.commit()
    db.refresh(new_post)

    return new_post

@app.get("/posts", response_model=list[PostResponse])
def get_posts(
    limit: int = 10,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    posts = db.query(Post)\
              .order_by(Post.created_at.desc())\
              .limit(limit)\
              .offset(offset)\
              .all()

    return posts

@app.get("/posts/{post_id}", response_model=PostResponse)
def get_post(post_id: int, db: Session = Depends(get_db)):
    post = db.query(Post).filter(Post.id == post_id).first()

    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    return post

@app.put("/posts/{post_id}", response_model=PostResponse)
def update_post(
    post_id: int,
    post_data: PostCreate,
    db: Session = Depends(get_db),
    current_user: str = Depends(get_current_user)
):
    post = db.query(Post).filter(Post.id == post_id).first()

    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    db_user = db.query(User).filter(User.username == current_user).first()

    if post.author_id != db_user.id:
        raise HTTPException(status_code=403, detail="Not allowed to edit this post")

    post.title = post_data.title
    post.content = post_data.content

    db.commit()
    db.refresh(post)

    return post

@app.delete("/posts/{post_id}")
def delete_post(
    post_id: int,
    db: Session = Depends(get_db),
    current_user: str = Depends(get_current_user)
):
    post = db.query(Post).filter(Post.id == post_id).first()

    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    db_user = db.query(User).filter(User.username == current_user).first()

    if post.author_id != db_user.id:
        raise HTTPException(status_code=403, detail="Not allowed to delete this post")

    db.delete(post)
    db.commit()

    return {"message": "Post deleted successfully"}
