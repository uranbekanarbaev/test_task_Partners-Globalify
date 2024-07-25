from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from app import schemas, crud
from app.database import SessionLocal, get_db

# Constants
SECRET_KEY = "YOUR_SECRET_KEY"  # Replace with your actual secret key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 password bearer for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify if the provided plain password matches the hashed password.
    
    Args:
        plain_password (str): The plain text password.
        hashed_password (str): The hashed password stored in the database.
    
    Returns:
        bool: True if passwords match, False otherwise.
    """
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """
    Hash the provided password.
    
    Args:
        password (str): The plain text password.
    
    Returns:
        str: The hashed password.
    """
    return pwd_context.hash(password)

def authenticate_user(db: Session, username: str, password: str):
    """
    Authenticate a user by verifying their username and password.
    
    Args:
        db (Session): The database session.
        username (str): The username of the user.
        password (str): The plain text password of the user.
    
    Returns:
        User: The authenticated user if credentials are valid, otherwise False.
    """
    user = crud.get_user(db, username=username)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create an access token with an expiration time.
    
    Args:
        data (dict): The data to include in the token payload.
        expires_delta (Optional[timedelta]): The expiration time of the token.
    
    Returns:
        str: The encoded JWT access token.
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    """
    Retrieve the current user based on the provided token.
    
    Args:
        db (Session): The database session.
        token (str): The access token.
    
    Returns:
        User: The current authenticated user.
    
    Raises:
        HTTPException: If the token is invalid or the user does not exist.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = crud.get_user(db, username=username)
    if user is None:
        raise credentials_exception
    return user
