from sqlalchemy.orm import Session
from app.models.user import User
from app.core.security import verify_password, get_password_hash, create_access_token
from app.schemas.user import UserLogin
from datetime import timedelta

class AuthService:
    @staticmethod
    def authenticate_user(db: Session, username: str, password: str):
        user = db.query(User).filter(User.username == username).first()
        if not user:
            return None
        if not verify_password(password, user.password_hash):
            return None
        return user
    
    @staticmethod
    def create_user(db: Session, username: str, password: str, is_admin: bool = False):
        hashed_password = get_password_hash(password)
        db_user = User(
            username=username,
            password_hash=hashed_password,
            is_admin=is_admin
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return db_user
    
    @staticmethod
    def get_user_by_username(db: Session, username: str):
        return db.query(User).filter(User.username == username).first()
    
    @staticmethod
    def login(db: Session, login_data: UserLogin):
        user = AuthService.authenticate_user(db, login_data.username, login_data.password)
        if not user:
            return None
        
        access_token = create_access_token(
            data={"sub": user.username, "user_id": user.id},
            expires_delta=timedelta(minutes=60 * 24)
        )
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": user
        }
