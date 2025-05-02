# database/user_db.py

import os
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Enum as SQLEnum
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql import func
import enum

# Database connection details
DATABASE_URL = os.getenv('DATABASE_URL')

# Engine and session setup
engine = create_engine(DATABASE_URL, echo=False)
db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()

class UserRole(enum.Enum):
    USER = "user"
    CREATOR = "creator"

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    phone = Column(String(20), nullable=True) # Assuming phone is optional
    avatar_url = Column(String(255), nullable=True) # Added avatar URL
    role = Column(SQLEnum(UserRole), nullable=True) # Allow NULL, remove default
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

def init_db():
    print("Initializing User DB")
    Base.metadata.create_all(bind=engine)

def add_user(name: str, email: str, phone: str = None, avatar_url: str = None, role: UserRole = None) -> User | None:
    """Adds a new user to the database. Role is optional and defaults to NULL."""
    try:
        user = User(
            name=name,
            email=email,
            phone=phone,
            avatar_url=avatar_url,
            role=role # Pass role (will be NULL if None is passed)
        )
        db_session.add(user)
        db_session.commit()
        print(f"User {email} added successfully.")
        return user
    except IntegrityError:
        db_session.rollback()
        print(f"Error: User with email {email} already exists.")
        return None
    except Exception as e:
        db_session.rollback()
        print(f"Error adding user {email}: {e}")
        return None

def find_user_by_email(email: str) -> User | None:
    """Finds a user by their email address."""
    try:
        return User.query.filter_by(email=email).first()
    except Exception as e:
        print(f"Error finding user by email {email}: {e}")
        return None
