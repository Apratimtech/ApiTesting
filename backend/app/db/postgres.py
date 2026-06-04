import os

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker

# =========================================================
# LOAD ENVIRONMENT VARIABLES
# =========================================================

load_dotenv()

# =========================================================
# DATABASE URL
# =========================================================
# postgresql://postgres:password@localhost/trustedge

DATABASE_URL = os.getenv("DATABASE_URL","postgresql://neondb_owner:npg_9DUt1mAoVPEN@ep-holy-king-aokcy0os-pooler.c-2.ap-southeast-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require")

# =========================================================
# SQLALCHEMY ENGINE
# =========================================================
# Engine manages:
# - DB connections
# - Connection pooling
# - SQL communication
# - Reconnection handling

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
    echo=False,
)

# =========================================================
# SESSION FACTORY
# =========================================================
# Creates database sessions for every request

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

# =========================================================
# BASE MODEL
# =========================================================
# Parent class for all database models

Base = declarative_base()

# =========================================================
# DATABASE DEPENDENCY
# =========================================================
# Creates and closes DB session safely

def get_db():

    db = SessionLocal()

    try:
        yield db

        db.commit()

    except Exception:

        db.rollback()

        raise

    finally:

        db.close()
