from sqlalchemy import create_engine, Column, String, DateTime, Text, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import json

# SQLite database setup
import os
db_path = os.path.join(os.path.dirname(__file__), "security_findings.db")
SQLALCHEMY_DATABASE_URL = f"sqlite:///{db_path}"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class FindingDB(Base):
    __tablename__ = "findings"
    
    id = Column(String, primary_key=True, index=True)
    rule_id = Column(String, index=True)
    severity = Column(String, index=True)
    resource_type = Column(String, index=True)
    resource_name = Column(String, index=True)
    resource_account_id = Column(String, index=True)
    evidence = Column(Text)  # JSON string
    ai_explanation = Column(Text)
    ai_remediation = Column(Text)  # JSON string
    timestamp = Column(DateTime, default=datetime.utcnow)

# Create tables
Base.metadata.create_all(bind=engine)

def get_db():
    """Dependency to get database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def save_finding(db, finding_data):
    """Save a finding to the database."""
    finding = FindingDB(
        id=finding_data["id"],
        rule_id=finding_data["rule_id"],
        severity=finding_data["severity"],
        resource_type=finding_data["resource"]["type"],
        resource_name=finding_data["resource"]["name"],
        resource_account_id=finding_data["resource"]["account_id"],
        evidence=json.dumps(finding_data["evidence"]),
        ai_explanation=finding_data["ai_explanation"],
        ai_remediation=json.dumps(finding_data["ai_remediation"]),
        timestamp=datetime.fromisoformat(finding_data["timestamp"].replace("Z", "+00:00"))
    )
    db.add(finding)
    db.commit()
    return finding

def get_findings(db, skip=0, limit=100, severity=None, resource_type=None, account_id=None):
    """Get findings with optional filters."""
    query = db.query(FindingDB)
    
    if severity:
        query = query.filter(FindingDB.severity == severity)
    if resource_type:
        query = query.filter(FindingDB.resource_type == resource_type)
    if account_id:
        query = query.filter(FindingDB.resource_account_id == account_id)
    
    total = query.count()
    findings = query.offset(skip).limit(limit).all()
    
    return findings, total

def get_finding_by_id(db, finding_id):
    """Get a specific finding by ID."""
    return db.query(FindingDB).filter(FindingDB.id == finding_id).first()

def clear_findings(db):
    """Clear all findings from the database."""
    db.query(FindingDB).delete()
    db.commit()
