#!/usr/bin/env python3
"""
Policy Service for Secure Agent-to-Agent Communication Framework

This service handles JWT token issuance, validation, and policy enforcement
for secure communication between agents.
"""

import os
import time
import logging
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set

import jwt
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator
from pymongo import MongoClient
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import uvicorn

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration
SECRET = os.getenv("POLICY_SECRET", "super-secure-jwt-secret-key-change-in-production")
MONGO_URL = os.getenv("MONGO_URL", "mongodb://admin:securepass123@localhost:27017/policy_db?authSource=admin")
MAX_TOKEN_TTL = int(os.getenv("MAX_TOKEN_TTL", "3600"))  # 1 hour max
MIN_TOKEN_TTL = int(os.getenv("MIN_TOKEN_TTL", "60"))    # 1 minute min


# Initialize FastAPI app
app = FastAPI(
    title="Secure Agent Policy Service",
    description="JWT token issuance and policy enforcement for agent communication",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# MongoDB connection with explicit health check and timeouts
try:
    mongo_client = MongoClient(
        MONGO_URL,
        serverSelectionTimeoutMS=5000,
        connectTimeoutMS=5000
    )
    # Force connection to validate URI/auth quickly
    mongo_client.admin.command("ping")
    db = mongo_client["policy_db"]
    tokens_collection = db["active_tokens"]
    audit_collection = db["audit_log"]
    agents_collection = db["registered_agents"]
    logger.info("Connected to MongoDB successfully")
except Exception as e:
    logger.error(f"Failed to connect to MongoDB: {e}")
    mongo_client = None

class TokenRequest(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=50, pattern="^[a-zA-Z0-9_-]+$")
    target_agent: str = Field(..., min_length=1, max_length=50, pattern="^[a-zA-Z0-9_-]+$")
    ttl_seconds: int = Field(default=300, ge=MIN_TOKEN_TTL, le=MAX_TOKEN_TTL)
    requested_rights: List[str] = Field(default=["send_message"])
    
    @validator('agent_id', 'target_agent')
    def validate_agent_ids(cls, v):
        if v.startswith('_') or v.endswith('_'):
            raise ValueError('Agent ID cannot start or end with underscore')
        return v

class TokenValidationRequest(BaseModel):
    token: str
    sender_id: str
    recipient_id: str
    action: str = "send_message"

class AgentRegistration(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=50, pattern="^[a-zA-Z0-9_-]+$")
    public_key_fingerprint: str
    capabilities: List[str] = Field(default=["send_message", "receive_message"])

class TokenResponse(BaseModel):
    token: str
    expires_at: int
    issued_at: int
    rights: List[str]

def log_audit_event(event_type: str, agent_id: str, details: Dict):
    """Log security audit events."""
    if mongo_client:
        try:
            audit_event = {
                "timestamp": datetime.utcnow(),
                "event_type": event_type,
                "agent_id": agent_id,
                "details": details,
                "source_ip": "localhost"  # In production, get from request
            }
            audit_collection.insert_one(audit_event)
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")

def is_agent_registered(agent_id: str) -> bool:
    """Check if an agent is registered."""
    if not mongo_client:
        return True  # Allow all agents if DB is not available
    
    try:
        return agents_collection.find_one({"agent_id": agent_id}) is not None
    except Exception as e:
        logger.error(f"Failed to check agent registration: {e}")
        return True

def revoke_token(token_jti: str):
    """Add token to revocation list."""
    if mongo_client:
        try:
            tokens_collection.insert_one({
                "jti": token_jti,
                "revoked_at": datetime.utcnow(),
                "status": "revoked"
            })
        except Exception as e:
            logger.error(f"Failed to revoke token: {e}")

def is_token_revoked(token_jti: str) -> bool:
    """Check if a token has been revoked."""
    if not mongo_client:
        return False
    
    try:
        return tokens_collection.find_one({"jti": token_jti, "status": "revoked"}) is not None
    except Exception as e:
        logger.error(f"Failed to check token revocation: {e}")
        return False

@app.get("/")
def root():
    """Health check endpoint."""
    return {
        "message": "Secure Agent Policy Service is running!",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "status": "healthy"
    }

@app.get("/health")
def health_check():
    """Detailed health check."""
    mongo_status = "disconnected"
    try:
        if mongo_client:
            mongo_client.admin.command("ping")
            mongo_status = "connected"
    except Exception:
        mongo_status = "disconnected"
    return {
        "status": "healthy",
        "mongodb": mongo_status,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/register", response_model=Dict[str, str])
def register_agent(registration: AgentRegistration):
    """Register a new agent."""
    if not is_agent_registered(registration.agent_id):
        if mongo_client:
            try:
                agent_doc = {
                    "agent_id": registration.agent_id,
                    "public_key_fingerprint": registration.public_key_fingerprint,
                    "capabilities": registration.capabilities,
                    "registered_at": datetime.utcnow(),
                    "status": "active"
                }
                agents_collection.insert_one(agent_doc)
                
                log_audit_event("agent_registered", registration.agent_id, {
                    "capabilities": registration.capabilities
                })
                
                logger.info(f"Registered new agent: {registration.agent_id}")
                return {"status": "registered", "agent_id": registration.agent_id}
            except Exception as e:
                logger.error(f"Failed to register agent: {e}")
                raise HTTPException(status_code=500, detail="Registration failed")
    
    return {"status": "already_registered", "agent_id": registration.agent_id}

@app.post("/issue", response_model=TokenResponse)
def issue_token(req: TokenRequest):
    """Issue a JWT token for agent-to-agent communication."""
    
    # Validate agents are registered
    if not is_agent_registered(req.agent_id):
        log_audit_event("token_request_failed", req.agent_id, {
            "reason": "agent_not_registered",
            "target_agent": req.target_agent
        })
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Agent {req.agent_id} is not registered"
        )
    
    if not is_agent_registered(req.target_agent):
        log_audit_event("token_request_failed", req.agent_id, {
            "reason": "target_agent_not_registered",
            "target_agent": req.target_agent
        })
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Target agent {req.target_agent} is not registered"
        )
    
    # Generate token
    now = int(time.time())
    jti = secrets.token_urlsafe(16)  # Unique token ID
    
    payload = {
        "sub": req.agent_id,           # Subject (sender)
        "aud": req.target_agent,       # Audience (recipient)
        "iat": now,                    # Issued at
        "exp": now + req.ttl_seconds,  # Expiration
        "jti": jti,                    # JWT ID for revocation
        "rights": req.requested_rights, # Permissions
        "iss": "secure-agent-policy-service"  # Issuer
    }
    
    try:
        token = jwt.encode(payload, SECRET, algorithm="HS256")
        
        # Log successful token issuance
        log_audit_event("token_issued", req.agent_id, {
            "target_agent": req.target_agent,
            "ttl_seconds": req.ttl_seconds,
            "rights": req.requested_rights,
            "jti": jti
        })
        
        logger.info(f"Issued token for {req.agent_id} -> {req.target_agent} (TTL: {req.ttl_seconds}s)")
        
        return TokenResponse(
            token=token,
            expires_at=now + req.ttl_seconds,
            issued_at=now,
            rights=req.requested_rights
        )
        
    except Exception as e:
        logger.error(f"Failed to issue token: {e}")
        raise HTTPException(status_code=500, detail="Token generation failed")

@app.post("/validate")
def validate_token(validation_req: TokenValidationRequest):
    """Validate a JWT token for a specific action."""
    try:
        # Decode and verify token signature
        payload = jwt.decode(
            validation_req.token, 
            SECRET, 
            algorithms=["HS256"],
            options={
                "verify_exp": False, 
                "verify_iat": False,
                "verify_aud": False,
                "verify_iss": False
            }
        )
        
        # Check if token is revoked
        if is_token_revoked(payload.get("jti")):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked"
            )
        
        # Validate sender and recipient match token claims
        if payload.get("sub") != validation_req.sender_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Token sender mismatch"
            )
        
        if payload.get("aud") != validation_req.recipient_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Token recipient mismatch"
            )
        
        # Check if action is permitted
        rights = payload.get("rights", [])
        if validation_req.action not in rights:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Action '{validation_req.action}' not permitted"
            )
        
        # Log successful validation
        log_audit_event("token_validated", validation_req.sender_id, {
            "target_agent": validation_req.recipient_id,
            "action": validation_req.action,
            "jti": payload.get("jti")
        })
        
        return {
            "valid": True,
            "payload": payload,
            "message": "Token is valid"
        }
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}"
        )

@app.post("/revoke")
def revoke_token_endpoint(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Revoke a token (admin endpoint)."""
    try:
        payload = jwt.decode(credentials.credentials, SECRET, algorithms=["HS256"])
        jti = payload.get("jti")
        
        if jti:
            revoke_token(jti)
            log_audit_event("token_revoked", payload.get("sub", "unknown"), {
                "jti": jti,
                "revoked_by": "admin"
            })
            return {"status": "revoked", "jti": jti}
        else:
            raise HTTPException(status_code=400, detail="Token has no JTI")
            
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/audit/{agent_id}")
def get_audit_log(agent_id: str, limit: int = 100):
    """Get audit log for an agent (admin endpoint)."""
    if not mongo_client:
        raise HTTPException(status_code=503, detail="Audit service unavailable")
    
    try:
        events = list(audit_collection.find(
            {"agent_id": agent_id},
            {"_id": 0}
        ).sort("timestamp", -1).limit(limit))
        
        return {"agent_id": agent_id, "events": events}
    except Exception as e:
        logger.error(f"Failed to retrieve audit log: {e}")
        raise HTTPException(status_code=500, detail="Audit retrieval failed")

if __name__ == "__main__":
    uvicorn.run(
        "policy_service:app",
        host="0.0.0.0",
        port=8000,
        log_level="info",
        reload=False
    )
