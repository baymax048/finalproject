#!/usr/bin/env python3
"""
Web Backend for Secure Agent Communication Framework

This backend provides REST API endpoints for the web GUI including:
- User authentication and authorization
- Agent management
- Message handling with real-time updates
- Key management
- Audit log viewing
"""

import os
import time
import logging
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import jwt
import bcrypt
from fastapi import FastAPI, HTTPException, Depends, status, WebSocket, WebSocketDisconnect
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, EmailStr, validator
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

SECRET_KEY = os.getenv("JWT_SECRET", "secure-web-gui-secret-key-change-in-production")
MONGO_URL = os.getenv("MONGO_URL", "mongodb://admin:securepass123@localhost:27017/?authSource=admin")
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 7

app = FastAPI(
    title="Secure Agent Communication Web API",
    description="Web API for secure agent communication management",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

try:
    mongo_client = MongoClient(MONGO_URL, serverSelectionTimeoutMS=5000)
    mongo_client.admin.command("ping")
    db = mongo_client["agent_web_db"]
    users_col = db["users"]
    agents_col = db["agents"]
    messages_col = db["messages"]
    keys_col = db["encryption_keys"]
    audit_col = db["audit_logs"]
    tokens_col = db["jwt_tokens"]

    users_col.create_index("email", unique=True)
    agents_col.create_index("agent_id", unique=True)
    agents_col.create_index("user_id")
    messages_col.create_index([("created_at", -1)])

    logger.info("Connected to MongoDB successfully")
except Exception as e:
    logger.error(f"Failed to connect to MongoDB: {e}")
    mongo_client = None

class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: str = Field(..., min_length=1)

    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        return v

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int

class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str
    role: str
    created_at: datetime
    last_login: Optional[datetime]

class AgentCreate(BaseModel):
    agent_id: str = Field(..., pattern="^[a-zA-Z0-9_-]+$")
    public_key_fingerprint: str
    capabilities: List[str] = Field(default=["send_message", "receive_message"])

class AgentResponse(BaseModel):
    id: str
    agent_id: str
    user_id: str
    public_key_fingerprint: str
    capabilities: List[str]
    status: str
    last_seen: Optional[datetime]
    created_at: datetime

class MessageCreate(BaseModel):
    recipient_agent_id: str
    content: str
    metadata: Optional[Dict] = {}

class MessageResponse(BaseModel):
    id: str
    message_id: str
    sender_agent_id: str
    recipient_agent_id: str
    sender_name: str
    recipient_name: str
    content: str
    status: str
    metadata: Dict
    sent_at: datetime

class WebSocketManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, user_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[user_id] = websocket
        logger.info(f"WebSocket connected for user: {user_id}")

    def disconnect(self, user_id: str):
        if user_id in self.active_connections:
            del self.active_connections[user_id]
            logger.info(f"WebSocket disconnected for user: {user_id}")

    async def send_message(self, user_id: str, message: dict):
        if user_id in self.active_connections:
            try:
                await self.active_connections[user_id].send_json(message)
            except Exception as e:
                logger.error(f"Failed to send WebSocket message: {e}")
                self.disconnect(user_id)

    async def broadcast_to_user(self, user_id: str, message_type: str, data: dict):
        await self.send_message(user_id, {"type": message_type, "data": data})

ws_manager = WebSocketManager()

async def notify_user(user_id: str, event_type: str, data: dict):
    await ws_manager.broadcast_to_user(user_id, event_type, data)

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

def create_token(user_id: str, token_type: str = "access") -> tuple:
    if token_type == "access":
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    else:
        expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    jti = secrets.token_urlsafe(16)
    payload = {
        "sub": user_id,
        "type": token_type,
        "exp": expire,
        "iat": datetime.utcnow(),
        "jti": jti
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

    if mongo_client:
        tokens_col.insert_one({
            "jti": jti,
            "user_id": user_id,
            "token_type": token_type,
            "expires_at": expire,
            "revoked": False,
            "created_at": datetime.utcnow()
        })

    return token, expire

def verify_token(token: str) -> Dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

        if mongo_client:
            token_doc = tokens_col.find_one({"jti": payload.get("jti")})
            if token_doc and token_doc.get("revoked"):
                raise HTTPException(status_code=401, detail="Token has been revoked")

        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    payload = verify_token(credentials.credentials)
    user_id = payload.get("sub")

    if not mongo_client:
        raise HTTPException(status_code=503, detail="Database unavailable")

    user = users_col.find_one({"_id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return user

def log_audit(event_type: str, user_id: str, details: Dict, severity: str = "info"):
    if mongo_client:
        try:
            audit_col.insert_one({
                "event_type": event_type,
                "user_id": user_id,
                "event_data": details,
                "severity": severity,
                "created_at": datetime.utcnow()
            })
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")

@app.get("/")
def root():
    return {
        "message": "Secure Agent Communication Web API",
        "version": "1.0.0",
        "status": "healthy"
    }

@app.get("/health")
def health_check():
    mongo_status = "disconnected"
    try:
        if mongo_client:
            mongo_client.admin.command("ping")
            mongo_status = "connected"
    except:
        mongo_status = "disconnected"

    return {
        "status": "healthy",
        "mongodb": mongo_status,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/api/auth/register", response_model=TokenResponse)
def register(user_data: UserRegister):
    if not mongo_client:
        raise HTTPException(status_code=503, detail="Database unavailable")

    if users_col.find_one({"email": user_data.email}):
        raise HTTPException(status_code=400, detail="Email already registered")

    user_id = secrets.token_urlsafe(16)
    password_hash = hash_password(user_data.password)

    user_doc = {
        "_id": user_id,
        "email": user_data.email,
        "password_hash": password_hash,
        "full_name": user_data.full_name,
        "role": "agent_operator",
        "created_at": datetime.utcnow(),
        "last_login": None,
        "is_active": True
    }

    users_col.insert_one(user_doc)

    log_audit("user_registered", user_id, {"email": user_data.email})

    access_token, access_expire = create_token(user_id, "access")
    refresh_token, refresh_expire = create_token(user_id, "refresh")

    logger.info(f"User registered: {user_data.email}")

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )

@app.post("/api/auth/login", response_model=TokenResponse)
def login(credentials: UserLogin):
    if not mongo_client:
        raise HTTPException(status_code=503, detail="Database unavailable")

    user = users_col.find_one({"email": credentials.email})
    if not user or not verify_password(credentials.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account is inactive")

    users_col.update_one(
        {"_id": user["_id"]},
        {"$set": {"last_login": datetime.utcnow()}}
    )

    log_audit("user_login", user["_id"], {"email": credentials.email})

    access_token, access_expire = create_token(user["_id"], "access")
    refresh_token, refresh_expire = create_token(user["_id"], "refresh")

    logger.info(f"User logged in: {credentials.email}")

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )

@app.get("/api/auth/me", response_model=UserResponse)
def get_current_user_info(current_user: dict = Depends(get_current_user)):
    return UserResponse(
        id=current_user["_id"],
        email=current_user["email"],
        full_name=current_user["full_name"],
        role=current_user["role"],
        created_at=current_user["created_at"],
        last_login=current_user.get("last_login")
    )

@app.post("/api/agents", response_model=AgentResponse)
def create_agent(agent_data: AgentCreate, current_user: dict = Depends(get_current_user)):
    if not mongo_client:
        raise HTTPException(status_code=503, detail="Database unavailable")

    if agents_col.find_one({"agent_id": agent_data.agent_id}):
        raise HTTPException(status_code=400, detail="Agent ID already exists")

    agent_id = secrets.token_urlsafe(16)
    agent_doc = {
        "_id": agent_id,
        "agent_id": agent_data.agent_id,
        "user_id": current_user["_id"],
        "public_key_fingerprint": agent_data.public_key_fingerprint,
        "capabilities": agent_data.capabilities,
        "status": "active",
        "last_seen": None,
        "metadata": {},
        "created_at": datetime.utcnow()
    }

    agents_col.insert_one(agent_doc)

    log_audit("agent_created", current_user["_id"], {
        "agent_id": agent_data.agent_id,
        "capabilities": agent_data.capabilities
    })

    logger.info(f"Agent created: {agent_data.agent_id} by {current_user['email']}")

    return AgentResponse(**agent_doc, id=agent_id)

@app.get("/api/agents", response_model=List[AgentResponse])
def list_agents(current_user: dict = Depends(get_current_user)):
    if not mongo_client:
        raise HTTPException(status_code=503, detail="Database unavailable")

    agents = list(agents_col.find({"user_id": current_user["_id"]}))

    return [AgentResponse(**agent, id=agent["_id"]) for agent in agents]

@app.get("/api/agents/{agent_id}", response_model=AgentResponse)
def get_agent(agent_id: str, current_user: dict = Depends(get_current_user)):
    if not mongo_client:
        raise HTTPException(status_code=503, detail="Database unavailable")

    agent = agents_col.find_one({"agent_id": agent_id, "user_id": current_user["_id"]})
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    return AgentResponse(**agent, id=agent["_id"])

@app.get("/api/messages", response_model=List[MessageResponse])
def list_messages(
    limit: int = 100,
    offset: int = 0,
    current_user: dict = Depends(get_current_user)
):
    if not mongo_client:
        raise HTTPException(status_code=503, detail="Database unavailable")

    user_agents = list(agents_col.find({"user_id": current_user["_id"]}, {"_id": 1}))
    agent_ids = [agent["_id"] for agent in user_agents]

    messages = list(messages_col.find({
        "$or": [
            {"sender_agent_id": {"$in": agent_ids}},
            {"recipient_agent_id": {"$in": agent_ids}}
        ]
    }).sort("sent_at", -1).skip(offset).limit(limit))

    for msg in messages:
        sender = agents_col.find_one({"_id": msg["sender_agent_id"]})
        recipient = agents_col.find_one({"_id": msg["recipient_agent_id"]})
        msg["sender_name"] = sender["agent_id"] if sender else "Unknown"
        msg["recipient_name"] = recipient["agent_id"] if recipient else "Unknown"

    return [MessageResponse(**msg, id=msg["_id"]) for msg in messages]

@app.get("/api/audit", response_model=List[Dict])
def get_audit_logs(
    limit: int = 100,
    offset: int = 0,
    current_user: dict = Depends(get_current_user)
):
    if not mongo_client:
        raise HTTPException(status_code=503, detail="Database unavailable")

    logs = list(audit_col.find({"user_id": current_user["_id"]})
                .sort("created_at", -1)
                .skip(offset)
                .limit(limit))

    for log in logs:
        log["id"] = str(log.pop("_id"))

    return logs

@app.get("/api/stats")
def get_stats(current_user: dict = Depends(get_current_user)):
    if not mongo_client:
        raise HTTPException(status_code=503, detail="Database unavailable")

    user_agents = list(agents_col.find({"user_id": current_user["_id"]}, {"_id": 1}))
    agent_ids = [agent["_id"] for agent in user_agents]

    total_agents = len(agent_ids)
    active_agents = agents_col.count_documents({
        "user_id": current_user["_id"],
        "status": "active"
    })

    total_messages = messages_col.count_documents({
        "$or": [
            {"sender_agent_id": {"$in": agent_ids}},
            {"recipient_agent_id": {"$in": agent_ids}}
        ]
    })

    sent_messages = messages_col.count_documents({"sender_agent_id": {"$in": agent_ids}})
    received_messages = messages_col.count_documents({"recipient_agent_id": {"$in": agent_ids}})

    return {
        "total_agents": total_agents,
        "active_agents": active_agents,
        "total_messages": total_messages,
        "sent_messages": sent_messages,
        "received_messages": received_messages
    }

@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: str):
    await ws_manager.connect(user_id, websocket)
    try:
        while True:
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(user_id)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "web_backend:app",
        host="0.0.0.0",
        port=8001,
        log_level="info",
        reload=False
    )
