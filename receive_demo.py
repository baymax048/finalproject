#!/usr/bin/env python3
"""
Receive Demo - Secure Agent Message Receiver

This demo shows how to securely receive and decrypt messages from other agents
using the Agent SDK with audit logging and proper error handling.
"""

import sys
import os
import argparse
import logging
import json
import hashlib
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, Any
from getpass import getpass

from agent_sdk import AgentSDK, AgentSDKError
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AuditLogger:
    """Secure audit logging with tamper-evident hash chaining."""
    
    def __init__(self, mongo_url: str = "mongodb://admin:securepass123@localhost:27017/?authSource=admin", db_name: str = "audit_db"):
        """Initialize audit logger with MongoDB connection."""
        self.mongo_url = mongo_url
        self.db_name = db_name
        self.client = None
        self.db = None
        self.audit_col = None
        self.connected = False
        
        self._connect()
    
    def _connect(self):
        """Connect to MongoDB with error handling."""
        try:
            self.client = MongoClient(
                self.mongo_url,
                serverSelectionTimeoutMS=5000,  # 5 second timeout
                connectTimeoutMS=5000
            )
            # Test connection and auth
            self.client.admin.command("ping")
            
            self.db = self.client[self.db_name]
            self.audit_col = self.db["events"]
            self.connected = True
            logger.info("Connected to MongoDB for audit logging")
            
        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            logger.warning(f"MongoDB connection failed: {e}")
            logger.info("Audit logging will be disabled")
            self.connected = False
        except Exception as e:
            logger.error(f"Unexpected MongoDB error: {e}")
            self.connected = False
    
    def log_event(self, event_type: str, agent_id: str, details: Dict[str, Any]):
        """Log an audit event with hash chaining for tamper evidence."""
        if not self.connected:
            logger.debug(f"Audit event (MongoDB unavailable): {event_type} for {agent_id}")
            return
        
        try:
            # Get the last event for hash chaining
            last_event = self.audit_col.find_one(sort=[("seq", -1)]) or {"seq": 0, "hash": ""}
            seq = last_event["seq"] + 1
            
            # Create new event
            event = {
                "seq": seq,
                "timestamp": datetime.utcnow(),
                "event_type": event_type,
                "agent_id": agent_id,
                "details": details,
                "ts": int(time.time())
            }
            
            # Calculate hash for tamper evidence (hash chaining)
            event_str = json.dumps(event, sort_keys=True, default=str).encode()
            prev_hash = last_event["hash"].encode() if last_event["hash"] else b""
            event_hash = hashlib.sha256(prev_hash + event_str).hexdigest()
            event["hash"] = event_hash
            
            # Insert into database
            self.audit_col.insert_one(event)
            logger.debug(f"Logged audit event: {event_type} (seq: {seq})")
            
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")

def create_message_handler(agent_sdk: AgentSDK, audit_logger: AuditLogger, 
                          validate_tokens: bool = True) -> callable:
    """Create a message handler function with audit logging."""
    
    def handler(payload: Dict[str, Any]):
        """Handle received encrypted messages."""
        try:
            sender = payload.get("sender", "unknown")
            message_id = payload.get("message_id", "unknown")
            timestamp = payload.get("timestamp", int(time.time()))
            
            logger.info(f"Processing message from {sender} (ID: {message_id})")
            
            # Validate token if enabled
            if validate_tokens and "token" in payload:
                token_valid = agent_sdk.validate_token(
                    token=payload["token"],
                    sender_id=sender,
                    recipient_id=agent_sdk.agent_id,
                    action="send_message"
                )
                
                if not token_valid:
                    logger.warning(f"Invalid token from {sender}, rejecting message")
                    audit_logger.log_event("message_rejected", agent_sdk.agent_id, {
                        "sender": sender,
                        "reason": "invalid_token",
                        "message_id": message_id
                    })
                    return
                
                logger.debug(f"Token validation passed for {sender}")
            
            # Decrypt message
            try:
                plaintext = agent_sdk.decrypt_message(payload)
                message_text = plaintext.decode('utf-8')
                
                # Display received message
                print(f"\n📨 Message from {sender}:")
                print(f"   Content: {message_text}")
                print(f"   Time: {datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')}")
                
                # Display metadata if present
                metadata = payload.get("metadata", {})
                if metadata:
                    print(f"   Metadata: {metadata}")
                
                print()  # Empty line for readability
                
                # Log successful receipt
                audit_logger.log_event("message_received", agent_sdk.agent_id, {
                    "sender": sender,
                    "message_id": message_id,
                    "message_length": len(plaintext),
                    "timestamp": timestamp,
                    "metadata": metadata
                })
                
                logger.info(f"Successfully processed message from {sender}")
                
            except Exception as e:
                logger.error(f"Failed to decrypt message from {sender}: {e}")
                audit_logger.log_event("message_decrypt_failed", agent_sdk.agent_id, {
                    "sender": sender,
                    "message_id": message_id,
                    "error": str(e)
                })
                
        except Exception as e:
            logger.error(f"Message handler error: {e}")
            audit_logger.log_event("message_handler_error", agent_sdk.agent_id, {
                "error": str(e),
                "payload_keys": list(payload.keys()) if isinstance(payload, dict) else "invalid"
            })
    
    return handler

def main():
    """Main function for receiving secure messages."""
    parser = argparse.ArgumentParser(description="Receive encrypted messages from agents")
    parser.add_argument("--agent-id", default="agentB", help="Receiver agent ID")
    parser.add_argument("--keys-dir", default="keys", help="Directory containing key files")
    parser.add_argument("--mongo-url", default="mongodb://admin:securepass123@localhost:27017/?authSource=admin", 
                       help="MongoDB connection URL")
    parser.add_argument("--no-token-validation", action="store_true", 
                       help="Disable token validation (for testing)")
    parser.add_argument("--queue-name", help="Custom queue name (default: {agent_id}_queue)")
    parser.add_argument("--password", action="store_true", help="Use password-protected private key")
    
    args = parser.parse_args()
    
    # Construct paths
    keys_dir = Path(args.keys_dir)
    priv_key_path = keys_dir / f"{args.agent_id}_priv.pem"
    pub_key_path = keys_dir / f"{args.agent_id}_pub.pem"
    queue_name = args.queue_name or f"{args.agent_id}_queue"
    
    # Verify key files exist
    for key_file in [priv_key_path, pub_key_path]:
        if not key_file.exists():
            logger.error(f"Key file not found: {key_file}")
            logger.info("Please run 'python generate_keys.py' first to generate keys")
            return 1
    
    try:
        # Get password if needed
        password = None
        if args.password:
            password = getpass(f"Enter password for {args.agent_id} private key: ").encode()
        
        # Initialize audit logger
        logger.info("Initializing audit logger...")
        audit_logger = AuditLogger(args.mongo_url)
        
        # Initialize receiver agent
        logger.info(f"Initializing receiver agent: {args.agent_id}")
        with AgentSDK(
            agent_id=args.agent_id,
            priv_key_path=str(priv_key_path),
            pub_key_path=str(pub_key_path),
            password=password
        ) as receiver:
            
            # Log agent startup
            audit_logger.log_event("agent_started", args.agent_id, {
                "queue_name": queue_name,
                "token_validation": not args.no_token_validation,
                "mongo_connected": audit_logger.connected
            })
            
            # Create message handler
            handler = create_message_handler(
                receiver, 
                audit_logger, 
                validate_tokens=not args.no_token_validation
            )
            
            # Start listening
            print(f"\n🔐 Secure Agent Message Receiver")
            print(f"Agent ID: {args.agent_id}")
            print(f"Queue: {queue_name}")
            print(f"Token Validation: {'Enabled' if not args.no_token_validation else 'Disabled'}")
            print(f"Audit Logging: {'Enabled' if audit_logger.connected else 'Disabled'}")
            print("\nWaiting for messages... (Press Ctrl+C to stop)\n")
            
            # Listen for messages
            receiver.listen(queue_name, handler)
            
        return 0
        
    except KeyboardInterrupt:
        print("\n\nShutting down receiver...")
        logger.info("Receiver shutdown by user")
        return 0
    except AgentSDKError as e:
        logger.error(f"Agent SDK Error: {e}")
        print(f"❌ Agent SDK Error: {e}")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        print(f"❌ Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
