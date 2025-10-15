#!/usr/bin/env python3
"""
Secure Agent SDK for Agent-to-Agent Communication Framework

This SDK provides secure messaging capabilities with encryption, authentication,
file integrity verification, and comprehensive logging for agent communication.
"""

import json
import requests
import time
import os
import base64
import hashlib
import logging
import secrets
from pathlib import Path
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime

import pika
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.exceptions import InvalidSignature

# Configuration
POLICY_URL = os.getenv("POLICY_URL", "http://localhost:8000/issue")
VALIDATE_URL = os.getenv("VALIDATE_URL", "http://localhost:8000/validate")
RABBIT_HOST = os.getenv("RABBIT_HOST", "localhost")
RABBIT_PORT = int(os.getenv("RABBIT_PORT", "5672"))
RABBIT_USER = os.getenv("RABBIT_USER", "guest")
RABBIT_PASS = os.getenv("RABBIT_PASS", "guest")
MAX_MESSAGE_SIZE = int(os.getenv("MAX_MESSAGE_SIZE", "1048576"))  # 1MB
CONNECTION_TIMEOUT = int(os.getenv("CONNECTION_TIMEOUT", "30"))

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AgentSDKError(Exception):
    """Base exception for Agent SDK errors."""
    pass

class AuthenticationError(AgentSDKError):
    """Authentication related errors."""
    pass

class EncryptionError(AgentSDKError):
    """Encryption/decryption related errors."""
    pass

class CommunicationError(AgentSDKError):
    """Communication related errors."""
    pass

class ValidationError(AgentSDKError):
    """Validation related errors."""
    pass

def calculate_file_hash(file_path: str) -> str:
    """Calculate SHA-256 hash of a file for integrity verification."""
    try:
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except Exception as e:
        logger.error(f"Failed to calculate hash for {file_path}: {e}")
        raise ValidationError(f"File hash calculation failed: {e}")

def load_public_key(path: str):
    """Load and validate a public key from PEM file."""
    try:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Public key file not found: {path}")
        
        with open(path, "rb") as f:
            key_data = f.read()
        
        public_key = load_pem_public_key(key_data)
        logger.debug(f"Successfully loaded public key from {path}")
        return public_key
    except Exception as e:
        logger.error(f"Failed to load public key from {path}: {e}")
        raise ValidationError(f"Public key loading failed: {e}")

def load_private_key(path: str, password: Optional[bytes] = None):
    """Load and validate a private key from PEM file."""
    try:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Private key file not found: {path}")
        
        with open(path, "rb") as f:
            key_data = f.read()
        
        private_key = load_pem_private_key(key_data, password=password)
        logger.debug(f"Successfully loaded private key from {path}")
        return private_key
    except Exception as e:
        logger.error(f"Failed to load private key from {path}: {e}")
        raise ValidationError(f"Private key loading failed: {e}")

class AgentSDK:
    """
    Secure Agent SDK for encrypted agent-to-agent communication.
    
    Features:
    - RSA + AES hybrid encryption
    - JWT token-based authentication
    - Message integrity verification
    - Comprehensive logging and error handling
    - File integrity checks
    """
    
    def __init__(self, agent_id: str, priv_key_path: Optional[str] = None, 
                 pub_key_path: Optional[str] = None, password: Optional[bytes] = None):
        """
        Initialize the Agent SDK.
        
        Args:
            agent_id: Unique identifier for this agent
            priv_key_path: Path to private key file
            pub_key_path: Path to public key file
            password: Password for encrypted private key
        """
        self.agent_id = agent_id
        self.priv = None
        self.pub = None
        self.conn = None
        self.ch = None
        self.message_handlers: Dict[str, Callable] = {}
        
        # Load keys if provided
        if priv_key_path:
            self.priv = load_private_key(priv_key_path, password)
            self.priv_key_path = priv_key_path
            self.priv_key_hash = calculate_file_hash(priv_key_path)
            logger.info(f"Loaded private key for agent {agent_id}")
        
        if pub_key_path:
            self.pub = load_public_key(pub_key_path)
            self.pub_key_path = pub_key_path
            self.pub_key_hash = calculate_file_hash(pub_key_path)
            logger.info(f"Loaded public key for agent {agent_id}")
        
        # Initialize RabbitMQ connection
        self._connect_rabbitmq()
        
        logger.info(f"Agent SDK initialized for {agent_id}")

    def _connect_rabbitmq(self):
        """Establish connection to RabbitMQ with retry logic."""
        max_retries = 3
        retry_delay = 2
        
        for attempt in range(max_retries):
            try:
                credentials = pika.PlainCredentials(RABBIT_USER, RABBIT_PASS)
                parameters = pika.ConnectionParameters(
                    host=RABBIT_HOST,
                    port=RABBIT_PORT,
                    credentials=credentials,
                    connection_attempts=3,
                    retry_delay=retry_delay,
                    socket_timeout=CONNECTION_TIMEOUT
                )
                
                self.conn = pika.BlockingConnection(parameters)
                self.ch = self.conn.channel()
                
                logger.info(f"Connected to RabbitMQ at {RABBIT_HOST}:{RABBIT_PORT}")
                return
                
            except Exception as e:
                logger.warning(f"RabbitMQ connection attempt {attempt + 1} failed: {e}")
                if attempt == max_retries - 1:
                    raise CommunicationError(f"Failed to connect to RabbitMQ after {max_retries} attempts: {e}")
                time.sleep(retry_delay)

    def verify_key_integrity(self):
        """Verify that key files haven't been tampered with."""
        try:
            if hasattr(self, 'priv_key_path') and hasattr(self, 'priv_key_hash'):
                current_hash = calculate_file_hash(self.priv_key_path)
                if current_hash != self.priv_key_hash:
                    raise ValidationError("Private key file has been modified!")
            
            if hasattr(self, 'pub_key_path') and hasattr(self, 'pub_key_hash'):
                current_hash = calculate_file_hash(self.pub_key_path)
                if current_hash != self.pub_key_hash:
                    raise ValidationError("Public key file has been modified!")
            
            logger.debug("Key integrity verification passed")
            return True
        except Exception as e:
            logger.error(f"Key integrity verification failed: {e}")
            raise

    def request_token(self, target_agent: str, ttl: int = 300, 
                     requested_rights: List[str] = None) -> str:
        """
        Request a JWT token for communicating with target agent.
        
        Args:
            target_agent: ID of the target agent
            ttl: Token time-to-live in seconds
            requested_rights: List of requested permissions
        
        Returns:
            JWT token string
        """
        if requested_rights is None:
            requested_rights = ["send_message"]
        
        try:
            payload = {
                "agent_id": self.agent_id,
                "target_agent": target_agent,
                "ttl_seconds": ttl,
                "requested_rights": requested_rights
            }
            
            logger.info(f"Requesting token for {self.agent_id} -> {target_agent}")
            
            response = requests.post(
                POLICY_URL, 
                json=payload,
                timeout=CONNECTION_TIMEOUT,
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            
            token_data = response.json()
            token = token_data["token"]
            
            logger.info(f"Successfully obtained token for {target_agent}")
            return token
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Token request failed: {e}")
            raise AuthenticationError(f"Failed to obtain token: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during token request: {e}")
            raise AuthenticationError(f"Token request error: {e}")

    def validate_token(self, token: str, sender_id: str, recipient_id: str, 
                      action: str = "send_message") -> bool:
        """
        Validate a JWT token with the policy service.
        
        Args:
            token: JWT token to validate
            sender_id: ID of the sender
            recipient_id: ID of the recipient
            action: Action being performed
        
        Returns:
            True if token is valid
        """
        try:
            payload = {
                "token": token,
                "sender_id": sender_id,
                "recipient_id": recipient_id,
                "action": action
            }
            
            response = requests.post(
                VALIDATE_URL,
                json=payload,
                timeout=CONNECTION_TIMEOUT,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                logger.debug(f"Token validation successful for {sender_id} -> {recipient_id}")
                return True
            else:
                logger.warning(f"Token validation failed: {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Token validation error: {e}")
            return False

    def send_message(self, recipient_queue: str, recipient_pubkey_path: str, 
                    message: bytes, token: str, metadata: Dict = None):
        """
        Send an encrypted message to another agent.
        
        Args:
            recipient_queue: RabbitMQ queue name for recipient
            recipient_pubkey_path: Path to recipient's public key
            message: Message bytes to encrypt and send
            token: JWT authentication token
            metadata: Optional metadata to include
        """
        try:
            # Verify our key integrity
            self.verify_key_integrity()
            
            # Validate message size
            if len(message) > MAX_MESSAGE_SIZE:
                raise ValidationError(f"Message too large: {len(message)} > {MAX_MESSAGE_SIZE}")
            
            # Generate ephemeral AES key for message encryption
            aes_key = AESGCM.generate_key(bit_length=256)
            aes = AESGCM(aes_key)
            iv = os.urandom(12)  # 96-bit IV for GCM
            
            # Encrypt message with AES-GCM
            ciphertext = aes.encrypt(iv, message, None)
            
            # Load recipient's public key and encrypt AES key
            recipient_pub = load_public_key(recipient_pubkey_path)
            wrapped_key = recipient_pub.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Calculate message hash for integrity
            message_hash = hashlib.sha256(message).hexdigest()
            
            # Create message payload
            payload = {
                "sender": self.agent_id,
                "token": token,
                "iv": base64.b64encode(iv).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "wrapped_key": base64.b64encode(wrapped_key).decode(),
                "message_hash": message_hash,
                "timestamp": int(time.time()),
                "message_id": secrets.token_urlsafe(16),
                "metadata": metadata or {}
            }
            
            # Publish to RabbitMQ
            self.ch.basic_publish(
                exchange='',
                routing_key=recipient_queue,
                body=json.dumps(payload),
                properties=pika.BasicProperties(
                    delivery_mode=2,  # Make message persistent
                    timestamp=int(time.time())
                )
            )
            
            logger.info(f"Message sent from {self.agent_id} to {recipient_queue}")
            logger.debug(f"Message ID: {payload['message_id']}")
            
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            raise CommunicationError(f"Message sending failed: {e}")

    def listen(self, my_queue: str, handler: Callable[[Dict], None]):
        """
        Listen for incoming messages on a queue.
        
        Args:
            my_queue: Queue name to listen on
            handler: Function to handle received messages
        """
        try:
            # Declare queue with durability
            self.ch.queue_declare(queue=my_queue, durable=True)
            
            def callback(ch, method, properties, body):
                try:
                    data = json.loads(body)
                    logger.info(f"Received message on {my_queue} from {data.get('sender', 'unknown')}")
                    
                    # Call the handler
                    handler(data)
                    
                    # Acknowledge message
                    ch.basic_ack(delivery_tag=method.delivery_tag)
                    
                except Exception as e:
                    logger.error(f"Message handling error: {e}")
                    # Reject message and don't requeue
                    ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
            
            # Set up consumer
            self.ch.basic_qos(prefetch_count=1)  # Process one message at a time
            self.ch.basic_consume(queue=my_queue, on_message_callback=callback)
            
            logger.info(f"[{self.agent_id}] Listening for messages on {my_queue}")
            self.ch.start_consuming()
            
        except KeyboardInterrupt:
            logger.info("Stopping message consumption...")
            self.ch.stop_consuming()
        except Exception as e:
            logger.error(f"Error in message listener: {e}")
            raise CommunicationError(f"Message listening failed: {e}")

    def decrypt_message(self, payload: Dict) -> bytes:
        """
        Decrypt a received message payload.
        
        Args:
            payload: Message payload dictionary
        
        Returns:
            Decrypted message bytes
        """
        try:
            # Verify our key integrity
            self.verify_key_integrity()
            
            if not self.priv:
                raise EncryptionError("No private key available for decryption")
            
            # Extract encrypted components
            iv = base64.b64decode(payload["iv"])
            ciphertext = base64.b64decode(payload["ciphertext"])
            wrapped_key = base64.b64decode(payload["wrapped_key"])
            
            # Decrypt AES key using our private key
            aes_key = self.priv.decrypt(
                wrapped_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt message using AES key
            aes = AESGCM(aes_key)
            plaintext = aes.decrypt(iv, ciphertext, None)
            
            # Verify message integrity if hash is provided
            if "message_hash" in payload:
                calculated_hash = hashlib.sha256(plaintext).hexdigest()
                if calculated_hash != payload["message_hash"]:
                    raise ValidationError("Message integrity check failed")
                logger.debug("Message integrity verification passed")
            
            logger.info(f"Successfully decrypted message from {payload.get('sender', 'unknown')}")
            return plaintext
            
        except Exception as e:
            logger.error(f"Message decryption failed: {e}")
            raise EncryptionError(f"Decryption failed: {e}")

    def close(self):
        """Close RabbitMQ connection."""
        try:
            if self.conn and not self.conn.is_closed:
                self.conn.close()
                logger.info(f"Closed connection for agent {self.agent_id}")
        except Exception as e:
            logger.error(f"Error closing connection: {e}")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
