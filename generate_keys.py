#!/usr/bin/env python3
"""
Secure Key Generation Module for Agent-to-Agent Communication Framework

This module provides secure RSA key pair generation with proper file permissions,
key validation, and optional password protection for private keys.
"""

import os
import sys
import stat
import logging
import argparse
from pathlib import Path
from getpass import getpass
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def secure_file_permissions(file_path: str, is_private: bool = False) -> None:
    """Set secure file permissions for key files."""
    try:
        if is_private:
            # Private key: readable only by owner (600)
            os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)
        else:
            # Public key: readable by owner and group (644)
            os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
        logger.info(f"Set secure permissions for {file_path}")
    except OSError as e:
        logger.error(f"Failed to set permissions for {file_path}: {e}")

def validate_key_pair(private_key_path: str, public_key_path: str) -> bool:
    """Validate that a key pair is valid and matches."""
    try:
        # Load private key
        with open(private_key_path, 'rb') as f:
            private_key = load_pem_private_key(f.read(), password=None)
        
        # Load public key
        with open(public_key_path, 'rb') as f:
            public_key = load_pem_public_key(f.read())
        
        # Verify they match by comparing public key from private key
        derived_public = private_key.public_key()
        
        # Compare public key numbers
        return (derived_public.public_numbers().n == public_key.public_numbers().n and
                derived_public.public_numbers().e == public_key.public_numbers().e)
    
    except Exception as e:
        logger.error(f"Key validation failed: {e}")
        return False

def gen_keypair(name: str, key_size: int = 4096, use_password: bool = False, 
                output_dir: str = "keys") -> bool:
    """
    Generate a secure RSA key pair with proper file handling.
    
    Args:
        name: Agent name for key files
        key_size: RSA key size (default: 4096 bits)
        use_password: Whether to password-protect private key
        output_dir: Directory to store keys
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Create output directory if it doesn't exist
        Path(output_dir).mkdir(exist_ok=True)
        
        private_key_path = os.path.join(output_dir, f"{name}_priv.pem")
        public_key_path = os.path.join(output_dir, f"{name}_pub.pem")
        
        # Check if keys already exist
        if os.path.exists(private_key_path) or os.path.exists(public_key_path):
            response = input(f"Keys for {name} already exist. Overwrite? (y/N): ")
            if response.lower() != 'y':
                logger.info(f"Skipping key generation for {name}")
                return True
        
        logger.info(f"Generating {key_size}-bit RSA key pair for {name}...")
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        
        # Get password if requested
        password = None
        if use_password:
            password = getpass(f"Enter password for {name} private key: ").encode()
            encryption_algorithm = serialization.BestAvailableEncryption(password)
        else:
            encryption_algorithm = serialization.NoEncryption()
        
        # Serialize private key
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        
        # Get public key and serialize
        public_key = private_key.public_key()
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Write private key
        with open(private_key_path, 'wb') as f:
            f.write(pem_private)
        secure_file_permissions(private_key_path, is_private=True)
        
        # Write public key
        with open(public_key_path, 'wb') as f:
            f.write(pem_public)
        secure_file_permissions(public_key_path, is_private=False)
        
        # Validate the generated key pair
        if validate_key_pair(private_key_path, public_key_path):
            logger.info(f"✓ Successfully created and validated key pair for {name}")
            logger.info(f"  Private key: {private_key_path}")
            logger.info(f"  Public key: {public_key_path}")
            return True
        else:
            logger.error(f"Key pair validation failed for {name}")
            return False
            
    except Exception as e:
        logger.error(f"Failed to generate key pair for {name}: {e}")
        return False

def main():
    """Main function with command-line interface."""
    parser = argparse.ArgumentParser(description="Generate secure RSA key pairs for agents")
    parser.add_argument("agents", nargs="*", default=["agentA", "agentB"],
                       help="Agent names to generate keys for")
    parser.add_argument("--key-size", type=int, default=4096,
                       help="RSA key size in bits (default: 4096)")
    parser.add_argument("--password", action="store_true",
                       help="Password-protect private keys")
    parser.add_argument("--output-dir", default="keys",
                       help="Output directory for keys (default: keys)")
    
    args = parser.parse_args()
    
    success_count = 0
    total_count = len(args.agents)
    
    for agent in args.agents:
        if gen_keypair(agent, args.key_size, args.password, args.output_dir):
            success_count += 1
    
    logger.info(f"Key generation complete: {success_count}/{total_count} successful")
    
    if success_count == total_count:
        logger.info("All key pairs generated successfully!")
        return 0
    else:
        logger.error("Some key pairs failed to generate")
        return 1

if __name__ == "__main__":
    sys.exit(main())
