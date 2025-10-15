#!/usr/bin/env python3
"""
Send Demo - Secure Agent Message Sender

This demo shows how to securely send encrypted messages between agents
using the Agent SDK with proper error handling and logging.
"""

import sys
import os
import argparse
import logging
from pathlib import Path
from getpass import getpass

from agent_sdk import AgentSDK, AgentSDKError

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    """Main function for sending secure messages."""
    parser = argparse.ArgumentParser(description="Send encrypted messages between agents")
    parser.add_argument("--sender-id", default="agentA", help="Sender agent ID")
    parser.add_argument("--recipient-id", default="agentB", help="Recipient agent ID")
    parser.add_argument("--message", default="Secret command: start analysis on dataset X", 
                       help="Message to send")
    parser.add_argument("--keys-dir", default="keys", help="Directory containing key files")
    parser.add_argument("--ttl", type=int, default=300, help="Token TTL in seconds")
    parser.add_argument("--interactive", action="store_true", help="Interactive mode")
    parser.add_argument("--password", action="store_true", help="Use password-protected private key")
    
    args = parser.parse_args()
    
    # Construct key file paths
    keys_dir = Path(args.keys_dir)
    sender_priv_key = keys_dir / f"{args.sender_id}_priv.pem"
    sender_pub_key = keys_dir / f"{args.sender_id}_pub.pem"
    recipient_pub_key = keys_dir / f"{args.recipient_id}_pub.pem"
    recipient_queue = f"{args.recipient_id}_queue"
    
    # Verify key files exist
    for key_file in [sender_priv_key, sender_pub_key, recipient_pub_key]:
        if not key_file.exists():
            logger.error(f"Key file not found: {key_file}")
            logger.info("Please run 'python generate_keys.py' first to generate keys")
            return 1
    
    try:
        # Get password if needed
        password = None
        if args.password:
            password = getpass(f"Enter password for {args.sender_id} private key: ").encode()
        
        # Initialize sender agent
        logger.info(f"Initializing sender agent: {args.sender_id}")
        with AgentSDK(
            agent_id=args.sender_id,
            priv_key_path=str(sender_priv_key),
            pub_key_path=str(sender_pub_key),
            password=password
        ) as sender:
            
            if args.interactive:
                # Interactive mode
                print(f"\n🔐 Secure Agent Communication Demo")
                print(f"Sender: {args.sender_id}")
                print(f"Recipient: {args.recipient_id}")
                print("Enter messages to send (type 'quit' to exit):\n")
                
                while True:
                    try:
                        message_text = input(f"{args.sender_id} > ")
                        if message_text.lower() in ['quit', 'exit', 'q']:
                            break
                        
                        if not message_text.strip():
                            continue
                        
                        # Request token for this message
                        logger.info(f"Requesting token for {args.sender_id} -> {args.recipient_id}")
                        token = sender.request_token(
                            target_agent=args.recipient_id,
                            ttl=args.ttl,
                            requested_rights=["send_message"]
                        )
                        
                        # Send message
                        message_bytes = message_text.encode('utf-8')
                        metadata = {
                            "message_type": "interactive",
                            "sender_name": args.sender_id,
                            "recipient_name": args.recipient_id
                        }
                        
                        sender.send_message(
                            recipient_queue=recipient_queue,
                            recipient_pubkey_path=str(recipient_pub_key),
                            message=message_bytes,
                            token=token,
                            metadata=metadata
                        )
                        
                        print(f"✓ Message sent to {args.recipient_id}")
                        
                    except KeyboardInterrupt:
                        print("\nExiting...")
                        break
                    except AgentSDKError as e:
                        logger.error(f"SDK Error: {e}")
                        print(f"❌ Failed to send message: {e}")
                    except Exception as e:
                        logger.error(f"Unexpected error: {e}")
                        print(f"❌ Unexpected error: {e}")
            
            else:
                # Single message mode
                logger.info(f"Requesting token for {args.sender_id} -> {args.recipient_id}")
                token = sender.request_token(
                    target_agent=args.recipient_id,
                    ttl=args.ttl,
                    requested_rights=["send_message"]
                )
                
                # Prepare message
                message_bytes = args.message.encode('utf-8')
                metadata = {
                    "message_type": "demo",
                    "sender_name": args.sender_id,
                    "recipient_name": args.recipient_id,
                    "demo_version": "1.0"
                }
                
                # Send message
                logger.info(f"Sending message to {recipient_queue}")
                sender.send_message(
                    recipient_queue=recipient_queue,
                    recipient_pubkey_path=str(recipient_pub_key),
                    message=message_bytes,
                    token=token,
                    metadata=metadata
                )
                
                print(f"✓ Successfully sent encrypted message to {args.recipient_id}")
                print(f"  Message: {args.message}")
                print(f"  Queue: {recipient_queue}")
                
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
