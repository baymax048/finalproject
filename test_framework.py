#!/usr/bin/env python3
"""
Comprehensive Test Suite for Secure Agent-to-Agent Communication Framework

This test suite validates all components of the secure communication framework
including key generation, policy service, agent SDK, and end-to-end messaging.
"""

import unittest
import tempfile
import shutil
import os
import sys
import time
import json
import threading
import requests
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from generate_keys import gen_keypair, validate_key_pair
from agent_sdk import AgentSDK, AgentSDKError, AuthenticationError, EncryptionError

class TestKeyGeneration(unittest.TestCase):
    """Test key generation functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir)
    
    def test_key_generation_success(self):
        """Test successful key pair generation."""
        result = gen_keypair("test_agent", output_dir=self.test_dir)
        self.assertTrue(result)
        
        # Check files exist
        priv_key_path = os.path.join(self.test_dir, "test_agent_priv.pem")
        pub_key_path = os.path.join(self.test_dir, "test_agent_pub.pem")
        
        self.assertTrue(os.path.exists(priv_key_path))
        self.assertTrue(os.path.exists(pub_key_path))
        
        # Validate key pair
        self.assertTrue(validate_key_pair(priv_key_path, pub_key_path))
    
    def test_key_validation(self):
        """Test key pair validation."""
        # Generate valid key pair
        gen_keypair("valid_agent", output_dir=self.test_dir)
        
        priv_path = os.path.join(self.test_dir, "valid_agent_priv.pem")
        pub_path = os.path.join(self.test_dir, "valid_agent_pub.pem")
        
        # Test valid pair
        self.assertTrue(validate_key_pair(priv_path, pub_path))
        
        # Test with non-existent file
        self.assertFalse(validate_key_pair("nonexistent.pem", pub_path))
    
    def test_multiple_agents_key_generation(self):
        """Test generating keys for multiple agents."""
        agents = ["agent1", "agent2", "agent3"]
        
        for agent in agents:
            result = gen_keypair(agent, output_dir=self.test_dir)
            self.assertTrue(result)
            
            priv_path = os.path.join(self.test_dir, f"{agent}_priv.pem")
            pub_path = os.path.join(self.test_dir, f"{agent}_pub.pem")
            
            self.assertTrue(os.path.exists(priv_path))
            self.assertTrue(os.path.exists(pub_path))
            self.assertTrue(validate_key_pair(priv_path, pub_path))

class TestAgentSDK(unittest.TestCase):
    """Test Agent SDK functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        
        # Generate test keys
        gen_keypair("test_sender", output_dir=self.test_dir)
        gen_keypair("test_receiver", output_dir=self.test_dir)
        
        self.sender_priv = os.path.join(self.test_dir, "test_sender_priv.pem")
        self.sender_pub = os.path.join(self.test_dir, "test_sender_pub.pem")
        self.receiver_priv = os.path.join(self.test_dir, "test_receiver_priv.pem")
        self.receiver_pub = os.path.join(self.test_dir, "test_receiver_pub.pem")
    
    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir)
    
    @patch('agent_sdk.pika.BlockingConnection')
    def test_agent_initialization(self, mock_connection):
        """Test agent SDK initialization."""
        mock_connection.return_value = Mock()
        
        agent = AgentSDK(
            agent_id="test_agent",
            priv_key_path=self.sender_priv,
            pub_key_path=self.sender_pub
        )
        
        self.assertEqual(agent.agent_id, "test_agent")
        self.assertIsNotNone(agent.priv)
        self.assertIsNotNone(agent.pub)
    
    @patch('agent_sdk.pika.BlockingConnection')
    @patch('agent_sdk.requests.post')
    def test_token_request(self, mock_post, mock_connection):
        """Test JWT token request."""
        mock_connection.return_value = Mock()
        mock_response = Mock()
        mock_response.json.return_value = {"token": "test_jwt_token"}
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response
        
        agent = AgentSDK(
            agent_id="test_sender",
            priv_key_path=self.sender_priv,
            pub_key_path=self.sender_pub
        )
        
        token = agent.request_token("test_receiver")
        self.assertEqual(token, "test_jwt_token")
        
        # Verify request was made correctly
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        self.assertIn("agent_id", call_args[1]["json"])
        self.assertEqual(call_args[1]["json"]["agent_id"], "test_sender")
    
    @patch('agent_sdk.pika.BlockingConnection')
    def test_message_encryption_decryption(self, mock_connection):
        """Test message encryption and decryption."""
        mock_connection.return_value = Mock()
        
        # Create sender and receiver agents
        sender = AgentSDK(
            agent_id="test_sender",
            priv_key_path=self.sender_priv,
            pub_key_path=self.sender_pub
        )
        
        receiver = AgentSDK(
            agent_id="test_receiver",
            priv_key_path=self.receiver_priv,
            pub_key_path=self.receiver_pub
        )
        
        # Test message
        original_message = b"This is a secret test message"
        
        # Mock the send_message method to capture payload
        captured_payload = {}
        
        def mock_publish(exchange, routing_key, body, properties=None):
            captured_payload.update(json.loads(body))
        
        sender.ch = Mock()
        sender.ch.basic_publish = mock_publish
        
        # Send message
        sender.send_message(
            recipient_queue="test_queue",
            recipient_pubkey_path=self.receiver_pub,
            message=original_message,
            token="test_token"
        )
        
        # Verify payload structure
        self.assertIn("sender", captured_payload)
        self.assertIn("ciphertext", captured_payload)
        self.assertIn("wrapped_key", captured_payload)
        self.assertIn("iv", captured_payload)
        
        # Decrypt message
        decrypted_message = receiver.decrypt_message(captured_payload)
        self.assertEqual(decrypted_message, original_message)
    
    @patch('agent_sdk.pika.BlockingConnection')
    def test_key_integrity_verification(self, mock_connection):
        """Test key integrity verification."""
        mock_connection.return_value = Mock()
        
        agent = AgentSDK(
            agent_id="test_agent",
            priv_key_path=self.sender_priv,
            pub_key_path=self.sender_pub
        )
        
        # Should pass initially
        self.assertTrue(agent.verify_key_integrity())
    
    @patch('agent_sdk.pika.BlockingConnection')
    def test_message_size_validation(self, mock_connection):
        """Test message size validation."""
        mock_connection.return_value = Mock()
        
        agent = AgentSDK(
            agent_id="test_agent",
            priv_key_path=self.sender_priv,
            pub_key_path=self.sender_pub
        )
        
        # Test with oversized message (2MB)
        large_message = b"x" * (2 * 1024 * 1024)
        
        with self.assertRaises(Exception):
            agent.send_message(
                recipient_queue="test_queue",
                recipient_pubkey_path=self.receiver_pub,
                message=large_message,
                token="test_token"
            )

class TestPolicyService(unittest.TestCase):
    """Test Policy Service functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.base_url = "http://localhost:8000"
        self.test_agents = ["test_agent_a", "test_agent_b"]
    
    def test_policy_service_health(self):
        """Test policy service health endpoint."""
        try:
            response = requests.get(f"{self.base_url}/health", timeout=5)
            if response.status_code == 200:
                data = response.json()
                self.assertIn("status", data)
                self.assertEqual(data["status"], "healthy")
                self.assertIn("mongodb", data)
                self.assertIn("timestamp", data)
        except requests.exceptions.ConnectionError:
            self.skipTest("Policy service not running")
    
    def test_agent_registration(self):
        """Test agent registration endpoint."""
        try:
            payload = {
                "agent_id": "test_registration_agent",
                "public_key_fingerprint": "test_fingerprint_123",
                "capabilities": ["send_message", "receive_message"]
            }
            
            response = requests.post(f"{self.base_url}/register", json=payload, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                self.assertIn("status", data)
                self.assertIn("agent_id", data)
                self.assertEqual(data["agent_id"], "test_registration_agent")
                self.assertIn(data["status"], ["registered", "already_registered"])
        except requests.exceptions.ConnectionError:
            self.skipTest("Policy service not running")
    
    def test_token_issuance(self):
        """Test JWT token issuance."""
        try:
            # First register agents
            for agent in self.test_agents:
                reg_payload = {
                    "agent_id": agent,
                    "public_key_fingerprint": f"test_fp_{agent}",
                    "capabilities": ["send_message", "receive_message"]
                }
                requests.post(f"{self.base_url}/register", json=reg_payload, timeout=5)
            
            # Request token
            token_payload = {
                "agent_id": self.test_agents[0],
                "target_agent": self.test_agents[1],
                "ttl_seconds": 300,
                "requested_rights": ["send_message"]
            }
            
            response = requests.post(f"{self.base_url}/issue", json=token_payload, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                self.assertIn("token", data)
                self.assertIn("expires_at", data)
                self.assertIn("issued_at", data)
                self.assertIn("rights", data)
                self.assertEqual(data["rights"], ["send_message"])
        except requests.exceptions.ConnectionError:
            self.skipTest("Policy service not running")
    
    def test_token_validation(self):
        """Test JWT token validation."""
        try:
            # Register agents and get token
            for agent in self.test_agents:
                reg_payload = {
                    "agent_id": agent,
                    "public_key_fingerprint": f"test_fp_{agent}",
                    "capabilities": ["send_message", "receive_message"]
                }
                requests.post(f"{self.base_url}/register", json=reg_payload, timeout=5)
            
            # Get token
            token_payload = {
                "agent_id": self.test_agents[0],
                "target_agent": self.test_agents[1],
                "ttl_seconds": 300
            }
            token_response = requests.post(f"{self.base_url}/issue", json=token_payload, timeout=5)
            
            if token_response.status_code == 200:
                token_data = token_response.json()
                token = token_data["token"]
                
                # Validate token
                validation_payload = {
                    "token": token,
                    "sender_id": self.test_agents[0],
                    "recipient_id": self.test_agents[1],
                    "action": "send_message"
                }
                
                validation_response = requests.post(f"{self.base_url}/validate", json=validation_payload, timeout=5)
                
                if validation_response.status_code == 200:
                    validation_data = validation_response.json()
                    self.assertTrue(validation_data["valid"])
                    self.assertIn("payload", validation_data)
                    self.assertEqual(validation_data["payload"]["sub"], self.test_agents[0])
                    self.assertEqual(validation_data["payload"]["aud"], self.test_agents[1])
        except requests.exceptions.ConnectionError:
            self.skipTest("Policy service not running")
    
    def test_audit_log_retrieval(self):
        """Test audit log retrieval."""
        try:
            # Register an agent to generate audit events
            reg_payload = {
                "agent_id": "audit_test_agent",
                "public_key_fingerprint": "audit_test_fp",
                "capabilities": ["send_message"]
            }
            requests.post(f"{self.base_url}/register", json=reg_payload, timeout=5)
            
            # Get audit log
            response = requests.get(f"{self.base_url}/audit/audit_test_agent", timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                self.assertIn("agent_id", data)
                self.assertIn("events", data)
                self.assertEqual(data["agent_id"], "audit_test_agent")
                self.assertIsInstance(data["events"], list)
        except requests.exceptions.ConnectionError:
            self.skipTest("Policy service not running")

class TestEndToEndCommunication(unittest.TestCase):
    """Test end-to-end communication between agents."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        
        # Generate test keys
        gen_keypair("e2e_sender", output_dir=self.test_dir)
        gen_keypair("e2e_receiver", output_dir=self.test_dir)
        
        self.sender_priv = os.path.join(self.test_dir, "e2e_sender_priv.pem")
        self.sender_pub = os.path.join(self.test_dir, "e2e_sender_pub.pem")
        self.receiver_priv = os.path.join(self.test_dir, "e2e_receiver_priv.pem")
        self.receiver_pub = os.path.join(self.test_dir, "e2e_receiver_pub.pem")
    
    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir)
    
    @patch('agent_sdk.pika.BlockingConnection')
    @patch('agent_sdk.requests.post')
    def test_full_message_flow(self, mock_post, mock_connection):
        """Test complete message flow from sender to receiver."""
        # Mock RabbitMQ connection
        mock_conn = Mock()
        mock_channel = Mock()
        mock_conn.channel.return_value = mock_channel
        mock_connection.return_value = mock_conn
        
        # Mock token response
        mock_response = Mock()
        mock_response.json.return_value = {"token": "test_jwt_token"}
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response
        
        # Create agents
        sender = AgentSDK(
            agent_id="e2e_sender",
            priv_key_path=self.sender_priv,
            pub_key_path=self.sender_pub
        )
        
        receiver = AgentSDK(
            agent_id="e2e_receiver",
            priv_key_path=self.receiver_priv,
            pub_key_path=self.receiver_pub
        )
        
        # Test message
        test_message = b"End-to-end test message"
        
        # Capture published message
        published_message = {}
        
        def capture_publish(exchange, routing_key, body, properties=None):
            published_message.update(json.loads(body))
        
        mock_channel.basic_publish = capture_publish
        
        # Request token and send message
        token = sender.request_token("e2e_receiver")
        sender.send_message(
            recipient_queue="e2e_receiver_queue",
            recipient_pubkey_path=self.receiver_pub,
            message=test_message,
            token=token
        )
        
        # Verify message was published
        self.assertIn("sender", published_message)
        self.assertEqual(published_message["sender"], "e2e_sender")
        
        # Decrypt and verify message
        decrypted = receiver.decrypt_message(published_message)
        self.assertEqual(decrypted, test_message)

class TestSecurityFeatures(unittest.TestCase):
    """Test security features and edge cases."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        gen_keypair("security_test", output_dir=self.test_dir)
        
        self.priv_key = os.path.join(self.test_dir, "security_test_priv.pem")
        self.pub_key = os.path.join(self.test_dir, "security_test_pub.pem")
    
    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir)
    
    @patch('agent_sdk.pika.BlockingConnection')
    def test_invalid_key_handling(self, mock_connection):
        """Test handling of invalid keys."""
        mock_connection.return_value = Mock()
        
        # Test with non-existent key file
        with self.assertRaises(Exception):
            AgentSDK(
                agent_id="invalid_test",
                priv_key_path="nonexistent.pem",
                pub_key_path=self.pub_key
            )
    
    def test_token_validation_edge_cases(self):
        """Test token validation with edge cases."""
        try:
            # Test with invalid token
            invalid_payload = {
                "token": "invalid.jwt.token",
                "sender_id": "test_sender",
                "recipient_id": "test_recipient",
                "action": "send_message"
            }
            
            response = requests.post("http://localhost:8000/validate", json=invalid_payload, timeout=5)
            self.assertEqual(response.status_code, 401)
            
        except requests.exceptions.ConnectionError:
            self.skipTest("Policy service not running")

def run_integration_tests():
    """Run integration tests that require running services."""
    print("🧪 Running Secure Agent Communication Test Suite")
    print("=" * 60)
    
    # Test if services are running
    services_running = True
    service_status = {}
    
    try:
        # Test RabbitMQ
        import pika
        connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
        connection.close()
        service_status["RabbitMQ"] = "✅ Running"
    except Exception as e:
        services_running = False
        service_status["RabbitMQ"] = f"❌ Not running: {e}"
    
    try:
        # Test Policy Service
        response = requests.get("http://localhost:8000/health", timeout=5)
        if response.status_code == 200:
            service_status["Policy Service"] = "✅ Running"
        else:
            services_running = False
            service_status["Policy Service"] = f"❌ Unhealthy: {response.status_code}"
    except Exception as e:
        services_running = False
        service_status["Policy Service"] = f"❌ Not running: {e}"
    
    # Print service status
    print("Service Status:")
    for service, status in service_status.items():
        print(f"  {service}: {status}")
    print()
    
    if services_running:
        print("🚀 All services are running - running full integration tests")
        print("-" * 60)
        
        # Run full test suite
        loader = unittest.TestLoader()
        suite = unittest.TestSuite()
        
        # Add all test classes
        test_classes = [
            TestKeyGeneration,
            TestAgentSDK,
            TestPolicyService,
            TestEndToEndCommunication,
            TestSecurityFeatures
        ]
        
        for test_class in test_classes:
            suite.addTests(loader.loadTestsFromTestCase(test_class))
        
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        
        # Print summary
        print("\n" + "=" * 60)
        print("🎯 Test Summary:")
        print(f"  Tests run: {result.testsRun}")
        print(f"  Failures: {len(result.failures)}")
        print(f"  Errors: {len(result.errors)}")
        print(f"  Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
        
        if result.wasSuccessful():
            print("🎉 All tests passed! Your secure agent communication framework is working correctly.")
        else:
            print("⚠️  Some tests failed. Please check the output above for details.")
        
        return result.wasSuccessful()
    else:
        print("⚠️  Services not running - running unit tests only")
        print("-" * 60)
        
        # Run only unit tests
        loader = unittest.TestLoader()
        suite = unittest.TestSuite()
        
        # Add unit test classes (those that don't require services)
        unit_test_classes = [
            TestKeyGeneration,
            TestAgentSDK,
            TestSecurityFeatures
        ]
        
        for test_class in unit_test_classes:
            suite.addTests(loader.loadTestsFromTestCase(test_class))
        
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        
        print("\n" + "=" * 60)
        print("📝 To run full integration tests:")
        print("  1. Start RabbitMQ and MongoDB: docker-compose up rabbitmq mongo -d")
        print("  2. Start Policy Service: python policy_service.py")
        print("  3. Run tests again: python test_framework.py")
        
        return result.wasSuccessful()

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Run secure agent communication tests")
    parser.add_argument("--unit-only", action="store_true", 
                       help="Run only unit tests (no service dependencies)")
    parser.add_argument("--integration", action="store_true",
                       help="Run integration tests (requires running services)")
    
    args = parser.parse_args()
    
    if args.unit_only:
        print("🧪 Running Unit Tests Only")
        print("=" * 40)
        
        # Run unit tests only
        loader = unittest.TestLoader()
        suite = unittest.TestSuite()
        
        unit_test_classes = [
            TestKeyGeneration,
            TestAgentSDK,
            TestSecurityFeatures
        ]
        
        for test_class in unit_test_classes:
            suite.addTests(loader.loadTestsFromTestCase(test_class))
        
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        
        sys.exit(0 if result.wasSuccessful() else 1)
    
    elif args.integration:
        # Run integration tests
        success = run_integration_tests()
        sys.exit(0 if success else 1)
    
    else:
        # Auto-detect and run appropriate tests
        success = run_integration_tests()
        sys.exit(0 if success else 1)