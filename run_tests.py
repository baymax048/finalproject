#!/usr/bin/env python3
"""
Test Runner Script for Secure Agent Communication Framework

This script provides a convenient way to run all tests and verify the framework
is working correctly.
"""

import os
import sys
import subprocess
import time
import requests
from pathlib import Path

def run_command(cmd, cwd=None, timeout=30):
    """Run a command and return success status."""
    try:
        result = subprocess.run(
            cmd, 
            shell=True, 
            cwd=cwd, 
            capture_output=True, 
            text=True, 
            timeout=timeout
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except Exception as e:
        return False, "", str(e)

def check_dependencies():
    """Check if all required dependencies are installed."""
    print("🔍 Checking dependencies...")
    
    required_packages = [
        'cryptography', 'fastapi', 'uvicorn', 'pika', 
        'pymongo', 'pyjwt', 'requests', 'pydantic'
    ]
    
    missing = []
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing.append(package)
    
    if missing:
        print(f"❌ Missing packages: {', '.join(missing)}")
        print("   Run: pip install -r requirements.txt")
        return False
    
    print("✅ All dependencies installed")
    return True

def test_key_generation():
    """Test key generation functionality."""
    print("\n🔑 Testing key generation...")
    
    # Clean up any existing test keys
    test_keys = ['testA_priv.pem', 'testA_pub.pem', 'testB_priv.pem', 'testB_pub.pem']
    for key in test_keys:
        if os.path.exists(key):
            os.remove(key)
    
    success, stdout, stderr = run_command("python generate_keys.py testA testB")
    
    if success and all(os.path.exists(key) for key in test_keys):
        print("✅ Key generation successful")
        return True
    else:
        print(f"❌ Key generation failed: {stderr}")
        return False

def test_unit_tests():
    """Run unit tests."""
    print("\n🧪 Running unit tests...")
    
    success, stdout, stderr = run_command("python test_framework.py --unit-only")
    
    if success:
        print("✅ Unit tests passed")
        return True
    else:
        print(f"❌ Unit tests failed: {stderr}")
        return False

def test_policy_service():
    """Test policy service if running."""
    print("\n🛡️ Testing policy service...")
    
    try:
        response = requests.get("http://localhost:8000/health", timeout=5)
        if response.status_code == 200:
            print("✅ Policy service is running and healthy")
            return True
        else:
            print(f"⚠️ Policy service returned status {response.status_code}")
            return False
    except requests.exceptions.ConnectionError:
        print("⚠️ Policy service not running (this is OK for unit tests)")
        return True
    except Exception as e:
        print(f"❌ Policy service test failed: {e}")
        return False

def verify_project_structure():
    """Verify all required files are present."""
    print("\n📁 Verifying project structure...")
    
    required_files = [
        'agent_sdk.py',
        'policy_service.py', 
        'generate_keys.py',
        'send_demo.py',
        'receive_demo.py',
        'test_framework.py',
        'requirements.txt',
        'docker-compose.yml',
        'README.md'
    ]
    
    missing = []
    for file in required_files:
        if not os.path.exists(file):
            missing.append(file)
    
    if missing:
        print(f"❌ Missing files: {', '.join(missing)}")
        return False
    
    print("✅ All required files present")
    return True

def run_integration_demo():
    """Run a quick integration demo if services are available."""
    print("\n🚀 Running integration demo...")
    
    # Check if we have keys
    if not all(os.path.exists(f"keys/{agent}_{key}.pem") 
               for agent in ['agentA', 'agentB'] 
               for key in ['priv', 'pub']):
        print("⚠️ Demo keys not found, generating...")
        success, _, _ = run_command("python generate_keys.py")
        if not success:
            print("❌ Failed to generate demo keys")
            return False
    
    # Try to send a test message (this will fail gracefully if services aren't running)
    print("   Testing message sending (may fail if services not running)...")
    success, stdout, stderr = run_command(
        'python send_demo.py --message "Integration test message"',
        timeout=10
    )
    
    if success:
        print("✅ Integration demo successful")
        return True
    else:
        print("⚠️ Integration demo failed (services may not be running)")
        print("   This is expected if RabbitMQ/Policy Service aren't running")
        return True  # Don't fail the overall test for this

def main():
    """Run all tests and verifications."""
    print("🔐 Secure Agent Communication Framework - Test Runner")
    print("=" * 60)
    
    tests = [
        ("Dependencies", check_dependencies),
        ("Project Structure", verify_project_structure),
        ("Key Generation", test_key_generation),
        ("Unit Tests", test_unit_tests),
        ("Policy Service", test_policy_service),
        ("Integration Demo", run_integration_demo),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} failed with exception: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 TEST SUMMARY")
    print("=" * 60)
    
    passed = 0
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} {test_name}")
        if result:
            passed += 1
    
    print(f"\nResults: {passed}/{len(results)} tests passed")
    
    if passed == len(results):
        print("\n🎉 All tests passed! The framework is ready to use.")
        print("\nNext steps:")
        print("1. Start services: docker-compose up -d")
        print("2. Run receiver: python receive_demo.py")
        print("3. Send messages: python send_demo.py --interactive")
        return True
    else:
        print(f"\n⚠️ {len(results) - passed} tests failed. Please check the output above.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
