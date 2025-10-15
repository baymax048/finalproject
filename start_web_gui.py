#!/usr/bin/env python3
"""
Secure Agent Communication - Robust Startup Script
Handles process management, port cleanup, and graceful shutdown
"""
import os
import sys
import time
import signal
import subprocess
import threading
import atexit
import platform
from typing import List, Optional, Dict
from pathlib import Path

# Global state
processes: List[subprocess.Popen] = []
process_info: Dict[int, str] = {}
shutdown_flag = False
PORTS_TO_MANAGE = [5173, 8000, 8001]

def is_windows():
    """Check if running on Windows"""
    return platform.system() == "Windows"

def output_reader(pipe, prefix: str):
    """Thread function to read and print process output"""
    try:
        for line in iter(pipe.readline, ''):
            if line and not shutdown_flag:
                print(f"[{prefix}] {line.rstrip()}")
        pipe.close()
    except Exception:
        pass

def kill_process_on_port(port: int) -> bool:
    """Kill any process using the specified port"""
    try:
        if is_windows():
            # Find process using the port
            result = subprocess.run(
                f'netstat -ano | findstr ":{port}"',
                shell=True,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.stdout:
                lines = result.stdout.strip().split('\n')
                pids = set()
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 5:
                        pid = parts[-1]
                        if pid.isdigit():
                            pids.add(pid)
                
                for pid in pids:
                    try:
                        subprocess.run(
                            f'taskkill /F /PID {pid}',
                            shell=True,
                            capture_output=True,
                            timeout=5
                        )
                        print(f"✓ Killed process {pid} on port {port}")
                    except Exception as e:
                        print(f"⚠ Could not kill process {pid}: {e}")
                
                return len(pids) > 0
        else:
            # Unix-like systems
            result = subprocess.run(
                f'lsof -ti:{port}',
                shell=True,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.stdout:
                pids = result.stdout.strip().split('\n')
                for pid in pids:
                    if pid:
                        try:
                            subprocess.run(
                                f'kill -9 {pid}',
                                shell=True,
                                timeout=5
                            )
                            print(f"✓ Killed process {pid} on port {port}")
                        except Exception as e:
                            print(f"⚠ Could not kill process {pid}: {e}")
                return True
        
        return False
    except Exception as e:
        print(f"⚠ Error checking/killing port {port}: {e}")
        return False

def cleanup_ports():
    """Clean up all managed ports"""
    print("\n🧹 Cleaning up ports...")
    for port in PORTS_TO_MANAGE:
        if kill_process_on_port(port):
            time.sleep(0.5)
    print("✓ Port cleanup complete\n")

def check_port_in_use(port: int) -> bool:
    """Check if a port is in use"""
    try:
        if is_windows():
            result = subprocess.run(
                f'netstat -ano | findstr ":{port}"',
                shell=True,
                capture_output=True,
                text=True,
                timeout=5
            )
        else:
            result = subprocess.run(
                f'lsof -i :{port}',
                shell=True,
                capture_output=True,
                text=True,
                timeout=5
            )
        return bool(result.stdout.strip())
    except Exception:
        return False

def wait_for_port(port: int, timeout: int = 30, service_name: str = "Service") -> bool:
    """Wait for a port to become available"""
    print(f"⏳ Waiting for {service_name} on port {port}...", end='', flush=True)
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        if check_port_in_use(port):
            print(f" Ready!")
            return True
        time.sleep(0.5)
        print(".", end='', flush=True)
    
    print(f" Timeout!")
    return False

def run_command(
    command: str,
    cwd: Optional[str] = None,
    prefix: str = "CMD",
    env: Optional[dict] = None
) -> Optional[subprocess.Popen]:
    """Run a command and return process object"""
    print(f"🚀 Starting {prefix}...")
    
    try:
        # Prepare environment
        process_env = os.environ.copy()
        if env:
            process_env.update(env)
        
        # Create process
        process = subprocess.Popen(
            command,
            cwd=cwd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1,
            env=process_env
        )
        
        # Start output reader thread
        thread = threading.Thread(
            target=output_reader,
            args=(process.stdout, prefix),
            daemon=True
        )
        thread.start()
        
        # Store process info
        processes.append(process)
        process_info[process.pid] = prefix
        
        return process
        
    except Exception as e:
        print(f"❌ Failed to start {prefix}: {e}")
        return None

def check_dependencies() -> bool:
    """Check if all required dependencies are available"""
    print("🔍 Checking dependencies...")
    errors = []
    
    # Check Python version
    if sys.version_info < (3, 7):
        errors.append("Python 3.7+ required")
    
    # Check Docker
    try:
        subprocess.run("docker --version", shell=True, capture_output=True, timeout=5, check=True)
    except Exception:
        errors.append("Docker not found")
    
    # Check Node.js
    try:
        subprocess.run("node --version", shell=True, capture_output=True, timeout=5, check=True)
    except Exception:
        errors.append("Node.js not found")
    
    # Check npm
    try:
        subprocess.run("npm --version", shell=True, capture_output=True, timeout=5, check=True)
    except Exception:
        errors.append("npm not found")
    
    if errors:
        print("\n❌ Missing dependencies:")
        for error in errors:
            print(f"  • {error}")
        return False
    
    print("✓ All dependencies available\n")
    return True

def start_docker_services():
    """Start Docker services if not running"""
    print("🐳 Checking Docker services...")
    
    try:
        # Check if services are running
        cmd = "docker ps --filter name=secure-agent-mongo --format '{{.Names}}'"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        
        if not result.stdout.strip():
            print("Starting MongoDB and RabbitMQ...")
            subprocess.run(
                "docker-compose up -d",
                shell=True,
                capture_output=True,
                timeout=60,
                check=True
            )
            print("⏳ Waiting for services to initialize...")
            time.sleep(10)
        else:
            print("✓ Docker services already running\n")
        
        return True
    except Exception as e:
        print(f"❌ Failed to start Docker services: {e}")
        return False

def start_services():
    """Start all services"""
    print("\n" + "="*70)
    print(" 🚀 SECURE AGENT COMMUNICATION - STARTUP")
    print("="*70 + "\n")
    
    # Step 0: Check dependencies
    if not check_dependencies():
        return False
    
    # Step 1: Clean up ports
    cleanup_ports()
    
    # Step 2: Start Docker services
    if not start_docker_services():
        return False
    
    # Step 3: Start backend services
    print("🔧 Starting backend services...\n")
    
    # Policy Service
    policy_proc = run_command("python policy_service.py", prefix="POLICY")
    if not policy_proc:
        return False
    time.sleep(2)
    
    if not wait_for_port(8000, service_name="Policy Service"):
        print("⚠ Warning: Policy service may not be responding")
    
    # Web Backend
    web_backend_proc = run_command("python web_backend.py", prefix="BACKEND")
    if not web_backend_proc:
        return False
    time.sleep(2)
    
    if not wait_for_port(8001, service_name="Web Backend"):
        print("⚠ Warning: Web backend may not be responding")
    
    # Step 4: Start frontend
    print("\n🎨 Starting frontend...\n")
    web_gui_dir = Path("web-gui")
    
    if not web_gui_dir.exists():
        print(f"❌ Directory '{web_gui_dir}' not found")
        return False
    
    # Check and install dependencies
    node_modules = web_gui_dir / "node_modules"
    if not node_modules.exists():
        print("📦 Installing frontend dependencies...")
        result = subprocess.run(
            "npm install",
            cwd=str(web_gui_dir),
            shell=True,
            capture_output=True,
            timeout=300
        )
        if result.returncode != 0:
            print(f"❌ npm install failed: {result.stderr.decode()}")
            return False
        print("✓ Dependencies installed\n")
    
    # Start frontend
    frontend_proc = run_command("npm run dev", cwd=str(web_gui_dir), prefix="FRONTEND")
    if not frontend_proc:
        return False
    
    time.sleep(3)
    
    # Success message
    print("\n" + "="*70)
    print(" ✅ ALL SERVICES STARTED SUCCESSFULLY!")
    print("="*70)
    print("\n🌐 Application URL: http://localhost:5173")
    print("\n📡 API Endpoints:")
    print("  • Web Backend:    http://localhost:8001")
    print("  • Policy Service: http://localhost:8000")
    print("  • RabbitMQ UI:    http://localhost:15672 (guest/guest)")
    print("  • MongoDB UI:     http://localhost:8081 (admin/admin123)")
    print(f"\n🔧 Running {len(processes)} processes")
    print("\n⚠️  Press Ctrl+C to stop all services")
    print("="*70 + "\n")
    
    return True

def cleanup():
    """Cleanup function to terminate all processes and ports"""
    global shutdown_flag
    
    if shutdown_flag:
        return
    
    shutdown_flag = True
    
    print("\n\n" + "="*70)
    print(" 🛑 SHUTTING DOWN...")
    print("="*70 + "\n")
    
    # Terminate all child processes
    for proc in processes:
        try:
            service_name = process_info.get(proc.pid, "Unknown")
            print(f"⏹️  Stopping {service_name} (PID: {proc.pid})...", end='', flush=True)
            
            proc.terminate()
            
            try:
                proc.wait(timeout=5)
                print(" ✓")
            except subprocess.TimeoutExpired:
                print(" forcing...", end='', flush=True)
                proc.kill()
                proc.wait()
                print(" ✓")
        except Exception as e:
            print(f" ⚠ {e}")
    
    # Clean up ports
    print("\n🧹 Cleaning up ports...")
    time.sleep(1)
    cleanup_ports()
    
    print("="*70)
    print(" ✅ SHUTDOWN COMPLETE")
    print("="*70 + "\n")

def signal_handler(sig, frame):
    """Handle interrupt signals"""
    cleanup()
    sys.exit(0)

def main():
    """Main entry point"""
    # Register cleanup on exit
    atexit.register(cleanup)
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Start all services
        if not start_services():
            print("\n❌ STARTUP FAILED")
            cleanup()
            sys.exit(1)
        
        # Keep running
        print("🔄 Running... (Press Ctrl+C to stop)\n")
        while not shutdown_flag:
            time.sleep(1)
            
            # Check if any process died
            for proc in processes[:]:
                if proc.poll() is not None:
                    service_name = process_info.get(proc.pid, "Unknown")
                    print(f"\n⚠️  WARNING: {service_name} (PID: {proc.pid}) stopped unexpectedly!")
                    processes.remove(proc)
            
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"\n❌ Error: {e}")
    finally:
        cleanup()

if __name__ == "__main__":
    main()