#!/usr/bin/env python3
"""
Secure Agent Communication - Web GUI Startup Script (Robust Version)
"""
import os
import sys
import time
import signal
import subprocess
import threading
from typing import List, Optional
from pathlib import Path

# Global list to store process objects
processes: List[subprocess.Popen] = []
shutdown_flag = False

def output_reader(pipe, prefix: str):
    """Thread function to read and print process output"""
    try:
        for line in iter(pipe.readline, ''):
            if line and not shutdown_flag:
                print(f"[{prefix}] {line.rstrip()}")
        pipe.close()
    except Exception:
        pass

def run_command(
    command: str, 
    cwd: Optional[str] = None, 
    shell: bool = True,
    prefix: str = "CMD",
    wait: bool = False
) -> Optional[subprocess.Popen]:
    """
    Run a shell command and return the process object
    
    Args:
        command: Command to execute
        cwd: Working directory
        shell: Use shell execution
        prefix: Prefix for log output
        wait: Wait for command to complete
    """
    print(f"[{prefix}] Running: {command}")
    
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            shell=shell,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )
        
        if wait:
            # Wait for process to complete
            for line in iter(process.stdout.readline, ''):
                if line:
                    print(f"[{prefix}] {line.rstrip()}")
            process.wait()
            return None
        else:
            # Start thread to read output
            thread = threading.Thread(
                target=output_reader, 
                args=(process.stdout, prefix),
                daemon=True
            )
            thread.start()
            processes.append(process)
            return process
            
    except Exception as e:
        print(f"[{prefix}] ERROR: {e}")
        return None

def check_port_in_use(port: int) -> bool:
    """Check if a port is already in use"""
    try:
        if os.name == 'nt':  # Windows
            result = subprocess.run(
                f'netstat -ano | findstr ":{port}"',
                shell=True,
                capture_output=True,
                text=True,
                timeout=5
            )
        else:  # Unix-like
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
    print(f"Waiting for {service_name} on port {port}...")
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        if check_port_in_use(port):
            print(f"✓ {service_name} is ready on port {port}")
            return True
        time.sleep(1)
    
    print(f"✗ Timeout waiting for {service_name} on port {port}")
    return False

def check_docker_services() -> bool:
    """Check if MongoDB and RabbitMQ are running"""
    try:
        if os.name == 'nt':  # Windows
            cmd = "docker ps | findstr secure-agent-mongo"
        else:  # Unix-like
            cmd = "docker ps | grep secure-agent-mongo"
            
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=10
        )
        return bool(result.stdout.strip())
    except Exception as e:
        print(f"Error checking Docker services: {e}")
        return False

def check_dependencies() -> bool:
    """Check if all required dependencies are available"""
    errors = []
    
    # Check Python
    if sys.version_info < (3, 7):
        errors.append("Python 3.7 or higher is required")
    
    # Check Docker
    try:
        subprocess.run(
            "docker --version",
            shell=True,
            capture_output=True,
            timeout=5,
            check=True
        )
    except Exception:
        errors.append("Docker is not installed or not in PATH")
    
    # Check Node.js
    try:
        subprocess.run(
            "node --version",
            shell=True,
            capture_output=True,
            timeout=5,
            check=True
        )
    except Exception:
        errors.append("Node.js is not installed or not in PATH")
    
    # Check npm
    try:
        subprocess.run(
            "npm --version",
            shell=True,
            capture_output=True,
            timeout=5,
            check=True
        )
    except Exception:
        errors.append("npm is not installed or not in PATH")
    
    if errors:
        print("\n❌ Missing dependencies:")
        for error in errors:
            print(f"  - {error}")
        print()
        return False
    
    return True

def start_services():
    """Start all required services"""
    print("=" * 60)
    print(" Secure Agent Communication - Web GUI Startup")
    print("=" * 60)
    print()
    
    # Check dependencies
    print("Step 0: Checking dependencies...")
    if not check_dependencies():
        print("Please install missing dependencies and try again.")
        return False
    print("✓ All dependencies are available\n")
    
    # Step 1: Check infrastructure services
    print("Step 1: Checking infrastructure services...")
    if not check_docker_services():
        print("Starting MongoDB and RabbitMQ with Docker Compose...")
        run_command(
            "docker-compose up -d",
            prefix="DOCKER",
            wait=True
        )
        print("Waiting for services to be ready...")
        time.sleep(10)
    else:
        print("✓ Infrastructure services already running\n")
    
    # Step 2: Start backend services
    print("Step 2: Starting backend services...")
    
    # Check if ports are already in use
    if check_port_in_use(8000):
        print("⚠ Warning: Port 8000 is already in use. Policy service may already be running.")
    else:
        print("Starting policy service (port 8000)...")
        policy_proc = run_command(
            "python policy_service.py",
            prefix="POLICY"
        )
        if policy_proc:
            print(f"✓ Policy service started (PID: {policy_proc.pid})")
            wait_for_port(8000, service_name="Policy Service")
        else:
            print("✗ Failed to start policy service")
            return False
    
    time.sleep(2)
    
    if check_port_in_use(8001):
        print("⚠ Warning: Port 8001 is already in use. Web backend may already be running.")
    else:
        print("\nStarting web backend (port 8001)...")
        web_backend_proc = run_command(
            "python web_backend.py",
            prefix="BACKEND"
        )
        if web_backend_proc:
            print(f"✓ Web backend started (PID: {web_backend_proc.pid})")
            wait_for_port(8001, service_name="Web Backend")
        else:
            print("✗ Failed to start web backend")
            return False
    
    time.sleep(2)
    
    # Step 3: Start frontend
    print("\nStep 3: Starting frontend...")
    web_gui_dir = Path("web-gui")
    
    if not web_gui_dir.exists():
        print(f"✗ Error: Directory '{web_gui_dir}' not found")
        return False
    
    # Check if node_modules exists
    node_modules = web_gui_dir / "node_modules"
    if not node_modules.exists():
        print("Installing frontend dependencies...")
        run_command(
            "npm install",
            cwd=str(web_gui_dir),
            prefix="NPM",
            wait=True
        )
        print("✓ Dependencies installed\n")
    else:
        print("✓ Frontend dependencies already installed\n")
    
    if check_port_in_use(5173):
        print("⚠ Warning: Port 5173 is already in use. Frontend may already be running.")
    else:
        print("Starting frontend development server (port 5173)...")
        frontend_proc = run_command(
            "npm run dev",
            cwd=str(web_gui_dir),
            prefix="FRONTEND"
        )
        if frontend_proc:
            print(f"✓ Frontend started (PID: {frontend_proc.pid})")
            time.sleep(3)  # Give Vite time to start
        else:
            print("✗ Failed to start frontend")
            return False
    
    # Print service information
    print("\n" + "=" * 60)
    print(" ✓ All services started successfully!")
    print("=" * 60)
    print("\n🌐 Access the application at: http://localhost:5173")
    print("\n📡 API Endpoints:")
    print("  - Web Backend:    http://localhost:8001")
    print("  - Policy Service: http://localhost:8000")
    print("  - RabbitMQ UI:    http://localhost:15672 (guest/guest)")
    print("  - MongoDB UI:     http://localhost:8081 (admin/admin123)")
    
    if len(processes) > 0:
        print(f"\n🔧 Running Processes: {len(processes)}")
        for i, proc in enumerate(processes, 1):
            print(f"  {i}. PID: {proc.pid}")
    
    print("\n⚠  To stop all services, press Ctrl+C")
    print("=" * 60 + "\n")
    
    return True

def cleanup():
    """Cleanup function to terminate all child processes"""
    global shutdown_flag
    shutdown_flag = True
    
    print("\n🛑 Shutting down services...")
    
    for i, proc in enumerate(processes, 1):
        try:
            print(f"  Stopping process {i} (PID: {proc.pid})...")
            proc.terminate()
            
            # Wait for graceful shutdown
            try:
                proc.wait(timeout=5)
                print(f"  ✓ Process {i} stopped gracefully")
            except subprocess.TimeoutExpired:
                print(f"  ⚠ Process {i} did not stop, forcing...")
                proc.kill()
                proc.wait()
                print(f"  ✓ Process {i} force stopped")
                
        except Exception as e:
            print(f"  ✗ Error stopping process {i}: {e}")
    
    print("\n✓ All services have been stopped.")

def signal_handler(sig, frame):
    """Handle Ctrl+C signal"""
    cleanup()
    sys.exit(0)

def main():
    """Main entry point"""
    # Set up signal handler for clean shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        if not start_services():
            print("\n❌ Failed to start services")
            cleanup()
            sys.exit(1)
        
        # Keep the script running
        if os.name == 'nt':  # Windows
            print("Press Ctrl+C to exit...")
            try:
                # Use a loop instead of msvcrt for better portability
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
        else:  # Unix-like systems
            try:
                signal.pause()
            except AttributeError:
                # Fallback for systems without signal.pause()
                while True:
                    time.sleep(1)
                    
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"\n❌ Error: {e}")
    finally:
        cleanup()
        sys.exit(0)

if __name__ == "__main__":
    main()