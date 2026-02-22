import os
import shutil
import subprocess
import time
import urllib.request
import urllib.error
import tempfile

def test_tinyweb():
    # Setup test directory in the current folder to avoid Windows AppData hidden attributes
    cwd = os.getcwd()
    test_dir = tempfile.mkdtemp(prefix="tinyweb_test_", dir=cwd)
    exe_path = r"C:\q\TinyWeb\SRC\Tiny.exe"
    history_file = r"C:\q\TinyWeb\history.html"
    
    # Copy file to serve as history.html AND as index.html (to prevent startup error)
    target_history = os.path.join(test_dir, "history.html")
    target_index = os.path.join(test_dir, "index.html")
    shutil.copy2(history_file, target_history)
    shutil.copy2(history_file, target_index)
    
    print(f"[*] Setting up test environment in {test_dir}")
    
    # Start TinyWeb process
    port = "8080"
    process = subprocess.Popen([exe_path, test_dir, port], 
                               stdout=subprocess.DEVNULL, 
                               stderr=subprocess.DEVNULL)
    
    try:
        # Give server a moment to start and poll until ready
        url = f"http://127.0.0.1:{port}/history.html"
        print(f"[*] Querying {url}")
        
        max_retries = 10
        for i in range(max_retries):
            try:
                # Read local file
                with open(target_history, 'rb') as f:
                    local_content = f.read()
                    
                # Query server
                response = urllib.request.urlopen(url)
                served_content = response.read()
                break # Success!
            except urllib.error.HTTPError as e:
                print(f"[-] HTTP Error {e.code}: {e.reason}")
                print(f"    Body: {e.read().decode('utf-8', errors='ignore')}")
                raise e
            except urllib.error.URLError as e:
                if getattr(e, 'reason', None) and isinstance(e.reason, ConnectionRefusedError) and i < max_retries - 1:
                    time.sleep(0.5)
                    continue
                raise e
        
        # Compare contents
        if local_content == served_content:
            print("[+] SUCCESS: Served content matches local file exactly.")
            print(f"    File size: {len(local_content)} bytes")
        else:
            print("[-] ERROR: Served content does NOT match local file!")
            print(f"    Local size: {len(local_content)}")
            print(f"    Served size: {len(served_content)}")
            
    except Exception as e:
        print(f"[-] Test failed with error: {e}")
    finally:
        # Cleanup
        print("[*] Shutting down TinyWeb server...")
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            
        print(f"[*] Cleaning up directory {test_dir}")
        shutil.rmtree(test_dir, ignore_errors=True)

if __name__ == "__main__":
    test_tinyweb()
