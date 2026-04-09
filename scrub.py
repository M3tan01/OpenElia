#!/usr/bin/env python3
import os
import shutil
import platform

def scrub():
    print("🛡️ OpenElia Universal Sanitization Start")
    
    # 1. Purge state and artifacts
    target_dirs = ["state", "artifacts"]
    for d in target_dirs:
        if os.path.exists(d):
            print(f"[+] Purging {d}/...")
            for filename in os.listdir(d):
                file_path = os.path.join(d, filename)
                try:
                    if os.path.isfile(file_path) or os.path.islink(file_path):
                        if filename != ".gitkeep":
                            os.unlink(file_path)
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                except Exception as e:
                    print(f'Failed to delete {file_path}. Reason: {e}')
    
    # 2. Clean __pycache__
    print("[+] Cleaning Python cache...")
    for root, dirs, files in os.walk(".", topdown=False):
        for name in dirs:
            if name == "__pycache__":
                shutil.rmtree(os.path.join(root, name))

    # 3. System specific cleanup
    if platform.system() == "Darwin":
        print("[+] Removing .DS_Store files...")
        # Use a safe method without shell expansion issues
        for root, dirs, files in os.walk("."):
            for file in files:
                if file == ".DS_Store":
                    try:
                        os.unlink(os.path.join(root, file))
                    except Exception as e:
                        print(f'Failed to remove .DS_Store file: {e}')

    print("✅ Sanitization complete. Safe to push.")

if __name__ == "__main__":
    scrub()
