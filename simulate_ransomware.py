import os
import time
import shutil

# Create a test folder inside the watched directory
WATCH_PATH = os.getenv("WATCH_PATH", "./watch_dir")
TEST_FOLDER = os.path.join(WATCH_PATH, "test_simulation")
os.makedirs(TEST_FOLDER, exist_ok=True)

print("[*] Creating test files...")
# Step 1 - Create 50 fake files
for i in range(50):
    filepath = os.path.join(TEST_FOLDER, f"document_{i}.txt")
    with open(filepath, 'w') as f:
        f.write(f"This is test document number {i}. " * 50)

print("[*] Simulating encryption - renaming files rapidly...")
# Step 2 - Rename them all rapidly (like ransomware does after encrypting)
for i in range(50):
    old = os.path.join(TEST_FOLDER, f"document_{i}.txt")
    new = os.path.join(TEST_FOLDER, f"document_{i}.locked")
    os.rename(old, new)
    time.sleep(0.05)  # Very fast renaming

print("[*] Writing high entropy data...")
# Step 3 - Write random bytes (simulates encrypted content)
import random
for i in range(10):
    filepath = os.path.join(TEST_FOLDER, f"encrypted_{i}.enc")
    with open(filepath, 'wb') as f:
        f.write(bytes([random.randint(0, 255) for _ in range(10000)]))

print("[*] Simulation complete. Check your detector!")
print(f"[*] Test files created in: {TEST_FOLDER}")
print("[*] Run this WHILE main.py is running in another terminal")