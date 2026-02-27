import os
import time
import random

# ── Config ────────────────────────────────────────────────────────────────────
WATCH_PATH  = os.getenv("WATCH_PATH", "./watch_dir")
TEST_FOLDER = os.path.join(WATCH_PATH, "test_simulation")
os.makedirs(TEST_FOLDER, exist_ok=True)

# ── Step 0: Clean up leftover files from previous runs ────────────────────────
print("[*] Cleaning up previous simulation files...")
for f in os.listdir(TEST_FOLDER):
    try:
        os.remove(os.path.join(TEST_FOLDER, f))
    except Exception:
        pass

# ── Step 1: Create 50 normal text files ──────────────────────────────────────
print("[*] Creating test files...")
for i in range(50):
    filepath = os.path.join(TEST_FOLDER, f"document_{i}.txt")
    with open(filepath, 'w') as f:
        f.write(f"This is test document number {i}. " * 50)

time.sleep(1)  # Let file monitor register the creates

# ── Step 2: Rename them rapidly to .locked (ransomware behavior) ──────────────
print("[*] Simulating encryption — renaming files rapidly...")
for i in range(50):
    old = os.path.join(TEST_FOLDER, f"document_{i}.txt")
    new = os.path.join(TEST_FOLDER, f"document_{i}.locked")
    try:
        os.replace(old, new)  # os.replace works on Windows, overwrites safely
        print(f"    Renamed: document_{i}.txt → document_{i}.locked")
    except FileNotFoundError:
        print(f"    [!] Skipped (not found): document_{i}.txt")
    except PermissionError:
        print(f"    [!] Skipped (locked by another process): document_{i}.txt")
    time.sleep(0.05)  # Fast but not instant — mimics real ransomware

# ── Step 3: Write high entropy random bytes (simulates encrypted content) ──────
print("[*] Writing high entropy data...")
for i in range(10):
    filepath = os.path.join(TEST_FOLDER, f"encrypted_{i}.enc")
    with open(filepath, 'wb') as f:
        f.write(bytes([random.randint(0, 255) for _ in range(10000)]))
    print(f"    Created: encrypted_{i}.enc")

time.sleep(1)

# ── Step 4: Simulate mass deletes (ransomware deletes originals/backups) ───────
print("[*] Simulating backup deletion...")
for i in range(10):
    filepath = os.path.join(TEST_FOLDER, f"document_{i}.locked")
    try:
        os.remove(filepath)
        print(f"    Deleted: document_{i}.locked")
    except Exception:
        pass
    time.sleep(0.02)

# ── Done ──────────────────────────────────────────────────────────────────────
print("\n[*] Simulation complete!")
print(f"[*] Test files in: {TEST_FOLDER}")
print("[*] Check your SENTINEL dashboard for alerts and AI prediction.")