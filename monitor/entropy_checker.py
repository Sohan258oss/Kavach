import math
import os

SUSPICIOUS_EXTENSIONS_SKIP = ['.exe', '.dll', '.zip', '.png', '.jpg', '.mp3', '.mp4', '.pdf']

def calculate_entropy(filepath):
    """Calculate Shannon entropy of a file. High entropy = possibly encrypted."""
    try:
        # Skip files that are naturally high entropy — reduces false positives
        ext = os.path.splitext(filepath)[1].lower()
        if ext in SUSPICIOUS_EXTENSIONS_SKIP:
            return 0.0

        # Skip large files over 50MB — too slow to read fully
        if os.path.getsize(filepath) > 50 * 1024 * 1024:
            # Sample first and last 1MB instead
            with open(filepath, 'rb') as f:
                data = f.read(1024 * 1024) + f.seek(-1024 * 1024, 2) or b''
                data = f.read()
        else:
            with open(filepath, 'rb') as f:
                data = f.read()

        if not data:
            return 0.0

        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1

        entropy = 0.0
        length = len(data)
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)

        return round(entropy, 4)

    except (PermissionError, FileNotFoundError):
        return 0.0
    except Exception:
        return -1.0

def is_suspicious_entropy(filepath, threshold=7.2):
    """Files with entropy > 7.2 out of 8 are likely encrypted."""
    entropy = calculate_entropy(filepath)
    if entropy < 0:
        return False, 0.0
    return entropy > threshold, entropy