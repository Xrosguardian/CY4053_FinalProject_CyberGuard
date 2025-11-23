import re
import hashlib
import random

# Common passwords for offline "de-hashing" simulation
COMMON_PASSWORDS = [
    "password", "123456", "12345678", "123456789", "12345", "1234567", "qwerty", 
    "admin", "welcome", "google", "unknown", "server", "admin123", "user", 
    "guest", "root", "toor", "kali", "cyber", "hacker", "password123", 
    "letmein", "sunshine", "iloveyou", "dragon", "baseball", "monkey"
]

def check_strength(password):
    score = 0
    feedback = []
    
    if len(password) >= 8: score += 1
    else: feedback.append("Too short (<8 chars)")
    
    if re.search(r"[A-Z]", password): score += 1
    else: feedback.append("No uppercase letters")
    
    if re.search(r"[a-z]", password): score += 1
    else: feedback.append("No lowercase letters")
    
    if re.search(r"\d", password): score += 1
    else: feedback.append("No numbers")
    
    if re.search(r"[!@#$%^&*]", password): score += 1
    else: feedback.append("No special characters")
    
    return score, feedback

def hash_check(password, target_hash, algo="md5"):
    """
    Simulates checking a password against a leaked hash.
    """
    if algo == "md5":
        hashed = hashlib.md5(password.encode()).hexdigest()
    elif algo == "sha256":
        hashed = hashlib.sha256(password.encode()).hexdigest()
    else:
        return False, "Unsupported Algorithm"
        
    if hashed == target_hash:
        return True, f"MATCH FOUND! Hash: {hashed}"
    return False, f"No Match. Input Hash: {hashed}"

def generate_hashes(text):
    """Generates MD5 and SHA256 hashes for a given string."""
    md5_hash = hashlib.md5(text.encode()).hexdigest()
    sha256_hash = hashlib.sha256(text.encode()).hexdigest()
    return {"MD5": md5_hash, "SHA256": sha256_hash}

def crack_hash(target_hash, algo="md5"):
    """
    Simulates 'De-hashing' by performing a dictionary attack 
    against a predefined list of common passwords.
    """
    for pwd in COMMON_PASSWORDS:
        if algo.lower() == "md5":
            generated = hashlib.md5(pwd.encode()).hexdigest()
        elif algo.lower() == "sha256":
            generated = hashlib.sha256(pwd.encode()).hexdigest()
        else:
            return False, "Unsupported Algorithm"
            
        if generated == target_hash:
            return True, pwd
            
    return False, "Password not found in dictionary."