import os

def check_files():
    """Verifies that identity.txt and consent.txt exist."""
    missing = []
    if not os.path.exists("identity.txt"):
        missing.append("identity.txt")
    if not os.path.exists("consent.txt"):
        missing.append("consent.txt")
    
    if missing:
        return False, f"MISSING FILES: {', '.join(missing)}"
    
    with open("identity.txt", "r") as f:
        identity_content = f.read()
    
    return True, identity_content