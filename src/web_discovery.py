import requests
import pandas as pd

COMMON_DIRS = [
    "admin", "login", "dashboard", "uploads", "images", 
    "css", "js", "api", "config", "backup", "db"
]

def scan_directories(base_url):
    discovered = []
    
    if not base_url.startswith("http"):
        base_url = "http://" + base_url
    
    if base_url.endswith("/"):
        base_url = base_url[:-1]

    # Add a user-agent to look like a real browser
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberGuardToolkit/1.0'}

    for directory in COMMON_DIRS:
        url = f"{base_url}/{directory}"
        try:
            response = requests.get(url, headers=headers, timeout=2)
            if response.status_code != 404:
                discovered.append({
                    "URL": url, 
                    "Status": response.status_code, 
                    "Size": len(response.content)
                })
        except requests.exceptions.RequestException:
            continue
            
    return pd.DataFrame(discovered)