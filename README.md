# 💀 CyberGuard // Hybrid Hacking Toolkit

**Project Code:** CY4053 Final Project  
**Theme:** Cyberpunk 2077  
**Scenario:** PayBuddy FinTech Security Assessment Tool

---

## 🎥 Video Demo



---

## 👥 Team: CyberGuard

| Name | ID |
| :--- | :--- |
| **Abdullah Pervez** | 22i-2252 |
| **Sharim** | 22i-2259 |
| **Mustafa Adnan** | 22i-2275 |

---

## 📜 Project Overview

**CyberGuard** is a modular, Python-based penetration testing suite designed for the fictional FinTech startup **PayBuddy**. It provides a unified interface for security professionals to test internal APIs, audit password policies, and analyze network traffic in a safe, authorized environment.

This toolkit strictly adheres to **ethical hacking guidelines**. It includes mandatory identity verification and consent protocols before unlocking any offensive capabilities.

## 🚀 Key Features

* **Cyberpunk UI:** Immersive, dark-mode interface built with Streamlit.
* **Role-Based Access:** Secure login system with operator registration.
* **Legal Compliance:** Mandatory "I CONSENT" handshake protocol.
* **Report Generation:** Auto-generates PDF reports with embedded charts and screenshots.
* **No External Tools:** 100% Python implementation (No Nmap/Dirb binaries used).

---

## 🛠️ Modules

### 📡 Port Scanner
* Uses raw Python sockets to detect open ports and grab service banners.
* Multi-threaded for speed.

### 🔐 Password Fortress
* **Strength Test:** Entropy calculation and regex-based policy checks.
* **Hash Generator:** MD5/SHA256 generation.
* **Offline Cracker:** Dictionary attack simulation against local wordlists.

### ⚠️ Load/Stress Tester (DoS Sim)
* Async (`aiohttp`) stress testing to measure API latency under load.
* Generates real-time latency graphs.
* **Safety Limit:** Capped at 500 requests to prevent actual DoS.

### 🕵️ Web Discovery
* Directory brute-forcing using `requests`.
* Identifies common paths (e.g., `/admin`, `/login`, `/config`).

### 🦈 Packet Sniffer
* Layer 2/3 traffic analysis using **Scapy**.
* Captures live traffic and saves `.pcap` files for Wireshark.
* Visualizes protocol distribution (TCP/UDP/ICMP).

---

## ⚙️ Installation Guide

### Prerequisites
* **Python 3.8** or higher
* **Windows Users:** [Npcap](https://npcap.com/) is required for Packet Sniffing.
    > **Important:** During Npcap installation, you **must** check the box:  
    > `Install Npcap in WinPcap API-compatible Mode`

### Step 1: Clone the Repository
```bash
git clone [https://github.com/your-username/CyberGuard-Toolkit.git](https://github.com/your-username/CyberGuard-Toolkit.git)
cd CyberGuard-Toolkit
```

### Step 2: Set Up Virtual Environment (Recommended)

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**Mac/Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 💻 Usage Instructions

### 1. Launch the System
Run the application using Streamlit:
```bash
streamlit run streamlit_app.py
```
> **Note:** For Packet Sniffing to work correctly on local interfaces, you may need to run your terminal/IDE as **Administrator**.

### 2. Authentication Flow
1.  **Register:** Go to the "OPERATOR REGISTRATION" tab and create an account.
2.  **Login:** Use your new credentials to access the system.
3.  **Consent:** Read the legal warning and type `I CONSENT` to unlock the modules.

### 3. Using the Modules
* **Select a Target:** Use the Sidebar to pick a recommended target (e.g., `testphp.vulnweb.com`) or enter a manual IP.
* **Run Tools:** Navigate through the sidebar radio buttons to access different tools.
* **Generate Report:** On the "Dashboard", click **GENERATE MISSION REPORT** to download a PDF summary of your session, including graphs of your attacks.

---

## 📂 Project Structure

```text
CY4053_FinalProject_CyberGuard/
├── identity.txt                # Team identity file (Required)
├── consent.txt                 # Approved targets list (Required)
├── streamlit_app.py            # Main Application UI (Streamlit)
├── requirements.txt            # Python dependencies
├── users.json                  # Local database for user creds (Auto-generated)
├── src/                        # Source Code
│   ├── identity_checker.py     # Module 0: Safety Logic
│   ├── port_scanner.py         # Module 1: Sockets Logic
│   ├── password_tester.py      # Module 2: Hash/Crack Logic
│   ├── load_tester.py          # Module 3: Async DoS Logic
│   ├── web_discovery.py        # Module 4: Dirb Logic
│   ├── packet_analyzer.py      # Module 5: Scapy Logic
│   └── reporter.py             # Module 6: PDF Generation
└── evidence/                   # Output folder for Reports, PCAPs, and Screenshots
```

---

## 🔧 Troubleshooting

**`WARNING: No libpcap provider available`**
* **Cause:** Scapy cannot access your network card driver.
* **Fix:** Install [Npcap](https://npcap.com/). Ensure **"WinPcap API-compatible Mode"** is checked during install.
* **Workaround:** The tool will automatically switch to "Layer 3 Mode" (IP only) if Npcap is missing, but you won't see MAC addresses.

**`Access Denied` on Packet Capture**
* **Fix:** Close VS Code/Terminal and re-open it by right-clicking and choosing **"Run as Administrator"**.

---

## ⚖️ Legal Disclaimer

**EDUCATIONAL PURPOSE ONLY.**

This toolkit is developed strictly for the **CY4053 Final Project**. Usage is restricted to:
1.  Localhost (`127.0.0.1`)
2.  Authorized test sites (`scanme.nmap.org`, `testphp.vulnweb.com`)
3.  Explicitly consented targets listed in `consent.txt`

The developers (**Abdullah, Sharim, Mustafa**) assume no liability for misuse of this software.
