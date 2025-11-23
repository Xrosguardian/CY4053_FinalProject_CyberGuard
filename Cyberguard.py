import streamlit as st
import pandas as pd
import datetime
import os
import json
import hashlib
import matplotlib.pyplot as plt
from src import identity_checker, port_scanner, password_tester, load_tester, web_discovery, packet_analyzer, reporter

# --- CONFIGURATION & CSS ---
st.set_page_config(page_title="CyberGuard Toolkit", page_icon="💀", layout="wide")

CYBERPUNK_CSS = """
<style>
    /* General Background */
    .stApp {
        background-color: #0d0d0d;
        color: #00ff41;
        font-family: 'Courier New', Courier, monospace;
    }
    
    /* Inputs */
    .stTextInput input, .stNumberInput input, .stSelectbox, .stTextArea {
        background-color: #1a1a1a !important;
        color: #00ff41 !important;
        border: 1px solid #00ff41 !important;
    }
    
    /* Buttons */
    div.stButton > button {
        background-color: #000000;
        color: #ff0055;
        border: 2px solid #ff0055;
        font-weight: bold;
        text-transform: uppercase;
        border-radius: 0px;
        transition: all 0.3s ease;
    }
    div.stButton > button:hover {
        background-color: #ff0055;
        color: #ffffff;
        box-shadow: 0 0 15px #ff0055;
    }
    
    /* Success Messages */
    .stSuccess {
        background-color: #1a1a1a;
        color: #00ff41;
        border-left: 5px solid #00ff41;
    }
    
    /* Headers */
    h1, h2, h3 {
        color: #fcee0a; /* Cyberpunk Yellow */
        text-shadow: 2px 2px #ff0055;
        text-transform: uppercase;
    }
    
    /* Dataframes */
    div[data-testid="stDataFrame"] {
        border: 1px solid #00ff41;
    }
    
    /* Sidebar */
    [data-testid="stSidebar"] {
        background-color: #050505;
        border-right: 1px solid #333;
    }
</style>
"""
st.markdown(CYBERPUNK_CSS, unsafe_allow_html=True)

# --- SESSION STATE INITIALIZATION ---
if 'logs' not in st.session_state: st.session_state['logs'] = []
if 'auth_status' not in st.session_state: st.session_state['auth_status'] = False
if 'user' not in st.session_state: st.session_state['user'] = None
if 'consent_given' not in st.session_state: st.session_state['consent_given'] = False
if 'global_target' not in st.session_state: st.session_state['global_target'] = ""

# --- HELPER FUNCTIONS ---
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def load_users():
    if not os.path.exists("users.json"):
        return {}
    with open("users.json", "r") as f:
        return json.load(f)

def save_user(username, password):
    users = load_users()
    users[username] = hash_password(password)
    with open("users.json", "w") as f:
        json.dump(users, f)

def authenticate(username, password):
    users = load_users()
    if username in users and users[username] == hash_password(password):
        return True
    return False

def log_activity(module, target, data, image_path=None):
    entry = {
        "module": module,
        "target": target,
        "user": st.session_state['user'],
        "time": str(datetime.datetime.now()),
        "data": data,
        "image_path": image_path
    }
    st.session_state['logs'].append(entry)

# --- APP FLOW CONTROL ---

# 1. AUTHENTICATION PHASE
if not st.session_state['auth_status']:
    st.title("CYBERGUARD // ACCESS CONTROL")
    st.markdown("---")
    
    tab1, tab2 = st.tabs(["LOGIN", "OPERATOR REGISTRATION"])
    
    with tab1:
        st.subheader("IDENTIFY YOURSELF")
        l_user = st.text_input("Username", key="l_user")
        l_pass = st.text_input("Password", type="password", key="l_pass")
        
        if st.button("AUTHENTICATE"):
            if authenticate(l_user, l_pass):
                st.session_state['auth_status'] = True
                st.session_state['user'] = l_user
                st.success("ACCESS GRANTED")
                st.rerun()
            else:
                st.error("INVALID CREDENTIALS")

    with tab2:
        st.subheader("NEW OPERATOR SIGNUP")
        s_user = st.text_input("New Username", key="s_user")
        s_pass = st.text_input("New Password", type="password", key="s_pass")
        
        if st.button("REGISTER OPERATOR"):
            if s_user and s_pass:
                users = load_users()
                if s_user in users:
                    st.error("OPERATOR ALREADY EXISTS")
                else:
                    save_user(s_user, s_pass)
                    st.success("REGISTRATION SUCCESSFUL. PLEASE LOGIN.")
            else:
                st.warning("FIELDS CANNOT BE EMPTY")

# 2. CONSENT PHASE
elif not st.session_state['consent_given']:
    st.title("⚠️ LEGAL COMPLIANCE PROTOCOL")
    st.markdown("---")
    st.warning("UNAUTHORIZED ACCESS TO COMPUTER SYSTEMS IS ILLEGAL.")
    st.info("This toolkit is strictly for educational purposes and authorized penetration testing only.")
    
    st.markdown("""
    **USER AGREEMENT:**
    1. I will only test targets listed in `consent.txt`.
    2. I have obtained written permission from the system owner.
    3. I will not use this tool for malicious purposes.
    4. I accept full responsibility for my actions.
    """)
    
    consent_input = st.text_input("TYPE 'I CONSENT' TO PROCEED:", "")
    
    if st.button("VERIFY AGREEMENT"):
        if consent_input.strip().upper() == "I CONSENT":
            st.session_state['consent_given'] = True
            st.rerun()
        else:
            st.error("VERIFICATION FAILED. YOU MUST TYPE 'I CONSENT' EXACTLY.")

# 3. MAIN DASHBOARD
else:
    # --- SIDEBAR CHECKS ---
    st.sidebar.title("🔐 SYSTEM STATUS")
    valid_id, id_msg = identity_checker.check_files()

    if not valid_id:
        st.error("CRITICAL ERROR: MISSING IDENTITY FILES")
        st.stop()
    else:
        st.sidebar.success("IDENTITY: VERIFIED")
        st.sidebar.info(f"OPERATOR: {st.session_state['user']}")

    st.sidebar.divider()
    
    # --- GLOBAL TARGET INPUT (UPDATED WITH RECOMMENDATIONS) ---
    st.sidebar.markdown("### 🎯 MISSION TARGET")
    
    # List of safe/legal targets mapping to their URLs
    RECOMMENDED_TARGETS = {
        "Manual Entry": "",
        "Nmap ScanMe (Ports)": "scanme.nmap.org",
        "VulnWeb (Web Test)": "testphp.vulnweb.com",
        "httpbin (Load Test)": "http://httpbin.org/get",
        "HackThisSite (General)": "hackthissite.org",
        "Localhost (Loopback)": "127.0.0.1"
    }
    
    # Dropdown for quick selection
    target_choice = st.sidebar.selectbox("RECOMMENDED INTEL", list(RECOMMENDED_TARGETS.keys()))
    
    # Update global target if a recommendation is picked
    if target_choice != "Manual Entry":
        st.session_state['global_target'] = RECOMMENDED_TARGETS[target_choice]

    # Text input (editable, defaults to selection)
    st.session_state['global_target'] = st.sidebar.text_input(
        "SET URL/IP", 
        value=st.session_state['global_target'],
        placeholder="e.g. testphp.vulnweb.com"
    )
    
    current_target = st.session_state['global_target'] if st.session_state['global_target'] else "NO TARGET SET"
    st.sidebar.caption(f"LOCKED ON: {current_target}")
    
    st.sidebar.divider()
    
    tool_choice = st.sidebar.radio("SELECT MODULE", 
        ["Dashboard", "Port Scanner", "Password Fortress", "Load/Stress Tester", "Web Discovery", "Packet Sniffer"])
    
    if st.sidebar.button("LOGOUT"):
        st.session_state['auth_status'] = False
        st.session_state['consent_given'] = False
        st.session_state['user'] = None
        st.rerun()

    # --- MAIN CONTENT ---
    st.title(f"CYBERGUARD // {tool_choice.upper()}")
    st.markdown(f"**CURRENT TARGET:** `{current_target}`")
    st.markdown("---")

    if tool_choice == "Dashboard":
        st.subheader("MISSION STATUS")
        st.write("System Ready. Select a module from the sidebar to begin operation.")
        
        col1, col2, col3 = st.columns(3)
        col1.metric("Modules Online", "5/5")
        col2.metric("Security Level", "HIGH")
        col3.metric("Session Time", "ACTIVE")
        
        if st.button("GENERATE MISSION REPORT"):
            if st.session_state['logs']:
                report_path = reporter.generate_report(st.session_state['logs'])
                st.success(f"Report generated: {report_path}")
                st.info("Report includes embedded screenshots of all graphs.")
                with open(report_path, "rb") as f:
                    st.download_button("DOWNLOAD PDF REPORT", f, file_name="Mission_Report.pdf")
            else:
                st.warning("No data logged yet.")

    elif tool_choice == "Port Scanner":
        st.subheader("📡 NETWORK PORT SCANNER")
        target = st.text_input("TARGET IP/DOMAIN", value=st.session_state['global_target'])
        ports_str = st.text_input("PORTS (comma separated)", "21,22,80,443,8080")
        
        if st.button("INITIATE SCAN"):
            if not target:
                st.error("TARGET REQUIRED")
            else:
                try:
                    ports = [int(p.strip()) for p in ports_str.split(',')]
                    with st.spinner("Scanning target matrix..."):
                        scanner = port_scanner.PortScanner()
                        df = scanner.run_scan(target, ports)
                        
                        if not df.empty:
                            st.dataframe(df)
                            log_activity("Port Scan", target, df.to_dict())
                        else:
                            st.warning("No open ports found or host unreachable.")
                except Exception as e:
                    st.error(f"Scan Error: {e}")

    elif tool_choice == "Password Fortress":
        st.subheader("🔐 PASSWORD OPERATIONS CENTER")
        tab1, tab2, tab3 = st.tabs(["STRENGTH & CHECK", "HASH GENERATOR", "DE-HASHER (CRACKER)"])
        
        with tab1:
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("### STRENGTH TEST")
                pwd = st.text_input("Enter Password", type="password")
                if pwd:
                    score, feedback = password_tester.check_strength(pwd)
                    st.metric("Entropy Score", f"{score}/5")
                    if feedback:
                        st.error("\n".join(feedback))
                    else:
                        st.success("Strong Password Detected")
            
            with col2:
                st.markdown("### MANUAL HASH VERIFICATION")
                check_pwd = st.text_input("Password to Verify", key="v_pwd")
                target_hash = st.text_input("Target MD5 Hash", key="v_hash")
                if st.button("VERIFY MATCH"):
                    match, msg = password_tester.hash_check(check_pwd, target_hash)
                    if match:
                        st.success(msg)
                    else:
                        st.error(msg)

        with tab2:
            st.markdown("### HASH GENERATOR")
            text_to_hash = st.text_input("Enter Text to Hash")
            if text_to_hash:
                hashes = password_tester.generate_hashes(text_to_hash)
                st.code(f"MD5:    {hashes['MD5']}")
                st.code(f"SHA256: {hashes['SHA256']}")
                log_activity("Hash Gen", "Local", hashes)

        with tab3:
            st.markdown("### OFFLINE DE-HASHER")
            crack_target = st.text_input("Enter Hash to Crack")
            algo_choice = st.selectbox("Algorithm", ["MD5", "SHA256"])
            
            if st.button("ATTEMPT CRACK"):
                with st.spinner("Running Dictionary Attack..."):
                    found, result = password_tester.crack_hash(crack_target, algo_choice)
                    if found:
                        st.success(f"CRACKED! Password: {result}")
                        log_activity("Hash Crack", "Local", f"Cracked: {result}")
                    else:
                        st.error(result)

    elif tool_choice == "Load/Stress Tester":
        st.subheader("⚠️ API STRESS TESTER (DoS Sim)")
        st.warning("AUTHORIZED TARGETS ONLY. Do not exceed 500 requests.")
        
        target_url = st.text_input("Target URL", value=st.session_state['global_target'])
        req_count = st.slider("Request Count", 10, 500, 50)
        
        if st.button("LAUNCH STRESS TEST"):
            if not target_url:
                st.error("TARGET REQUIRED")
            else:
                with st.spinner("Flooding target..."):
                    df = load_tester.trigger_load_test(target_url, req_count)
                    
                    # 1. Create Chart for UI
                    st.line_chart(df["Latency (ms)"])
                    st.dataframe(df)
                    avg_lat = df["Latency (ms)"].mean()
                    st.metric("Average Latency", f"{avg_lat:.2f} ms")

                    # 2. Generate "Screenshot" (Static Image) for Report
                    fig, ax = plt.subplots()
                    ax.plot(df["Latency (ms)"], color='#00ff41')
                    # Style to match Cyberpunk theme
                    ax.set_facecolor('#0d0d0d')
                    fig.patch.set_facecolor('#0d0d0d')
                    ax.tick_params(colors='#00ff41')
                    ax.xaxis.label.set_color('#00ff41')
                    ax.yaxis.label.set_color('#00ff41')
                    ax.set_title("Latency Response Time (ms)", color='#fcee0a')
                    ax.grid(True, color='#333333')

                    # 3. Save Screenshot
                    if not os.path.exists("evidence"):
                        os.makedirs("evidence")
                    chart_path = f"evidence/load_test_{datetime.datetime.now().strftime('%H%M%S')}.png"
                    plt.savefig(chart_path)
                    
                    # 4. Log with Image Path
                    log_activity("Load Test", target_url, f"Avg Latency: {avg_lat}", image_path=chart_path)

    elif tool_choice == "Web Discovery":
        st.subheader("🕵️ WEB DIRECTORY ENUMERATION")
        target_url = st.text_input("Target URL", value=st.session_state['global_target'])
        
        if st.button("START DISCOVERY"):
            if not target_url:
                st.error("TARGET REQUIRED")
            else:
                with st.spinner("Brute-forcing directories..."):
                    df = web_discovery.scan_directories(target_url)
                    if not df.empty:
                        st.success(f"Found {len(df)} directories")
                        st.dataframe(df)
                        log_activity("Web Discovery", target_url, df.to_dict())
                    else:
                        st.info("No common directories found.")

    elif tool_choice == "Packet Sniffer":
        st.subheader("🦈 PACKET CAPTURE")
        count = st.slider("Packet Count", 5, 50, 10)
        
        if st.button("START CAPTURE"):
            with st.spinner("Sniffing network traffic..."):
                try:
                    df, pcap_file = packet_analyzer.capture_packets(packet_count=count)
                    st.dataframe(df)
                    st.success(f"PCAP saved: {pcap_file}")
                    
                    # 1. Generate "Screenshot" (Pie Chart of Protocols)
                    if not df.empty:
                        proto_counts = df['Protocol'].value_counts()
                        fig, ax = plt.subplots()
                        ax.pie(proto_counts, labels=proto_counts.index, autopct='%1.1f%%', 
                               textprops={'color':"#00ff41"}, colors=['#ff0055', '#fcee0a', '#00ff41'])
                        fig.patch.set_facecolor('#0d0d0d')
                        ax.set_title("Captured Traffic Protocol Distribution", color='#fcee0a')
                        
                        # 2. Save Screenshot
                        pcap_chart_path = f"evidence/pcap_stats_{datetime.datetime.now().strftime('%H%M%S')}.png"
                        plt.savefig(pcap_chart_path)
                        st.pyplot(fig)
                        
                        log_activity("Packet Capture", "Local Network", f"Captured {count} packets", image_path=pcap_chart_path)
                    else:
                        log_activity("Packet Capture", "Local Network", f"Captured {count} packets (Empty)")

                except Exception as e:
                    st.error(f"Capture failed: {e} (Ensure you are running as Admin/Root)")

    # --- FOOTER ---
    st.markdown("---")
    st.markdown(f"**OPERATOR:** {st.session_state['user']} | **SESSION ID:** {hash(str(datetime.datetime.now()))}")
    st.markdown("Authorized by PayBuddy Security Protocol")