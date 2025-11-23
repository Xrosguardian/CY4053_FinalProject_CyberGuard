import socket
import threading
import pandas as pd
from datetime import datetime

class PortScanner:
    def __init__(self):
        self.results = []

    def scan_port(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "Unknown"
                self.results.append({"Port": port, "State": "Open", "Service": service})
            sock.close()
        except Exception as e:
            pass

    def run_scan(self, target, ports):
        self.results = []
        threads = []
        
        # Resolve hostname
        try:
            ip = socket.gethostbyname(target)
        except:
            return pd.DataFrame()

        for port in ports:
            t = threading.Thread(target=self.scan_port, args=(ip, port))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
            
        return pd.DataFrame(self.results)