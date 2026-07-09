import re
import socket
from urllib.parse import urlparse
from cryptography.fernet import Fernet
import os

class SecurityAnalyzer:
    @staticmethod
    def analyze_password(password):
        score = 0
        feedback = []
        is_weak = False
        
        if len(password) < 8:
            feedback.append("Password is too short (minimum 8 characters).")
            is_weak = True
        else:
            score += 1
            
        if not re.search(r"[A-Z]", password):
            feedback.append("Missing uppercase letter.")
            is_weak = True
        else:
            score += 1
            
        if not re.search(r"[a-z]", password):
            feedback.append("Missing lowercase letter.")
            is_weak = True
        else:
            score += 1
            
        if not re.search(r"[0-9]", password):
            feedback.append("Missing number.")
            is_weak = True
        else:
            score += 1
            
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            feedback.append("Missing special character.")
            is_weak = True
        else:
            score += 1

        strength = "Strong"
        if score < 3:
            strength = "Weak"
        elif score < 5:
            strength = "Medium"
            
        return {
            "strength": strength,
            "score": score,
            "feedback": feedback,
            "is_weak": is_weak or strength == "Weak"
        }

    @staticmethod
    def check_url(url):
        if not url.startswith('http'):
            url = 'http://' + url
            
        parsed = urlparse(url)
        issues = []
        is_unsafe = False
        
        if parsed.scheme == 'http':
            issues.append("Uses unencrypted HTTP instead of HTTPS.")
            is_unsafe = True
            
        # Basic suspicious pattern check
        suspicious_keywords = ['login', 'update', 'secure', 'account', 'verify', 'bank']
        if any(keyword in parsed.netloc for keyword in suspicious_keywords):
            issues.append("URL contains suspicious keywords in domain.")
            is_unsafe = True
            
        # Check IP address as domain
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", parsed.netloc):
            issues.append("URL uses an IP address instead of a domain name.")
            is_unsafe = True
            
        status = "Unsafe" if is_unsafe else "Safe"
        
        return {
            "status": status,
            "issues": issues,
            "is_unsafe": is_unsafe
        }

    @staticmethod
    def scan_ports(target, ports=[21, 22, 80, 443, 3306, 8080]):
        open_ports = []
        try:
            target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            return {"error": "Hostname could not be resolved."}
            
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
            
        # Determine risk based on typically risky open ports
        risky_ports = [21, 22, 23, 3389] # FTP, SSH, Telnet, RDP
        found_risky = [p for p in open_ports if p in risky_ports]
        
        is_risky = len(found_risky) > 0
        
        return {
            "target": target_ip,
            "open_ports": open_ports,
            "risky_ports": found_risky,
            "is_risky": is_risky
        }

class FileEncryptor:
    @staticmethod
    def generate_key():
        return Fernet.generate_key()
        
    @staticmethod
    def encrypt_file(file_data, key):
        f = Fernet(key)
        return f.encrypt(file_data)
        
    @staticmethod
    def decrypt_file(file_data, key):
        try:
            f = Fernet(key)
            return f.decrypt(file_data)
        except Exception:
            return None
