from scapy.all import IP, TCP, Raw, send
import time

print("🔥 Initializing Red Team DPI Attack Vector...")
time.sleep(1)

target_ip = "192.168.100.1"  # <-- Make sure this is your local network IP
target_port = 80           # Targeting HTTP port
# Sending a classic SQL injection attempt
payload_data = "GET /login.php?user=' OR 1=1-- HTTP/1.1\r\nHost: target\r\n\r\n"

print(f"🎯 Forging SQL Injection packet to {target_ip}:{target_port}...")

malicious_packet = IP(dst=target_ip) / TCP(dport=target_port, flags="PA") / Raw(load=payload_data)

try:
    send(malicious_packet, verbose=False)
    print("✅ SQLi Ghost packet injected successfully!")
    print("👀 Check the dashboard. The DPI engine should flag this!")
except PermissionError:
    print("❌ ERROR: You must run this script with 'sudo'.")