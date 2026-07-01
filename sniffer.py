print("Loading Zetech University Lightweight NIDS Engine...")
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from scapy.all import sniff, IP, TCP, UDP, Raw # NEW: Imported 'Raw' for DPI

# --- DEEP PACKET INSPECTION (DPI) SIGNATURES ---
DPI_SIGNATURES = {
    "SQL_INJECTION": b"' OR 1=1",
    "DIR_TRAVERSAL": b"../../../etc/passwd",
    "XSS_ATTACK": b"<script>alert",
    "MALICIOUS_PROBE": b"ROOT LOGIN ATTEMPT"
}

THREAT_SIGNATURES = {}
ENGINE_ACTIVE = True 

def get_db_connection():
    conn = sqlite3.connect('zetech_nids.db', timeout=5)
    conn.execute('PRAGMA journal_mode=WAL;')
    return conn

# --- UPDATED: DPI Memory Loader ---
def load_signatures_into_memory():
    global THREAT_SIGNATURES
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # Ensure we fetch the payload_keyword safely
        cursor.execute("SELECT rule_id, threat_type, protocol, port, payload_keyword FROM SIGNATURE_RULE")
        rules = cursor.fetchall()
        
        THREAT_SIGNATURES.clear() 
        for rule in rules:
            rule_id, threat_type, protocol, port, keyword = rule
            # Store the keyword alongside the standard rule data
            THREAT_SIGNATURES[(protocol.upper(), int(port))] = (rule_id, threat_type, keyword)
        conn.close()
        print(f"[+] Loaded {len(THREAT_SIGNATURES)} signatures (DPI Engine Active).")
    except sqlite3.OperationalError:
        pass


def start_port_scan_detector():
    """
    Background worker that monitors the database to detect if a 
    single IP is probing multiple distinct ports (Reconnaissance).
    """
    print("[*] Zetech NIDS: Port Scan Detection Module Activated.")
    
    while True:
        try:
            # Open connection using WAL mode to prevent locking issues with the sniffer
            conn = sqlite3.connect('zetech_nids.db', timeout=5)
            conn.execute('PRAGMA journal_mode=WAL;')
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # SQL Analysis: Find IPs hitting 15+ DISTINCT ports within the last 10 seconds
            analysis_query = """
                SELECT source_ip, COUNT(DISTINCT dst_port) as unique_ports_hit,
                       MAX(dest_ip) as dest_ip, MAX(protocol) as protocol,
                       MAX(src_port) as src_port, MAX(dst_port) as dst_port
                FROM LOGS
                WHERE time_logged >= datetime('now', '-10 seconds', 'localtime')
                GROUP BY source_ip
                HAVING unique_ports_hit >= 15
            """
            cursor.execute(analysis_query)
            suspects = cursor.fetchall()

            for suspect in suspects:
                attacker_ip = suspect['source_ip']
                ports_counted = suspect['unique_ports_hit']
                
                # Anti-Spam Check: Don't flood the ALERT_LOG if we already flagged this IP in the last 30 seconds
                cursor.execute("""
                    SELECT 1 FROM ALERT_LOG 
                    WHERE source_ip = ? AND rule_id = 9001
                    AND time_logged >= datetime('now', '-30 seconds', 'localtime')
                    LIMIT 1
                """, (attacker_ip,))
                
                if not cursor.fetchone():
                    # Rule 9001 designated for Port Scan Detection
                    print(f"[🚨] ALERT: Port Scan detected from {attacker_ip}! Probed {ports_counted} unique ports.")
                    
                    cursor.execute("""
                        INSERT INTO ALERT_LOG (time_logged, source_ip, dest_ip, protocol, src_port, dst_port, rule_id)
                        VALUES (datetime('now', 'localtime'), ?, ?, ?, ?, ?, 9001)
                    """, (attacker_ip, suspect['dest_ip'], suspect['protocol'], suspect['src_port'], suspect['dst_port']))
                    
                    conn.commit()

            conn.close()
        except Exception as e:
            print(f"[-] Port Scan Detector Error: {e}")
        
        # Analyze the database state every 3 seconds
        time.sleep(3)

# To spin this engine loop up alongside your sniffer, add this to your main startup logic:
# threading.Thread(target=start_port_scan_detector, daemon=True).start()

def start_packet_flood_detector():
    """
    Background worker that monitors the database to detect if a 
    single IP is flooding the network with excessive traffic volume (DoS).
    """
    print("[*] Zetech NIDS: Packet Flood Detection Module Activated.")
    
    while True:
        try:
            conn = sqlite3.connect('zetech_nids.db', timeout=5)
            conn.execute('PRAGMA journal_mode=WAL;')
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # SQL Analysis: Find any IP sending more than 200 packets in the last 2 seconds
            analysis_query = """
                SELECT source_ip, COUNT(*) as packet_count,
                       MAX(dest_ip) as dest_ip, MAX(protocol) as protocol,
                       MAX(src_port) as src_port, MAX(dst_port) as dst_port
                FROM LOGS
                WHERE time_logged >= datetime('now', '-2 seconds', 'localtime')
                GROUP BY source_ip
                HAVING packet_count >= 200
            """
            cursor.execute(analysis_query)
            suspects = cursor.fetchall()

            for suspect in suspects:
                attacker_ip = suspect['source_ip']
                volume = suspect['packet_count']
                
                # Anti-Spam Check: Don't flood the ALERT_LOG if we already flagged this flood in the last 20 seconds
                cursor.execute("""
                    SELECT 1 FROM ALERT_LOG 
                    WHERE source_ip = ? AND rule_id = 9002
                    AND time_logged >= datetime('now', '-20 seconds', 'localtime')
                    LIMIT 1
                """, (attacker_ip,))
                
                if not cursor.fetchone():
                    # Rule 9002 designated for Packet Flooding / DoS Detection
                    print(f"[🚨] ALERT: Packet Flood detected from {attacker_ip}! Volume: {volume} packets/2s.")
                    
                    cursor.execute("""
                        INSERT INTO ALERT_LOG (time_logged, source_ip, dest_ip, protocol, src_port, dst_port, rule_id)
                        VALUES (datetime('now', 'localtime'), ?, ?, ?, ?, ?, 9002)
                    """, (attacker_ip, suspect['dest_ip'], suspect['protocol'], suspect['src_port'], suspect['dst_port']))
                    
                    conn.commit()

            conn.close()
        except Exception as e:
            print(f"[-] Packet Flood Detector Error: {e}")
        
        # Check velocity every 1 second for rapid response
        time.sleep(1)
 

def engine_command_monitor():
    global ENGINE_ACTIVE
    counter = 0
    while True:
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('CREATE TABLE IF NOT EXISTS ENGINE_CONTROL (id INTEGER PRIMARY KEY CHECK (id = 1), status TEXT NOT NULL)')
            cursor.execute('INSERT OR IGNORE INTO ENGINE_CONTROL (id, status) VALUES (1, "running")')
            conn.commit()
            
            cursor.execute("SELECT status FROM ENGINE_CONTROL WHERE id = 1")
            row = cursor.fetchone()
            if row:
                status = row[0]
                if status == "stopped" and ENGINE_ACTIVE:
                    ENGINE_ACTIVE = False
                    print("\n[!] DASHBOARD COMMAND RECEIVED: Engine paused. Dropping packets...")
                elif status == "running" and not ENGINE_ACTIVE:
                    ENGINE_ACTIVE = True
                    print("\n[+] DASHBOARD COMMAND RECEIVED: Engine resumed. Sniffing active...")
            conn.close()
            
            counter += 1
            if counter >= 3:
                load_signatures_into_memory()
                counter = 0
                
        except Exception:
            pass
        time.sleep(2)

def log_janitor():
    """
    Runs continuously in a background thread. Reads the UI retention setting 
    and deletes general LOGS older than the specified timeframe.
    """
    print("[*] Log Retention Janitor activated and safeguarding database storage...")
    while True:
        try:
            conn = sqlite3.connect('zetech_nids.db', timeout=1)
            cursor = conn.cursor()
            
            # Read what the user selected in the UI dropdown
            cursor.execute("SELECT retention_hours FROM SYSTEM_SETTINGS WHERE id = 1")
            row = cursor.fetchone()
            
            if row:
                retention_hours = row[0]
                
                # If it's not set to "Keep Forever" (999999)
                if retention_hours < 999999:
                    # Calculate the exact local cutoff time
                    cutoff_delta = datetime.now() - timedelta(hours=retention_hours)
                    cutoff_timestamp = cutoff_delta.strftime('%Y-%m-%d %H:%M:%S')
                    
                    # Delete old records ONLY from general LOGS table (Option A)
                    cursor.execute("DELETE FROM LOGS WHERE time_logged < ?", (cutoff_timestamp,))
                    deleted_count = cursor.rowcount
                    
                    if deleted_count > 0:
                        print(f"[🧹 JANITOR] Automatically cleared {deleted_count} expired rows from general LOGS.")
                    
                    conn.commit()
            conn.close()
        except Exception as e:
            print(f"[-] Janitor encountered an error: {e}")
        
        # Check every 10 seconds during development so you can see it work instantly
        time.sleep(10)

def log_all_traffic(src_ip, dst_ip, protocol, src_port, dst_port, rule_id=None):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO LOGS (source_ip, dest_ip, protocol, src_port, dst_port, rule_id)
                          VALUES (?, ?, ?, ?, ?, ?)''', (src_ip, dst_ip, protocol, src_port, dst_port, rule_id))
        conn.commit()
        conn.close()
    except Exception:
        pass 

def log_alert_to_db(src_ip, dst_ip, protocol, src_port, dst_port, rule_id, threat_type):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO ALERT_LOG (source_ip, dest_ip, protocol, src_port, dst_port, rule_id)
                          VALUES (?, ?, ?, ?, ?, ?)''', (src_ip, dst_ip, protocol, src_port, dst_port, rule_id))
        conn.commit()
        conn.close()
        print(f"\n[!!! INTRUSION DETECTED !!!]")
        print(f"│ Threat:   {threat_type}")
        print(f"│ Ports:    Src: {src_port} ──> Dst: {dst_port} ({protocol})")
        print(f"│ Match:    {src_ip} ──> {dst_ip}")
        print(f"└─ Logged securely to ALERT_LOG database table.\n")
    except Exception:
        pass

# --- UPDATED: The DPI Core Logic ---
def packet_callback(packet):
    if not ENGINE_ACTIVE or not packet.haslayer(IP):
        return 

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol, src_port, dst_port = None, None, None
    
    if packet.haslayer(TCP):
        protocol, src_port, dst_port = "TCP", packet[TCP].sport, packet[TCP].dport
    elif packet.haslayer(UDP):
        protocol, src_port, dst_port = "UDP", packet[UDP].sport, packet[UDP].dport
    else:
        return # Skip non-TCP/UDP traffic

    # 1. Perform Deep Packet Inspection (DPI)
    dpi_threat = None
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        for name, sig in DPI_SIGNATURES.items():
            if sig in payload:
                dpi_threat = name
                break

    # 2. Assign Rule ID: DPI takes priority
    matched_rule_id = None
    if dpi_threat:
        matched_rule_id = f"DPI: {dpi_threat}"
        log_alert_to_db(src_ip, dst_ip, protocol, src_port, dst_port, matched_rule_id, dpi_threat)
    else:
        # Check standard port rules if no DPI signature found
        if (protocol, dst_port) in THREAT_SIGNATURES:
            rule_id, threat_type, keyword = THREAT_SIGNATURES[(protocol, dst_port)]
            matched_rule_id = rule_id
            log_alert_to_db(src_ip, dst_ip, protocol, src_port, dst_port, rule_id, threat_type)

    # 3. Log everything to the main stream
    log_all_traffic(src_ip, dst_ip, protocol, src_port, dst_port, matched_rule_id)

def main():
    print("=" * 60)
    print("        ZETECH UNIVERSITY INTELLIGENT NIDS ENGINE        ")
    print("=" * 60)
    
    load_signatures_into_memory()
    threading.Thread(target=log_janitor, daemon=True).start()
    threading.Thread(target=engine_command_monitor, daemon=True).start()
    threading.Thread(target=start_port_scan_detector, daemon=True).start()
    threading.Thread(target=start_packet_flood_detector, daemon=True).start()
    
    print("[*] Checking system settings for designated network interface...")
    
    # --- NEW ADDITION: Fetch the user's selected interface from the database ---
    conn = get_db_connection()
    try:
        # We use row_factory to easily grab the column by name
        conn.row_factory = sqlite3.Row 
        row = conn.execute("SELECT interface FROM SYSTEM_SETTINGS WHERE id = 1").fetchone()
        selected_iface = row['interface'] if row and row['interface'] else None
    except Exception:
        selected_iface = None
    finally:
        conn.close()

    # --- NEW ADDITION: Bind the sniffer dynamically based on UI selection ---
    try:
        if selected_iface:
            print(f"[*] Binding engine strictly to target interface: {selected_iface}")
            sniff(iface=selected_iface, prn=packet_callback, store=False)
        else:
            print("[*] No specific interface selected. Binding to all default routes...")
            sniff(prn=packet_callback, store=False)
    except PermissionError:
        print("\n[ERROR] Raw socket binding requires privileges. Run as root/admin.")
if __name__ == "__main__":
    main()