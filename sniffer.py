print("Loading Zetech University Lightweight NIDS Engine...")
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from scapy.all import sniff, IP, TCP, UDP, Raw # NEW: Imported 'Raw' for DPI

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
    if not ENGINE_ACTIVE:
        return 

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        protocol = None
        src_port = None
        dst_port = None
        
        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            
        if protocol and src_port and dst_port:
            matched_rule_id = None
            
            # Check if this port is actively monitored by our rules
            if (protocol, dst_port) in THREAT_SIGNATURES:
                rule_id, threat_type, keyword = THREAT_SIGNATURES[(protocol, dst_port)]
                
                # OPTION B LOGIC: If a keyword exists, perform Deep Packet Inspection
                if keyword:
                    if packet.haslayer(Raw): # Does this packet have a data payload?
                        try:
                            # Convert raw bytes into readable text
                            payload = packet[Raw].load.decode('utf-8', errors='ignore')
                            
                            # Search the payload for the exact malicious string
                            if keyword.lower() in payload.lower():
                                matched_rule_id = rule_id
                                log_alert_to_db(src_ip, dst_ip, protocol, src_port, dst_port, rule_id, f"{threat_type} [DPI TRIGGER: {keyword}]")
                        except Exception:
                            pass
                
                # STANDARD LOGIC: If no keyword is set, simply block by Port alone
                else:
                    matched_rule_id = rule_id
                    log_alert_to_db(src_ip, dst_ip, protocol, src_port, dst_port, rule_id, threat_type)

            log_all_traffic(src_ip, dst_ip, protocol, src_port, dst_port, matched_rule_id)

def main():
    print("=" * 60)
    print("        ZETECH UNIVERSITY INTELLIGENT NIDS ENGINE        ")
    print("=" * 60)
    
    load_signatures_into_memory()
    threading.Thread(target=log_janitor, daemon=True).start()
    threading.Thread(target=engine_command_monitor, daemon=True).start()
    
    print("[*] Monitoring network interface cards for traffic and intrusions...")
    try:
        sniff(prn=packet_callback, store=False)
    except PermissionError:
        print("\n[ERROR] Raw socket binding requires privileges.")

if __name__ == "__main__":
    main()