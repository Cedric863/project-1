from scapy.all import IP, TCP, Raw, send
import time

def launch_simulated_attack():
    print("=" * 50)
    print("      ZETECH NIDS - LIVE FIRE SIMULATOR      ")
    print("=" * 50)
    
    # Target configurations to match your DPI rule
    target_ip = "127.0.0.1" # Targeting your own local machine
    target_port = 9090
    malicious_payload = "This is a HACKER payload"

    print(f"[*] Forging malicious packet destined for Port {target_port}...")
    time.sleep(1)
    
    # Craft the raw packet: IP Layer -> TCP Layer -> Raw Data Payload
    attack_packet = IP(dst=target_ip) / TCP(dport=target_port, sport=44444) / Raw(load=malicious_payload)
    
    print(f"[+] Injecting Payload: '{malicious_payload}'")
    # Send the packet onto the network interface
    send(attack_packet, verbose=False)
    
    print("[*] Boom. Packet deployed.")
    print("[*] Switch over to your NIDS Dashboard to verify interception!")
    print("=" * 50)

if __name__ == "__main__":
    launch_simulated_attack()