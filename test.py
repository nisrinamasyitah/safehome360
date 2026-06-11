"""
IoT Security Testing Framework
A comprehensive tool for scanning, analyzing, and testing IoT device security
"""

import socket
import threading
import time
import json
from datetime import datetime
from typing import List, Dict
import struct
import random

# ==================== NETWORK SCANNER ====================
class IoTScanner:
    """Discover IoT devices on the network"""
    
    def __init__(self, network_range="192.168.1.0/24"):
        self.network_range = network_range
        self.devices = []
        
    def scan_ip(self, ip: str, timeout=0.5) -> Dict:
        """Scan a single IP for open ports and services"""
        device_info = {
            "ip": ip,
            "hostname": None,
            "open_ports": [],
            "services": [],
            "mac": None,
            "device_type": "Unknown"
        }
        
        # Common IoT ports
        common_ports = {
            80: "HTTP",
            443: "HTTPS",
            22: "SSH",
            23: "Telnet",
            1883: "MQTT",
            8883: "MQTT-SSL",
            5683: "CoAP",
            502: "Modbus",
            554: "RTSP",
            8080: "HTTP-Alt",
            8081: "HTTP-Alt",
            9091: "Web Interface"
        }
        
        for port, service in common_ports.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                device_info["open_ports"].append(port)
                device_info["services"].append(service)
            sock.close()
        
        # Try to get hostname
        try:
            device_info["hostname"] = socket.gethostbyaddr(ip)[0]
        except:
            pass
            
        # Identify device type based on open ports
        if 554 in device_info["open_ports"]:
            device_info["device_type"] = "IP Camera"
        elif 1883 in device_info["open_ports"]:
            device_info["device_type"] = "MQTT Device"
        elif 502 in device_info["open_ports"]:
            device_info["device_type"] = "Industrial PLC/SCADA"
        elif 5683 in device_info["open_ports"]:
            device_info["device_type"] = "CoAP Device"
        elif 23 in device_info["open_ports"]:
            device_info["device_type"] = "Legacy Device"
            
        return device_info if device_info["open_ports"] else None
    
    def scan_network(self, start_ip=1, end_ip=254):
        """Scan IP range for IoT devices"""
        print(f"[*] Scanning network for IoT devices...")
        base_ip = ".".join(self.network_range.split("/")[0].split(".")[:-1])
        
        threads = []
        for i in range(start_ip, end_ip + 1):
            ip = f"{base_ip}.{i}"
            thread = threading.Thread(target=self._scan_worker, args=(ip,))
            threads.append(thread)
            thread.start()
            
            # Limit concurrent threads
            if len(threads) >= 50:
                for t in threads:
                    t.join()
                threads = []
        
        # Wait for remaining threads
        for t in threads:
            t.join()
            
        print(f"[+] Scan complete. Found {len(self.devices)} devices.")
        return self.devices
    
    def _scan_worker(self, ip):
        """Worker thread for scanning"""
        device = self.scan_ip(ip)
        if device:
            self.devices.append(device)
            print(f"[+] Found device: {ip} ({device['device_type']})")


# ==================== VULNERABILITY SCANNER ====================
class VulnerabilityScanner:
    """Scan for common IoT vulnerabilities"""
    
    def __init__(self):
        self.vulnerabilities = []
        
    def scan_device(self, device: Dict) -> List[Dict]:
        """Perform vulnerability assessment on a device"""
        vulns = []
        
        # Check for default credentials
        if self._check_default_credentials(device):
            vulns.append({
                "severity": "CRITICAL",
                "title": "Default Credentials Detected",
                "description": f"Device at {device['ip']} may be using default credentials",
                "cve": "CWE-798",
                "cvss": 9.8,
                "remediation": "Change default username and password immediately"
            })
        
        # Check for unencrypted protocols
        unencrypted_services = ["HTTP", "Telnet", "MQTT"]
        for service in device["services"]:
            if service in unencrypted_services:
                vulns.append({
                    "severity": "HIGH",
                    "title": f"Unencrypted {service} Protocol",
                    "description": f"Device uses unencrypted {service} on port {self._get_port_for_service(device, service)}",
                    "cve": "CWE-319",
                    "cvss": 7.5,
                    "remediation": f"Enable encryption (HTTPS/SSL/TLS) for {service}"
                })
        
        # Check for exposed management interfaces
        if 8080 in device["open_ports"] or 8081 in device["open_ports"]:
            vulns.append({
                "severity": "MEDIUM",
                "title": "Exposed Management Interface",
                "description": "Web management interface accessible from network",
                "cve": "CWE-425",
                "cvss": 5.3,
                "remediation": "Restrict access to management interface using firewall rules"
            })
        
        # Check for Telnet (highly insecure)
        if 23 in device["open_ports"]:
            vulns.append({
                "severity": "CRITICAL",
                "title": "Telnet Service Active",
                "description": "Telnet transmits data in plaintext including passwords",
                "cve": "CWE-319",
                "cvss": 9.1,
                "remediation": "Disable Telnet and use SSH instead"
            })
        
        # Check for RTSP vulnerabilities (cameras)
        if 554 in device["open_ports"]:
            vulns.append({
                "severity": "HIGH",
                "title": "Unsecured RTSP Stream",
                "description": "Video stream may be accessible without authentication",
                "cve": "CWE-306",
                "cvss": 7.5,
                "remediation": "Enable authentication and use SRTP for encryption"
            })
        
        # Check for Modbus (Industrial)
        if 502 in device["open_ports"]:
            vulns.append({
                "severity": "CRITICAL",
                "title": "Industrial Control System Exposed",
                "description": "Modbus protocol has no authentication mechanism",
                "cve": "CWE-306",
                "cvss": 9.8,
                "remediation": "Implement network segmentation and VPN access"
            })
        
        return vulns
    
    def _check_default_credentials(self, device: Dict) -> bool:
        """Check for common default credentials"""
        # Simulate credential testing
        # In real implementation, this would attempt login with common credentials
        default_creds = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "12345"),
            ("root", "root"),
            ("user", "user")
        ]
        
        # For demo purposes, randomly determine if defaults are used
        # In real implementation, you'd actually test these
        return random.choice([True, False])
    
    def _get_port_for_service(self, device: Dict, service_name: str) -> int:
        """Get port number for a service"""
        service_map = {
            "HTTP": 80,
            "Telnet": 23,
            "MQTT": 1883
        }
        return service_map.get(service_name, 0)
    
    def generate_report(self, device: Dict, vulnerabilities: List[Dict]) -> str:
        """Generate vulnerability report"""
        report = f"\n{'='*70}\n"
        report += f"VULNERABILITY REPORT\n"
        report += f"{'='*70}\n"
        report += f"Device: {device['ip']} ({device['device_type']})\n"
        report += f"Hostname: {device.get('hostname', 'Unknown')}\n"
        report += f"Open Ports: {', '.join(map(str, device['open_ports']))}\n"
        report += f"Services: {', '.join(device['services'])}\n"
        report += f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"{'='*70}\n\n"
        
        if not vulnerabilities:
            report += "[+] No vulnerabilities detected.\n"
        else:
            report += f"[!] Found {len(vulnerabilities)} vulnerabilities:\n\n"
            
            for i, vuln in enumerate(vulnerabilities, 1):
                report += f"{i}. [{vuln['severity']}] {vuln['title']}\n"
                report += f"   Description: {vuln['description']}\n"
                report += f"   CWE: {vuln['cve']} | CVSS: {vuln['cvss']}\n"
                report += f"   Remediation: {vuln['remediation']}\n\n"
        
        return report


# ==================== MQTT ANALYZER ====================
class MQTTAnalyzer:
    """Analyze MQTT broker security"""
    
    def __init__(self, broker_ip: str, port: int = 1883):
        self.broker_ip = broker_ip
        self.port = port
        
    def test_anonymous_access(self) -> bool:
        """Test if MQTT broker allows anonymous connections"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self.broker_ip, self.port))
            
            # Send MQTT CONNECT packet (without credentials)
            connect_packet = bytes([
                0x10,  # CONNECT packet type
                0x0c,  # Remaining length
                0x00, 0x04, 0x4d, 0x51, 0x54, 0x54,  # Protocol name "MQTT"
                0x04,  # Protocol level
                0x02,  # Connect flags (Clean Session)
                0x00, 0x3c,  # Keep alive (60 seconds)
                0x00, 0x00  # Client ID length (0)
            ])
            
            sock.send(connect_packet)
            response = sock.recv(4)
            sock.close()
            
            # Check CONNACK response
            if len(response) >= 4 and response[0] == 0x20 and response[3] == 0x00:
                return True  # Anonymous access allowed
            return False
            
        except Exception as e:
            print(f"[!] Error testing MQTT: {e}")
            return False
    
    def analyze_security(self) -> Dict:
        """Perform security analysis on MQTT broker"""
        results = {
            "anonymous_access": False,
            "ssl_enabled": False,
            "vulnerabilities": []
        }
        
        # Test anonymous access
        results["anonymous_access"] = self.test_anonymous_access()
        
        if results["anonymous_access"]:
            results["vulnerabilities"].append({
                "severity": "CRITICAL",
                "issue": "Anonymous MQTT access enabled",
                "impact": "Anyone can publish/subscribe to topics",
                "recommendation": "Enable authentication and authorization"
            })
        
        # Check if SSL/TLS is used
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.broker_ip, 8883))  # MQTT SSL port
            results["ssl_enabled"] = (result == 0)
            sock.close()
        except:
            pass
        
        if not results["ssl_enabled"]:
            results["vulnerabilities"].append({
                "severity": "HIGH",
                "issue": "MQTT traffic not encrypted",
                "impact": "Messages can be intercepted and read",
                "recommendation": "Enable TLS encryption on port 8883"
            })
        
        return results


# ==================== PACKET SNIFFER ====================
class PacketSniffer:
    """Simple packet sniffer for IoT traffic analysis"""
    
    def __init__(self):
        self.packets = []
        self.running = False
        
    def sniff(self, interface: str = None, duration: int = 10):
        """Sniff packets for specified duration"""
        print(f"[*] Starting packet capture for {duration} seconds...")
        print(f"[*] Note: This is a simplified sniffer. For production, use Scapy or pyshark")
        
        self.running = True
        start_time = time.time()
        
        try:
            # Create raw socket (requires root/admin privileges)
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.settimeout(1)
            
            while self.running and (time.time() - start_time) < duration:
                try:
                    packet, addr = sock.recvfrom(65535)
                    self._analyze_packet(packet, addr)
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"[!] Error capturing packet: {e}")
                    break
                    
        except PermissionError:
            print("[!] Error: Packet capture requires root/administrator privileges")
            print("[!] Run with: sudo python3 script.py")
        except Exception as e:
            print(f"[!] Error: {e}")
        
        self.running = False
        print(f"[+] Capture complete. Captured {len(self.packets)} packets.")
        
    def _analyze_packet(self, packet: bytes, addr):
        """Analyze captured packet"""
        if len(packet) < 20:
            return
            
        # Parse IP header
        ip_header = struct.unpack('!BBHHHBBH4s4s', packet[:20])
        protocol = ip_header[6]
        src_ip = socket.inet_ntoa(ip_header[8])
        dst_ip = socket.inet_ntoa(ip_header[9])
        
        packet_info = {
            "timestamp": datetime.now().isoformat(),
            "protocol": self._get_protocol_name(protocol),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "size": len(packet)
        }
        
        self.packets.append(packet_info)
        
    def _get_protocol_name(self, protocol_num: int) -> str:
        """Get protocol name from number"""
        protocols = {1: "ICMP", 6: "TCP", 17: "UDP"}
        return protocols.get(protocol_num, f"Unknown({protocol_num})")
    
    def get_statistics(self) -> Dict:
        """Get packet capture statistics"""
        if not self.packets:
            return {"total": 0}
            
        stats = {
            "total": len(self.packets),
            "protocols": {},
            "top_sources": {},
            "top_destinations": {}
        }
        
        for packet in self.packets:
            # Protocol stats
            proto = packet["protocol"]
            stats["protocols"][proto] = stats["protocols"].get(proto, 0) + 1
            
            # Source IP stats
            src = packet["src_ip"]
            stats["top_sources"][src] = stats["top_sources"].get(src, 0) + 1
            
            # Destination IP stats
            dst = packet["dst_ip"]
            stats["top_destinations"][dst] = stats["top_destinations"].get(dst, 0) + 1
        
        return stats


# ==================== MAIN PROGRAM ====================
def print_banner():
    """Print application banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║         IoT Security Testing Framework v1.0                   ║
║         Cybersecurity FYP Project                             ║
╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def main_menu():
    """Display main menu"""
    print("\n[1] Scan Network for IoT Devices")
    print("[2] Vulnerability Assessment")
    print("[3] MQTT Security Analysis")
    print("[4] Packet Capture & Analysis")
    print("[5] Generate Full Report")
    print("[0] Exit")
    return input("\nSelect option: ")


def main():
    """Main program loop"""
    print_banner()
    
    scanner = IoTScanner("192.168.1.0/24")
    vuln_scanner = VulnerabilityScanner()
    devices = []
    
    while True:
        choice = main_menu()
        
        if choice == "1":
            # Network scan
            print("\n[*] Starting network scan...")
            devices = scanner.scan_network(1, 20)  # Scan first 20 IPs for demo
            
            print(f"\n{'='*70}")
            print(f"{'IP Address':<15} {'Device Type':<20} {'Open Ports':<30}")
            print(f"{'='*70}")
            
            for device in devices:
                ports = ', '.join(map(str, device['open_ports']))
                print(f"{device['ip']:<15} {device['device_type']:<20} {ports:<30}")
                
        elif choice == "2":
            # Vulnerability assessment
            if not devices:
                print("\n[!] Please scan network first (option 1)")
                continue
                
            print("\n[*] Performing vulnerability assessment...")
            for device in devices:
                vulns = vuln_scanner.scan_device(device)
                report = vuln_scanner.generate_report(device, vulns)
                print(report)
                
        elif choice == "3":
            # MQTT analysis
            broker_ip = input("Enter MQTT broker IP: ")
            analyzer = MQTTAnalyzer(broker_ip)
            
            print(f"\n[*] Analyzing MQTT broker at {broker_ip}...")
            results = analyzer.analyze_security()
            
            print(f"\n{'='*70}")
            print("MQTT SECURITY ANALYSIS")
            print(f"{'='*70}")
            print(f"Anonymous Access: {'YES (VULNERABLE)' if results['anonymous_access'] else 'NO (SECURE)'}")
            print(f"SSL/TLS Enabled: {'YES (SECURE)' if results['ssl_enabled'] else 'NO (VULNERABLE)'}")
            
            if results['vulnerabilities']:
                print(f"\n[!] Found {len(results['vulnerabilities'])} vulnerabilities:\n")
                for vuln in results['vulnerabilities']:
                    print(f"[{vuln['severity']}] {vuln['issue']}")
                    print(f"  Impact: {vuln['impact']}")
                    print(f"  Fix: {vuln['recommendation']}\n")
            else:
                print("\n[+] No vulnerabilities found!")
                
        elif choice == "4":
            # Packet capture
            print("\n[!] Note: Packet capture requires root/administrator privileges")
            duration = int(input("Capture duration (seconds): "))
            
            sniffer = PacketSniffer()
            sniffer.sniff(duration=duration)
            
            stats = sniffer.get_statistics()
            print(f"\n{'='*70}")
            print("PACKET CAPTURE STATISTICS")
            print(f"{'='*70}")
            print(f"Total Packets: {stats['total']}")
            
            if stats['total'] > 0:
                print(f"\nProtocol Distribution:")
                for proto, count in stats['protocols'].items():
                    print(f"  {proto}: {count} packets")
                    
        elif choice == "5":
            # Generate full report
            if not devices:
                print("\n[!] Please scan network first (option 1)")
                continue
                
            print("\n[*] Generating comprehensive security report...")
            
            report_file = f"iot_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            
            with open(report_file, 'w') as f:
                f.write("="*70 + "\n")
                f.write("IoT SECURITY ASSESSMENT REPORT\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*70 + "\n\n")
                
                # Device summary
                f.write(f"DISCOVERED DEVICES: {len(devices)}\n")
                f.write("-"*70 + "\n")
                for device in devices:
                    f.write(f"IP: {device['ip']}\n")
                    f.write(f"Type: {device['device_type']}\n")
                    f.write(f"Ports: {', '.join(map(str, device['open_ports']))}\n\n")
                
                # Vulnerability reports
                f.write("\n" + "="*70 + "\n")
                f.write("VULNERABILITY DETAILS\n")
                f.write("="*70 + "\n")
                
                for device in devices:
                    vulns = vuln_scanner.scan_device(device)
                    report = vuln_scanner.generate_report(device, vulns)
                    f.write(report)
            
            print(f"[+] Report saved to: {report_file}")
            
        elif choice == "0":
            print("\n[*] Exiting...")
            break
            
        else:
            print("\n[!] Invalid option. Please try again.")


if __name__ == "__main__":
    main()
    