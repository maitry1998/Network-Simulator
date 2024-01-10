import os
import os.path
import socket
import select
import sys
import time
from collections import defaultdict, namedtuple
from station import EthernetFrame
import pickle
import struct
from station import ARPPacket, EthernetFrame, IPPacket
import signal
MACEntry = namedtuple('MACEntry', ['socket', 'timestamp'])
import threading

class Bridge:
    def __init__(self, lan_name, num_ports, timeout=300):
        self.lan_name = lan_name
        self.num_ports = num_ports
        self.timeout = timeout
        self.ip_link = lan_name + "_ip"
        self.port_link = lan_name + "_port"
        if self.check_existing_bridge():
            raise Exception("Bridge with name {} already exists.".format(lan_name))
        self.server_socket = self.create_server_socket()
        self.create_symbolic_links()
        self.client_sockets = {}
        self.mac_table = defaultdict(lambda: MACEntry(None, None))
        signal.signal(signal.SIGTSTP, self.signal_handler)
        self.mac_table_thread = threading.Thread(target=self.manage_mac_table)
        self.mac_table_thread.daemon = True  # Daemonize thread
        self.mac_table_thread.start()

    def manage_mac_table(self):
        while True:
            current_time = time.time()
            for mac, entry in list(self.mac_table.items()):
                if current_time - entry.timestamp > 60:  # 60 seconds timeout
                    del self.mac_table[mac]
                    if isinstance(mac,bytes):
                        mac = ':'.join(format(x, '02x') for x in mac)  # Format the MAC address
                    print("[DEBUG] MAC table entry for MAC ", mac, " timed out.")
            time.sleep(5)  # Sleep for a short period before checking again


    def signal_handler(self, signum, frame):
        # Handler for SIGTSTP 
        print("\nShutting down bridge.")
        self.shutdown_bridge()

    def check_existing_bridge(self):
        # Checking if the symbolic links for this lan_name already exist
        return os.path.islink(self.ip_link) or os.path.islink(self.port_link)

    def create_server_socket(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('', 0)) # Bind to all interfaces and a random available port
        server_socket.listen(self.num_ports)
        self.server_port = server_socket.getsockname()[1]
        print("Bridge running on port {}".format(self.server_port))
        return server_socket

    def create_symbolic_links(self):
        # Creating symbolic links for IP address and port number
        server_ip = socket.gethostbyname(socket.gethostname())
        os.symlink(server_ip, self.ip_link)
        os.symlink(str(self.server_port), self.port_link)
        print("Created symbolic links for IP " , server_ip , "and port" , self.server_port)

    def run(self):
        try:
            while True:
                readable_sockets, _, _ = select.select(
                    [self.server_socket] + list(self.client_sockets.values()) + [sys.stdin], [], [])
                
                for sock in readable_sockets:
                    if sock is self.server_socket:
                        self.accept_new_connection()
                    elif sock is sys.stdin:  # Checking if we have input from stdin
                        cmd = sys.stdin.readline().strip()
                        if cmd == "show sl":
                            self.show_self_learning_table()
                        elif cmd == "quit":
                            raise KeyboardInterrupt  
                    else:
                        self.handle_client_socket(sock)
                self.cleanup_mac_table()
        except KeyboardInterrupt:
            sys.exit(0)
            print("Shutting down bridge.")
        except Exception as e:
            print(e)
            sys.exit(0)
        finally:
            for sock in self.client_sockets.values():
                sock.close()
            self.server_socket.close()
            self.cleanup_symbolic_links() 
    
    def show_self_learning_table(self):
        current_time = time.time()
        latest_entries = {}

        if not self.mac_table:
            print("\n###############\nEmpty Table\n###############\n")
            return

        for mac, entry in self.mac_table.items():
            if isinstance(mac, bytes):
                mac_str = ':'.join(format(x, '02x') for x in mac).upper()  # Format the MAC address
            else:
                mac_str = mac.upper()

            if mac_str not in latest_entries or entry.timestamp > latest_entries[mac_str].timestamp:
                latest_entries[mac_str] = entry

        print("Self-Learning Table:\n")
        print("-" * 50)   
        print("{:<17}| {:<3}| {:<8}| {}".format("MAC", "SD", "Port", "TTL (sec)"))
        print("-" * 50)  

        for mac_str, entry in latest_entries.items():
            ttl = max(60 - (current_time - entry.timestamp), 0)   
            print("{:<17}| {:<3}| {:<8}| {:.2f}".format(mac_str, entry.socket.fileno(), entry.socket.getpeername()[1], ttl))

        print("-" * 50)  


    def cleanup_symbolic_links(self):
        os.unlink(self.ip_link)
        os.unlink(self.port_link)
        print("Removed symbolic links for IP and port.")

    def accept_new_connection(self):
        client_socket, addr = self.server_socket.accept()
        if len(self.client_sockets) < self.num_ports:
            self.client_sockets[addr] = client_socket
            client_socket.send(b"accept")
            print("Accepted connection from {}".format(addr))
        else:
            client_socket.send(b"reject")
            client_socket.close()
            print("Rejected connection from {} (Bridge full)".format(addr))

    def cleanup_client_socket(self, client_socket):
        disconnected_macs = [mac for mac, entry in self.mac_table.items() if entry.socket is client_socket]
        for mac in disconnected_macs:
            del self.mac_table[mac]
        
        self.client_sockets = {addr: sock for addr, sock in self.client_sockets.items() if sock != client_socket}
        
        # Closing the disconnected socket
        client_socket.close()

    def handle_client_socket(self, client_socket):
        try:
            data = client_socket.recv(5024)
            if not data:
                self.cleanup_client_socket(client_socket)
                return

            ethernet_frame = pickle.loads(data)

            if data:  
                # Updating the MAC address table with the source MAC address
                src_mac = ethernet_frame.src_mac
                self.mac_table[src_mac] = MACEntry(client_socket, time.time())

                # Determining whether to broadcast or unicast the frame
                dst_mac = ethernet_frame.dst_mac
                if dst_mac in self.mac_table:
                    #sending to the specific known destination MAC address
                    dst_socket = self.mac_table[dst_mac].socket
                    current_timestamp = time.time()
                    self.mac_table[src_mac] = MACEntry(self.mac_table[src_mac].socket, current_timestamp)
                    self.mac_table[dst_mac] = MACEntry(self.mac_table[dst_mac].socket, current_timestamp)
                    dst_socket.send(data)
                
                else:
                    # Broadcasting to all other connected sockets except the source
                    for other_socket in self.client_sockets.values():
                        if other_socket != client_socket:
                            other_socket.send(data)
            else:
                # Client has been disconnected
                self.cleanup_client_socket(client_socket)
        except Exception as e:
            print(e)

    def cleanup_mac_table(self):
        current_time = time.time()
        for mac, entry in list(self.mac_table.items()):
            if current_time - entry.timestamp > self.timeout:
                del self.mac_table[mac]

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python bridge.py lan-name num-ports")
        sys.exit(1)
        
    lan_name = sys.argv[1]
    num_ports = int(sys.argv[2])
    
    try:
        bridge = Bridge(lan_name, num_ports)
        bridge.run()
    except Exception as e:
        print(e)
 
