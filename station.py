# Maitry K Chauhan - mc22ck
# Harsha Tadepalli - kt22h
import socket
import json
import struct
import os
import sys
import select
import pdb
import time
import pickle
import threading
import signal

class EthernetFrame:
    def __init__(self, dst_mac, src_mac, payload):
        self.dst_mac = dst_mac
        self.src_mac = src_mac
        self.payload = payload
        self.type = self.get_type(payload)

    @staticmethod
    def get_type(payload):
        # This function will determine the type of payload
        if isinstance(payload, ARPPacket):
            return 0x0806  # Type field for ARP
        elif isinstance(payload, IPPacket):
            return 0x0800  # Type field for IP
        else:
            return 0x0000  # new type which is not known

    def serialize(self):
        return pickle.dumps(self)

    @staticmethod
    def mac_to_bytes(mac):
        return bytes.fromhex(mac.replace(':', ''))
    
    @staticmethod
    def bytes_to_mac(byte_data):
        return ':'.join(format(b, '02x') for b in byte_data)

    @staticmethod
    def deserialize(frame_data):
        return pickle.loads(frame_data)

class ARPPacket:
    def __init__(self, sender_mac, sender_ip, target_mac, target_ip, opcode=1):
         # If the MAC addresses are strings, we are converting them to bytes using mac_to_bytes
        self.sender_mac = sender_mac if isinstance(sender_mac, bytes) else ARPPacket.mac_to_bytes(sender_mac)
        self.sender_ip = socket.inet_aton(sender_ip)
        self.target_mac = target_mac if isinstance(target_mac, bytes) else ARPPacket.mac_to_bytes(target_mac)
        self.target_ip = socket.inet_aton(target_ip)
        self.opcode = opcode

    @staticmethod
    def mac_to_bytes(mac):
        return bytes.fromhex(mac.replace(':', ''))

    def serialize(self):
        return pickle.dumps(self)

    @staticmethod
    def deserialize(packet_data):
        return pickle.loads(packet_data)

class IPPacket:
    def __init__(self, src_ip, dest_ip, payload, protocol=socket.IPPROTO_TCP):
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.payload = payload
        self.protocol = protocol
        
    def serialize(self):
        return pickle.dumps(self)

    @staticmethod
    def deserialize(packet_data):
        return pickle.loads(packet_data)
    
class Station:
    def __init__(self, station_type, iface_file, routing_table_file, hostname_file):
        # this will be the identifier for router
        self.is_router = station_type == "-route"
        # Load and store the data from the files taken as argument into the data structures
        self.iface_info = self.load_iface_info(iface_file)
        self.routing_table = self.load_routing_table(routing_table_file)
        self.hostname_info = self.load_hostnames(hostname_file)
        self.sockets = {}  
        self.arp_cache = {}
        self.pending_queue = {}
        self.pending_queue_lock = threading.Lock()

        #threads for arp timer
        arp_cache_thread = threading.Thread(target=self.manage_arp_cache)
        arp_cache_thread.daemon = True   
        arp_cache_thread.start()


        signal.signal(signal.SIGINT, self.signal_handler)  # For Ctrl+C
        signal.signal(signal.SIGTSTP, self.signal_handler)  # For Ctrl+Z

        # Establishing connections to the bridges and retry
        self.initialize_station()

    def signal_handler(self, signum, frame):
        print("\nShutting down station due to interrupt.")
        self.shutdown_station()
        sys.exit(0)


    def shutdown_station(self):
        print("\nPerforming cleanup...\n")

        # Close all sockets
        for iface, sock in self.sockets.items():
            if sock:
                print("Closing socket for interface {}".format(iface))
                sock.close()

    def remove_from_pending_queue(self, next_hop_ip):
        """
        Removing packets from the pending queue that have already
        been sent to the next_hop_ip.
        """
        # with self.pending_queue_lock:
        if next_hop_ip in self.pending_queue:
            del self.pending_queue[next_hop_ip]
            print("[DEBUG] Removed packets for {} from the pending queue.".format(next_hop_ip))

    def run(self):
        # This method will now use select to handle user inputs using stdin 
        # and incoming messages from sockets , so we colab them
        inputs = [sys.stdin] + list(self.sockets.values())

        while True:
            # Waiting for input on stdin or one of the network sockets
            readable, writable, errored = select.select(inputs, [], [],5)
            for s in readable:
                if s is sys.stdin:
                    command = sys.stdin.readline().strip()  # Reading a line from stdin
                    if command == "show arp":
                        if self.arp_cache.items():
                            print("+----------------+----------------------+-------------+")
                            print("|      IP        |         MAC          |  Time Left  |")
                            print("+----------------+----------------------+-------------+")

                            current_time = time.time()
                            for ip, (mac, timestamp,sock) in self.arp_cache.items():
                                time_left = 60 - (current_time - timestamp)
                                if not isinstance(ip,str):
                                    formatted_ip = socket.inet_ntoa(ip)
                                else:
                                    formatted_ip = ip
                                if not mac:
                                    continue
                                if not isinstance(mac,str):
                                    formatted_mac = EthernetFrame.bytes_to_mac(mac)
                                else:
                                    formatted_mac = mac
                                print("| {:<13} | {:<15} | {:.2f} sec{}|".format(formatted_ip, formatted_mac, time_left, ' ' * (21 - len(str(time_left)))))
                            print("+----------------+----------------------+-------------+")

                        else:
                            print("################# \n#  Empty Cache  # \n#################")
                    elif command == "show host":
                        self.show_hostnames()
                    elif command == "show iface":
                        self.show_interfaces()
                    elif command == "show rtable":
                        self.show_routing_table()
                    elif command == "show pq":
                        self.show_pending_queue()
                    elif command.lower() == "quit":
                        self.shutdown_station()
                        break
                    else:
                        destination, message = self.parse_command(command)
                        if destination and message:
                            self.send_message(message, destination)
                        else:
                            print("Invalid command or destination.")
                else:
                    # here we have received a message on one of the network sockets as input
                    try:
                        data = s.recv(10000)
                        if data:
                            self.handle_recieving_data(data, s)
                        else:
                            print("Bridge has been disconnected. Shutting down station.")
                            sys.exit(0)
                    except Exception as e:
                        print(e)

    def show_hostnames(self):
        header = "{:<15} {:<15}".format("Hostname", "IP Address")
        print("-" * len(header))
        print(header)
        print("-" * len(header))
        for hostname, ip in self.hostname_info.items():
            print("{:<15} {:<15}".format(hostname, ip))
        print("-" * len(header))

    def show_pending_queue(self):
        if not self.pending_queue:
            print("###################")
            print("# Empty Queue #")
            print("###################")
        else:
            print("+------------------------------------------------+")
            print("+------------------------------------------------+")
            print("| next hop              | # PKTS Waiting         |")
            print("+------------------------------------------------+")
            print("+------------------------------------------------+")
            for next_hop_ip, packets in self.pending_queue.items():
                print("| {:<21} | {:<21} |".format(next_hop_ip, len(packets)))
                for packet in packets:
                    src_ip, dest_ip, message,sock_pq = packet
                    print("+------------------------------------------------+")
                    print("|                     IP PACKET                  |")
                    print("+------------------------------------------------+")
                    print("| MESSAGE      | SRC IP         | DEST IP        |")
                    print("| {:<12} | {:<14} | {:<14} |".format(message, src_ip, dest_ip))
                print("+-----------------------+------------------------+")


    def show_interfaces(self):
        header = "{:<10} {:<15} {:<15} {:<17} {:<5}".format("Interface", "IP Address", "Netmask", "MAC Address", "LAN")
        line = "-" * len(header)
        print(line)
        print(header)
        print(line)
        for iface, details in self.iface_info.items():
            print("{:<10} {:<15} {:<15} {:<17} {:<5}".format(iface, details['ip'], details['netmask'], details['mac'], details['lan']))
        print(line)

    def show_routing_table(self):
        header = "{:<15} {:<15} {:<15} {:<10}".format("Destination", "Gateway", "Netmask", "Interface")
        line = "-" * len(header)
        print(line)
        print(header)
        print(line)
        for route in self.routing_table:
            print("{:<15} {:<15} {:<15} {:<10}".format(route['destination'], route['gateway'], route['netmask'], route['iface']))
        print(line)

    def parse_command(self, command):
    # send B Hello is the messgae format
        parts = command.split(' ', 2)  # Splitting only on the first two spaces
        if len(parts) < 3 or parts[0].lower() != 'send':
            print("Invalid command format.")
            return None, None
        destination, message = parts[1], parts[2]
        return destination, message

    def fetch_arp_reply(self, next_hop_ip,timeout=5):
        """
        Wait for an ARP reply for the next_hop_ip within the given timeout period.
        """
        print("\n[DEBUG] Next hop ip is: ", next_hop_ip)
        readable, _, _ = select.select(list(self.sockets.values()), [], [],5)
        for sock in readable:
            data = sock.recv(10000)
            if not data:
                continue  # No data received, check the next socket

            # Try to deserialize the data into an Ethernet frame
            try:
                ethernet_frame = EthernetFrame.deserialize(data)
            except (ValueError, struct.error):
                continue  # Deserialization failed, listen for more data

            # Check if the frame contains an ARP packet
            if isinstance(ethernet_frame.payload, ARPPacket):
                arp_packet = ethernet_frame.payload

                # Check if the ARP packet is a reply containing the next hop IP
                if arp_packet.opcode == 2 and socket.inet_ntoa(arp_packet.sender_ip) == next_hop_ip:
                    # Found the ARP reply with the MAC address for the next hop IP
                    self.arp_cache[socket.inet_aton(next_hop_ip)] = (arp_packet.sender_mac, time.time(),sock)
                    print("[DEBUG] ARP reply received for IP: ",next_hop_ip)
                    return arp_packet.sender_mac, sock


    def send_message(self, message, dest_name):
        try:
            # Get the destination IP from the hostnames
            dest_ip = self.hostname_info.get(dest_name)
            if dest_ip is None:
                print("Hostname ",dest_name," not found.")
                return
            sockid = None

            # Determining the next hop based on the routing table
            next_hop_ip, iface_name = self.get_next_hop_details(dest_ip)

            if iface_name not in self.iface_info:
                print("No interface found for destination :",dest_name)
                return

            # determining interface for the ARP request
            iface_structure = self.iface_info[iface_name]

            # Checking the ARP cache for the next hop's MAC address
            if self.arp_cache.get(socket.inet_aton(next_hop_ip)):
                next_hop_mac, timestamp,sock = self.arp_cache.get(socket.inet_aton(next_hop_ip),(None, None,None))
            else:
                next_hop_mac, timestamp,sock = self.arp_cache.get(next_hop_ip,(None, None,None))

            if next_hop_mac is None:
                # Sent ARP request to find out the MAC address of the next hop
                self.broadcast_arp_request(iface_structure, next_hop_ip)
                # Waiting for the ARP reply
                next_hop_mac,sockid = self.fetch_arp_reply(next_hop_ip)
            
            #the ipaddress can be in string or bytes
            if next_hop_mac is not None:
                if timestamp and (time.time() - timestamp) < 60:
                    if isinstance(next_hop_ip,str) and self.arp_cache.get(socket.inet_aton(next_hop_ip)):
                        (a,b,c) = self.arp_cache[socket.inet_aton(next_hop_ip)]
                        self.arp_cache[socket.inet_aton(next_hop_ip)] = (a, time.time(),c)
                    elif isinstance(next_hop_ip,bytes) and self.arp_cache.get(next_hop_ip):
                        (a,b,c) = self.arp_cache[next_hop_ip]
                        self.arp_cache[next_hop_ip] = (a, time.time(),c)
                    elif isinstance(next_hop_ip,bytes) and self.arp_cache.get(socket.inet_ntoa(next_hop_ip)):
                        (a,b,c) = self.arp_cache[socket.inet_ntoa(next_hop_ip)]
                        self.arp_cache[socket.inet_ntoa(next_hop_ip)] = (a, time.time(),c)
                    elif isinstance(next_hop_ip,str) and self.arp_cache.get(next_hop_ip):
                        (a,b,c) = self.arp_cache[next_hop_ip]
                        self.arp_cache[next_hop_ip] = (a, time.time(),c)

                # Constructing and sending the Ethernet frame
                if sockid:
                    if next_hop_ip in self.pending_queue:
                        for src_ip, dest_ip, message,sockk in self.pending_queue[next_hop_ip]:

                            success = self.send_frame_to_next_hop(iface_structure, message, dest_ip, next_hop_mac, sockid)
                            if not success:
                                print("[ERROR] Failed to send queued packet to ", next_hop_ip)

                        del self.pending_queue[next_hop_ip]  # Clearing the queue for this IP as we sent it
                    success = self.send_frame_to_next_hop(iface_structure, message, dest_ip, next_hop_mac,sockid)
                    
                elif c:
                    print("[DEBUG] Fetched entry from ARP cache")

                    success = self.send_frame_to_next_hop(iface_structure, message, dest_ip, next_hop_mac,c)
                    if next_hop_ip in self.pending_queue:
                        for src_ip, dest_ip, message,sockk in self.pending_queue[next_hop_ip]:
                            success = self.send_frame_to_next_hop(iface_structure, message, dest_ip, next_hop_mac, c)
                            if not success:
                                print("[ERROR] Failed to send queued packet to ", next_hop_ip)

                        del self.pending_queue[next_hop_ip]
                if success:
                    print("[DEBUG] Packet sent to {}. Removing from pending queue.".format(next_hop_ip))
                    self.remove_from_pending_queue(next_hop_ip)
                else:
                    print("[ERROR] Failed to send packet to {}. Packet remains in queue.".format(next_hop_ip))
            else:
                print("Could not find MAC address for ",next_hop_ip)
        except Exception as e:
            print("Error in sending message: , ", e)

    def send_frame_to_next_hop(self,iface_structure, message, dest_ip, next_hop_mac,sockid,newsock=None,src_ip=None):
        # Constructing the IP packet to send to next hop
        if src_ip:
            ip_packet = IPPacket(src_ip, dest_ip, message)
        else:
            ip_packet = IPPacket(iface_structure['ip'], dest_ip, message)
        # Constructing the Ethernet frame for next hop
        try:
            #encapusalating ippacket and ethernet packet
            ethernet_frame = EthernetFrame(next_hop_mac, iface_structure['mac'], ip_packet)
            # Sending the Ethernet frame
            self.send_ethernet_frame(ethernet_frame, iface_structure['lan'],sockid,newsock)
            return True
        except:
            return False

    def get_next_hop_details(self, dest_ip):
    # Performing bitwise AND operation between the dest_ip and the subnet mask
    # after that we are comparing with the network prefix in the routing table to determine next hop
        for route in self.routing_table:
            # Converting the dest_ip, the subnet mask, and the destination network prefix to integers
            dest_addr = int.from_bytes(socket.inet_aton(dest_ip), 'big')
            netmask = int.from_bytes(socket.inet_aton(route['netmask']), 'big')
            network_prefix = int.from_bytes(socket.inet_aton(route['destination']), 'big')

            # Performing bitwise AND and comparing with network prefix
            if dest_addr & netmask == network_prefix:
                if route['gateway'] == '0.0.0.0':
                    return dest_ip, route['iface']
                return route['gateway'], route['iface']
        # If no match is found, we use the default gateway 
        default_route = self.routing_table[-1]
        return default_route['gateway'], default_route['iface']
    
    def send_ethernet_frame(self, frame, iface_name,sockid,newsock=None):
        try:
            serialized_frame = pickle.dumps(frame)
            if sockid:
                sockid.send( serialized_frame)
            else:
                newsock.send( serialized_frame)
        except Exception as e:
            print("Error in sending ethernet frame.")

    def send_raw_bytes_to_network(self, bytes_data):
        for iface_name, iface in self.iface_info.items():
            sock = self.sockets.get(iface_name)
            if sock:
                sock.send(bytes_data)

    def broadcast_arp_request(self,iface_structure, dest_ip):
        if dest_ip not in self.pending_queue:
            pass

        # Constructing the ARP request packet
        arp_request = ARPPacket(
            sender_mac=iface_structure['mac'],   
            sender_ip=iface_structure['ip'],     
            target_mac='00:00:00:00:00:00',    # Target MAC address is unknown for ARP request
            target_ip=dest_ip,                 # The IP address we want 
            opcode=1                           # Opcode for ARP request 
        )
        
        # Serializing the ARP request packet into bytes
        # Wrap the ARP request in an Ethernet frame for broadcast
        ethernet_frame = EthernetFrame(

            dst_mac=bytes.fromhex('ff:ff:ff:ff:ff:ff'.replace(':', '')),  # Destination MAC in bytes
            src_mac=bytes.fromhex(iface_structure['mac'].replace(':', '')), 
            payload=arp_request      # The ARP request is the payload of the Ethernet frame
        )
        
        # Serializing the Ethernet frame into bytes
        ethernet_frame_bytes = ethernet_frame.serialize()
        print("[DEBUG] Broadcasting ARP request for IP: ",dest_ip)
        # Sending the actual frame to the network (i.e., broadcast it)
        self.send_raw_bytes_to_network(ethernet_frame_bytes)

    def send_arp_reply(self, arp_request, sock, iface_structure):
        # Creating an ARP reply packet
        arp_reply = ARPPacket(
            sender_mac=iface_structure['mac'],          
            sender_ip=iface_structure['ip'],           
            target_mac=arp_request.sender_mac,         # The MAC address of the requester
            target_ip=socket.inet_ntoa(arp_request.sender_ip),  # The IP address of the requester
            opcode=2                                   # Opcode for ARP reply
        )
        
        dst_mac_bytes = arp_request.sender_mac if isinstance(arp_request.sender_mac, bytes) else ARPPacket.mac_to_bytes(arp_request.sender_mac)
        src_mac_bytes = iface_structure['mac'] if isinstance(iface_structure['mac'], bytes) else ARPPacket.mac_to_bytes(iface_structure['mac'])

        # Wraping the ARP reply in an Ethernet frame  
        ethernet_frame = EthernetFrame(
            dst_mac=dst_mac_bytes,            # requester's MAC address
            src_mac=src_mac_bytes,            # this station's MAC address
            payload=arp_reply                 # The ARP reply bytes
        )
        
        # Serializing the Ethernet frame into bytes
        ethernet_frame_bytes = ethernet_frame.serialize()
        
        # Sending the Ethernet frame containing the ARP reply back to the requester
        sock.send(ethernet_frame_bytes)

    def handle_recieving_data(self, data, sock):
        ethernet_frame = pickle.loads(data)
        try:
            if not data:
                # if Data is empty, which means the bridge has closed the connection
                print("[DEBUG] Bridge connection lost. Shutting down station.")
                sys.exit(0)   

            if isinstance(ethernet_frame.payload, ARPPacket):
                arp_packet = ethernet_frame.payload
                
                # ARP Reply Processing
                if arp_packet.opcode == 2:  # ARP reply

                    sender_ip_str = socket.inet_ntoa(arp_packet.sender_ip)
                    if sender_ip_str in self.pending_queue:
                        for src_ip, dest_ip, message,sock_pq in self.pending_queue[sender_ip_str]:
                            next_hop_mac = self.arp_cache[socket.inet_aton(sender_ip_str)][0]
                            self.send_frame_to_next_hop(self.iface_info[iface_name], message, dest_ip, next_hop_mac, sock, src_ip=src_ip)
                        del self.pending_queue[sender_ip_str]  # Clearing the queue for this IP

                # ARP Request Processing
                for iface_name, iface_structure in self.iface_info.items():
                    if socket.inet_ntoa(arp_packet.target_ip) == iface_structure['ip'] or socket.inet_ntoa(arp_packet.target_ip) == "0.0.0.0":
                        if arp_packet.opcode == 1:  # ARP request
                            self.update_arp_cache(arp_packet.sender_ip, arp_packet.sender_mac,sock)
                            print("\n [DEBUG] Sending ARP reply for next hop ip", socket.inet_ntoa(arp_packet.target_ip))
                            self.send_arp_reply(arp_packet, sock, iface_structure)
                            break

            elif isinstance(ethernet_frame.payload, IPPacket):
                print("\nPAYLOAD RECEIVED..\n")
                ip_packet = ethernet_frame.payload
                # Handle IP packet
                self.handle_ip_packet(ip_packet, sock)
            else:
                print("Unknown Payload type")

        except Exception as e:
            print("Error in handling incoming data.")


    def update_arp_cache(self, ip_address, mac_address,sock):
        self.arp_cache[ip_address] = (mac_address, time.time(),sock)

    def manage_arp_cache(self):
    # Checking and updating the ARP cache called by thread
        while True:
            current_time = time.time()
            for ip, (mac, timestamp,sock) in list(self.arp_cache.items()):
                if current_time - timestamp > 60:  # we have 60 seconds timeout
                    if isinstance(ip,str):
                        print("[DEBUG] ARP cache entry for IP ", ip, " timed out.")
                    else:
                        print("[DEBUG] ARP cache entry for IP ", socket.inet_ntoa(ip), " timed out.")
                    del self.arp_cache[ip]
            time.sleep(5)  # Sleeping for a short period before we are checking again


    def handle_ip_packet(self, ip_packet, sock):
        # Checking if the IP packet's destination IP matches this station's IP address
        try:
            for iface_name, iface_structure in self.iface_info.items():
                if (isinstance(ip_packet.dest_ip, bytes) and socket.inet_ntoa(ip_packet.dest_ip) == iface_structure['ip']) or (
                    ip_packet.dest_ip == iface_structure['ip']
                ):
                    self.process_ip_packet(ip_packet)
                    break
                elif self.is_router:
                    # Forwarding the packet if this station is a router as router does not display the message
                    self.forward_ip_packet(ip_packet,sock)
                    break
        except Exception as e:
            print("Error in handle ip packet !")


    def process_ip_packet(self, ip_packet):
        # Processing IP packet destined for this station
        message = ip_packet.payload

        # Converting IP addresses from bytes to string if needed
        src_ip_str = socket.inet_ntoa(ip_packet.src_ip) if isinstance(ip_packet.src_ip, bytes) else ip_packet.src_ip
        dest_ip_str = socket.inet_ntoa(ip_packet.dest_ip) if isinstance(ip_packet.dest_ip, bytes) else ip_packet.dest_ip

        # Printing headers and message
        print("+-----------------+-----------------+")
        print("| SRC IP          | DEST IP         |")
        print("+-----------------+-----------------+")
        print("| {:<15} | {:<15} |".format(src_ip_str, dest_ip_str))
        print("+-----------------+-----------------+")
        print("| Message: {:<25}|".format(message))
        print("+-----------------------------------+")


    def forward_ip_packet(self, ip_packet,sock):
        # Forwarding IP packet when this is a router
        try:
            if not isinstance(ip_packet.dest_ip, bytes):
                next_hop_ip, iface_name = self.get_next_hop_details(ip_packet.dest_ip)
            else:
                next_hop_ip, iface_name = self.get_next_hop_details(socket.inet_ntoa(ip_packet.dest_ip))
            if next_hop_ip:
                if self.arp_cache.get(ip_packet.src_ip):
                    mac_sender, timestamp,sock = self.arp_cache.get(ip_packet.src_ip,(None, None,None))
                    self.arp_cache[ip_packet.src_ip] = (mac_sender, time.time(), sock)
                elif self.arp_cache.get(socket.inet_aton(ip_packet.src_ip)):
                    mac_sender, timestamp,sock = self.arp_cache.get(socket.inet_aton(ip_packet.src_ip),(None, None,None))
                    self.arp_cache[socket.inet_aton(ip_packet.src_ip)] = (mac_sender, time.time(), sock)
                
                if self.arp_cache.get(socket.inet_aton(next_hop_ip)):
                    next_hop_mac, timestamp,sock = self.arp_cache.get(socket.inet_aton(next_hop_ip),(None, None,None))
                    self.arp_cache[socket.inet_aton(next_hop_ip)] = (next_hop_mac, time.time(), sock)

                else:
                    next_hop_mac, timestamp,sock = self.arp_cache.get(next_hop_ip,(None, None,None))
                    self.arp_cache[next_hop_ip] = (next_hop_mac, time.time(), sock)

                if not next_hop_mac:
                    # Sending ARP request if no MAC address is known for the next hop
                    self.broadcast_arp_request(self.iface_info[iface_name], next_hop_ip)
                    next_hop_mac,sock = self.fetch_arp_reply(next_hop_ip)
                if next_hop_mac:
                    self.send_frame_to_next_hop(self.iface_info[iface_name], ip_packet.payload, socket.inet_ntoa(ip_packet.dest_ip) if isinstance(ip_packet.dest_ip,bytes) else ip_packet.dest_ip, next_hop_mac,sock,newsock=None,src_ip = ip_packet.src_ip)
                    if next_hop_ip in self.pending_queue:
                        for src_ip, dest_ip, message,sockk in self.pending_queue[next_hop_ip]:
                            success = self.send_frame_to_next_hop(self.iface_info[iface_name], message, dest_ip, next_hop_mac, sock)
                            time.sleep(1)
                            if not success:
                                print("[ERROR] Failed to send queued packet to ", next_hop_ip)

                        del self.pending_queue[next_hop_ip]  # Clear the queue for this IP
                else:
                    print("No ARP entry for next hop IP: ",next_hop_ip)
            else:
                print("No route to host for IP: ",socket.inet_ntoa(ip_packet.dest_ip) if isinstance(ip_packet.dest_ip,bytes) else ip_packet.dest_ip)
        except Exception as e:
            print("Error in forwarding, Appending to pending queue!!")
            if next_hop_ip not in self.pending_queue:
                self.pending_queue[next_hop_ip] = []
            self.pending_queue[next_hop_ip].append((self.iface_info[iface_name]['ip'], ip_packet.dest_ip, ip_packet.payload,sock))


    def load_iface_info(self, iface_file):
        iface_info = {}
        try:
            with open(iface_file, 'r') as file:
                for line in file:
                    parts = line.split()
                    if len(parts) == 5:
                        iface_name, ip, netmask, mac, lan = parts
                        iface_info[iface_name] = {'ip': ip, 'netmask': netmask, 'mac': mac, 'lan': lan}
                        print("{} {} {} {} {}".format(iface_name, ip, netmask, mac, lan))
        except Exception as e:
            print("Failed to load interface information: {}".format(e))
        return iface_info

    def load_routing_table(self, routing_table_file):
        routing_table = []
        try:
            with open(routing_table_file, 'r') as file:
                for line in file:
                    parts = line.split()
                    if len(parts) == 4:
                        destination, gateway, netmask, iface = parts
                        routing_table.append({'destination': destination, 'gateway': gateway, 'netmask': netmask, 'iface': iface})
                        print("{} {} {} {}".format(destination, gateway, netmask, iface))
        except Exception as e:
            print("Failed to load routing table: {}".format(e))
        return routing_table

    def load_hostnames(self, hostname_file):
        hostnames = {}
        try:
            with open(hostname_file, 'r') as file:
                for line in file:
                    parts = line.split()
                    if len(parts) == 2:
                        hostname, ip = parts
                        hostnames[hostname] = ip
                        print("{} {}".format(hostname, ip))
        except Exception as e:
            print("Failed to load hostnames: {}".format(e))
        return hostnames

    def read_bridge_info(self, bridge_name):
        # Our brridge info is stored in symbolic links
        ip_link = bridge_name + "_ip"
        port_link = bridge_name + "_port"
        if not os.path.islink(ip_link) or not os.path.islink(port_link):
            print("Bridge {} might not be running.".format(bridge_name))
            return None, None
        # Reading IP address
        try:
            bridge_ip = os.readlink(ip_link)

        except OSError as e:
            print("Could not read the IP link for " ,bridge_name , e )
            bridge_ip = None
        
        # Reading Port number
        try:
            bridge_port_str = os.readlink(port_link)
            bridge_port = int(bridge_port_str)
        except OSError as e:
            print("Could not read the port link for" , bridge_name, e )
            bridge_port = None
        except ValueError as e:
            print("Port number is not an integer: ",e)
            bridge_port = None
        
        # Return a tuple with the IP and port, or None if either couldn't be read
        return bridge_ip, bridge_port

    def save_socket_info(self, sockets, filename='sockets_info.txt'):
        with open(filename, 'a') as file:
            for iface, sock in sockets.items():
                if sock:  
                    file.write("{} {} {} {}\n".format(iface, sock.fileno(), sock.getpeername()[0], sock.getpeername()[1]))

    def connect_to_bridge(self, iface_name, bridge_ip, bridge_port):
        # Attempting to connect to the bridge at the given IP and port
        # We Created a non-blocking socket here to connect it to the bridge
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setblocking(0)  # Have set the socket to non-blocking
            sock.connect_ex((bridge_ip, bridge_port))  # Initiating the connection

            # Setting the socket back to blocking mode with a timeout of 2
            sock.setblocking(1)
            sock.settimeout(2.0)

            # Attempt to read from the socket a fix number of times
            for attempt in range(5):
                ready = select.select([sock], [], [], 2)
                if ready[0]:
                    response = sock.recv(10000).decode('utf-8')
                    if response == 'accept':
                        print("Interface ",iface_name,"connected to bridge ",bridge_ip ,": ",bridge_port)
                        self.sockets[iface_name] = sock
                        return response == 'accept'
                        print("Socket added for interface ",iface_name)
                        break
                    elif response == 'reject':
                        print("Interface {} rejected by bridge {}:{}".format(iface_name, bridge_ip, bridge_port))
                        sock.close()
                        # break
                else:
                    # No response is there..we retry
                    print("Retrying connection for interface {}...".format(iface_name))

            else:
                print("Interface {} could not connect to bridge {}:{}".format(iface_name, bridge_ip, bridge_port))
                sock.close()
                sys.exit(1)
        except socket.error as e:
            print("Socket error for interface {}: {}".format(iface_name, e))

    def initialize_station(self):
        print("initializing..\n")
        print("reading ifaces..\n")
        interface_status = {iface_name: False for iface_name in self.iface_info}

        for iface_name, iface in self.iface_info.items():
            print("{} {} {} {} {}\n".format(iface_name, iface['ip'], iface['netmask'], iface['mac'], iface['lan']))
        
        print("reading rtables..\n")
        for route in self.routing_table:
            print("{} {} {} {}\n".format(route['destination'], route['gateway'], route['netmask'], route['iface']))
        
        print("reading hosts..\n")
        for hostname, ip in self.hostname_info.items():
            print("{} {}\n".format(hostname, ip))
        count = 0
        while count <=7 and not all(interface_status.values()):
            
        # Connect to each bridge for interfaces ---- This has retry mechanism
            for iface_name, iface in self.iface_info.items():
                if not interface_status[iface_name]:
                    print("{} {} \n".format(iface['lan'], iface['ip']))
                    print("iface {} try to connect to bridge {}...\n".format(iface_name, iface['lan']))
                    bridge_ip, bridge_port = self.read_bridge_info(iface['lan'])
                    if bridge_ip is not None and bridge_port is not None:
                        connected = self.connect_to_bridge(iface_name, bridge_ip, bridge_port)
                        interface_status[iface_name] = connected
            print("(Max 7 Try) Retrying: ", count+1)
            time.sleep(2)
            count+=1
            

        if all(interface_status.values()):
            print("\n[DEBUG] All interfaces connected successfully.\n")
        else:
            print("\nCANT CONNECT.. Exiting the station..\n")
            sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: python station.py [-route | -no] iface_file routing_table_file hostname_file")
        sys.exit(1)
    
    station_type = sys.argv[1]
    iface_file = sys.argv[2]
    routing_table_file = sys.argv[3]
    hostname_file = sys.argv[4]

    station = Station(station_type, iface_file, routing_table_file, hostname_file)
    station.run()


