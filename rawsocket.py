# -*- coding: utf-8 -*-
"""
@author: Rachel Rajan
"""
import socket, struct, select, time
#import pdb

# here define global constants, TIMEOUT and other constants
TIMEOUT = 5 # time out 5 seconds for select function
ICMP_ECHO = 8
ICMP_MAX_RECV = 2048

class RawSocket:
    
    def __init__(self, remotehost):  #Constructor: initialize instance variables
        self.sock = None # raw socket's handler
        self.remotehost = remotehost # tracert to the destination
        self.ttl = 1 # ttl for this icmp packet
        self.port = 33435 # random port number
        self.ip = self.getIP(remotehost) # ip of the destination
#        print("ping to ip = ", self.ip) # print msg
        self.myID = 1234 # id for this icmp packet
        self.seqNumber = 0 # sequence number for this icmp pkt
        self.packet_size = 55 #Packet size
        
    def getIP(self, hostname): #hostname is a string
        """call gethostbyname to convert host name of string (e.g., google.com)
        to its ip address (string)"""
        try:
            ip = socket.gethostbyname(hostname) # ip is a local variable
            print("Tracerouting to... ", ip)
            print("over a maximum of 30 hops")
        except socket.gaierror:
                print("Failed to gethostbyname")
                return None
        return ip # ip in string
    
    def createRawSocket(self): # create raw socket
        try:
            self.sock = socket.socket(
                    family = socket.AF_INET,
                    type = socket.SOCK_RAW,
                    proto = socket.IPPROTO_ICMP
            )
        except socket.error as e:
            print("failed. (socket error: '%s')" % e.args[1])
            raise # raise the original error
        return
    
    def checksum(self, packet): # packet in bytes, 
        """ Return checksum of a packet (including header and data).
        Network data is big-endian, hosts are typically little-endian """
        evenLength = (int(len(packet) / 2)) * 2
        sum = 0
        for count in range(0, evenLength, 2): # handle two bytes each time
            sum = sum + (packet[count + 1] * 256 + packet[count]) #low byte is at [count]
            if evenLength < len(packet): # if handle last byte if odd-number of bytes
                sum += packet[-1] # get last byte
                sum &= 0xffffffff # Truncate sum to 32 bits (a variance from ping.c)
                sum = (sum >> 16) + (sum & 0xffff) # Add high 16 bits to low 16 bits
                sum += (sum >> 16) # Add carry from above (if any)
                sum = ~sum & 0xffff # Invert and truncate to 16 bits
                return socket.htons(sum)
            
    def sendPing(self, ttl): # ttl is an int
#        pdb.set_trace()
        """ Create an icmp packet first, then use raw socket to sendto this packet """
        #Header has 8 bytes: type (8), code (8), checksum (16), id (16), sequence (16)
        checksum = 0 # initialize checksum to 0
        # Make a dummy header with a 0 checksum.
        header = struct.pack("!BBHHH", ICMP_ECHO, 0, checksum, self.myID, self.seqNumber)
        MAX_DATA_SIZE =[]
        init_val = 0x42
        for i in range(init_val, init_val + self.packet_size):
            MAX_DATA_SIZE += [(i & 0xff)]
        data = bytes(MAX_DATA_SIZE) # bytes of zeros
        packet = header + data
        checksum = self.checksum(packet) # compute checksum, in network order
        # Now that we have the right checksum, put that in. Create a new header
#        pdb.set_trace()

        header = struct.pack("!BBHHH", ICMP_ECHO, 0, checksum, self.myID, self.seqNumber)
        packet = header + data # Packet ready
        send_time = time.clock()
        self.ttl = ttl
        self.sock.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)
        try:
            num = self.sock.sendto(packet, (self.ip, self.port))
            print("bytes sent: ", num) # print msg for debugging!!!!
        except socket.error as e:
            print(" Failed (%s)" % (e.args[1]))
            self.sock.close()
            return
        return send_time
    
    def recvPing(self): # recv msg, return True if reach destination, next
        """Set timeout on receiving reply, call recvfrom(), interpret header info
        return True if reach destination """
        self.sock.setblocking(0)
        
        rem_time = TIMEOUT
        start_select = time.clock()
        
        dataReady = select.select([self.sock], [], [], )
        time_taken_to_select = time.clock() - start_select
        if dataReady[0] == []: # Timeout
            print("recvfrom Timeout!")
            return False
        recvd_time = time.clock()
        recPacket = b'' # empty bytes
        recPacket, addr = self.sock.recvfrom(ICMP_MAX_RECV)
        print("bytes received: ", len(recPacket)) # print for debugging!!!
        # first 20 bytes in recv pkt are IP header that contains router/destination IP
        ipHeader = recPacket[:20]
        iphVersion, iphTypeOfSvc, iphLength, \
        iphID, iphFlags, iphTTL, iphProtocol, \
        iphChecksum, iphSrcIP, iphDestIP = struct.unpack("!BBHHHBBHII", ipHeader)
        # next 8 bytes are ICMP reply header
        icmpHeader = recPacket[20:28]
        icmpType, icmpCode, icmpChecksum, \
        icmpPacketID, icmpSeqNumber = struct.unpack("!BBHHH", icmpHeader)
        print("icmpType = ", icmpType,", icmpCode = ", icmpCode) # for debugging!!
        ip_addr = socket.inet_ntoa(struct.pack("!I", iphSrcIP))
        try:
            rev_dns = socket.gethostbyaddr(str(ip_addr))
            print("IP address :", ip_addr, ", DNS name :",repr(rev_dns[0]))
        except socket.error:
            # fail gracefully
            print("IP address :", ip_addr, ", DNS name : <no DNS entry>")

        rem_time = rem_time - time_taken_to_select
#        print("timeout(ms) :" , rem_time)
        if rem_time <= 0:
            return False

    def close(self): # call sock.close(), next
        self.sock.close()
        
    def trace(self): 
        for ttl in range(1, 30, 1):
            print("ttl =", ttl)
            self.createRawSocket()
            startTime = time.clock() # get startTime, in milliseconds
            self.sendPing(ttl)
            self.recvPing()
            self.close()
            print("RTT (ms) = ", (time.clock() - startTime)) # in milliseconds
        return