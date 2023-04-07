import socket
import struct
import binascii

#code to get value in decimal form
#int(str(binascii.hexlify(VALUE_FROM_PACKET),'utf-8'),16)
   
   

def parse_ethernet_header(packet):
   print("Ethernet Header:")
   ethernet_header = packet[0][0:14]
   eth_header = struct.unpack("!6s 6s H", ethernet_header)
   
   source_mac = str(binascii.hexlify(eth_header[1], ':'), 'utf-8')
   dest_mac = str(binascii.hexlify(eth_header[0], ':'), 'utf-8')
   eth_type = socket.htons(eth_header[2]) 
   
   #prints dest_mac, source_mac, and type (IPv4 or IPv6)
   print (f"Destination MAC: {dest_mac}    Source MAC: {source_mac}    Type: {eth_type}")
   
   #returns eth_type so it can correctly parse the type of packet
   return eth_type
   
   
   
def parse_ip_header(packet):
   print("IP header:")
   ipheader = packet[0][14:34]
   version_plus_header_len, TOS, total_len, identification, flag_plus_offset, TTL, protocol, header_checksum, source_ip, dest_ip = struct.unpack("!1s1s2s2s2s1s1s2s4s4s", ipheader)
   
   #gets version and header length seperate 
   version_plus_header_len = str(binascii.hexlify(version_plus_header_len), 'utf-8')
   version = version_plus_header_len[0]
   header_len = version_plus_header_len[1]
   
   #gets flags and offset seperate
   flag_plus_offset = str(binascii.hexlify(flag_plus_offset), 'utf-8')
   flag_plus_offset = str(bin(int(flag_plus_offset, 16)))
   flag_plus_offset = flag_plus_offset.ljust(19, '0')
   flags = flag_plus_offset[2:5]
   offset = flag_plus_offset[5:18]
   
   #gets protocol number in decimal
   protocol = int(str(binascii.hexlify(protocol),'utf-8'),16)
   
   
   #prints all of the values
   print(f"Version: {version}     Header length: {int(header_len)*4} bytes    Type of Service: {str(binascii.hexlify(TOS), 'utf-8')}") 
   print(f"Total Length {int(str(binascii.hexlify(total_len),'utf-8'),16)}    Identification: 0x{str(binascii.hexlify(identification),'utf-8')}")
   print(f"Reserved Bit: {flags[0]}  Don't Fragment: {flags[1]}  More Fragment: {flags[2]}") 
   print(f"Offset: {offset}    Time to Live: {int(str(binascii.hexlify(TTL), 'utf-8'),16)}")
   
   #figures out the protocol
   if protocol == 6:
      print(f"Protocol: TCP ({protocol})")
   elif protocol == 1:
      print(f"Protocol: ICMP ({protocol})")
   elif protocol == 17:
      print(f"Protocol: UDP ({protocol})")
   elif protocol == 27:
      print(f"Protocol: RDP ({protocol})")
   else:
      print(f"Protocol: {protocol} (Unknown)")
   
   print(f"Header Checksum: {str(binascii.hexlify(header_checksum), 'utf-8')}")
   print(f"Source IP: {socket.inet_ntoa(source_ip)}    Destination IP: {socket.inet_ntoa(dest_ip)}")
   
   
   return protocol


def main():
   s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,  socket.ntohs(3))
   while True:
      packet = s.recvfrom(2048)
      eth_type = parse_ethernet_header(packet)
      
      #if IPv4
      if eth_type == 8:
         protocol = parse_ip_header(packet)
         
         
         
      print()

   
   
if __name__ == "__main__":
   main()
   
   
   
   
   