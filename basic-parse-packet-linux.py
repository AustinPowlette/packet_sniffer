import socket
from struct import unpack
from binascii import hexlify 

#code to get value in decimal form
#int(str(hexlify(VALUE_FROM_PACKET),'utf-8'),16)
   
   

def parse_ethernet_header(packet):
   print("Ethernet Header:")
   
   ethernet_header = packet[0][0:14]
   eth_header = unpack("!6s 6s H", ethernet_header)
   
   source_mac = str(hexlify(eth_header[1], ':'), 'utf-8')
   dest_mac = str(hexlify(eth_header[0], ':'), 'utf-8')
   eth_type = socket.htons(eth_header[2]) 
   
   #prints dest_mac, source_mac, and type (IPv4 or IPv6)
   print (f"Destination MAC: {dest_mac}    Source MAC: {source_mac}    Type: {eth_type}")
   print()
   #returns eth_type so it can correctly parse the type of packet
   return eth_type
   
   
   
def parse_ip_header(packet):
   print("\tIP header:")
   
   ipheader = packet[0][14:34]
   version_plus_header_len, TOS, total_len, identification, flag_plus_offset, TTL, protocol, header_checksum, source_ip, dest_ip = unpack("!1s1s2s2s2s1s1s2s4s4s", ipheader)
   
   #gets version and header length seperate 
   version_plus_header_len = str(hexlify(version_plus_header_len), 'utf-8')
   version = version_plus_header_len[0]
   header_len = version_plus_header_len[1]
   
   #gets flags and offset seperate
   flag_plus_offset = str(hexlify(flag_plus_offset), 'utf-8')
   flag_plus_offset = str(bin(int(flag_plus_offset, 16)))
   flag_plus_offset = flag_plus_offset.ljust(19, '0')
   flags = flag_plus_offset[2:5]
   offset = flag_plus_offset[5:18]
   
   #gets protocol number in decimal
   protocol = int(str(hexlify(protocol),'utf-8'),16)
   
   
   #prints all of the values
   print(f"\tVersion: {version}     Header length: {int(header_len)*4} bytes    Type of Service: {str(hexlify(TOS), 'utf-8')}") 
   print(f"\tTotal Length {int(str(hexlify(total_len),'utf-8'),16)}    Identification: 0x{str(hexlify(identification),'utf-8')}")
   print(f"\tReserved Bit: {flags[0]}  Don't Fragment: {flags[1]}  More Fragment: {flags[2]}") 
   print(f"\tOffset: {offset}    Time to Live: {int(str(hexlify(TTL), 'utf-8'),16)}")
   print(f"\tHeader Checksum: {str(hexlify(header_checksum), 'utf-8')}")
   print()
   #figures out the protocol
   if protocol == 6:
      print(f"\tProtocol: TCP ({protocol})")
   elif protocol == 1:
      print(f"\tProtocol: ICMP ({protocol})")
   elif protocol == 17:
      print(f"\tProtocol: UDP ({protocol})")
   elif protocol == 27:
      print(f"\tProtocol: RDP ({protocol})")
   else:
      print(f"\tProtocol: {protocol} (Unknown)")
   print()
   print(f"\tSource IP: {socket.inet_ntoa(source_ip)}    Destination IP: {socket.inet_ntoa(dest_ip)}")
   print()
   
   return protocol


def parse_tcp_header(packet):
   print("\t\tTCP Header:")
   
   tcp_header = packet[0][34:54]
   source_port, dest_port, seq_num, ack_num, offset_reserved_flags, window, checksum, urgent_pointer = unpack('!2s2s4s4s2s2s2s2s',tcp_header)
   
   #gets values in decimal form
   source_port = int(str(hexlify(source_port),'utf-8'),16)
   dest_port = int(str(hexlify(dest_port),'utf-8'),16)
   seq_num = int(str(hexlify(seq_num),'utf-8'),16)
   ack_num = int(str(hexlify(ack_num),'utf-8'),16)
   window = int(str(hexlify(window), 'utf-8'),16)
   
   #gets flags and offset value
   offset_reserved_flags = int(str(hexlify(offset_reserved_flags), 'utf-8'),16)
   offset = (offset_reserved_flags >> 12) * 4
   flag_urg = (offset_reserved_flags & 32) >> 5
   flag_ack = (offset_reserved_flags & 16) >> 4
   flag_psh = (offset_reserved_flags & 8) >> 3
   flag_rst = (offset_reserved_flags & 4) >> 2
   flag_syn = (offset_reserved_flags & 2) >> 1
   flag_fin = offset_reserved_flags & 1 
   
   
   
   print(f"\t\tSource Port: {str(source_port)}    Destination Port: {str(dest_port)}")
   print(f"\t\tSequence Number: {str(seq_num)}    Acknowledgement Number: {str(ack_num)}")
   print()
   print(f"\t\tURG flag: {str(flag_urg)}    ACK flag: {str(flag_ack)}    PSH flag: {str(flag_psh)}")
   print(f"\t\tRST flag: {str(flag_rst)}    SYN flag: {str(flag_syn)}    FIN flag: {str(flag_fin)}")
   print()
   print(f"\t\tWindow: {window}    Checksum: {str(hexlify(checksum), 'utf-8')}    Urgent Pointer: {str(hexlify(urgent_pointer), 'utf-8')}")


def parse_icmp_header(packet):
   print("\t\tICMP Header:")
   icmp_header = packet[0][34:38]
   icmp_type, code, checksum = unpack('!2s2s4s', icmp_header)
   
   #gets decimal values
   icmp_type = int(str(hexlify(icmp_type),'utf-8'),16)
   code = int(str(hexlify(code),'utf-8'),16)
   
   print(f"\t\tType: {str(icmp_type)}    Code: {str(code)}    Checksum: {str(hexlify(checksum), 'utf-8')}")
   
   
   
   
def parse_udp_header(packet):
   print("\t\tUDP Header:")
   udp_header = packet[0][34:42]
   source_port, dest_port, length, checksum = unpack('!2s2s2s2s', udp_header)
   
   #get decimal values
   source_port = int(str(hexlify(source_port),'utf-8'),16)
   dest_port = int(str(hexlify(dest_port),'utf-8'),16)
   length = int(str(hexlify(length),'utf-8'),16)
   
   print(f"\t\tSource Port: {str(source_port)}    Destination Port: {str(dest_port)}")
   print(f"\t\tLength: {str(length)}    Checksum: {str(hexlify(checksum),'utf-8')}")
   
   
   
   
def parse_rdp_header(packet):
   print("rdp not implemented yet")






def print_tcp_data(packet):
   tcp_data = packet[0][34:]
   print("\t\tTCP data")
   
   try:
      decoded_data = tcp_data.decode('utf-8')
      print(f"\t\t\t{decoded_data}")
   except:
      print(f"\t\t\t{tcp_data}")
   
   
def main():
   s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,  socket.ntohs(3))
   while True:
      packet = s.recvfrom(2048)
      
      #uses packet[0][0:14]
      eth_type = parse_ethernet_header(packet)
      
      #if IPv4
      if eth_type == 8:
      	 #uses packet[0][14:34]
         protocol = parse_ip_header(packet)
         
      #if IPv6
      elif eth_type == 0x86DD:
         print("IPv6 is not implemented yet")
         continue
      	 
      else:
         continue
         
      #TCP   
      if protocol == 6:
      	  #uses packet[0][34:54]
          parse_tcp_header(packet)
          #TODO print out characters
      #ICMP
      elif protocol == 1:
      	  #uses packet[0][34:38]
          parse_icmp_header(packet)
          
      #UDP
      elif protocol == 17:
          #uses packet[0][34:42]
          parse_udp_header(packet)
          
      #RDP
      elif protocol == 27:
          #uses packet[0][34:
          parse_rdp_header(packet)
          
         
      print()

   
   
if __name__ == "__main__":
   main()
   
   
   
   
   