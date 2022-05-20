import socket
import struct
import textwrap
import sys

tab1="\t -"
tab2="\t\t -"
tab3="\t\t\t -"
tab4="\t\t\t\t -"

data_tab1="\t "
data_tab2="\t\t "
data_tab3="\t\t\t "
data_tab4="\t\t\t\t "

def main():
    connection=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
# arguments
    args = sys.argv[1:]
    if len(args)==0:
        p=-1
    else:
        p = int(args[0])
    while p!=0:
        p-=1
        raw_data,address=connection.recvfrom(65536)
        des_mac,src_mac,ether_proto,data=ethernet_fram(raw_data)
        print("\n Ethernet Frame:")
        print(tab1+"destination:{},source:{},protocol:{}".format(des_mac,src_mac,ether_proto))
# protocol 8 for ipv4
        if ether_proto==8:
            (version,header_length,ttl,protocol,src,target,data)=IPV4_packet(data)
            print(tab1+"IPV4 packets:")
            print(tab2+"version:{},header length:{},ttl:{},protocol:{},src:{},target:{}".format(version,header_length,ttl,protocol,src,target))
# in ipv4 again protocol 1 is for icmp
#               protocol 17 is for udp
            if protocol==1:
                icmp_type, code, cheacksum, data=icmp_packet(data)
                print(tab1+"ICMP packet:")
                print(tab2+"type:{},code:{},cheacksum:{},".format(icmp_type, code, cheacksum))
                print(tab2+"data:")
                print(formate_multi_line(data_tab3,data,header_length))
            elif protocol==17:
                src_port, des_port, size, data=udp_segment(data)
                print(tab1+"UDP segment:")
                print(tab2+"source port:{},destination port:{},length:{}".format(src_port,des_port,size))
            else:
                print(tab1+"data:")
                print(formate_multi_line(data_tab2,data,header_length))
        else:
            print(tab1 + "data:")
            print(formate_multi_line(data_tab1, data,len(raw_data)))
def ethernet_fram(data):
    des_mac,src_mac,protocol=struct.unpack("! 6s 6s H",data[:14])
    return get_mac(src_mac),get_mac(des_mac),socket.htons(protocol),data[14:]

def get_mac(addr):
    addr=map('{:02X}'.format,addr)
    return ':'.join(addr).upper()

# version+header
#ttl+protocol+source+target
def IPV4_packet(data):
    version_header_length=data[0]
    version=version_header_length>>4
    header_length=(version_header_length & 15) * 4
    ttl,protocol,src,target=struct.unpack('! 8x B B 2x 4s 4s',data[:20])
    return version,header_length,ttl,protocol,ipv4(src),ipv4(target),data[header_length:]

def ipv4(addr):
    return '.'.join(map(str,addr))

def icmp_packet(data):
    icmp_type,code,cheacksum=struct.unpack('! B B H',data[:4])
    return  icmp_type,code,cheacksum,data[4:]

def tcp_segment(data):
    (src_port,des_port,sequence,ack,offset_reserved_flag)=struct.unpack('H H L L',data[:14])
    offset=(offset_reserved_flag>>12)*4
    flag_urg=(offset_reserved_flag & 32)>>5
    flag_ack=(offset_reserved_flag & 16)>>4
    flag_psh=(offset_reserved_flag & 8)>>3
    flag_rst=(offset_reserved_flag & 4)>>2
    flag_syn=(offset_reserved_flag & 2)>>1
    flag_fin=offset_reserved_flag & 1
    return src_port,des_port,sequence,ack,offset,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,data[offset:]

def udp_segment(data):
    src_port,des_port,size=struct.unpack('! H H 2x H',data[:8])
    return  src_port,des_port,size,data[8:]

def formate_multi_line(prefix,string,size):
    size-=len(prefix)
    if isinstance(string,bytes):
        string=''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size-=1
    return '\n'.join([prefix + line for line in textwrap.wrap(string,size)])

main()