from scapy.all import Ether, IP, Dot1Q, sendp, wrpcap, Raw, UDP, fragment

ice_mac_adress = "b4:96:91:b2:a1:99"
mlx_mac_adress = "08:c0:eb:88:c5:39"
i40e_mac_adress = "24:6e:96:85:c6:5a"
ixgbe_mac_adress_src = "ac:1f:6b:a1:18:83"
ixgbe_mac_adress_dst = "AC:1F:6B:A1:18:82"


ip_src_adress = "192.168.10.1"
ip_dst_adress = "193.1.1.2"
trunk_vlan = 14


VLAN = Dot1Q(vlan=trunk_vlan)
ETHER = Ether(src = mlx_mac_adress, dst = ice_mac_adress)
UDP_header = UDP(dport=80)
RAW = Raw(b"some request")
packets = []


for i in range(200):

        packets.append(ETHER / VLAN / IP(src = ip_src_adress, dst = ip_dst_adress) / UDP_header / RAW)
        packets.append(ETHER / VLAN / IP(src = ip_dst_adress, dst = ip_src_adress ) / UDP_header / RAW)

        packets.append(ETHER / VLAN / IP(src = ip_src_adress, dst = ip_dst_adress) / UDP(dport = i) / RAW)
        packets.append(ETHER / VLAN / IP(src = ip_dst_adress, dst = ip_src_adress ) / UDP(dport = i) / RAW)
        
        packets.append(ETHER / VLAN / IP(src = ip_src_adress + "7", dst = ip_dst_adress + "7") / UDP(dport = i) / RAW)
        packets.append(ETHER / VLAN / IP(src = ip_dst_adress + "7", dst = ip_src_adress + "7") / UDP(dport = i) / RAW)
        
        packets.append(ETHER / VLAN / IP(src = ip_dst_adress + "7" , dst = ip_src_adress + "7" ) / UDP_header / RAW)
        packets.append(ETHER / VLAN / IP(src = ip_src_adress + "7" , dst = ip_dst_adress + "7" ) / UDP_header / RAW)

    


#sendp(packets, iface="ens4f1") #af:00.1 claret
sendp(packets, iface="ens1f1") #3b:00.1 claret
#sendp(packets, iface="eno4") #03:00.1 dpdk-test2
