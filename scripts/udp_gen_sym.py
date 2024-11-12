from scapy.all import Ether, IP, Dot1Q, sendp, wrpcap, Raw, UDP

ice_mac_adress = "b4:96:91:b2:a1:99"
mlx_mac_adress = "08:c0:eb:88:c5:39"
i40e_mac_adress = "24:6e:96:85:c6:5a"

ip_src_adress = "192.168.10."
ip_dst_adress = "193.1.1."
trunk_vlan = 14


VLAN = Dot1Q(vlan=trunk_vlan)
ETHER = Ether(src = mlx_mac_adress, dst = i40e_mac_adress)
UDP = UDP(dport=80)
RAW = Raw(b"some request")
packets = []


for j in range(5):
    for i in range(200):
        packets.append(ETHER / VLAN / IP(src = ip_src_adress + str(i), dst = ip_dst_adress + str(i + 20)) / UDP / RAW)
        packets.append(ETHER / VLAN / IP(src = ip_dst_adress + str(i + 20), dst = ip_src_adress + str(i)) / UDP / RAW) 

#sendp(packets, iface="ens4f1") #af:00.1 claret
sendp(packets, iface="ens1f1") #3b:00.1 claret