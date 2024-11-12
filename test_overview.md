## Overview:
Test 1 is applicable only for ice cards, others can be tried with appropriate changes on different cards 

## test_1: 
### goal: 
- suricata - differentiate between use of legacy rss API and rte_flow rss rule 
	
#### suricata machine: 
- claret
#### suricata NIC driver: 
- ice
#### suricata interface: 
- 0000:af:00.1

#### traffic source machine: 
- claret
#### traffic source interface: 
- 0000:3b:00.1

#### other dependencies: 
- scapy
#### description: 
1. in runmode-dpdk.c in function PortConfSetRSSConf disable (comment / remove):
            - ".rss_hf" attribue of port_conf->rx_adv_conf.rss_conf
            - call of function "DeviceSetPMDSpecificRSS(&port_conf->rx_adv_conf.rss_conf, dev_driver);"
            - defining of "port_conf->rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;"
    
2. run suricata and udp_gen_sym.py
    
3. check packet distrbution between queues in suricata.log

4. To check results with rss turned off:
    in source-dpdk.c in function DevicePostStartPMDSpecificActions disable (comment / remove): 
        - "if (strcmp(driver_name, "net_ice") == 0)
            iceDeviceSetRSS(ptv->port_id, ptv->threads);"

5. run suricata and udp_gen_sym.py

6. check packet distrbution between queues in suricata.log
    
#### result: 
 - As shown in step 3. packets are distributed with RSS on all queues, meanwhile packets in step 6. are sent only to 1 queue (RSS turned off)

- The only thing that is set with RSS legacy API is hash key and hash key length, otherwise the rss is done via rte_flow rules

## test_2: 
### goal: 
- suricata - distribution throughout queues with no rss VS legacy RSS API VS rte_flow RSS

#### suricata machine: 
- claret
#### suricata NIC driver: 
- ice
#### suricata interface: 
- 0000:af:00.1

#### traffic source machine: 
- claret
#### traffic source interface: 
- 0000:3b:00.1

#### other dependencies: 
- scapy
#### description: 
- As shown in test_1, rte_flow rules have higher priority than legacy API in packet processing

1. run suricata and udp_gen_4_flows.py

2. check packet distrbution between queues in suricata.log
    - 2 queues should be used evenly
    - other queues are empty
    
3. To check results with rte_flow rss turned off: (the legacy API supports hashing only based off IP adresses, not UDP ports)
    in source-dpdk.c in function DevicePostStartPMDSpecificActions disable (comment / remove): 
        - "if (strcmp(driver_name, "net_ice") == 0)
            iceDeviceSetRSS(ptv->port_id, ptv->threads);"

4. run suricata and udp_gen_4_flows.py

5. check packet distrbution between queues in suricata.log
    - 2 queues should be used evenly
    - other queues are empty

6. to disable RSS alltogether:
    in runmode-dpdk.c in function DeviceInitPortConf disable (comment / remove):
        - function call "PortConfSetRSSConf(iconf, dev_info, port_conf);"

7. run udp_gen_flows.py

8. check packet distrbution between queues in suricata.log
    - only 1 queue should be used
    - other queues are empty
    
#### result: 
- The results show that rss is working the same with legacy RSS API and rte_flow RSS

## test_3: 
### goal: 
- suricata - different distribution on rx_queues based on hash type of RSS

#### suricata machine: 
- claret
#### suricata NIC driver: 
- ice
#### suricata interface: 
- 0000:af:00.1
#### suricata workers: 
- more than 2 (for example [2,4,6,8])

#### traffic source machine: 
- claret
#### traffic source interface: 
- 0000:3b:00.1

#### other dependencies: 
- scapy
#### description: 

1. run suricata and udp_gen_4_flows.py

2. RSS with hashing based on only on IP adresses: check packet distrbution between queues in suricata.log
    - 2 queues should be used evenly
    - other queues are empty
    
3. To check results with RSS with hashing based on IP and UDP ports:
    - go to function DeviceSetRSSFlowIPv4UDP in util-dpdk-rss.c
    - in function call "DeviceCreateRSSFlow(port_id, port_name, rss_conf, RTE_ETH_RSS_IPV4, pattern, nb_rx_queues);"
    change "RTE_ETH_RSS_IPV4" for "RTE_ETH_RSS_NONFRAG_IPV4_UDP"

4. run suricata and udp_gen_4_flows.py

5. check packet distrbution between queues in suricata.log
    - 2 queues should be used heavily
    - other queues should be used evenly with less traffic on them

### result: 
- The results show that RSS distributes packets differently based on different hashing types used on packets