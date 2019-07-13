#!/usr/bin/env python3

import scapy.all as scapy

def scan(ip):

    arp_request = scapy.ARP(pdst=ip)  # the name of the argument pdst is got by scapy.ls(scapy.ARP())
    #arp_request.show()

    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # the name of the argument dst is got by scapy.ls(scapy.Ether())
    #broadcast.show()

    arp_request_broadcast = broadcast/arp_request # scapy 's method to assemble frames
    #arp_request_broadcast.show()

    answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout=1,verbose=False) # srp function to send and receive packets

    # print(answered_list.summary())

    print("IP\t\t\tMAC Address\n-----------------------------------------------")

    clients_list = []

    for element  in answered_list:
        clients_dic = {"ip":element[1].psrc, "mac":element[1].hwsrc}
        clients_list.append(clients_dic)

    return clients_list

def print_result(result_list):
    print("IP\t\t\tMAC Address\n----------------------------------------------------")
    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])


scan_result = scan("10.0.2.1/24")
print_result(scan_result)