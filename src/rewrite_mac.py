#! /usr/bin/env python

from scapy.all import *

bind_layers(UDP, ISAKMP, sport=500)
bind_layers(UDP, ISAKMP, dport=501)

mac_sut = '08:00:27:78:bf:be'

#
#  ip_sut                      ip_fuzzer
#  WIN7 |--------------------> Linux VM
#                                 |
#                                 |
#                                 \/
#                              Local machine
#                              ip_local
#  

while True:
   pkts = sniff(filter='port 500', count=1)
   try:
     if pkts[0][Ether].dst != mac_sut:
        try:
           del pkts[0][ISAKMP_payload_Transform].length
        except AttributeError:
           print 'Not ISAKMP_payload_Transform payload'
        pkt=pkts[0]
        pkt[Ether].dst = mac_sut
        del pkt[UDP].len
        sendp(pkt)
        print(pkt.command())
   except AttributeError:
      print 'AttributeError'
