'''
Packet sniffer in python using the pcapy python library
 
Project website
http://oss.coresecurity.com/projects/pcapy.html
'''
import socket
from struct import *
import datetime
import pcapy
import sys
import datetime
from threading import Thread
from time import sleep
import subprocess
import atexit
import os

# Config vars
block_address_ipv4 = "0.0.0.0"
block_address_ipv6 = "fd00"

block_address_ipv4_bytes = None
block_address_ipv6_bytes = None

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class Request:
	def __init__(self,packet):
		self.transaction_id = unpack(">H", packet[0:2])[0]
		self.flags = bin(unpack(">H", packet[2:4])[0])[2:]
		self.nQuestions = unpack(">H", packet[4:6])[0]
		self.nAnswerRRs = unpack(">H", packet[6:8])[0]
		self.AuthorityRRs = unpack(">H", packet[8:10])[0]
		self.AdditionalRRs = unpack(">H", packet[10:12])[0]
		rest = packet[12:]
		endQuery = rest.index(b'\x00')+1
		self.Query = rest[:endQuery]
		self.Type = unpack(">H", rest[endQuery:endQuery+2])[0]
		self.Class = unpack(">H", rest[endQuery+2:endQuery+4])[0]
		self.RequestLength = 12+len(self.Query)+4

class Answer:
	def __init__(self, answer_block):
		self.Name = unpack(">H", answer_block[0:2])[0] # pretty much always c0 0c
		self.Type = unpack(">H", answer_block[2:4])[0]
		self.Class = unpack(">H", answer_block[4:6])[0]
		self.Ttl = unpack(">I", answer_block[6:10])[0]
		self.DataLength = unpack(">H", answer_block[10:12])[0] if len(answer_block) >= 12 else 0
		self.AnswerLength = 12+self.DataLength
		self.Address = answer_block[12:self.AnswerLength] if self.DataLength > 0 else ''

class Response(Request):
	blocked_or_empty = False

	def __init__(self, packet):
		Request.__init__(self, packet)
		if self.flags[0] != '1': 
			raise TypeError("Packet is not a response")
		answer_block = packet[self.RequestLength:]
		self.Answers = []
		if len(answer_block) == 0:
			self.blocked_or_empty = True
		else:
			while len(answer_block) > 0:
				answer = Answer(answer_block)
				answer_block = answer_block[answer.AnswerLength:]
				self.Answers.append(answer)

	def is_blocked(self):
		self.blocked_or_empty = True
		for a in self.Answers:
			self.blocked_or_empty = not(any(a.Address))
			if not self.blocked_or_empty:
				if a.Type == 1:
					result = a.Address.startswith(block_address_ipv4_bytes.encode())
					self.blocked_or_empty = result
					#return (a.Address[0] == '\xc0' and a.Address[1] == '\xa8')
				elif a.Type == 28:
					result = a.Address.startswith(block_address_ipv6_bytes.encode())
					self.blocked_or_empty = result
					#return a.Address[1] == '\x00' and (a.Address[0] == '\xfc' or a.Address[0] == '\xfd')
		return self.blocked_or_empty

class MyDict:
	def __init__(self):
		self.d = {}
		self.lastdraw = datetime.datetime.now()
		self.nUrls = 0

	def hit(self, url, blocked):
		if not url in self.d.keys() :
			self.d.update({url: {'hits': 0, 'lastupdate':  datetime.datetime.now(), 'blocked':blocked}})
			self.nUrls +=1
		self.d[url]['hits'] += 1
		self.d[url]['lastupdate'] = datetime.datetime.now()
		self.d[url]['blocked'] = blocked
		
	def draw(self):
		epoch = datetime.datetime.utcfromtimestamp(0)
		l = []
		blocks = 0
		for k in self.d.keys():
			if self.d[k]['blocked']: blocks+=1
			l.append( [k, self.d[k]['hits'], self.d[k]['lastupdate'], self.d[k]['blocked'] ] )
		l = sorted(l, key=lambda tpl: (tpl[2]-epoch).total_seconds(), reverse=True )
		
		print( "{0}/{1} blocked ({2}%) [DNS packets: {3}]".format(blocks, self.nUrls, int((float(blocks)/self.nUrls)*100) if blocks > 0 else 0, packets_filtered ) )
		print( bcolors.BOLD + "[{0:26}] [{1:7}] ({2}) | {3}".format("TIMESTAMP", "STATUS", "HITS", "DOMAIN") + bcolors.ENDC )
		i = -1
		for line in l:
			i+=1
			pl=""
			if line[2] > self.lastdraw: pl += bcolors.UNDERLINE
			if line[3]: pl += bcolors.FAIL
			else: pl += bcolors.OKGREEN
			pl += "[{0:26}] [{3}] ({1:4}) | {2}".format(str(line[2]), line[1], line[0], "BLOCKED" if line[3] else "ALLOWED" ) + bcolors.ENDC
			print( pl )
			
			if i == 15:
				break
		self.lastdraw = datetime.datetime.now()

packets_filtered =0
urldict = MyDict()

ovpn_process = None

def print_ovpn_status():
	# check if openvpn is running
	is_process_running = ovpn_process.poll() == None
	print( bcolors.BOLD + "{0}VPN STATUS: {1}".format(bcolors.OKGREEN if is_process_running else bcolors.FAIL, "RUNNING" if is_process_running else "STOPPED") + bcolors.ENDC )
		

def prep_block_address():
	global block_address_ipv4_bytes
	global block_address_ipv6_bytes

	addr_arr4 = block_address_ipv4.split('.')
	hexArr4 = ""
	for c in addr_arr4:
		if c == '*':
			continue
		hexArr4 += chr(int(c))
	block_address_ipv4_bytes = hexArr4

	addr_arr6 = block_address_ipv6.split(':')
	for block in addr_arr6:
		hexArr6 = ""
		byte1 = block[2:]
		byte2 = block[:2]
		hexArr6 += chr(int(byte2, 16))
		hexArr6 += chr(int(byte1, 16))
	block_address_ipv6_bytes = hexArr6

def draw():
	os.system("clear")
	#print_ovpn_status()
	urldict.draw()
		
def main(argv):
	prep_block_address()
	#start_ovpn()
	
	sleep(10)
	tL = []
	devices = pcapy.findalldevs()
	 
	#start sniffing packets
	for d in devices:
		print( "Found device : " + d )
		if 'eth' in d:
			print(f"Starting packet filter on {d}.")
			t = Thread(target=open_device, args=(d,) )
			t.start()	
			tL.append(t)

	while(len(tL) > 0):
		sleep(5)
		draw()
			

def open_device(dev):
	'''
	open device
	# Arguments here are:
	#   device
	#   snaplen (maximum number of bytes to capture _per_packet_)
	#   promiscious mode (1 for true)
	#   timeout (in milliseconds)
	'''
	cap = pcapy.open_live(dev , 65536 , 1 , 0)
	cap.setfilter("src port 53") 
	while(1) :
		(header, packet) = cap.next()
		parse_packet(packet)

#function to parse a packet
def parse_packet(packet) :
	global urldict
	global packets_filtered
	packets_filtered += 1
	 
	#parse ethernet header
	eth_length = 14
	 
	eth_header = packet[:eth_length]
	eth = unpack('!6s6sH' , eth_header)
	eth_protocol = socket.ntohs(eth[2])
	
	#Parse IP packets, IP Protocol number = 8
	if eth_protocol == 8 :
		#Parse IP header
		#take first 20 characters for the ip header
		ip_header = packet[eth_length:20+eth_length]
		 
		#now unpack them :)
		iph = unpack('!BBHHHBBH4s4s' , ip_header)
 
		version_ihl = iph[0]
		version = version_ihl >> 4
		ihl = version_ihl & 0xF
 
		iph_length = ihl * 4
 
		ttl = iph[5]
		protocol = iph[6]
		s_addr = socket.inet_ntoa(iph[8]);
		d_addr = socket.inet_ntoa(iph[9]);
 

		#UDP packets
		if protocol == 17 :
			u = iph_length + eth_length
			udph_length = 8
			udp_header = packet[u:u+8]
 
			#now unpack them :)
			udph = unpack('!HHHH' , udp_header)
			 
			source_port = udph[0]
			dest_port = udph[1]
			length = udph[2]
			checksum = udph[3]
			 
			h_size = eth_length + iph_length + udph_length
			data_size = len(packet) - h_size
	
			if not source_port == 53: return
			 
			#get data from the packet
			try:
				data = packet[h_size:]
				r = Response(data)
				data_mapped = "".join(map(datafilter, r.Query))
				blocked_or_empty = r.blocked_or_empty or r.is_blocked()
				urldict.hit(data_mapped.strip('.'), blocked_or_empty)
			except TypeError as e:
				print(e)
				pass
		#some other IP packet like IGMP
		else :
			print( 'Protocol other than UDP.' )
			 
 
def datafilter(c):
  char_c = str(chr(c))
  if char_c.lower() not in "qwertyuiopasdfghjklzxzcvbnm":
    return '.'
  return char_c

if __name__ == "__main__":
  main(sys.argv)