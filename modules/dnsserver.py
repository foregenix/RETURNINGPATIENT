from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from operator import attrgetter
import socket
import struct
import serverlogic
import binascii
import threading
import os
import serverlogic
import sys
import signal

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class DNSMessage:
	def __init__(self,packet_id,content):
		self.packet_id=packet_id
		self.content=content
class DNSPacket:
	
	def __init__(self,transaction_id,host,message,packet_id,packet_number):
		self.transaction_id=transaction_id
		self.host=host
		self.message=message
		self.packet_id=packet_id
		self.packet_number=packet_number

		

class DNSPacketQueue:
	
	def __init__(self):
		self.packetList=[]
	
	def hostExists(self, host):
		pos=-1
		for i in self.packetList:				
			current_host=i.host
			if host==current_host: 
				pos+=1
				break
		return pos

	def addMessage(self,packet):
		corrected_packet=DNSPacket(packet.transaction_id,packet.host,packet.message[4:].replace('.',''),packet.packet_id,packet.packet_number)
		if self.isMessageNew(corrected_packet.host,corrected_packet.packet_id,corrected_packet.message):
			self.packetList.append(corrected_packet)
			return True
		return False

	def isMessageNew(self,host,packet_id,message):
		for packet in self.packetList:
			if (packet.host==host and packet.packet_id==packet_id and packet.message==message):
				return False
		return True

	def getHostPacketNumbers(self,host,packet_id):		
		packetsForHost = []		
		for i in self.packetList:									
			if i.host==host and i.packet_id==packet_id:									
				packetsForHost.append(i.packet_number)
		return packetsForHost

	def getHostPackets(self,host,packet_id):
		packetsForHost = []
		for i in self.packetList:
			
			if i.host==host and i.packet_id==packet_id:	
				packetsForHost.append(i)				
		return packetsForHost
			
	def isComplete(self,host,packet_id):		
		messages=self.getHostPacketNumbers(host,packet_id)	
		comp=	len(messages)==(max(messages))+1
		return comp
	
	def getCompleteMessage(self,host,packet_id):
		message=""
		packets=self.getHostPackets(host,packet_id)
		for i in packets:
			message+=i.message
		return message.replace('.','')

	def removeIDperHost(self,host,packet_id):
		for i in range(len(self.packetList)-1,-1,-1):
			if (host==self.packetList[i].host and packet_id==self.packetList[i].packet_id):
				del self.packetList[i]
	
	def getAll(self):
		return self.packetList

	def count(self):
		return len(self.packetList)
			


class DNSHandler(DatagramProtocol):
	compute=None
	packets = DNSPacketQueue()
	domain=""
	ip=""
		
	
	def datagramReceived(self,data,addr):
		host=addr[0]		
		if data:
			new_packet=self.parsePacket(data,host)			
			self.packets.addMessage(new_packet)
			if self.packets.isComplete(host,new_packet.packet_id):
				complete_message=self.packets.getCompleteMessage(host,new_packet.packet_id)
				dns_message= DNSMessage(new_packet.packet_id,complete_message)
				self.packets.removeIDperHost(host,dns_message.packet_id)
				response=self.compute.read(dns_message.content,dns_message.packet_id)
				if response!=None:
					try:
						resp=self.write_response(new_packet,response)
						response_packet=binascii.unhexlify(resp)
						self.transport.write(response_packet,addr)
					except Exception as e:
						print("DEBUG: ",str(e))
			else:
				resp=self.dummy_reply(new_packet)
				dummy_packet=binascii.unhexlify(resp)
				self.transport.write(dummy_packet,addr)

	def get_next_label_length(self,content,index):
		_label_length_tuple=struct.unpack("!B",bytes([content[index]]))
		_label_length=_label_length_tuple[0]
		return _label_length

	def parsePacket(self,dnspacket,host):
		header_str=dnspacket[:12]
		header=struct.unpack("!HHHHHH",header_str) #We want to read the header (first 6 bytes) as short numbers, we don't care about the rest now
		transaction_id=header[0]
		query_count=header[2]	
		content=dnspacket[12:] # we remove the headers, this leave us with query_count*messages	
		query=1
		c=0
		total=""
		packet_id=int(chr(content[1])+chr(content[2]),16)
		packet_counter=int(chr(content[3])+chr(content[4]),16)
		while (query<=query_count) :
			label_length=self.get_next_label_length(content,c)
			message=""
			c+=1		
			if label_length>0:			
				label=""			
				for x in range(c,c+label_length):
					label=label+chr(content[x])
				message+=label+'.'
				c+=label_length			
			else: 	
				message+='.'
				query+=1
				c+=4 #we Discard QTYPE and QCLASS	
			total+=message
		new_packet=DNSPacket(transaction_id,host,total,packet_id,packet_counter)
		return new_packet

	def dummy_reply(self,packet):
		try:
			transaction_id=format(packet.transaction_id, '04x')
			flags="81800001"
			queries=packet.message.split("..")
			labels=queries[0].split('.')
			formatted_query=""
			for label in labels:
				formatted_query+=format(len(label),'02x')
				formatted_query+=label.encode("utf-8").hex()
			formatted_query+="00"
			answers="0001"
			authority_answers="0000"
			other_answers="0000"
			type_class="00010001"
			name="c00c"
			resp_type_class="00010001"
			resp_ttl="00000001"
			len_ip="0004"
			ip_hex=""
			ip=self.ip.split('.')
			for octet in ip:
				ip_hex+=format(int(octet),'02x')
			message=transaction_id+flags+answers+authority_answers+other_answers+formatted_query+type_class+name+resp_type_class+resp_ttl+len_ip+ip_hex
			return message
		except :
			return ""

	def write_response(self, packet,response):
		try:
			transaction_id=format(packet.transaction_id, '04x')
			flags="81800001"
			queries=packet.message.split("..")
			labels=queries[0].split('.')
			formatted_query=""
			for label in labels:
				formatted_query+=format(len(label),'02x')
				formatted_query+=label.encode("utf-8").hex()
			formatted_query+="00"
			answers="0001"
			authority_answers="0000"
			other_answers="0000"
			type_class="00100001"
			name="c00c"
			resp_type_class="00100001"
			resp_ttl="00000001"
			len_response=format(len(response),'02x')
			len_plusone=format(len(response)+1,'04x')
			message=transaction_id+flags+answers+authority_answers+other_answers+formatted_query+type_class+name+resp_type_class+resp_ttl+len_plusone+len_response+response.hex()
			return message
		except Exception as e:
			print("DEBUG: write_response error: ",str(e))

	def split_len(self,seq,length):
		return [seq[i:i+length] for i in range(0,len(seq),length)]


def exit_gracefully(signum, frame):
	reactor.stop()
	raise(SystemExit)

if __name__ == '__main__':
		signal.signal(signal.SIGTERM,exit_gracefully)
		store=sys.argv[1]
		ip=sys.argv[2]
		port=sys.argv[3]
		log_path=sys.argv[4]
		log_level=sys.argv[5]
		handler=DNSHandler()
		handler.ip=ip
		handler.compute=serverlogic.logic(store,log_path,log_level)
		reactor.listenUDP(int(port),handler,ip,1024)
		reactor.run()


