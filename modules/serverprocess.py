import os
import subprocess
import psutil
import logging

class constants:
	serverScript="dnsserver.py"
	serverScriptFolder="modules"
	serverPath=""
	python="python3"
	

class serverprocess:	
	
	@staticmethod
	def path(app_path):
		return 
	@staticmethod
	def start(app_path,ip,port,domain):
		if (app_path is not ""):
			serverPath=serverprocess.path(app_path)
			server_process=subprocess.Popen([constants.python,serverPath, str(ip),str(port),str(domain)],stdin='/dev/null', stdout='/dev/null', stderr='/dev/null')	
			pid=server_process.pid
			server_process=None		
			return 	pid
		return -1

	@staticmethod
	def check(pid):	
		try:			
			if (psutil.pid_exists(int(pid))):
				return 0
			else:
				return -1
		except Exception as e:
			return str(e)
		
	@staticmethod
	def kill(pid):
		try:
			if (serverprocess.check(pid)==0):
				p=psutil.Process(int(pid))
				p.terminate()
				#gone, alive = psutil.wait_procs(p, timeout=3, callback=on_terminate)
				#for p in alive:
				p.kill()			
				return 0
			return -1
		except Exception as e:
			return str(e)

