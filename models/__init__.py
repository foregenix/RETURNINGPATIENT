# -*- coding: utf-8 -*-
import os
import stat

serverScript="dnsserver.py"
serverScriptFolder="modules"
dbFolder="databases"
dbFile="storage.sqlite"
server_script_path=os.path.join(request.folder,"modules","dnsserver.py")
st = os.stat(server_script_path)
os.chmod(server_script_path, st.st_mode | stat.S_IEXEC)
server_path=os.path.join(request.folder,serverScriptFolder,serverScript)
db_path=os.path.join(request.folder,dbFolder,dbFile)
