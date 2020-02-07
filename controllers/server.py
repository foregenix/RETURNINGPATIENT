# -*- coding: utf-8 -*-
import os
import platform
import psutil
import base64
import signal
from Cryptodome import Random
from Cryptodome.PublicKey import RSA
from Cryptodome.Util import number
from subprocess import Popen, PIPE, STDOUT


@auth.requires_login()
def index():
    error_message=session.error_message
    session.error_message=""
    log_path=db(db.settings.name=="SERVER_LOGS").select(db.settings.value).first().value
    app_folder=request.folder
    showing_folder=log_path.replace(app_folder,".")
     ##CHECK IF A SERVER IS RUNNING##
    is_server_running=False
    pid=db(db.server).select(db.server.server_PID).first()
    if (pid is not None):
        server_pid=int(pid.server_PID)
        if (server_pid>0):
            if (psutil.pid_exists(int(server_pid))):
                is_server_running=True
    else:
        server_pid=-1
    server=db.server(1)
    db.server.custom_listening_ip.show_if=(db.server.listening_ip=="Custom IP")
    server_form=SQLFORM(db.server,server,showid=False,submit_button="Submit",_id='detailsform').process()
    if server_form.accepted:
        if server_form.vars.listening_ip!="Custom IP":
                server_form.vars.custom_listening_ip=None
        redirect(URL('index'))
    try:
        textarea_logs=""
        with open(log_path) as f:
            logs=(f.readlines())
        for log in logs:
            textarea_logs+=log.replace('\n','&#13;&#10;')
    except IOError:
        logs="Log file not accessible"
    return locals()

@auth.requires_login()
def start():
    serverlib=local_import('serverprocess')
    server=serverlib.serverprocess
    is_server_running=False
    pid=db(db.server).select(db.server.server_PID).first()
    if (pid is not None):
            server_pid=int(pid.server_PID)
            if (server_pid>0):
                if (psutil.pid_exists(int(server_pid))):
                    is_server_running=True
    else:
        server_pid=-1
    if (is_server_running==False):
            details=db(db.server).select().first()
            if (details is not None):
                ip=details.custom_listening_ip
                if (ip is None):
                    ip=details.listening_ip
                    if (ip=="Custom IP"):
                        session.error_message="Please select an IP address or specify a custom one"
                        redirect(URL('index'))
                port=details.port
                if (ip is None):
                    session.error_message="Please specify the IP address of the local interface to listen on"
                    redirect(URL('index'))
                elif (port is None):
                    session.error_message="There is an error with the application settings. Please contact the administrator"
                    redirect(URL('index'))
                else:
                    port=int(port)
                    key=details.privkey
                    if (key is None):
                        pkey=RSA.generate(4096,Random.new().read)
                        key=pkey.exportKey('PEM')
                        db(db.server).update(privkey=key)
                    details=db(db.server).select().first()
                    key=details.privkey
                    pkey=RSA.import_key(key)
                    db(db.campaign_details).update(keye=str(base64.b64encode(number.long_to_bytes(pkey.publickey().e))))
                    db(db.campaign_details).update(keyn=str(base64.b64encode(number.long_to_bytes(pkey.publickey().n))))
                    log_path=db(db.settings.name=="SERVER_LOGS").select(db.settings.value).first().value
                    log_level=details.log_level
                    if log_level is None:
                        log_level=="INFO"
                    python=db(db.settings.name=="PYTHON").select(db.settings.value).first().value
                    if (platform.system()=='Linux'):
                        server_process=Popen(["sudo",python,server_path, db_path, str(ip),str(port),log_path,log_level],stderr=PIPE)
                    else:
                        server_process=Popen([python,server_path, db_path, str(ip),str(port),log_path,log_level],stderr=PIPE)
                    try:
                        o, e = server_process.communicate(timeout=5)
                    except:
                        e=""
                    if (e==""):
                        server_pid=server_process.pid
                        db(db.server).update(server_PID=server_pid)
                    else:
                        session.error_message=e
                        #do something
            redirect(URL('index'))
    else:
        session.error_message="There is already a server running"
        redirect(URL('index'))

@auth.requires_login()
def stop():
    is_server_running=False
    pid=db(db.server).select(db.server.server_PID).first()
    if (pid is not None):
            server_pid=int(pid.server_PID)
            if (server_pid>0):
                if (psutil.pid_exists(int(server_pid))):
                    is_server_running=True
    if (is_server_running):
        try:
            os.kill(int(server_pid),signal.SIGTERM)
            os.wait()
            if (psutil.pid_exists(int(server_pid))==False):
                db(db.server).update(server_PID=-1)
        finally:
                redirect(URL('index'))
    redirect(URL('index'))
