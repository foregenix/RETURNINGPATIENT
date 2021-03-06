# -*- coding: utf-8 -*-
@auth.requires_login()
def index():
    rows=db(db.hosts.campaign_id>0).select(db.hosts.id,db.hosts.name)
    return locals()

@auth.requires_login()
def add():
    session.host_id=request.args(0,cast=int)
    if (session.campaign_id is None):
        redirect(URL('hosts','index'))
    else:
        if (session.host_id is None):
            redirect(URL('campaigns','show',args=session.campaign_id))
        else:
            db(db.hosts.id==session.host_id).update(campaign_id=session.campaign_id)
            redirect(URL('campaigns','show',args=session.campaign_id))
@auth.requires_login()
def remove():
    session.host_id=request.args(0,cast=int)
    if (session.campaign_id is None):
        redirect(URL('hosts','index'))
    else:
        if (session.host_id is None):
            redirect(URL('campaigns','show',args=session.campaign_id))
        else:
            db(db.hosts.id==session.host_id).update(campaign_id=0)
            redirect(URL('campaigns','show',args=session.campaign_id))
@auth.requires_login()
def show():
    session.host_id=request.args(0,cast=int)
    error_message=session.error_message
    session.error_message=""
    command_result=None
    host=db(db.hosts.id==session.host_id).select(db.hosts.id,db.hosts.campaign_id,db.hosts.name,db.hosts.last_seen,db.hosts.terminated).first()
    if (host is not None):
        if (host.campaign_id==0):
            campaign_name="Unassigned"
        else:
            campaign_name=db(db.campaign.id==host.campaign_id).select(db.campaign.name).first().name
        db.next_commands.timestamp.default=request.now
        db.next_commands.host_id.default=session.host_id
        db.next_commands.state.default="PENDING"
        command_form=SQLFORM(db.next_commands,submit_button="Add to Queue").process()
    next_commands=db(db.next_commands.host_id==session.host_id).select(db.next_commands.id,db.next_commands.next_command,db.next_commands.state,db.next_commands.timestamp)
    executed_commands=db(db.executed_commands.host_id==session.host_id).select(db.executed_commands.id,db.executed_commands.command,db.executed_commands.timestamp)
    if (session.command_id is not None):
        command=db(db.executed_commands.id==session.command_id).select(db.executed_commands.result).first()
        if (command is not None):
            command_result=command.result
            session.command_id=None
    return locals()

@auth.requires_login()
def queue():
    next_commands=db(db.next_commands.host_id==session.host_id).select(db.next_commands.id,db.next_commands.next_command,db.next_commands.state,db.next_commands.timestamp)
    return locals()

@auth.requires_login()
def executed():
    executed_commands=db(db.executed_commands.host_id==session.host_id).select(db.executed_commands.id,db.executed_commands.command,db.executed_commands.timestamp)
    return locals()


@auth.requires_login()
def showcommandresult():
    session.command_id=request.args(0,cast=int)
    redirect(URL('show',args=session.host_id))
