@auth.requires_login()
def index():
    session.host_id=request.args(0,cast=int)
    error_message=session.error_message
    session.error_message=""
    command_result=None
    host=db(db.hosts.id==session.host_id).select(db.hosts.id,db.hosts.campaign_id,db.hosts.name,db.hosts.last_seen).first()
    db.next_commands.timestamp.default=request.now
    db.next_commands.host_id.default=session.host_id
    db.next_commands.state.default="PENDING"
    db.next_commands.next_command.default="terminate"
    db.next_commands.next_command.readable=False
    db.next_commands.next_command.writable=False
    yes_button=SQLFORM(db.next_commands,submit_button="YES")
    if yes_button.accepts(request, session):
        db(db.hosts.id == session.host_id).update(terminated = "True")
        redirect(URL('hosts','show', args=(session.host_id)))

    return locals()
