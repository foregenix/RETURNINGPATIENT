@auth.requires_login()
def send():
    session.host_id=request.args(0,cast=int)
    error_message=session.error_message
    session.error_message=""
    command_result=None
    host=db(db.hosts.id==session.host_id).select(db.hosts.id,db.hosts.campaign_id,db.hosts.name).first()
    host_name=host.name
    if (host.campaign_id==0):
            campaign_name="Unassigned"
    else:
            campaign_name=db(db.campaign.id==host.campaign_id).select(db.campaign.name).first().name
    if (host_name is not None and host_name!="Unregistered Host"):
        number_of_files=db(db.next_files.host_id==session.host_id).count()
        db.next_files.file_name.readable=False
        db.next_files.timestamp.default=request.now
        db.next_files.host_id.default=session.host_id
        db.next_files.direction.default=0
        db.next_files.insecure.default=True
        db.next_files.insecure.writable=False
        db.next_files.state.default="PENDING"
        db.next_files.remote_path.default="AUTO"
        send_file_form=SQLFORM(db.next_files,submit_button="Send File",showid=False,upload=URL('upload'),fields=['uploaded_file', 'remote_path','turbo','insecure','execute'])
        send_file_form.element('textarea[name=remote_path]')['_rows'] = '1'
        if request.vars.uploaded_file != None:
            send_file_form.vars.file_name = request.vars.uploaded_file.filename
        if send_file_form.accepts(request, session):
            response.flash = 'form accepted'
    else:
        redirect(URL('hosts','index'))
    return locals()

@auth.requires_login()
def list():
    session.host_id=request.args(0,cast=int)
    queued_files=db(db.next_files.host_id==session.host_id).select(db.next_files.id,db.next_files.file_name,db.next_files.remote_path,db.next_files.state,db.next_files.timestamp)
    return locals()
