# -*- coding: utf-8 -*-
# this file is released under public domain and you can use without limitations

# ----------------------------------------------------------------------------------------------------------------------
# this is the main application menu add/remove items as required
# ----------------------------------------------------------------------------------------------------------------------

response.menu = [
    (T('Home'), False, URL('default', 'index'), []),
    (T('All Campaigns'), False, URL('campaigns', 'index'), []),
    (T('All Hosts'), False, URL('hosts', 'index'), []),
    (T('Server Status'), False, URL('server', 'index'), [])
]
if auth.has_membership(role="admin"):
    response.menu.extend([(T('App Admin'), False, URL(c='appadmin'), [])])

# ----------------------------------------------------------------------------------------------------------------------
# provide shortcuts for development. you can remove everything below in production
# ----------------------------------------------------------------------------------------------------------------------
